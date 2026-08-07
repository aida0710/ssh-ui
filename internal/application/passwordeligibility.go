package application

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"sshc/internal/effective"
	"sshc/internal/knownhosts"
)

// ホストと保存されたパスワードとの間に立ちはだかるものを表す code である。
const (
	// BlockerPasswordAuthenticationOff は、このホストに PasswordAuthentication
	// no が設定されていることを報告する。これはクライアント側の設定なので、
	// クライアントはどれほど良いパスワードでも決して提示しない。それを保存
	// することは、使えない秘密を保存することになり、両方の意味で最悪である。
	BlockerPasswordAuthenticationOff = "password_authentication_off"
	// BlockerAliasNotSimple は、ホストではなく pattern であることを報告する。パスワードは
	// 1 台のマシンの 1 個のアカウントに属するものであり、`*`にはそのようなものは存在しない。
	BlockerAliasNotSimple = "alias_not_simple"
	// WarnIdentityFileConfigured は、このホストに既に鍵が設定されている
	// ことを報告する。それでもパスワードを尋ねてくる可能性はある——その鍵が
	// 向こう側で認可されていないかもしれない——のでこれは block しないが、決してパスワードを
	// 尋ねてこないホストのために保存されたパスワードは、何の見返りもない露出である。
	WarnIdentityFileConfigured = "identity_file_configured"
	// WarnHostKeyUnknown は、known_hosts にこのホストの情報が何もないことを
	// 報告する。したがって最初の接続は鍵を信頼するかどうかを尋ねることに
	// なり、このアプリケーションはユーザーに代わってその問いに答えることを
	// 拒否するので、接続はパスワードが使われないままそこで止まる。
	WarnHostKeyUnknown = "host_key_unknown"
	// WarnHostNameUnresolved は、engine が HostName を特定できなかったことを
	// 報告する。パスワードはいずれにせよ alias の下に保存されるので、
	// これは推測せずに言明される。
	WarnHostNameUnresolved = "hostname_unresolved"
)

// PasswordEligibility は、何も保存する前に、このアプリケーションが
// 1 個の alias のパスワード保存について知っていることである。
//
// Blocker と Warning は意図的に分けて扱われている。blocker は保存した
// パスワードを使えなくする事実であり、その場合拒否することは制限では
// なくむしろ親切である。warning はユーザーの方がよく知っているかもしれ
// ない事実である——設定されてはいるが向こう側で認可されていない鍵は
// 普通の状況である——ので、これは言明され、判断はそれが属する場所に委ねられる。
type PasswordEligibility struct {
	Alias    string   `json:"alias"`
	Storable bool     `json:"storable"`
	Blockers []Notice `json:"blockers"`
	Warnings []Notice `json:"warnings"`
	HostName string   `json:"hostName,omitempty"`
	Port     string   `json:"port,omitempty"`
}

// PasswordEligibility は設定と known_hosts を読み、この alias と保存された
// パスワードとの間に立ちはだかるものを報告する。
//
// これは読むだけである。書き込むことも、接続することも、ssh を実行する
// ことも決してない。ここでのすべては、このアプリケーションが既に
// パースしているファイルから答えられるものであり、パスワードを保存すべきか
// 判断するために接続を開くようなチェックは、ユーザーが求めていない接続になってしまう。
func (s *Service) PasswordEligibility(alias string) (PasswordEligibility, error) {
	report := PasswordEligibility{
		Alias:    alias,
		Blockers: []Notice{},
		Warnings: []Notice{},
	}
	if err := ValidateAlias(alias); err != nil {
		report.Blockers = append(report.Blockers, Notice{Code: BlockerAliasNotSimple, Detail: alias})
		return report, nil
	}

	graph, err := s.resolve()
	if err != nil {
		return PasswordEligibility{}, err
	}
	projection := effective.Project(graph, alias)

	if source, ok := projection.Value("PasswordAuthentication"); ok {
		if strings.EqualFold(strings.TrimSpace(source.Value), "no") {
			report.Blockers = append(report.Blockers, Notice{
				Code: BlockerPasswordAuthenticationOff,
				Path: s.displayPath(source.Path), Line: source.Line,
			})
		}
	}
	if source, ok := projection.Value("IdentityFile"); ok {
		report.Warnings = append(report.Warnings, Notice{
			Code: WarnIdentityFileConfigured,
			Path: s.displayPath(source.Path), Line: source.Line, Detail: source.Value,
		})
	}

	host := alias
	if source, ok := projection.Value("HostName"); ok && strings.TrimSpace(source.Value) != "" {
		host = strings.TrimSpace(source.Value)
	} else {
		report.Warnings = append(report.Warnings, Notice{Code: WarnHostNameUnresolved, Detail: alias})
	}
	report.HostName = host
	if source, ok := projection.Value("Port"); ok {
		if _, err := strconv.Atoi(strings.TrimSpace(source.Value)); err == nil {
			report.Port = strings.TrimSpace(source.Value)
		}
	}

	known, err := s.hostKeyIsKnown(host, report.Port)
	if err != nil {
		return PasswordEligibility{}, err
	}
	if !known {
		report.Warnings = append(report.Warnings, Notice{Code: WarnHostKeyUnknown, Detail: host})
	}

	report.Storable = len(report.Blockers) == 0
	return report, nil
}

// hostKeyIsKnown は、known_hosts が既にこのホストの鍵を保持しているかを報告する。
//
// デフォルト以外のポートは known_hosts に`[host]:port`の形で書かれるので、
// 両方の形を試す。ファイルが無いことはエラーではない。それはどこにも
// まだ接続したことのないマシンの通常の状態であり、答えは単純に no である。
func (s *Service) hostKeyIsKnown(host, port string) (bool, error) {
	body, err := s.workspace.FileSystem().ReadFile(filepath.Join(s.workspace.Root(), "known_hosts"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	candidates := []string{host}
	if port != "" && port != "22" {
		candidates = append(candidates, "["+host+"]:"+port)
	}
	for _, line := range knownhosts.ParseFile(body).Entries() {
		if line.Entry == nil {
			continue
		}
		for _, candidate := range candidates {
			if line.Entry.MatchesHost(candidate) {
				return true, nil
			}
		}
	}
	return false, nil
}
