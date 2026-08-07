package knownhosts

import (
	"context"
	"crypto/subtle"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"sshc/internal/storage"
)

var (
	ErrUnverifiedCandidate = errors.New("a scanned key needs a matching fingerprint or an explicit acknowledgement")
	ErrEntryChanged        = errors.New("the entry on disk is not the entry that was displayed")
	ErrNoSuchEntry         = errors.New("no such known_hosts entry")
	ErrUnsupportedKeyType  = errors.New("unsupported host key type")
)

// supportedKeyTypes は、このアプリケーションが known_hosts に書き込む種別の集合。
// それ以外は、検査せずに通すのではなく拒否する。
var supportedKeyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"rsa-sha2-256":                       true,
	"rsa-sha2-512":                       true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,3}$`)

// Target は削除するエントリひとつを特定する。Digest はユーザーが見た行そのものの
// ハッシュなので、その間に編集されたファイルで違う行を失うことはない。
type Target struct {
	Line   int
	Digest string
}

// Listing は、このファイルの検索可能なビュー。
type Listing struct {
	Path  string
	Lines []Line
}

// Service は、トランザクションマネージャを通して known_hosts を読み書きする。
type Service struct {
	Workspace *storage.Workspace
	Manager   *storage.Manager
	Scanner   Scanner
}

// NewService は本番用の依存を配線する。
func NewService(workspace *storage.Workspace, manager *storage.Manager, scanner Scanner) *Service {
	return &Service{Workspace: workspace, Manager: manager, Scanner: scanner}
}

// Path は、このサービスが管理する known_hosts ファイル。
func (s *Service) Path() string { return filepath.Join(s.Workspace.Root(), "known_hosts") }

func (s *Service) read() ([]byte, error) {
	contents, err := s.Workspace.FileSystem().ReadFile(s.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return contents, err
}

// Listing は query に一致するエントリを返す。
func (s *Service) Listing(query string) (Listing, error) {
	contents, err := s.read()
	if err != nil {
		return Listing{}, err
	}
	return Listing{Path: s.Path(), Lines: Search(ParseFile(contents), query)}, nil
}

// Evidence は現在のファイルのダイジェスト。known_hosts の変更に対するアクション
// トークンはこれに結び付けられるので、外部からの編集は確認を無効にする。
func (s *Service) Evidence() (string, error) {
	contents, err := s.read()
	if err != nil {
		return "", err
	}
	return storage.Digest(contents), nil
}

// Scan は、あるホストの鍵を ssh-keyscan に尋ねる。返される候補は、この呼び出しに
// おいて信頼されることはない。その判断は Add が別途行う。
func (s *Service) Scan(ctx context.Context, host string, port int) ([]Candidate, error) {
	return s.Scanner.Scan(ctx, host, port)
}

// Delete は、求められた行を取り除き、それ以外のバイトには一切触れない。
//
// 各 target は、ユーザーに表示された行のダイジェストを持つ。もはやそのハッシュに
// ならない行は拒否される。したがって、確認とリクエストのあいだに編集されたファイル
// で、誰も削除に同意していない行が失われることはない。
func (s *Service) Delete(targets []Target) (storage.Result, error) {
	contents, err := s.read()
	if err != nil {
		return storage.Result{}, err
	}
	file := ParseFile(contents)

	removing := make(map[int]bool, len(targets))
	for _, target := range targets {
		found := false
		for _, line := range file.Lines {
			if line.Number != target.Line {
				continue
			}
			found = true
			if storage.Digest([]byte(line.Raw)) != target.Digest {
				return storage.Result{}, ErrEntryChanged
			}
			removing[line.Number] = true
		}
		if !found {
			return storage.Result{}, ErrNoSuchEntry
		}
	}

	remaining := &File{}
	for _, line := range file.Lines {
		if removing[line.Number] {
			continue
		}
		remaining.Lines = append(remaining.Lines, line)
	}
	return s.commit("known_hosts.delete", contents, remaining.Render())
}

// Add は、ユーザーが意図した鍵であると証明したうえで、スキャンした鍵を 1 行追加する。
//
// expectedFingerprint が鍵の実際のフィンガープリントと一致するか、ユーザーがその鍵
// は未検証であると明示的に承認したかのいずれかである。行は、クライアントが送って
// きたテキストを信用せず、検証済みの部品から組み立て直される。
func (s *Service) Add(candidate Candidate, expectedFingerprint string, acknowledged bool) (storage.Result, error) {
	if !supportedKeyTypes[candidate.KeyType] {
		return storage.Result{}, ErrUnsupportedKeyType
	}
	if !base64Pattern.MatchString(candidate.Key) {
		return storage.Result{}, ErrInvalidKey
	}
	fingerprint, err := Fingerprint(candidate.Key)
	if err != nil {
		return storage.Result{}, err
	}
	switch {
	case expectedFingerprint != "":
		if subtle.ConstantTimeCompare([]byte(expectedFingerprint), []byte(fingerprint)) != 1 {
			return storage.Result{}, ErrUnverifiedCandidate
		}
	case !acknowledged:
		return storage.Result{}, ErrUnverifiedCandidate
	}

	hostField := candidate.Host
	if candidate.Port != 22 {
		hostField = "[" + candidate.Host + "]:" + strconv.Itoa(candidate.Port)
	}
	newLine := hostField + " " + candidate.KeyType + " " + candidate.Key

	contents, err := s.read()
	if err != nil {
		return storage.Result{}, err
	}
	file := ParseFile(contents)
	for _, line := range file.Lines {
		if strings.TrimSpace(line.Raw) == newLine {
			// 完全な重複。書くものはない。
			return storage.Result{}, nil
		}
	}

	updated := string(contents)
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += newLine + "\n"
	return s.commit("known_hosts.add", contents, []byte(updated))
}

func (s *Service) commit(operation string, previous, updated []byte) (storage.Result, error) {
	if err := s.Workspace.EnsureDirectory(s.Workspace.Root()); err != nil {
		return storage.Result{}, err
	}
	return s.Manager.Commit(storage.Request{
		Operation: operation,
		Changes: []storage.Change{{
			Path:         s.Path(),
			Contents:     updated,
			Precondition: storage.Precondition{Exists: previous != nil, Digest: storage.Digest(previous)},
		}},
	})
}
