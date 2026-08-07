// Package effective は、OpenSSH がひとつの Host alias に対して実際に使う設定を
// 説明し、評価する。
//
// このパッケージのどれも、ユーザーから得た明示的な確認を呼び出し側が渡さない限り、
// プログラムを起動しない。OpenSSH の設定を評価すること自体が、コマンドを実行しうる
// からである。
package effective

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"sshc/internal/config"
)

// TokenEscapeWarning は、実行を伴うすべてのディレクティブの隣に表示される。
//
// OpenSSH は %h、%p、%r などを、シェル向けの引用をせずに実行するコマンドへ展開する。
// そのため、設定から取られたホスト名やユーザーの値が、そのままそのシェルへ届き
// うる。
const TokenEscapeWarning = "OpenSSH does not shell-escape the tokens it expands. A hostname, port or user value can reach the shell of this command unchanged."

// Executable は、OpenSSH にプログラムを実行させうるディレクティブひとつ。
type Executable struct {
	// Keyword は正規の綴り。Match の criterion の場合は "Match exec"。
	Keyword string
	// Command は、ファイルに現れるとおりの引数テキスト。
	Command string
	Path    string
	// Line は 1 始まり。
	Line int
	// Condition は、それを囲む Host または Match のヘッダー。グローバルブロックでは空。
	Condition string
	// OnEvaluate は、設定を評価するだけでそれが実行される場合に true。
	OnEvaluate bool
	// OnConnect は、接続を確立するとそれが実行される場合に true。
	OnConnect bool
	// Overridable は、コマンドラインオプションで一回分だけ無効にできる場合に true。
	Overridable bool
}

// Report は、設定から到達できる実行を伴うディレクティブをすべて列挙する。
//
// 走査をひとつの alias に絞らないのは意図的である。OpenSSH はファイルを読みながら
// Match 行を評価するので、グラフのどこにある Match exec も、どの alias の評価中で
// あっても実行されうる。読み手には、絞り込まれた部分集合ではなく、そのファイルが
// 起動しうるコマンドをすべて見る資格がある。
type Report struct {
	Directives []Executable
}

var executableDirectives = map[string]Executable{
	"proxycommand":      {Keyword: "ProxyCommand", OnConnect: true},
	"knownhostscommand": {Keyword: "KnownHostsCommand", OnConnect: true},
	"localcommand":      {Keyword: "LocalCommand", OnConnect: true, Overridable: true},
	"remotecommand":     {Keyword: "RemoteCommand", OnConnect: true, Overridable: true},
}

// Scan は、グラフ内のすべてのファイルから実行を伴うディレクティブを集める。
func Scan(graph *config.Graph) Report {
	report := Report{}
	if graph == nil {
		return report
	}
	for _, filePath := range graph.Order {
		node := graph.Nodes[filePath]
		if node == nil || node.File == nil {
			continue
		}
		for _, block := range node.File.Blocks() {
			condition := node.File.Condition(block)
			if block.Kind == config.BlockMatch {
				for _, criterion := range block.Criteria {
					// config は Match の criterion キーワードを小文字にする。
					if criterion.Keyword != "exec" {
						continue
					}
					report.Directives = append(report.Directives, Executable{
						Keyword:    "Match exec",
						Command:    criterion.Argument,
						Path:       filePath,
						Line:       block.Header + 1,
						Condition:  condition,
						OnEvaluate: true,
						OnConnect:  true,
					})
				}
			}
			for index := block.Start; index < block.End; index++ {
				line := node.File.Lines[index]
				if line.Kind != config.LineDirective {
					continue
				}
				template, ok := executableDirectives[strings.ToLower(line.Keyword)]
				if !ok {
					continue
				}
				directive := template
				directive.Command = argumentText(line)
				directive.Path = filePath
				directive.Line = index + 1
				directive.Condition = condition
				report.Directives = append(report.Directives, directive)
			}
		}
	}
	return report
}

// EvaluationNeedsConfirmation は、`ssh -G` がコマンドを実行しうるかを報告する。
func (r Report) EvaluationNeedsConfirmation() bool {
	for _, directive := range r.Directives {
		if directive.OnEvaluate {
			return true
		}
	}
	return false
}

// ConnectionNeedsConfirmation は、接続がコマンドを実行しうるかを報告する。
func (r Report) ConnectionNeedsConfirmation() bool {
	return len(r.Directives) > 0
}

// Unavoidable は、どのコマンドラインオプションでも無効にできないディレクティブを
// 返す。そのいずれかを実行することになる接続は、ユーザーが正確なコマンドテキストを
// 確認したあとでのみ開始される。
func (r Report) Unavoidable() []Executable {
	var remaining []Executable
	for _, directive := range r.Directives {
		if directive.OnConnect && !directive.Overridable {
			remaining = append(remaining, directive)
		}
	}
	return remaining
}

// Evidence は、確認ダイアログが表示しなければならない内容の安定したダイジェスト。
//
// アクショントークンはこの値に結び付けられるので、確認と実行のあいだに編集された
// 設定は、黙って別のコマンドを実行するのではなく、その確認を無効に
// する。
func (r Report) Evidence() string {
	entries := make([]string, 0, len(r.Directives))
	for _, directive := range r.Directives {
		entries = append(entries, fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s",
			directive.Keyword, directive.Command, directive.Path, directive.Line, directive.Condition))
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:])
}

// argumentText は、ディレクティブの引数部分を、インデント・キーワード・区切り・
// 行末を除いて、書かれたとおりに返す。
func argumentText(line config.Line) string {
	var builder strings.Builder
	for _, argument := range line.Arguments {
		builder.WriteString(argument.Lead)
		builder.WriteString(argument.Raw)
	}
	return strings.TrimSpace(builder.String())
}
