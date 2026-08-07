// Package remotekey は、リモートアカウントの authorized_keys ファイルに公開鍵を
// インストールする。
//
// リモートで実行するコマンドはパッケージ定数である。鍵は標準入力を通って渡り、
// 固定のルーチンがそれをシェル変数へ読み込む。したがって呼び出し側の入力が、
// コマンドライン・シェル文字列・ヒアドキュメントに差し込まれることは決してない。
package remotekey

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"sshc/internal/effective"
	"sshc/internal/knownhosts"
	"sshc/internal/platform"
)

const (
	// ProbeMarker は、POSIX シェルが返してこなければならない語。
	ProbeMarker = "sshc-posix-shell"
	// ProbeCommand は、リモートアカウントに POSIX シェルがあるかを判定するための
	// 固定コマンド。既知の語をひとつだけ出力し、それ以外は何も出さない。
	ProbeCommand = `printf '%s\n' sshc-posix-shell`
	// RemotePath は、このパッケージが追記するファイル。
	RemotePath = "~/.ssh/authorized_keys"

	// 登録の結果。
	RegistrationAdded    = "added"
	RegistrationExisting = "already_present"

	// DefaultTimeout は、リモート操作一回に上限を設ける。
	DefaultTimeout = 30 * time.Second
)

// Routine はリモートで走るプログラムの全体。呼び出し側の入力を一切含まない。
//
// 鍵は標準入力で届き "$key" に読み込まれる。grep -x -F は行全体をリテラルとして
// 比較するので、すでに存在する鍵が重複することはない。権限は何かを書く前に
// 締められる。
const Routine = `set -e
umask 077
key=$(cat)
case "$key" in
  ssh-*|ecdsa-*|sk-*) ;;
  *) echo "sshc: unsupported key" >&2; exit 3 ;;
esac
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
if grep -qxF "$key" "$HOME/.ssh/authorized_keys"; then
  echo "sshc: already-present"
  exit 0
fi
printf '%s\n' "$key" >> "$HOME/.ssh/authorized_keys"
echo "sshc: added"
`

var (
	ErrInvalidPublicKey  = errors.New("public key must be exactly one valid OpenSSH public key line")
	ErrUnsupportedRemote = errors.New("this remote environment does not provide the POSIX shell this operation needs")
	ErrNotAcknowledged   = errors.New("connecting would run a configured command that has not been acknowledged")
)

// publicKeyPattern が受け付ける行はひとつの形だけ。既知のアルゴリズム名、base64
// のかたまり、そして制御文字を含まない任意のコメントである。
var publicKeyPattern = regexp.MustCompile(
	`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) ([A-Za-z0-9+/]+={0,3})( [^\x00-\x1f\x7f]*)?$`)

// PublicKey は、呼び出し側が選んだ鍵。選ぶのは鍵 vault サブシステムで、この
// パッケージが必要とするのは、その出所のファイルと正確な一行だけである。
type PublicKey struct {
	Path string
	Line string
}

// ParsePublicKey は公開鍵の一行を検証し、そのフィンガープリントを返す。
func ParsePublicKey(line string) (PublicKey, string, error) {
	trimmed := strings.TrimRight(line, "\n")
	if strings.ContainsAny(trimmed, "\n\r") || !publicKeyPattern.MatchString(trimmed) {
		return PublicKey{}, "", ErrInvalidPublicKey
	}
	fields := strings.Fields(trimmed)
	fingerprint, err := knownhosts.Fingerprint(fields[1])
	if err != nil {
		return PublicKey{}, "", ErrInvalidPublicKey
	}
	return PublicKey{Line: trimmed}, fingerprint, nil
}

// ManualSteps は、このパッケージが自動化しないリモートに対して表示する手順。
// 何をすべきかを説明するだけで、何かを実行することは決してない。
var ManualSteps = []string{
	"Open a session to the host yourself and check which shell the account uses.",
	"Create ~/.ssh with mode 700 and ~/.ssh/authorized_keys with mode 600 if they do not exist.",
	"Append the public key line shown above to ~/.ssh/authorized_keys as a single line.",
	"Confirm the file still contains one key per line and that no key was split or duplicated.",
}

// Plan は、リモートホスト上で何かが走る前にユーザーが確認する内容。
type Plan struct {
	Alias       string
	User        string
	Hostname    string
	Port        string
	ValuesFrom  string
	Fingerprint string
	KeyPath     string
	KeyLine     string
	RemotePath  string
	Routine     string
	Supported   bool
	Manual      []string
}

// Result は、完了した登録ひとつ分。
type Result struct {
	Outcome   string
	ExitCode  int
	Stderr    string
	Truncated bool
}

// Service は、プロセスの継ぎ目を通してリモート登録を実行する。
type Service struct {
	Runner     platform.OutputRunner
	Toolchain  platform.Toolchain
	ConfigPath string
	Timeout    time.Duration
	// Environment は子プロセスの完全な環境。通常は platform.MinimalEnvironment で
	// ある。
	Environment []string
}

// NewService は本番用の依存を配線する。
func NewService(runner platform.OutputRunner, toolchain platform.Toolchain, configPath string) *Service {
	return &Service{Runner: runner, Toolchain: toolchain, ConfigPath: configPath}
}

// Plan は、どこにも接触せずに変更内容を説明する。
//
// valuesFrom は、アカウントの詳細が `ssh -G` から来たのか、このアプリケーション
// 自身の設定読み取りから来たのかを記録する。確認ダイアログがどちらかを言える
// ようにするためである。
func (s Service) Plan(alias string, key PublicKey, fingerprint, user, hostname, port, valuesFrom string) Plan {
	return Plan{
		Alias:       alias,
		User:        user,
		Hostname:    hostname,
		Port:        port,
		ValuesFrom:  valuesFrom,
		Fingerprint: fingerprint,
		KeyPath:     key.Path,
		KeyLine:     key.Line,
		RemotePath:  RemotePath,
		Routine:     Routine,
		Supported:   true,
		Manual:      ManualSteps,
	}
}

// Register はリモートのシェルを調べ、そのうえで鍵をインストールする。
func (s Service) Register(ctx context.Context, report effective.Report, alias string, key PublicKey, acknowledged bool) (Result, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Result{}, err
	}
	if _, _, err := ParsePublicKey(key.Line); err != nil {
		return Result{}, err
	}
	if len(report.Unavoidable()) > 0 && !acknowledged {
		return Result{}, ErrNotAcknowledged
	}
	program, err := s.Toolchain.SSH()
	if err != nil {
		return Result{}, err
	}

	probe, err := s.run(ctx, program, alias, ProbeCommand, nil)
	if err != nil {
		return Result{}, err
	}
	if probe.ExitCode != 0 || strings.TrimSpace(string(probe.Stdout)) != ProbeMarker {
		return Result{}, ErrUnsupportedRemote
	}

	output, err := s.run(ctx, program, alias, Routine, []byte(key.Line+"\n"))
	if err != nil {
		return Result{}, err
	}
	result := Result{
		ExitCode:  output.ExitCode,
		Stderr:    string(output.Stderr),
		Truncated: output.Truncated,
	}
	switch {
	case strings.Contains(string(output.Stdout), "sshc: already-present"):
		result.Outcome = RegistrationExisting
	case strings.Contains(string(output.Stdout), "sshc: added"):
		result.Outcome = RegistrationAdded
	default:
		return result, ErrUnsupportedRemote
	}
	return result, nil
}

func (s Service) run(ctx context.Context, program, alias, remoteCommand string, stdin []byte) (platform.Output, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	arguments := []string{"-T", "-F", s.ConfigPath,
		"-o", "BatchMode=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ForwardAgent=no",
		"-o", "RequestTTY=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "NumberOfPasswordPrompts=0",
		"--", alias, remoteCommand,
	}
	return s.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: arguments,
		Stdin:     stdin,
		Timeout:   timeout,
		Env:       s.Environment,
	})
}
