package macos

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sshc/internal/platform"
)

const (
	defaultAgentTimeout = 30 * time.Second
	noIdentitiesMessage = "The agent has no identities."
)

// KeyAgent は ssh-add を駆動する。
//
// ssh-add は、標準入力が利用できるならそこからパスフレーズを読む。したがって
// このアダプタには SSH_ASKPASS も端末も不要であり、秘密が argv や環境に届くことは
// 決してない。呼び出しのたびに子プロセスの環境を platform.MinimalEnvironment で
// 置き換えるのは、SSH_ASKPASS が SSH_ASKPASS_REQUIRE=force と組み合わさると、
// ssh-add がその標準入力を無視して、このアプリケーションが選んだのではない
// プログラムにパスフレーズを尋ねてしまうからだ。鍵のパスは常にワークスペース内の
// 絶対パスなので、オプションとして読まれることは決して
// ない。
//
// --apple-use-keychain は、パスフレーズをログインキーチェーンにも保存する、
// 文書化された macOS のフラグ。ユーザーがそれを求めたときにだけ使う。
//
// プログラムのパスは定数ではなく Toolchain から来る。そのためこのアダプタは、
// アプリケーションの他の部分と同じ OpenSSH を実行し、PATH に依存することは
// 決してない。
type KeyAgent struct {
	runner    platform.OutputRunner
	toolchain platform.Toolchain
	lookup    func(string) (string, bool)
	timeout   time.Duration
}

// NewKeyAgent は macOS の ssh-add アダプタを組み立てる。lookup が子プロセスの
// 環境を供給するので、テストが開発者自身の環境に依存することはない。
func NewKeyAgent(runner platform.OutputRunner, toolchain platform.Toolchain, lookup func(string) (string, bool)) platform.KeyAgent {
	return KeyAgent{runner: runner, toolchain: toolchain, lookup: lookup, timeout: defaultAgentTimeout}
}

// Available は、このプロセスがそもそもエージェントに到達できるかを報告する。
// 話しかける先のソケットと、話す相手の ssh-add の両方が必要である。
func (agent KeyAgent) Available(_ context.Context) bool {
	if _, err := agent.toolchain.KeyAdd(); err != nil {
		return false
	}
	socket, ok := agent.lookup("SSH_AUTH_SOCK")
	return ok && socket != ""
}

func (agent KeyAgent) List(ctx context.Context) ([]platform.AgentIdentity, error) {
	output, err := agent.run(ctx, []string{"-l", "-E", "sha256"}, nil)
	if err != nil {
		return nil, err
	}
	if output.ExitCode == 1 && strings.Contains(string(output.Stdout)+string(output.Stderr), noIdentitiesMessage) {
		return []platform.AgentIdentity{}, nil
	}
	if output.ExitCode != 0 {
		return nil, agent.rejected(output)
	}
	return parseIdentities(string(output.Stdout)), nil
}

func (agent KeyAgent) Add(ctx context.Context, request platform.AgentAddRequest) error {
	arguments := make([]string, 0, 4)
	if request.LifetimeSeconds > 0 {
		arguments = append(arguments, "-t", strconv.Itoa(request.LifetimeSeconds))
	}
	if request.StoreInKeychain {
		arguments = append(arguments, "--apple-use-keychain")
	}
	arguments = append(arguments, request.PrivateKeyPath)

	output, err := agent.run(ctx, arguments, request.Passphrase)
	if err != nil {
		return err
	}
	if output.ExitCode != 0 {
		return agent.rejected(output)
	}
	return nil
}

func (agent KeyAgent) Remove(ctx context.Context, publicKeyPath string) error {
	output, err := agent.run(ctx, []string{"-d", publicKeyPath}, nil)
	if err != nil {
		return err
	}
	if output.ExitCode != 0 {
		return agent.rejected(output)
	}
	return nil
}

// run は ssh-add のプロセスが起動される唯一の場所。これにより、環境の洗浄と
// 「パスフレーズは標準入力から」というルールを、ある呼び出し側だけが忘れる
// ということが起きない。
func (agent KeyAgent) run(ctx context.Context, arguments []string, stdin []byte) (platform.Output, error) {
	if !agent.Available(ctx) {
		return platform.Output{}, platform.ErrAgentUnavailable
	}
	program, err := agent.toolchain.KeyAdd()
	if err != nil {
		return platform.Output{}, platform.ErrAgentUnavailable
	}
	timeout := agent.timeout
	if timeout <= 0 {
		timeout = defaultAgentTimeout
	}
	return agent.runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: arguments,
		Stdin:     stdin,
		Timeout:   timeout,
		Env:       platform.MinimalEnvironment(agent.lookup),
	})
}

func (agent KeyAgent) rejected(output platform.Output) error {
	message := strings.TrimSpace(string(output.Stderr))
	if message == "" {
		message = strings.TrimSpace(string(output.Stdout))
	}
	return fmt.Errorf("%w: %s", platform.ErrAgentRejected, agent.sanitize(message))
}

// sanitize はユーザーのホームディレクトリを '~' に置き換える。UI に表示される、
// あるいはそこからコピーされるメッセージが絶対パスを運ばないようにするためだ。
func (agent KeyAgent) sanitize(message string) string {
	home, ok := agent.lookup("HOME")
	if !ok || home == "" {
		return message
	}
	return strings.ReplaceAll(message, home, "~")
}

// parseIdentities は `ssh-add -l` の出力行を、
// "<bits> <fingerprint> <comment> (<ALGORITHM>)" の形式として読む。
func parseIdentities(output string) []platform.AgentIdentity {
	identities := make([]platform.AgentIdentity, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		bits, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		identities = append(identities, platform.AgentIdentity{
			Bits:        bits,
			Fingerprint: fields[1],
			Comment:     strings.Join(fields[2:len(fields)-1], " "),
			Algorithm:   strings.Trim(fields[len(fields)-1], "()"),
		})
	}
	return identities
}
