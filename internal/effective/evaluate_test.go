package effective_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/platform/macos"
)

// recordingRunner は、実行を求められたコマンドを記録し、あらかじめ用意した結果を
// 返す。このパッケージのどのテストも、これを通して本物のプロセスを起動しない。
type recordingRunner struct {
	commands []platform.Command
	output   platform.Output
	err      error
}

func (runner *recordingRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, runner.err
}

type fixedToolchain struct {
	ssh     string
	keyscan string
	keygen  string
	keyadd  string
	err     error
}

func (t fixedToolchain) SSH() (string, error)     { return t.ssh, t.err }
func (t fixedToolchain) KeyScan() (string, error) { return t.keyscan, t.err }
func (t fixedToolchain) KeyGen() (string, error)  { return t.keygen, t.err }
func (t fixedToolchain) KeyAdd() (string, error)  { return t.keyadd, t.err }

const sampleOutput = "host bastion\n" +
	"user ops\n" +
	"hostname 203.0.113.10\n" +
	"port 2222\n" +
	"identityfile ~/.ssh/id_ed25519\n" +
	"identityfile ~/.ssh/id_rsa\n" +
	"proxyjump ops@edge:2201,inner\n"

func TestEvaluateBuildsArgvWithoutAShellAndParsesOutput(t *testing.T) {
	runner := &recordingRunner{output: platform.Output{Stdout: []byte(sampleOutput)}}
	evaluator := effective.Evaluator{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: testConfig,
	}

	values, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", false)
	if err != nil {
		t.Fatalf("Evaluate = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v", runner.commands)
	}
	command := runner.commands[0]
	if command.Path != "/usr/bin/ssh" {
		t.Errorf("path = %q", command.Path)
	}
	want := []string{"-G", "-F", testConfig, "--", "bastion"}
	if !slices.Equal(command.Arguments, want) {
		t.Fatalf("arguments = %#v, want %#v", command.Arguments, want)
	}
	if command.Timeout != effective.DefaultEvaluationTimeout {
		t.Errorf("timeout = %s", command.Timeout)
	}

	if got := values.First("hostname"); got != "203.0.113.10" {
		t.Errorf("hostname = %q", got)
	}
	if got := values.All("identityfile"); len(got) != 2 || got[1] != "~/.ssh/id_rsa" {
		t.Errorf("identityfile = %#v", got)
	}
	if got := values.First("proxyjump"); got != "ops@edge:2201,inner" {
		t.Errorf("proxyjump = %q", got)
	}
	if got := values.First("absent"); got != "" {
		t.Errorf("absent keyword = %q", got)
	}
	if len(values.Keywords) != 6 || values.Keywords[0] != "host" {
		t.Errorf("keywords = %#v", values.Keywords)
	}
}

// TestEvaluateHandsOpenSSHTheEnvironmentItWasGiven は子プロセスの環境を守る。
// SSH_ASKPASS がエクスポートされていると、ssh はこのアプリケーションが供給する
// 標準入力を読む代わりに外部プログラムへパスフレーズを尋ね、プロンプトがこの
// プロセスの管理下から出てしまう。
func TestEvaluateHandsOpenSSHTheEnvironmentItWasGiven(t *testing.T) {
	runner := &recordingRunner{output: platform.Output{Stdout: []byte(sampleOutput)}}
	evaluator := effective.Evaluator{
		Runner:      runner,
		Toolchain:   fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath:  testConfig,
		Environment: []string{"HOME=/Users/tester", "PATH=/usr/bin"},
	}

	if _, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", false); err != nil {
		t.Fatalf("Evaluate = %v", err)
	}
	if got := runner.commands[0].Env; !slices.Equal(got, []string{"HOME=/Users/tester", "PATH=/usr/bin"}) {
		t.Errorf("env = %#v, want the configured environment", got)
	}
}

func TestEvaluateRefusesToRunWhenEvaluationCanExecuteACommand(t *testing.T) {
	runner := &recordingRunner{output: platform.Output{Stdout: []byte(sampleOutput)}}
	evaluator := effective.Evaluator{Runner: runner, Toolchain: fixedToolchain{ssh: "/usr/bin/ssh"}, ConfigPath: testConfig}
	report := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Match exec \"id -u\"\n\tUser root\n",
	}))

	if _, err := evaluator.Evaluate(context.Background(), report, "bastion", false); !errors.Is(err, effective.ErrEvaluationNotConfirmed) {
		t.Fatalf("Evaluate = %v, want ErrEvaluationNotConfirmed", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("a refused evaluation started a process: %#v", runner.commands)
	}

	if _, err := evaluator.Evaluate(context.Background(), report, "bastion", true); err != nil {
		t.Fatalf("confirmed Evaluate = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("confirmed evaluation did not run: %#v", runner.commands)
	}
}

func TestEvaluateRejectsUnsafeAliasesAndReportsOpenSSHFailures(t *testing.T) {
	runner := &recordingRunner{}
	evaluator := effective.Evaluator{Runner: runner, Toolchain: fixedToolchain{ssh: "/usr/bin/ssh"}, ConfigPath: testConfig}

	if _, err := evaluator.Evaluate(context.Background(), effective.Report{}, "-oProxyCommand=id", false); !errors.Is(err, platform.ErrUnsafeAlias) {
		t.Fatalf("unsafe alias = %v, want ErrUnsafeAlias", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("an unsafe alias started a process: %#v", runner.commands)
	}

	failing := &recordingRunner{output: platform.Output{
		ExitCode: 255,
		Stderr:   []byte("config: line 2: Bad configuration option: notadirective\n"),
	}}
	evaluator.Runner = failing
	_, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", false)
	var opensshError *effective.OpenSSHError
	if !errors.As(err, &opensshError) {
		t.Fatalf("Evaluate = %v, want *OpenSSHError", err)
	}
	if opensshError.ExitCode != 255 || !strings.Contains(opensshError.Stderr, "Bad configuration option") {
		t.Errorf("openssh error = %#v", opensshError)
	}
	if strings.Contains(opensshError.Error(), "Bad configuration option") {
		t.Error("the error message must not repeat captured output")
	}

	truncated := &recordingRunner{output: platform.Output{Stdout: []byte("host bastion\n"), Truncated: true}}
	evaluator.Runner = truncated
	if _, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", false); !errors.Is(err, effective.ErrOutputTruncated) {
		t.Fatalf("truncated output = %v, want ErrOutputTruncated", err)
	}
}

// TestEvaluateParsesInstalledOpenSSHOutput は、設定エンジンの計画がこのサブ
// システムに先送りした `ssh -G` 差分カバレッジの前半である。実行を伴うディレク
// ティブを含まないフィクスチャを一時ディレクトリに置いて本物の ssh を使い、
// OpenSSH が入っていなければスキップする。
func TestEvaluateParsesInstalledOpenSSHOutput(t *testing.T) {
	toolchain := macos.NewToolchain()
	if _, err := toolchain.SSH(); err != nil {
		t.Skip("OpenSSH ssh is not installed; skipping the real-binary check")
	}

	directory := t.TempDir()
	configPath := directory + "/config"
	if err := os.WriteFile(configPath, []byte("Host fixture\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	evaluator := effective.Evaluator{
		Runner:     macos.NewOutputRunner(),
		Toolchain:  toolchain,
		ConfigPath: configPath,
	}
	values, err := evaluator.Evaluate(context.Background(), effective.Report{}, "fixture", false)
	if err != nil {
		t.Fatalf("Evaluate = %v", err)
	}
	for keyword, want := range map[string]string{
		"hostname": "203.0.113.10",
		"user":     "ops",
		"port":     "2222",
	} {
		if got := values.First(keyword); got != want {
			t.Errorf("%s = %q, want %q", keyword, got, want)
		}
	}
}
