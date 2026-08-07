package keys

import (
	"context"
	"errors"
	"testing"
	"time"

	"sshc/internal/platform"
)

// fakeRunner は、実行されたはずの内容を記録し、用意された出力を返す。この
// パッケージのどのテストも、本物の子プロセスを起動しない。
type fakeRunner struct {
	commands []platform.Command
	output   platform.Output
	err      error
}

func (fake *fakeRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	fake.commands = append(fake.commands, command)
	return fake.output, fake.err
}

// fakeToolchain は固定の絶対パスで答えるので、どのテストも、開発者のマシンに
// たまたま入っている OpenSSH のプログラムに依存しない。
type fakeToolchain struct {
	err error
}

func (fake fakeToolchain) SSH() (string, error)     { return fake.resolve("/usr/bin/ssh") }
func (fake fakeToolchain) KeyScan() (string, error) { return fake.resolve("/usr/bin/ssh-keyscan") }
func (fake fakeToolchain) KeyGen() (string, error)  { return fake.resolve("/usr/bin/ssh-keygen") }
func (fake fakeToolchain) KeyAdd() (string, error)  { return fake.resolve("/usr/bin/ssh-add") }

func (fake fakeToolchain) resolve(path string) (string, error) {
	if fake.err != nil {
		return "", fake.err
	}
	return path, nil
}

func newFakeCatalogue(runner platform.OutputRunner, toolchain platform.Toolchain) CatalogueReader {
	return CatalogueReader{Runner: runner, Toolchain: toolchain, Timeout: time.Second}
}

const opensshQueryOutput = "ssh-ed25519\n" +
	"ssh-ed25519-cert-v01@openssh.com\n" +
	"sk-ssh-ed25519@openssh.com\n" +
	"ecdsa-sha2-nistp256\n" +
	"ecdsa-sha2-nistp384\n" +
	"ecdsa-sha2-nistp521\n" +
	"sk-ecdsa-sha2-nistp256@openssh.com\n" +
	"ssh-rsa\n"

func TestCatalogueOffersTheVariantsTheInstalledOpenSSHSupports(t *testing.T) {
	runner := &fakeRunner{output: platform.Output{Stdout: []byte(opensshQueryOutput)}}
	catalogue := newFakeCatalogue(runner, fakeToolchain{}).Read(context.Background())

	if catalogue.Source != "ssh -Q key" {
		t.Fatalf("Source = %q, want %q", catalogue.Source, "ssh -Q key")
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v, want exactly one", runner.commands)
	}
	command := runner.commands[0]
	wantArguments := []string{"-F", "/dev/null", "-Q", "key"}
	if command.Path != "/usr/bin/ssh" || len(command.Arguments) != len(wantArguments) {
		t.Fatalf("command = %s %v", command.Path, command.Arguments)
	}
	for index, want := range wantArguments {
		if command.Arguments[index] != want {
			t.Fatalf("Arguments[%d] = %q, want %q", index, command.Arguments[index], want)
		}
	}
	if len(command.Stdin) != 0 {
		t.Errorf("Stdin = %q, want an empty standard input", command.Stdin)
	}

	tests := []struct {
		algorithm Algorithm
		bits      int
		inProcess bool
	}{
		{AlgorithmEd25519, 256, true},
		{AlgorithmRSA, 2048, true},
		{AlgorithmRSA, 3072, true},
		{AlgorithmRSA, 4096, true},
		{AlgorithmECDSA, 256, true},
		{AlgorithmECDSA, 384, true},
		{AlgorithmECDSA, 521, true},
		{AlgorithmEd25519SK, 0, false},
		{AlgorithmECDSASK, 256, false},
	}
	if len(catalogue.Variants) != len(tests) {
		t.Fatalf("variants = %#v, want %d", catalogue.Variants, len(tests))
	}
	for index, test := range tests {
		variant := catalogue.Variants[index]
		if variant.Algorithm != test.algorithm || variant.Bits != test.bits {
			t.Errorf("variant[%d] = %s/%d, want %s/%d", index, variant.Algorithm, variant.Bits, test.algorithm, test.bits)
		}
		if variant.InProcess != test.inProcess {
			t.Errorf("variant[%d].InProcess = %v, want %v", index, variant.InProcess, test.inProcess)
		}
		if !variant.InProcess && variant.Reason == "" {
			t.Errorf("variant[%d] has no reason for leaving the process", index)
		}
	}
}

func TestCatalogueFallsBackToEd25519WhenOpenSSHCannotBeQueried(t *testing.T) {
	tests := []struct {
		name      string
		runner    *fakeRunner
		toolchain fakeToolchain
	}{
		{
			name:   "the program could not be run",
			runner: &fakeRunner{err: errors.New("child process failed to start")},
		},
		{
			name:   "the program reported a non-zero exit status",
			runner: &fakeRunner{output: platform.Output{ExitCode: 1}},
		},
		{
			name:      "the program is not installed",
			runner:    &fakeRunner{output: platform.Output{Stdout: []byte(opensshQueryOutput)}},
			toolchain: fakeToolchain{err: errors.New("OpenSSH program not found")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalogue := newFakeCatalogue(test.runner, test.toolchain).Read(context.Background())
			if catalogue.Source != "fallback" {
				t.Fatalf("Source = %q, want %q", catalogue.Source, "fallback")
			}
			if catalogue.Diagnostic != DiagnosticAlgorithmQueryFailed {
				t.Fatalf("Diagnostic = %q, want %q", catalogue.Diagnostic, DiagnosticAlgorithmQueryFailed)
			}
			if len(catalogue.Variants) != 1 || catalogue.Variants[0].Algorithm != AlgorithmEd25519 {
				t.Fatalf("variants = %#v, want Ed25519 only", catalogue.Variants)
			}
		})
	}
}

func TestHardwareCommandProducesAnUnambiguousArgumentList(t *testing.T) {
	command, err := HardwareCommand(AlgorithmEd25519SK, "id_yubikey", "aida@laptop", "/Users/example/.ssh")
	if err != nil {
		t.Fatalf("HardwareCommand error = %v", err)
	}
	want := []string{"ssh-keygen", "-t", "ed25519-sk", "-C", "aida@laptop", "-f", "/Users/example/.ssh/id_yubikey"}
	if len(command) != len(want) {
		t.Fatalf("command = %#v, want %#v", command, want)
	}
	for index := range want {
		if command[index] != want[index] {
			t.Fatalf("command[%d] = %q, want %q", index, command[index], want[index])
		}
	}

	rejections := []struct {
		name      string
		algorithm Algorithm
		fileName  string
		comment   string
		wantError error
	}{
		{"software algorithm", AlgorithmEd25519, "id_ed25519", "aida@laptop", ErrUnsupportedAlgorithm},
		{"traversal in name", AlgorithmEd25519SK, "../escape", "aida@laptop", ErrInvalidFileName},
		{"option injection in name", AlgorithmEd25519SK, "-oProxyCommand=id", "aida@laptop", ErrInvalidFileName},
		{"shell metacharacter in comment", AlgorithmECDSASK, "id_yubikey", "aida; rm -rf /", ErrInvalidComment},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			if _, err := HardwareCommand(test.algorithm, test.fileName, test.comment, "/Users/example/.ssh"); !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
}
