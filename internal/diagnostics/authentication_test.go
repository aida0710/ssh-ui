package diagnostics_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"ssh-ui/internal/config"
	"ssh-ui/internal/diagnostics"
	"ssh-ui/internal/effective"
	"ssh-ui/internal/platform"
)

type scriptedRunner struct {
	commands []platform.Command
	output   platform.Output
	err      error
}

func (runner *scriptedRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, runner.err
}

type fixedToolchain struct{ ssh, keyscan, keygen, keyadd string }

func (t fixedToolchain) SSH() (string, error)     { return t.ssh, nil }
func (t fixedToolchain) KeyScan() (string, error) { return t.keyscan, nil }
func (t fixedToolchain) KeyGen() (string, error)  { return t.keygen, nil }
func (t fixedToolchain) KeyAdd() (string, error)  { return t.keyadd, nil }

func reportFrom(t *testing.T, contents string) effective.Report {
	t.Helper()
	graph := &config.Graph{
		Root:  "/Users/tester/.ssh/config",
		Order: []string{"/Users/tester/.ssh/config"},
		Nodes: map[string]*config.Node{
			"/Users/tester/.ssh/config": {Path: "/Users/tester/.ssh/config", Editable: true, File: config.Parse([]byte(contents))},
		},
	}
	return effective.Scan(graph)
}

func TestHardeningOptionsDisableForwardingAndLocalCommand(t *testing.T) {
	options := diagnostics.HardeningOptions(7 * time.Second)
	joined := strings.Join(options, " ")
	for _, want := range []string{
		"BatchMode=yes",
		"PermitLocalCommand=no",
		"ClearAllForwardings=yes",
		"ForwardAgent=no",
		"ForwardX11=no",
		"ForwardX11Trusted=no",
		"ControlMaster=no",
		"ControlPath=none",
		"RemoteCommand=none",
		"RequestTTY=no",
		"SessionType=none",
		"StrictHostKeyChecking=yes",
		"NumberOfPasswordPrompts=0",
		"ConnectTimeout=7",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("hardening options are missing %q: %v", want, options)
		}
	}
	for index := 0; index < len(options); index += 2 {
		if options[index] != "-o" {
			t.Fatalf("option %d = %q, want -o", index, options[index])
		}
	}
}

func TestAuthenticationTestBuildsASafeCommandAndReadsTheMarker(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{
		Stderr:  []byte("debug1: Authenticated to bastion ([203.0.113.10]:22) using \"publickey\".\n"),
		Stopped: true,
	}}
	authentication := diagnostics.Authentication{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: "/Users/tester/.ssh/config",
	}

	result, err := authentication.Test(context.Background(), effective.Report{}, "bastion", false)
	if err != nil {
		t.Fatalf("Test = %v", err)
	}
	if !result.Authenticated || result.Outcome != diagnostics.OutcomeAuthenticated {
		t.Fatalf("result = %#v", result)
	}

	command := runner.commands[0]
	if command.Path != "/usr/bin/ssh" {
		t.Errorf("path = %q", command.Path)
	}
	if string(command.StopAfter) != diagnostics.AuthenticatedMarker {
		t.Errorf("stop marker = %q", command.StopAfter)
	}
	if command.Timeout != diagnostics.DefaultAuthenticationTimeout {
		t.Errorf("timeout = %s", command.Timeout)
	}
	if last := command.Arguments[len(command.Arguments)-2:]; !slices.Equal(last, []string{"--", "bastion"}) {
		t.Errorf("argv tail = %#v, want -- bastion", last)
	}
	if !slices.Contains(command.Arguments, "-v") || !slices.Contains(command.Arguments, "-F") {
		t.Errorf("argv = %#v", command.Arguments)
	}
}

func TestAuthenticationTestRefusesUntilUnavoidableCommandsAreAcknowledged(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{Stopped: true, Stderr: []byte(diagnostics.AuthenticatedMarker + "host\n")}}
	authentication := diagnostics.Authentication{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: "/Users/tester/.ssh/config",
	}
	report := reportFrom(t, "Host jump\n\tProxyCommand /usr/bin/nc %h %p\n")

	_, err := authentication.Test(context.Background(), report, "jump", false)
	var directiveError *diagnostics.ExecutableDirectiveError
	if !errors.As(err, &directiveError) {
		t.Fatalf("Test = %v, want *ExecutableDirectiveError", err)
	}
	if len(directiveError.Directives) != 1 || directiveError.Directives[0].Keyword != "ProxyCommand" {
		t.Fatalf("directives = %#v", directiveError.Directives)
	}
	if len(runner.commands) != 0 {
		t.Fatal("a refused authentication test started a process")
	}

	if _, err := authentication.Test(context.Background(), report, "jump", true); err != nil {
		t.Fatalf("acknowledged Test = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("acknowledged test did not run: %#v", runner.commands)
	}

	overridable := reportFrom(t, "Host jump\n\tLocalCommand /usr/bin/say hi\n")
	if _, err := authentication.Test(context.Background(), overridable, "jump", false); err != nil {
		t.Fatalf("a directive the command line disables must not block the test: %v", err)
	}
}

func TestAuthenticationTestClassifiesFailures(t *testing.T) {
	tests := []struct {
		name   string
		output platform.Output
		runErr error
		want   string
	}{
		{"denied", platform.Output{ExitCode: 255, Stderr: []byte("ops@203.0.113.10: Permission denied (publickey).\n")}, nil, diagnostics.OutcomeDenied},
		{"unknown host key", platform.Output{ExitCode: 255, Stderr: []byte("Host key verification failed.\n")}, nil, diagnostics.OutcomeHostKeyUnknown},
		{"changed host key", platform.Output{ExitCode: 255, Stderr: []byte("@@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@@\nHost key verification failed.\n")}, nil, diagnostics.OutcomeHostKeyChanged},
		{"dns", platform.Output{ExitCode: 255, Stderr: []byte("ssh: Could not resolve hostname missing.invalid: nodename nor servname provided\n")}, nil, diagnostics.OutcomeDNSFailure},
		{"refused", platform.Output{ExitCode: 255, Stderr: []byte("ssh: connect to host 203.0.113.10 port 22: Connection refused\n")}, nil, diagnostics.OutcomeRefused},
		{"timeout", platform.Output{}, platform.ErrTimedOut, diagnostics.OutcomeTimeout},
		{"other", platform.Output{ExitCode: 1, Stderr: []byte("something else\n")}, nil, diagnostics.OutcomeFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authentication := diagnostics.Authentication{
				Runner:     &scriptedRunner{output: test.output, err: test.runErr},
				Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
				ConfigPath: "/Users/tester/.ssh/config",
			}
			result, err := authentication.Test(context.Background(), effective.Report{}, "bastion", false)
			if err != nil {
				t.Fatalf("Test = %v", err)
			}
			if result.Outcome != test.want || result.Authenticated {
				t.Fatalf("result = %#v, want outcome %q", result, test.want)
			}
		})
	}
}

func TestAuthenticationTestRejectsUnsafeAliasesAndCapsReportedOutput(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{
		ExitCode:  255,
		Stderr:    []byte(strings.Repeat("x", diagnostics.MaxReportedOutput+4096)),
		Truncated: true,
	}}
	authentication := diagnostics.Authentication{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: "/Users/tester/.ssh/config",
	}

	if _, err := authentication.Test(context.Background(), effective.Report{}, "bad alias", false); !errors.Is(err, platform.ErrUnsafeAlias) {
		t.Fatalf("unsafe alias = %v, want ErrUnsafeAlias", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("an unsafe alias started a process")
	}

	result, err := authentication.Test(context.Background(), effective.Report{}, "bastion", false)
	if err != nil {
		t.Fatalf("Test = %v", err)
	}
	if len(result.Stderr) > diagnostics.MaxReportedOutput {
		t.Errorf("reported %d bytes, want at most %d", len(result.Stderr), diagnostics.MaxReportedOutput)
	}
	if !result.Truncated {
		t.Error("truncation was not reported")
	}
}
