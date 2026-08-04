package remotekey_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"ssh-ui/internal/effective"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/remotekey"
)

const (
	keyLine     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS fixture@example"
	fingerprint = "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs"
)

type scriptedRunner struct {
	commands []platform.Command
	outputs  []platform.Output
}

func (runner *scriptedRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	if len(runner.outputs) == 0 {
		return platform.Output{}, nil
	}
	next := runner.outputs[0]
	runner.outputs = runner.outputs[1:]
	return next, nil
}

type stubToolchain struct{}

func (stubToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (stubToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }
func (stubToolchain) KeyGen() (string, error)  { return "/usr/bin/ssh-keygen", nil }
func (stubToolchain) KeyAdd() (string, error)  { return "/usr/bin/ssh-add", nil }

func newService(runner platform.OutputRunner) remotekey.Service {
	return remotekey.Service{Runner: runner, Toolchain: stubToolchain{}, ConfigPath: "/Users/tester/.ssh/config"}
}

func TestParsePublicKeyAcceptsOnlyOneValidLine(t *testing.T) {
	key, computed, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatalf("ParsePublicKey = %v", err)
	}
	if key.Line != keyLine || computed != fingerprint {
		t.Fatalf("key = %#v, fingerprint = %q", key, computed)
	}

	rejected := []string{
		"",
		"ssh-ed25519",
		"ssh-ed25519 not-base64!",
		keyLine + "\nssh-ed25519 AAAA more",
		"rm -rf / AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS comment\rwith-cr",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS comment\x00nul",
	}
	for _, line := range rejected {
		if _, _, err := remotekey.ParsePublicKey(line); !errors.Is(err, remotekey.ErrInvalidPublicKey) {
			t.Errorf("ParsePublicKey(%q) = %v, want ErrInvalidPublicKey", line, err)
		}
	}
}

func TestRegisterProbesThenSendsTheKeyOnStandardInput(t *testing.T) {
	runner := &scriptedRunner{outputs: []platform.Output{
		{Stdout: []byte(remotekey.ProbeMarker + "\n")},
		{Stdout: []byte("ssh-ui: added\n")},
	}}
	key, _, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}

	result, err := newService(runner).Register(context.Background(), effective.Report{}, "bastion", key, false)
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if result.Outcome != remotekey.RegistrationAdded {
		t.Fatalf("result = %#v", result)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v", runner.commands)
	}

	probe := runner.commands[0]
	if probe.Arguments[len(probe.Arguments)-1] != remotekey.ProbeCommand {
		t.Errorf("probe argv = %#v", probe.Arguments)
	}
	register := runner.commands[1]
	if register.Arguments[len(register.Arguments)-1] != remotekey.Routine {
		t.Errorf("registration argv = %#v", register.Arguments)
	}
	if string(register.Stdin) != keyLine+"\n" {
		t.Errorf("stdin = %q, want the key line", register.Stdin)
	}
	if strings.Contains(remotekey.Routine, "fixture@example") {
		t.Error("the remote routine must never contain caller input")
	}
	if !slices.Contains(register.Arguments, "-T") {
		t.Errorf("registration argv = %#v, want -T", register.Arguments)
	}
	for _, argument := range register.Arguments {
		if strings.Contains(argument, "sh -c") {
			t.Fatalf("argv smuggled a shell invocation: %q", argument)
		}
	}

	// No argument may carry the key, the comment or the alias-derived data:
	// everything variable travels on standard input.
	for _, argument := range register.Arguments {
		if argument == remotekey.Routine {
			continue
		}
		if strings.Contains(argument, "AAAAC3Nza") || strings.Contains(argument, "fixture@example") {
			t.Fatalf("argv carried key material: %q", argument)
		}
	}
}

func TestRegisterReportsAnExistingKeyAndAnUnsupportedRemote(t *testing.T) {
	key, _, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}

	existing := &scriptedRunner{outputs: []platform.Output{
		{Stdout: []byte(remotekey.ProbeMarker + "\n")},
		{Stdout: []byte("ssh-ui: already-present\n")},
	}}
	result, err := newService(existing).Register(context.Background(), effective.Report{}, "bastion", key, false)
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if result.Outcome != remotekey.RegistrationExisting {
		t.Fatalf("result = %#v", result)
	}

	unsupported := &scriptedRunner{outputs: []platform.Output{
		{Stdout: []byte("Windows PowerShell\n"), ExitCode: 0},
	}}
	if _, err := newService(unsupported).Register(context.Background(), effective.Report{}, "bastion", key, false); !errors.Is(err, remotekey.ErrUnsupportedRemote) {
		t.Fatalf("Register = %v, want ErrUnsupportedRemote", err)
	}
	if len(unsupported.commands) != 1 {
		t.Fatal("an unsupported remote still received the registration routine")
	}
}

func TestRegisterRefusesUntilExecutableDirectivesAreAcknowledged(t *testing.T) {
	runner := &scriptedRunner{}
	key, _, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}
	report := effective.Report{Directives: []effective.Executable{
		{Keyword: "ProxyCommand", Command: "/usr/bin/nc %h %p", OnConnect: true},
	}}

	if _, err := newService(runner).Register(context.Background(), report, "bastion", key, false); !errors.Is(err, remotekey.ErrNotAcknowledged) {
		t.Fatalf("Register = %v, want ErrNotAcknowledged", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("a refused registration started a process")
	}

	if _, err := newService(runner).Register(context.Background(), effective.Report{}, "bad alias", key, false); !errors.Is(err, platform.ErrUnsafeAlias) {
		t.Fatalf("Register = %v, want ErrUnsafeAlias", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("an unsafe alias started a process")
	}
}

func TestPlanDescribesExactlyWhatWillHappen(t *testing.T) {
	key, computed, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}
	plan := newService(&scriptedRunner{}).Plan("bastion", key, computed, "ops", "203.0.113.10", "2222", "openssh")

	if !plan.Supported || plan.RemotePath != "~/.ssh/authorized_keys" {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.Routine != remotekey.Routine || plan.KeyLine != keyLine || plan.Fingerprint != fingerprint {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.User != "ops" || plan.Hostname != "203.0.113.10" || plan.Port != "2222" || plan.ValuesFrom != "openssh" {
		t.Fatalf("plan = %#v", plan)
	}
	if len(plan.Manual) == 0 || !strings.Contains(strings.Join(plan.Manual, "\n"), "authorized_keys") {
		t.Errorf("manual steps = %#v", plan.Manual)
	}
}
