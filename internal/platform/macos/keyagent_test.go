package macos_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"ssh-ui/internal/platform"
	"ssh-ui/internal/platform/macos"
)

// recordingRunner captures the command that would have run. No test in this
// package starts a real ssh-add or touches a real agent or Keychain.
type recordingRunner struct {
	commands []platform.Command
	outputs  []platform.Output
	err      error
}

func (recorder *recordingRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	recorder.commands = append(recorder.commands, command)
	if recorder.err != nil {
		return platform.Output{}, recorder.err
	}
	if len(recorder.outputs) == 0 {
		return platform.Output{}, nil
	}
	output := recorder.outputs[0]
	recorder.outputs = recorder.outputs[1:]
	return output, nil
}

// installedToolchain resolves ssh-add through an injected Stat, so no test here
// depends on which OpenSSH programs this machine happens to have.
func installedToolchain() macos.Toolchain {
	programs := fstest.MapFS{"usr/bin/ssh-add": &fstest.MapFile{Mode: 0o755}}
	return macos.Toolchain{
		Directories: []string{"/usr/bin"},
		Stat: func(name string) (fs.FileInfo, error) {
			return programs.Stat(strings.TrimPrefix(name, "/"))
		},
	}
}

// agentLookup deliberately offers the askpass variables that would redirect
// ssh-add to an external program of the user's choosing instead of letting it
// read the standard input this application supplies. Every test in this file
// runs against that hostile environment.
func agentLookup(name string) (string, bool) {
	switch name {
	case "SSH_AUTH_SOCK":
		return "/tmp/fake-agent.sock", true
	case "HOME":
		return "/Users/example", true
	case "PATH":
		return "/usr/bin:/bin", true
	case "SSH_ASKPASS":
		return "/opt/attacker/askpass", true
	case "SSH_ASKPASS_REQUIRE":
		return "force", true
	case "DISPLAY":
		return ":0", true
	default:
		return "", false
	}
}

// assertScrubbedEnvironment is the point of the whole adapter: a child must
// receive a replaced environment that cannot redirect it to an askpass program.
func assertScrubbedEnvironment(t *testing.T, command platform.Command) {
	t.Helper()
	if command.Env == nil {
		t.Fatalf("Env is nil, so the child inherits this process's environment")
	}
	for _, forbidden := range []string{"SSH_ASKPASS=", "SSH_ASKPASS_REQUIRE=", "DISPLAY="} {
		for _, entry := range command.Env {
			if strings.HasPrefix(entry, forbidden) {
				t.Fatalf("Env carried %q: %#v", forbidden, command.Env)
			}
		}
	}
	if strings.Contains(strings.Join(command.Env, "\n"), "/opt/attacker/askpass") {
		t.Fatalf("Env carried the askpass program: %#v", command.Env)
	}
	socket := false
	for _, entry := range command.Env {
		if entry == "SSH_AUTH_SOCK=/tmp/fake-agent.sock" {
			socket = true
		}
	}
	if !socket {
		t.Fatalf("Env = %#v, want the agent socket so the agent stays reachable", command.Env)
	}
}

func TestKeyAgentAddSendsThePassphraseOnlyOnStandardInput(t *testing.T) {
	recorder := &recordingRunner{outputs: []platform.Output{{}}}
	agent := macos.NewKeyAgent(recorder, installedToolchain(), agentLookup)

	err := agent.Add(context.Background(), platform.AgentAddRequest{
		PrivateKeyPath:  "/Users/example/.ssh/id_work",
		Passphrase:      []byte("correct horse"),
		LifetimeSeconds: 3600,
		StoreInKeychain: true,
	})
	if err != nil {
		t.Fatalf("Add error = %v", err)
	}
	if len(recorder.commands) != 1 {
		t.Fatalf("commands = %#v, want one", recorder.commands)
	}
	command := recorder.commands[0]
	if command.Path != "/usr/bin/ssh-add" {
		t.Errorf("Path = %q, want /usr/bin/ssh-add", command.Path)
	}
	want := []string{"-t", "3600", "--apple-use-keychain", "/Users/example/.ssh/id_work"}
	if strings.Join(command.Arguments, " ") != strings.Join(want, " ") {
		t.Fatalf("Arguments = %#v, want %#v", command.Arguments, want)
	}
	for _, argument := range command.Arguments {
		if strings.Contains(argument, "correct horse") {
			t.Fatalf("the passphrase appeared in an argument")
		}
	}
	if string(command.Stdin) != "correct horse" {
		t.Fatalf("Stdin = %q, want the passphrase", command.Stdin)
	}
	if strings.Contains(strings.Join(command.Env, "\n"), "correct horse") {
		t.Fatalf("the passphrase appeared in the environment")
	}
	assertScrubbedEnvironment(t, command)
}

func TestKeyAgentNeverGivesAChildAnAskpassEnvironment(t *testing.T) {
	recorder := &recordingRunner{outputs: []platform.Output{{}, {}, {}}}
	agent := macos.NewKeyAgent(recorder, installedToolchain(), agentLookup)

	if err := agent.Add(context.Background(), platform.AgentAddRequest{
		PrivateKeyPath: "/Users/example/.ssh/id_work",
		Passphrase:     []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Add error = %v", err)
	}
	if _, err := agent.List(context.Background()); err != nil {
		t.Fatalf("List error = %v", err)
	}
	if err := agent.Remove(context.Background(), "/Users/example/.ssh/id_work.pub"); err != nil {
		t.Fatalf("Remove error = %v", err)
	}

	if len(recorder.commands) != 3 {
		t.Fatalf("commands = %#v, want three", recorder.commands)
	}
	for index, command := range recorder.commands {
		t.Run(strings.Join(command.Arguments, " "), func(t *testing.T) {
			if command.Path != "/usr/bin/ssh-add" {
				t.Errorf("commands[%d].Path = %q", index, command.Path)
			}
			assertScrubbedEnvironment(t, command)
		})
	}
}

func TestKeyAgentReportsRejectionWithoutLeakingTheHomePath(t *testing.T) {
	recorder := &recordingRunner{outputs: []platform.Output{{
		ExitCode: 1,
		Stderr:   []byte("Bad passphrase, try again for /Users/example/.ssh/id_work: \n"),
	}}}
	agent := macos.NewKeyAgent(recorder, installedToolchain(), agentLookup)

	err := agent.Add(context.Background(), platform.AgentAddRequest{
		PrivateKeyPath: "/Users/example/.ssh/id_work",
		Passphrase:     []byte("wrong"),
	})
	if !errors.Is(err, platform.ErrAgentRejected) {
		t.Fatalf("error = %v, want ErrAgentRejected", err)
	}
	if strings.Contains(err.Error(), "/Users/example") {
		t.Fatalf("the error carried the absolute home path: %v", err)
	}
	if !strings.Contains(err.Error(), "~/.ssh/id_work") {
		t.Fatalf("the error lost the useful part of the message: %v", err)
	}
}

func TestKeyAgentListParsesIdentitiesAndAnEmptyAgent(t *testing.T) {
	recorder := &recordingRunner{outputs: []platform.Output{{
		Stdout: []byte("256 SHA256:abcdef aida@laptop (ED25519)\n2048 SHA256:012345 work key (RSA)\n"),
	}}}
	identities, err := macos.NewKeyAgent(recorder, installedToolchain(), agentLookup).List(context.Background())
	if err != nil {
		t.Fatalf("List error = %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("identities = %#v, want two", identities)
	}
	if identities[0].Bits != 256 || identities[0].Fingerprint != "SHA256:abcdef" || identities[0].Algorithm != "ED25519" {
		t.Errorf("identities[0] = %#v", identities[0])
	}
	if identities[1].Comment != "work key" {
		t.Errorf("identities[1].Comment = %q, want %q", identities[1].Comment, "work key")
	}
	if arguments := strings.Join(recorder.commands[0].Arguments, " "); arguments != "-l -E sha256" {
		t.Errorf("Arguments = %q, want %q", arguments, "-l -E sha256")
	}

	empty := &recordingRunner{outputs: []platform.Output{{
		ExitCode: 1,
		Stdout:   []byte("The agent has no identities.\n"),
	}}}
	none, err := macos.NewKeyAgent(empty, installedToolchain(), agentLookup).List(context.Background())
	if err != nil {
		t.Fatalf("List error = %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("identities = %#v, want none", none)
	}
}

func TestKeyAgentRefusesWhenNoAgentSocketIsAdvertised(t *testing.T) {
	recorder := &recordingRunner{}
	agent := macos.NewKeyAgent(recorder, installedToolchain(), func(string) (string, bool) { return "", false })

	if agent.Available(context.Background()) {
		t.Fatalf("Available = true without SSH_AUTH_SOCK")
	}
	if err := agent.Add(context.Background(), platform.AgentAddRequest{PrivateKeyPath: "/Users/example/.ssh/id_work"}); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Fatalf("Add error = %v, want ErrAgentUnavailable", err)
	}
	if _, err := agent.List(context.Background()); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Fatalf("List error = %v, want ErrAgentUnavailable", err)
	}
	if err := agent.Remove(context.Background(), "/Users/example/.ssh/id_work.pub"); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Fatalf("Remove error = %v, want ErrAgentUnavailable", err)
	}
	if len(recorder.commands) != 0 {
		t.Fatalf("a command ran without an agent: %#v", recorder.commands)
	}
}

func TestKeyAgentRefusesWhenSSHAddIsNotInstalled(t *testing.T) {
	recorder := &recordingRunner{}
	missing := macos.Toolchain{
		Directories: []string{"/usr/bin"},
		Stat:        func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist },
	}
	agent := macos.NewKeyAgent(recorder, missing, agentLookup)

	if agent.Available(context.Background()) {
		t.Fatalf("Available = true without an ssh-add to run")
	}
	if err := agent.Add(context.Background(), platform.AgentAddRequest{PrivateKeyPath: "/Users/example/.ssh/id_work"}); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Fatalf("Add error = %v, want ErrAgentUnavailable", err)
	}
	if len(recorder.commands) != 0 {
		t.Fatalf("a command ran without ssh-add: %#v", recorder.commands)
	}
}
