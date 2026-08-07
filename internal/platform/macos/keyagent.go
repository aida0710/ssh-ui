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

// KeyAgent drives ssh-add.
//
// ssh-add reads a passphrase from standard input when one is available, so this
// adapter needs neither SSH_ASKPASS nor a terminal, and the secret never
// reaches argv or the environment. Every invocation replaces the child
// environment with platform.MinimalEnvironment, because SSH_ASKPASS together
// with SSH_ASKPASS_REQUIRE=force would make ssh-add ignore that standard input
// and ask a program this application did not choose for the passphrase
// instead. The key path is always an absolute path inside the workspace, so it
// can never be read as an option.
//
// --apple-use-keychain is the documented macOS flag that also stores the
// passphrase in the login Keychain. It is used only when the user asked for it.
//
// The program path comes from a Toolchain rather than a constant, so this
// adapter runs the same OpenSSH the rest of the application does and never
// depends on PATH.
type KeyAgent struct {
	runner    platform.OutputRunner
	toolchain platform.Toolchain
	lookup    func(string) (string, bool)
	timeout   time.Duration
}

// NewKeyAgent builds the macOS ssh-add adapter. The lookup supplies the child
// environment, so a test never depends on the developer's own environment.
func NewKeyAgent(runner platform.OutputRunner, toolchain platform.Toolchain, lookup func(string) (string, bool)) platform.KeyAgent {
	return KeyAgent{runner: runner, toolchain: toolchain, lookup: lookup, timeout: defaultAgentTimeout}
}

// Available reports whether this process can reach an agent at all: it needs a
// socket to talk to and an ssh-add to talk with.
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

// run is the single place an ssh-add process is started, so the scrubbed
// environment and the passphrase-on-stdin rule cannot be forgotten by one
// caller.
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

// sanitize replaces the user's home directory with '~' so a message shown in
// the UI, or copied out of it, carries no absolute path.
func (agent KeyAgent) sanitize(message string) string {
	home, ok := agent.lookup("HOME")
	if !ok || home == "" {
		return message
	}
	return strings.ReplaceAll(message, home, "~")
}

// parseIdentities reads `ssh-add -l` output lines of the form
// "<bits> <fingerprint> <comment> (<ALGORITHM>)".
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
