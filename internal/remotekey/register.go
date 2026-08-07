// Package remotekey installs a public key in a remote account's
// authorized_keys file.
//
// The remote command is a package constant. The key travels on standard
// input, where the fixed routine reads it into a shell variable, so no caller
// input is ever spliced into a command line, a shell string or a here-document.
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
	// ProbeMarker is what a POSIX shell must echo back.
	ProbeMarker = "sshc-posix-shell"
	// ProbeCommand is the fixed command used to decide whether the remote
	// account has a POSIX shell. It prints one known word and nothing else.
	ProbeCommand = `printf '%s\n' sshc-posix-shell`
	// RemotePath is the file this package appends to.
	RemotePath = "~/.ssh/authorized_keys"

	// Registration outcomes.
	RegistrationAdded    = "added"
	RegistrationExisting = "already_present"

	// DefaultTimeout bounds one remote operation.
	DefaultTimeout = 30 * time.Second
)

// Routine is the complete remote program. It contains no caller input.
//
// The key arrives on standard input and is read into "$key"; grep -x -F
// compares whole lines literally, so a key that is already present is never
// duplicated; the permissions are tightened before anything is written.
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

// publicKeyPattern accepts one line: a known algorithm name, a base64 blob and
// an optional comment without any control character.
var publicKeyPattern = regexp.MustCompile(
	`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) ([A-Za-z0-9+/]+={0,3})( [^\x00-\x1f\x7f]*)?$`)

// PublicKey is the key the caller selected. The key vault subsystem chooses
// it; this package needs only the file it came from and its exact line.
type PublicKey struct {
	Path string
	Line string
}

// ParsePublicKey validates one public key line and returns its fingerprint.
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

// ManualSteps are the instructions shown for a remote this package will not
// automate. They describe what to do, they never run anything.
var ManualSteps = []string{
	"Open a session to the host yourself and check which shell the account uses.",
	"Create ~/.ssh with mode 700 and ~/.ssh/authorized_keys with mode 600 if they do not exist.",
	"Append the public key line shown above to ~/.ssh/authorized_keys as a single line.",
	"Confirm the file still contains one key per line and that no key was split or duplicated.",
}

// Plan is what the user confirms before anything runs on the remote host.
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

// Result is one completed registration.
type Result struct {
	Outcome   string
	ExitCode  int
	Stderr    string
	Truncated bool
}

// Service performs remote registration through the process seam.
type Service struct {
	Runner     platform.OutputRunner
	Toolchain  platform.Toolchain
	ConfigPath string
	Timeout    time.Duration
	// Environment is the child's complete environment, normally
	// platform.MinimalEnvironment.
	Environment []string
}

// NewService wires the production dependencies together.
func NewService(runner platform.OutputRunner, toolchain platform.Toolchain, configPath string) *Service {
	return &Service{Runner: runner, Toolchain: toolchain, ConfigPath: configPath}
}

// Plan describes the change without contacting anything.
//
// valuesFrom records whether the account details came from `ssh -G` or from
// this application's own reading of the configuration, so the confirmation
// dialog can say which.
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

// Register probes the remote shell and then installs the key.
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
