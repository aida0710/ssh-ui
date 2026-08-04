package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ssh-ui/internal/effective"
	"ssh-ui/internal/platform"
)

const (
	// AuthenticatedMarker is the phrase OpenSSH prints once a session is
	// authenticated. Watching for it lets the test finish as soon as the
	// question is answered instead of waiting for its own timeout.
	AuthenticatedMarker = "Authenticated to "
	// MaxReportedOutput bounds the captured stderr handed back for display.
	MaxReportedOutput = 8 << 10
	// DefaultAuthenticationTimeout bounds one authentication test.
	DefaultAuthenticationTimeout = 20 * time.Second
	// DefaultConnectTimeout is passed to OpenSSH so a stalled TCP connection
	// fails before this application's own timeout fires.
	DefaultConnectTimeout = 8 * time.Second
)

// Authentication test outcomes.
const (
	OutcomeAuthenticated  = "authenticated"
	OutcomeDenied         = "authentication_denied"
	OutcomeHostKeyUnknown = "host_key_unknown"
	OutcomeHostKeyChanged = "host_key_changed"
	OutcomeDNSFailure     = "dns_failure"
	OutcomeRefused        = "connection_refused"
	OutcomeTimeout        = "timeout"
	OutcomeFailed         = "failed"
)

// ExecutableDirectiveError reports that connecting would run a command that no
// command-line option can disable, and that the user has not confirmed it.
type ExecutableDirectiveError struct {
	Directives []effective.Executable
}

func (e *ExecutableDirectiveError) Error() string {
	return fmt.Sprintf("connecting would run %d configured command(s) that cannot be disabled", len(e.Directives))
}

// AuthenticationResult is one completed authentication test.
type AuthenticationResult struct {
	Outcome       string
	Authenticated bool
	ExitCode      int
	Stderr        string
	Truncated     bool
	Elapsed       time.Duration
}

// Authentication runs one real SSH authentication attempt.
type Authentication struct {
	Runner         platform.OutputRunner
	Toolchain      platform.Toolchain
	ConfigPath     string
	Timeout        time.Duration
	ConnectTimeout time.Duration
}

// HardeningOptions returns the command-line options that neutralise everything
// this test does not need. Command-line options take precedence over every
// configuration file, which is why the test can rely on them: SessionType=none
// asks for no shell and no remote command, ClearAllForwardings drops local,
// remote and dynamic forwards, PermitLocalCommand=no blocks LocalCommand, and
// StrictHostKeyChecking=yes refuses to trust an unknown host key silently.
func HardeningOptions(connectTimeout time.Duration) []string {
	seconds := int(connectTimeout.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	settings := []string{
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
		"ConnectTimeout=" + strconv.Itoa(seconds),
	}
	options := make([]string, 0, len(settings)*2)
	for _, setting := range settings {
		options = append(options, "-o", setting)
	}
	return options
}

// Test authenticates against alias and stops as soon as the answer is known.
//
// acknowledged must come from a consumed action token that displayed the exact
// commands in report.Unavoidable(); without it, a configuration that would run
// such a command does not start.
func (a Authentication) Test(ctx context.Context, report effective.Report, alias string, acknowledged bool) (AuthenticationResult, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return AuthenticationResult{}, err
	}
	if blocking := report.Unavoidable(); len(blocking) > 0 && !acknowledged {
		return AuthenticationResult{}, &ExecutableDirectiveError{Directives: blocking}
	}
	program, err := a.Toolchain.SSH()
	if err != nil {
		return AuthenticationResult{}, err
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = DefaultAuthenticationTimeout
	}
	connectTimeout := a.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = DefaultConnectTimeout
	}

	arguments := []string{"-v", "-F", a.ConfigPath}
	arguments = append(arguments, HardeningOptions(connectTimeout)...)
	arguments = append(arguments, "--", alias)

	output, runErr := a.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: arguments,
		Timeout:   timeout,
		StopAfter: []byte(AuthenticatedMarker),
	})
	if runErr != nil && !errors.Is(runErr, platform.ErrTimedOut) {
		return AuthenticationResult{}, runErr
	}

	result := AuthenticationResult{
		ExitCode:  output.ExitCode,
		Stderr:    trimOutput(string(output.Stderr)),
		Truncated: output.Truncated,
		Elapsed:   output.Elapsed,
	}
	result.Truncated = result.Truncated || len(output.Stderr) > MaxReportedOutput
	result.Outcome, result.Authenticated = classify(output, runErr)
	return result, nil
}

func classify(output platform.Output, runErr error) (string, bool) {
	stderr := string(output.Stderr)
	if strings.Contains(stderr, AuthenticatedMarker) || strings.Contains(string(output.Stdout), AuthenticatedMarker) {
		return OutcomeAuthenticated, true
	}
	if errors.Is(runErr, platform.ErrTimedOut) {
		return OutcomeTimeout, false
	}
	switch {
	case strings.Contains(stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return OutcomeHostKeyChanged, false
	case strings.Contains(stderr, "Host key verification failed"):
		return OutcomeHostKeyUnknown, false
	case strings.Contains(stderr, "Permission denied"):
		return OutcomeDenied, false
	case strings.Contains(stderr, "Could not resolve hostname"):
		return OutcomeDNSFailure, false
	case strings.Contains(stderr, "Connection refused"):
		return OutcomeRefused, false
	case strings.Contains(stderr, "Connection timed out"), strings.Contains(stderr, "Operation timed out"):
		return OutcomeTimeout, false
	default:
		return OutcomeFailed, false
	}
}

func trimOutput(text string) string {
	if len(text) <= MaxReportedOutput {
		return text
	}
	return text[:MaxReportedOutput]
}
