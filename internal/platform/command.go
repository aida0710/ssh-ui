package platform

import (
	"context"
	"errors"
	"time"
)

// MaxCapturedOutput bounds how many bytes of one stream this application keeps
// in memory for a single external command.
const MaxCapturedOutput = 64 << 10

var (
	// ErrTimedOut reports that a command did not finish within its timeout and
	// was killed.
	ErrTimedOut = errors.New("command did not finish before its timeout")
	// ErrProgramPathNotAbsolute rejects a program that would otherwise be
	// looked up through PATH.
	ErrProgramPathNotAbsolute = errors.New("program path must be absolute")
)

// Command is one external process.
//
// Path is an absolute program path and Arguments is its argv tail. There is no
// field for a command line, because this application never builds one: nothing
// here is ever interpreted by a shell.
type Command struct {
	Path      string
	Arguments []string
	// Stdin is the complete standard input. It is always supplied, so a child
	// never inherits the terminal and never blocks on a prompt.
	Stdin []byte
	// Timeout kills the process when it is exceeded. Zero means the caller's
	// context is the only bound.
	Timeout time.Duration
	// StopAfter stops the process as soon as this byte sequence appears in
	// stdout or stderr. It lets a long-lived command report a decisive result
	// without waiting for its own timeout.
	StopAfter []byte
	// Env is the child's complete environment. A nil Env inherits this
	// process's environment; a non-nil Env replaces it entirely, including
	// when it is empty. Callers that run an OpenSSH program should pass
	// MinimalEnvironment so the child cannot be redirected by a variable the
	// user happens to have exported.
	Env []string
}

// askpassVariables are deliberately withheld from every child.
//
// With SSH_ASKPASS and SSH_ASKPASS_REQUIRE set, ssh-add and ssh ask an
// external program for a passphrase instead of reading the standard input this
// application supplies, which would move a secret out of this process's
// control and onto a program it did not choose. DISPLAY is withheld for the
// same reason.
var minimalEnvironmentVariables = []string{"HOME", "PATH", "LANG", "SSH_AUTH_SOCK"}

// MinimalEnvironment returns the smallest environment an OpenSSH client
// program needs, taking each value from lookup and omitting the ones that are
// not set. SSH_AUTH_SOCK is kept because reaching a running agent is a
// supported operation; SSH_ASKPASS, SSH_ASKPASS_REQUIRE and DISPLAY are not
// included at all.
func MinimalEnvironment(lookup func(name string) (string, bool)) []string {
	environment := make([]string, 0, len(minimalEnvironmentVariables))
	for _, name := range minimalEnvironmentVariables {
		if value, ok := lookup(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

// Output is the bounded result of one external command. A non-zero exit status
// is data, not an error: it is reported in ExitCode with err == nil.
type Output struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
	Stopped   bool
	Elapsed   time.Duration
}

// OutputRunner runs one external program and returns its bounded output.
type OutputRunner interface {
	RunOutput(ctx context.Context, command Command) (Output, error)
}

// Toolchain locates the OpenSSH programs installed on this machine.
//
// Every program this application is willing to run is named here, so a caller
// can never assemble a program path of its own: it asks for the one it needs
// and receives an absolute path or an error.
type Toolchain interface {
	SSH() (string, error)
	KeyScan() (string, error)
	KeyGen() (string, error)
	KeyAdd() (string, error)
}
