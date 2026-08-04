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
