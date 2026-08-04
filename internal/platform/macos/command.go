package macos

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"ssh-ui/internal/platform"
)

// OutputRunner runs external programs with a direct argv.
//
// It never invokes a shell, always supplies a fixed standard input so a child
// cannot read the terminal, and never keeps more than
// platform.MaxCapturedOutput bytes of either stream.
type OutputRunner struct{}

// NewOutputRunner returns the macOS process adapter.
func NewOutputRunner() platform.OutputRunner { return OutputRunner{} }

func (OutputRunner) RunOutput(ctx context.Context, command platform.Command) (platform.Output, error) {
	if !filepath.IsAbs(command.Path) {
		return platform.Output{}, platform.ErrProgramPathNotAbsolute
	}

	runContext, stop := context.WithCancel(ctx)
	defer stop()
	if command.Timeout > 0 {
		timedContext, cancelTimeout := context.WithTimeout(runContext, command.Timeout)
		defer cancelTimeout()
		runContext = timedContext
	}

	process := exec.CommandContext(runContext, command.Path, command.Arguments...)
	process.Stdin = bytes.NewReader(command.Stdin)
	if command.Env != nil {
		process.Env = command.Env
	}
	// WaitDelay bounds how long Wait blocks on inherited pipes after the
	// process is killed, so a stuck child cannot hold a request open.
	process.WaitDelay = 2 * time.Second

	stdout := &boundedBuffer{limit: platform.MaxCapturedOutput, marker: command.StopAfter, stop: stop}
	stderr := &boundedBuffer{limit: platform.MaxCapturedOutput, marker: command.StopAfter, stop: stop}
	process.Stdout = stdout
	process.Stderr = stderr

	started := time.Now()
	runErr := process.Run()
	output := platform.Output{
		Stdout:    stdout.contents(),
		Stderr:    stderr.contents(),
		Truncated: stdout.overflowed() || stderr.overflowed(),
		Stopped:   stdout.sawMarker() || stderr.sawMarker(),
		Elapsed:   time.Since(started),
	}

	var exitError *exec.ExitError
	switch {
	case runErr == nil:
		return output, nil
	case output.Stopped:
		// The caller asked to stop at the marker, so the non-zero status only
		// reflects this application's own cancellation.
		output.ExitCode = -1
		return output, nil
	case errors.Is(ctx.Err(), context.Canceled):
		output.ExitCode = -1
		return output, ctx.Err()
	case errors.Is(runContext.Err(), context.DeadlineExceeded):
		output.ExitCode = -1
		return output, platform.ErrTimedOut
	case errors.As(runErr, &exitError):
		output.ExitCode = exitError.ExitCode()
		return output, nil
	default:
		return output, runErr
	}
}

// boundedBuffer collects at most limit bytes and can stop the process as soon
// as marker appears. os/exec writes to it from its copying goroutine, so every
// field is guarded.
type boundedBuffer struct {
	mutex     sync.Mutex
	buffer    bytes.Buffer
	tail      []byte
	limit     int
	marker    []byte
	stop      context.CancelFunc
	truncated bool
	found     bool
}

func (b *boundedBuffer) Write(chunk []byte) (int, error) {
	b.mutex.Lock()
	switch remaining := b.limit - b.buffer.Len(); {
	case remaining <= 0:
		b.truncated = true
	case len(chunk) > remaining:
		b.buffer.Write(chunk[:remaining])
		b.truncated = true
	default:
		b.buffer.Write(chunk)
	}

	if len(b.marker) > 0 && !b.found {
		// Search across chunk boundaries by keeping the last marker-1 bytes.
		window := append(append([]byte(nil), b.tail...), chunk...)
		if bytes.Contains(window, b.marker) {
			b.found = true
		}
		if len(window) >= len(b.marker) {
			b.tail = append([]byte(nil), window[len(window)-len(b.marker)+1:]...)
		} else {
			b.tail = window
		}
	}
	found := b.found
	b.mutex.Unlock()

	if found && b.stop != nil {
		b.stop()
	}
	return len(chunk), nil
}

func (b *boundedBuffer) contents() []byte {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

func (b *boundedBuffer) overflowed() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.truncated
}

func (b *boundedBuffer) sawMarker() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.found
}
