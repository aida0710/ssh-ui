package macos

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"sshc/internal/platform"
)

// OutputRunner は、argv を直接指定して外部プログラムを実行する。
//
// シェルを起動することは決してなく、子プロセスが端末を読めないよう常に固定の
// 標準入力を与え、どちらのストリームについても platform.MaxCapturedOutput
// バイトを超えて保持することはない。
type OutputRunner struct{}

// NewOutputRunner は macOS のプロセスアダプタを返す。
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
	// WaitDelay は、プロセスが kill されたあと Wait が継承したパイプ上でどれだけ
	// ブロックするかに上限を設ける。詰まった子がリクエストを開けたままにできない。
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
		// 呼び出し側がマーカーで止めるよう求めたので、非ゼロのステータスはこの
		// アプリケーション自身のキャンセルを反映しているにすぎない。
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

// boundedBuffer は最大 limit バイトを集め、marker が現れた時点でプロセスを止め
// られる。os/exec がコピー用の goroutine からここへ書くので、すべてのフィールドは
// 保護されている。
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
		// 直前の marker-1 バイトを保持して、チャンクの境界をまたいで探索する。
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
