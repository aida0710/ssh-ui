package macos_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"ssh-ui/internal/platform"
	"ssh-ui/internal/platform/macos"
)

// These tests run only local, non-networked system programs with a fixed argv:
// /bin/echo, /bin/cat, /bin/sleep, /usr/bin/false and /usr/bin/yes. They never
// start ssh, never touch the network and never read the real home directory.

func TestRunOutputCapturesStdoutAndExitStatus(t *testing.T) {
	runner := macos.NewOutputRunner()

	output, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/bin/echo",
		Arguments: []string{"one", "two three"},
	})
	if err != nil {
		t.Fatalf("RunOutput = %v", err)
	}
	if got := string(output.Stdout); got != "one two three\n" {
		t.Errorf("stdout = %q", got)
	}
	if output.ExitCode != 0 || output.Truncated || output.Stopped {
		t.Errorf("output = %#v", output)
	}

	failure, err := runner.RunOutput(context.Background(), platform.Command{Path: "/usr/bin/false"})
	if err != nil {
		t.Fatalf("RunOutput(/usr/bin/false) = %v, want a captured exit status", err)
	}
	if failure.ExitCode != 1 {
		t.Errorf("exit code = %d, want 1", failure.ExitCode)
	}
}

func TestRunOutputFeedsFixedStandardInput(t *testing.T) {
	output, err := macos.NewOutputRunner().RunOutput(context.Background(), platform.Command{
		Path:  "/bin/cat",
		Stdin: []byte("payload without a shell\n"),
	})
	if err != nil {
		t.Fatalf("RunOutput = %v", err)
	}
	if got := string(output.Stdout); got != "payload without a shell\n" {
		t.Errorf("stdout = %q", got)
	}
}

func TestRunOutputStopsAtTheTimeoutAndTruncatesOutput(t *testing.T) {
	runner := macos.NewOutputRunner()

	if _, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/bin/sleep",
		Arguments: []string{"30"},
		Timeout:   150 * time.Millisecond,
	}); !errors.Is(err, platform.ErrTimedOut) {
		t.Fatalf("RunOutput(sleep) = %v, want ErrTimedOut", err)
	}

	flood, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/usr/bin/yes",
		Arguments: []string{"flood"},
		Timeout:   400 * time.Millisecond,
	})
	if !errors.Is(err, platform.ErrTimedOut) {
		t.Fatalf("RunOutput(yes) = %v, want ErrTimedOut", err)
	}
	if !flood.Truncated {
		t.Error("unbounded output was not reported as truncated")
	}
	if len(flood.Stdout) > platform.MaxCapturedOutput {
		t.Errorf("captured %d bytes, want at most %d", len(flood.Stdout), platform.MaxCapturedOutput)
	}
}

func TestRunOutputStopsAsSoonAsTheMarkerAppears(t *testing.T) {
	started := time.Now()
	output, err := macos.NewOutputRunner().RunOutput(context.Background(), platform.Command{
		Path:      "/usr/bin/yes",
		Arguments: []string{"authenticated-marker"},
		Timeout:   10 * time.Second,
		StopAfter: []byte("authenticated-marker"),
	})
	if err != nil {
		t.Fatalf("RunOutput = %v", err)
	}
	if !output.Stopped {
		t.Fatalf("output = %#v, want Stopped", output)
	}
	if !bytes.Contains(output.Stdout, []byte("authenticated-marker")) {
		t.Error("captured output does not contain the marker")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("marker did not stop the process early: %s", elapsed)
	}
}

func TestRunOutputRefusesRelativeProgramsAndHonoursCancellation(t *testing.T) {
	runner := macos.NewOutputRunner()

	if _, err := runner.RunOutput(context.Background(), platform.Command{Path: "echo"}); !errors.Is(err, platform.ErrProgramPathNotAbsolute) {
		t.Fatalf("relative program = %v, want ErrProgramPathNotAbsolute", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	if _, err := runner.RunOutput(ctx, platform.Command{Path: "/bin/sleep", Arguments: []string{"30"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run = %v, want context.Canceled", err)
	}
}

func TestRunOutputReplacesTheChildEnvironmentWhenAsked(t *testing.T) {
	runner := macos.NewOutputRunner()

	inherited, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/usr/bin/env",
		Arguments: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(inherited.Stdout, []byte("PATH=")) {
		t.Fatalf("a nil Env did not inherit this process's environment: %q", inherited.Stdout)
	}

	replaced, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/usr/bin/env",
		Arguments: []string{},
		Env:       []string{"HOME=/tmp/ssh-ui-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(replaced.Stdout)); got != "HOME=/tmp/ssh-ui-test" {
		t.Fatalf("child environment = %q, want exactly the supplied entry", got)
	}
}
