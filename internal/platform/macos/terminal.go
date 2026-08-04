package macos

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ssh-ui/internal/platform"
)

// ErrTerminalUnavailable reports that the automation program is missing.
var ErrTerminalUnavailable = errors.New("osascript is not available")

// TerminalScript is the complete automation payload and a constant.
//
// The alias is delivered as an argument to `on run argv` and is never
// concatenated into this text, so there is no AppleScript string for an alias
// to escape from. `quoted form of` then produces a POSIX-quoted token for the
// shell Terminal runs, and the caller has already restricted the alias to a
// character set with no shell metacharacters at all. Two independent barriers
// therefore stand between an alias and either interpreter.
const TerminalScript = `on run argv
	set targetAlias to item 1 of argv
	set sshCommand to "ssh -- " & quoted form of targetAlias
	tell application "Terminal"
		activate
		do script sshCommand
	end tell
end run
`

// LaunchError reports that the automation program refused the request.
type LaunchError struct {
	ExitCode int
	Stderr   string
}

func (e *LaunchError) Error() string {
	return fmt.Sprintf("terminal launch failed with status %d", e.ExitCode)
}

// Terminal opens Terminal.app through osascript.
type Terminal struct {
	Runner  platform.OutputRunner
	Program string
	Timeout time.Duration
}

// NewTerminal returns the macOS Terminal launcher.
func NewTerminal(runner platform.OutputRunner) Terminal {
	return Terminal{Runner: runner, Program: "/usr/bin/osascript", Timeout: 10 * time.Second}
}

// Launch opens `ssh -- <alias>` in a new Terminal window.
func (t Terminal) Launch(ctx context.Context, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	program := t.Program
	if program == "" {
		program = "/usr/bin/osascript"
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	output, err := t.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-", alias},
		Stdin:     []byte(TerminalScript),
		Timeout:   timeout,
	})
	if err != nil {
		return err
	}
	if output.ExitCode != 0 {
		return &LaunchError{ExitCode: output.ExitCode, Stderr: string(output.Stderr)}
	}
	return nil
}
