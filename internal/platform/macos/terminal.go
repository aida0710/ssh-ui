package macos

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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

// TerminalPasswordScript opens the connection through this application's own
// command line.
//
// It runs `ssh-ui <alias>`, which asks the running application for a one-time
// token and execs ssh with the environment set. The window used to be given
// that environment directly — five variables and the token among them — which
// put a live credential-bearing token into the Terminal's scrollback and into
// whatever history file the shell keeps. Now nothing of it is ever printed.
//
// It keeps the property that matters: nothing is concatenated into this text.
// The alias and the path to this binary arrive through `on run argv` and are
// quoted individually, so there is no AppleScript string for either to escape
// from and no shell word either can split.
const TerminalPasswordScript = `on run argv
	set targetAlias to item 1 of argv
	set helperPath to item 2 of argv
	set sshCommand to quoted form of helperPath & " " & quoted form of targetAlias
	tell application "Terminal"
		activate
		do script sshCommand
	end tell
end run
`

// ErrHelperPathNotAbsolute rejects a helper this application would have to
// find through PATH, which is to say a helper someone else could supply.
var ErrHelperPathNotAbsolute = errors.New("askpass helper path must be absolute")

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

// LaunchWithPassword opens ssh in Terminal with the askpass helper armed.
//
// The helper path must be absolute so that nothing resolves it through PATH.
// The token is single use and belongs to this alias; it is visible in the
// Terminal window's scrollback and in the process table, which discloses that
// a connection is being made and nothing about the password itself.
func (t Terminal) LaunchWithPassword(ctx context.Context, alias, helperPath, endpoint, token string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	if !filepath.IsAbs(helperPath) {
		return ErrHelperPathNotAbsolute
	}
	return t.run(ctx, TerminalPasswordScript, []string{"-", alias, helperPath})
}

// Launch opens `ssh -- <alias>` in a new Terminal window.
func (t Terminal) Launch(ctx context.Context, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	return t.run(ctx, TerminalScript, []string{"-", alias})
}

func (t Terminal) run(ctx context.Context, script string, arguments []string) error {
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
		Arguments: arguments,
		Stdin:     []byte(script),
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
