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

// TerminalPasswordScript is the same payload with the askpass helper armed.
//
// It keeps the property that matters: nothing is concatenated into this text.
// The alias, the helper path, the loopback endpoint and the one-time token all
// arrive through `on run argv` and are quoted individually, so there is no
// AppleScript string for any of them to escape from and no shell word any of
// them can split.
//
// SSH_ASKPASS_REQUIRE=force is what makes OpenSSH consult the helper rather
// than the terminal it is running in, and NumberOfPasswordPrompts=1 stops a
// wrong stored password being offered three times, which on some servers
// counts towards a lockout.
const TerminalPasswordScript = `on run argv
	set targetAlias to item 1 of argv
	set helperPath to item 2 of argv
	set askpassURL to item 3 of argv
	set askpassToken to item 4 of argv
	set sshCommand to "SSH_ASKPASS=" & quoted form of helperPath & ¬
		" SSH_ASKPASS_REQUIRE=force" & ¬
		" SSH_UI_ASKPASS_URL=" & quoted form of askpassURL & ¬
		" SSH_UI_ASKPASS_TOKEN=" & quoted form of askpassToken & ¬
		" SSH_UI_ASKPASS_ALIAS=" & quoted form of targetAlias & ¬
		" ssh -o NumberOfPasswordPrompts=1 -- " & quoted form of targetAlias
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
	return t.run(ctx, TerminalPasswordScript, []string{"-", alias, helperPath, endpoint, token})
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
