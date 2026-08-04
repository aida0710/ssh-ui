package macos_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"ssh-ui/internal/platform"
	"ssh-ui/internal/platform/macos"
)

type terminalRunner struct {
	commands []platform.Command
	output   platform.Output
}

func (runner *terminalRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, nil
}

func TestTerminalDeliversTheAliasAsAnArgumentNotAsScriptText(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.NewTerminal(runner)

	if err := terminal.Launch(context.Background(), "bastion"); err != nil {
		t.Fatalf("Launch = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v", runner.commands)
	}

	command := runner.commands[0]
	if command.Path != "/usr/bin/osascript" {
		t.Errorf("path = %q", command.Path)
	}
	if !slices.Equal(command.Arguments, []string{"-", "bastion"}) {
		t.Fatalf("arguments = %#v, want [- bastion]", command.Arguments)
	}
	if string(command.Stdin) != macos.TerminalScript {
		t.Error("the AppleScript sent on stdin is not the package constant")
	}
	if strings.Contains(macos.TerminalScript, "bastion") {
		t.Error("the alias must never be part of the script text")
	}
	if !strings.Contains(macos.TerminalScript, "quoted form of") {
		t.Error("the script must quote the argument before handing it to a shell")
	}
}

// TestTerminalRefusesAnAliasThatCouldEscapeItsQuoting covers the payloads that
// would matter if the alias were ever concatenated into the script: AppleScript
// string termination, a `do shell script` call, and POSIX shell metacharacters.
// Each must be refused outright rather than escaped, because escaping is a
// guarantee this application does not want to have to make.
func TestTerminalRefusesAnAliasThatCouldEscapeItsQuoting(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.NewTerminal(runner)

	unsafe := []string{
		"a b",
		"a\"b",
		"a'b",
		"-oProxyCommand=id",
		"a;id",
		"a\nb",
		`bastion" & (do shell script "id") & "`,
		`bastion"; do shell script "rm -rf ~"; "`,
		"$(id)",
		"`id`",
		"a|id",
		"a&id",
		"a\\b",
		"a\x00b",
	}
	for _, alias := range unsafe {
		if err := terminal.Launch(context.Background(), alias); !errors.Is(err, platform.ErrUnsafeAlias) {
			t.Errorf("Launch(%q) = %v, want ErrUnsafeAlias", alias, err)
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("an unsafe alias reached osascript: %#v", runner.commands)
	}
}

func TestTerminalReportsAFailedLaunch(t *testing.T) {
	runner := &terminalRunner{output: platform.Output{ExitCode: 1, Stderr: []byte("execution error\n")}}

	err := macos.NewTerminal(runner).Launch(context.Background(), "bastion")
	var launchError *macos.LaunchError
	if !errors.As(err, &launchError) || launchError.ExitCode != 1 {
		t.Fatalf("Launch = %v, want *LaunchError", err)
	}
}
