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

func TestLaunchWithPasswordPassesEveryValueAsAnArgument(t *testing.T) {
	// The script is a constant. If a value ever reaches it by concatenation,
	// an alias or a token becomes an AppleScript expression.
	runner := &terminalRunner{}
	terminal := macos.Terminal{Runner: runner, Program: "/usr/bin/osascript"}

	err := terminal.LaunchWithPassword(context.Background(),
		"bastion", "/Applications/ssh-ui", "http://127.0.0.1:5555/askpass", "one-time-token")
	if err != nil {
		t.Fatalf("LaunchWithPassword = %v", err)
	}

	if len(runner.commands) != 1 {
		t.Fatalf("commands = %d", len(runner.commands))
	}
	command := runner.commands[0]
	want := []string{"-", "bastion", "/Applications/ssh-ui", "http://127.0.0.1:5555/askpass", "one-time-token"}
	if !slices.Equal(command.Arguments, want) {
		t.Errorf("arguments = %#v, want %#v", command.Arguments, want)
	}
	if string(command.Stdin) != macos.TerminalPasswordScript {
		t.Error("the script handed to osascript is not the constant")
	}
	for _, value := range want[1:] {
		if strings.Contains(macos.TerminalPasswordScript, value) {
			t.Errorf("the script constant contains %q, so it was built by interpolation", value)
		}
	}
}

func TestTerminalPasswordScriptArmsTheHelperAndBoundsThePrompts(t *testing.T) {
	for _, fragment := range []string{
		"SSH_ASKPASS=",
		"SSH_ASKPASS_REQUIRE=force",
		"SSH_UI_ASKPASS_URL=",
		"SSH_UI_ASKPASS_TOKEN=",
		"SSH_UI_ASKPASS_ALIAS=",
		"NumberOfPasswordPrompts=1",
	} {
		if !strings.Contains(macos.TerminalPasswordScript, fragment) {
			t.Errorf("the script is missing %q", fragment)
		}
	}
	// Every value must be quoted for the shell Terminal runs.
	if strings.Count(macos.TerminalPasswordScript, "quoted form of") != 5 {
		t.Errorf("not every value is quoted: %q", macos.TerminalPasswordScript)
	}
}

func TestLaunchWithPasswordRefusesARelativeHelperAndAnUnsafeAlias(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.Terminal{Runner: runner, Program: "/usr/bin/osascript"}

	if err := terminal.LaunchWithPassword(context.Background(),
		"bastion", "ssh-ui", "http://127.0.0.1:1/askpass", "t"); !errors.Is(err, macos.ErrHelperPathNotAbsolute) {
		t.Errorf("a relative helper = %v, want ErrHelperPathNotAbsolute", err)
	}
	if err := terminal.LaunchWithPassword(context.Background(),
		"bad alias", "/Applications/ssh-ui", "http://127.0.0.1:1/askpass", "t"); err == nil {
		t.Error("an unsafe alias was launched")
	}
	if len(runner.commands) != 0 {
		t.Errorf("a refused launch still reached osascript: %#v", runner.commands)
	}
}
