package macos_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"sshc/internal/platform"
	"sshc/internal/platform/macos"
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

// TestTerminalRefusesAnAliasThatCouldEscapeItsQuoting は、alias がスクリプトに
// 連結されていたら問題になったであろうペイロードを網羅する。AppleScript の文字列
// 終端、`do shell script` の呼び出し、そして POSIX シェルのメタ文字である。
// いずれもエスケープではなく無条件に拒否しなければならない。エスケープは、この
// アプリケーションが背負いたくない保証だからだ。
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
	// スクリプトは定数である。値が連結によってそこへ届くようになれば、alias や
	// トークンが AppleScript の式になってしまう。
	runner := &terminalRunner{}
	terminal := macos.Terminal{Runner: runner, Program: "/usr/bin/osascript"}

	err := terminal.LaunchWithPassword(context.Background(),
		"bastion", "/Applications/sshc", "http://127.0.0.1:5555/askpass", "one-time-token")
	if err != nil {
		t.Fatalf("LaunchWithPassword = %v", err)
	}

	if len(runner.commands) != 1 {
		t.Fatalf("commands = %d", len(runner.commands))
	}
	command := runner.commands[0]
	// エンドポイントもトークンも、もうここにはない。ウィンドウはこのアプリケーション
	// 自身のコマンドラインを実行し、そのコマンドが必要になったときにトークンを求める。
	// したがって、有効なトークンが Terminal のスクロールバックに書かれることはない。
	want := []string{"-", "bastion", "/Applications/sshc"}
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

// ウィンドウは、シェルの履歴が保持すべきでないものを何も運ばない。
//
// 以前はワンタイムトークンそのものを運んでおり、それはシェルが履歴に書き、
// Terminal がスクロールバックに残すコマンドラインの中にあった。いま実行するのは
// このバイナリと alias である。トークンはそのプロセスが要求するもので、表示される
// ことはない。
func TestTerminalPasswordScriptCarriesNoCredential(t *testing.T) {
	for _, absent := range []string{
		"SSH_ASKPASS=",
		"SSHC_ASKPASS_URL=",
		"SSHC_ASKPASS_TOKEN=",
		"SSHC_ASKPASS_ALIAS=",
	} {
		if strings.Contains(macos.TerminalPasswordScript, absent) {
			t.Errorf("the script still carries %q into the window", absent)
		}
	}
	// すべての値は、Terminal の実行するシェル向けに引用されていなければならない。
	if strings.Count(macos.TerminalPasswordScript, "quoted form of") != 2 {
		t.Errorf("not every value is quoted: %q", macos.TerminalPasswordScript)
	}
}

func TestLaunchWithPasswordRefusesARelativeHelperAndAnUnsafeAlias(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.Terminal{Runner: runner, Program: "/usr/bin/osascript"}

	if err := terminal.LaunchWithPassword(context.Background(),
		"bastion", "sshc", "http://127.0.0.1:1/askpass", "t"); !errors.Is(err, macos.ErrHelperPathNotAbsolute) {
		t.Errorf("a relative helper = %v, want ErrHelperPathNotAbsolute", err)
	}
	if err := terminal.LaunchWithPassword(context.Background(),
		"bad alias", "/Applications/sshc", "http://127.0.0.1:1/askpass", "t"); err == nil {
		t.Error("an unsafe alias was launched")
	}
	if len(runner.commands) != 0 {
		t.Errorf("a refused launch still reached osascript: %#v", runner.commands)
	}
}
