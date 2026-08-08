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

// disk は、アプリケーションが置かれているディスクを表す。テストが
// ファイルシステムに依存しないための唯一の継ぎ目であり、ここに無いものは
// 無いものとして扱われる。
func disk(contents map[string][]string) func(string) []string {
	return func(directory string) []string { return contents[directory] }
}

func TestTerminalDeliversTheAliasAsAnArgumentNotAsScriptText(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.NewTerminal(runner, "")

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
	terminal := macos.NewTerminal(runner, "")

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

	err := macos.NewTerminal(runner, "").Launch(context.Background(), "bastion")
	var launchError *macos.LaunchError
	if !errors.As(err, &launchError) || launchError.ExitCode != 1 {
		t.Fatalf("Launch = %v, want *LaunchError", err)
	}
}

// kitty のウィンドウは子プロセスが終わると閉じる。--hold が無ければ、接続が即座に
// 失敗したときにユーザーは理由を読めない。
// kitty のウィンドウは子プロセスが終わると閉じる。--hold が無ければ、接続が即座に
// 失敗したときにユーザーは理由を読めない。
//
// argv 側の端末は `open` を通す。アプリケーションを探すのは Launch Services の
// 仕事であり、こちらがバンドルの場所を当てにすると、/Applications に入れなかった
// 人の環境で黙って壊れるからである。
func TestArgvTerminalsAreOpenedByBundleWithoutAShell(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.Terminal{
		Runner:  runner,
		Open:    "/usr/bin/open",
		Entries: disk(map[string][]string{"/Applications": {"kitty.app"}}),
	}

	if err := terminal.LaunchIn(context.Background(), platform.TerminalChoice{ID: platform.TerminalKitty}, "bastion"); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || runner.commands[0].Path != "/usr/bin/open" {
		t.Fatalf("commands = %#v", runner.commands)
	}
	want := []string{"-n", "-b", "net.kovidgoyal.kitty", "--args", "--hold", "/usr/bin/ssh", "--", "bastion"}
	if !slices.Equal(runner.commands[0].Arguments, want) {
		t.Errorf("arguments = %#v, want %#v", runner.commands[0].Arguments, want)
	}
	if len(runner.commands[0].Stdin) != 0 {
		t.Error("an argv terminal was handed a script")
	}

	if err := terminal.LaunchWithPasswordIn(context.Background(), platform.TerminalChoice{ID: platform.TerminalKitty},
		"bastion", "/Applications/sshc", "http://127.0.0.1:1", "token"); err != nil {
		t.Fatal(err)
	}
	want = []string{"-n", "-b", "net.kovidgoyal.kitty", "--args", "--hold", "/Applications/sshc", "bastion"}
	if !slices.Equal(runner.commands[1].Arguments, want) {
		t.Errorf("password arguments = %#v, want %#v", runner.commands[1].Arguments, want)
	}
}

// 新しい端末を足すことは、行をひとつ書くことでなければならない。表がその形を
// 保っているかを、語彙の側から確かめる。
func TestEveryTerminalInTheVocabularyCanBeLaunched(t *testing.T) {
	for _, id := range platform.TerminalIDs {
		runner := &terminalRunner{}
		terminal := macos.Terminal{
			Runner: runner, Open: "/usr/bin/open", Program: "/usr/bin/osascript",
			Entries: disk(map[string][]string{"/Applications": {"iTerm.app", "kitty.app", "Ghostty.app", "WezTerm.app", "Term.app"}}),
		}
		choice := platform.TerminalChoice{ID: id}
		if id == platform.TerminalCustom {
			choice.Application = "/Applications/Term.app"
			choice.Arguments = []string{"-e"}
		}
		if err := terminal.LaunchIn(context.Background(), choice, "bastion"); err != nil {
			t.Fatalf("%s = %v", id, err)
		}
		if len(runner.commands) != 1 {
			t.Fatalf("%s ran %d commands", id, len(runner.commands))
		}
		// どちらの経路でも alias は argv として届く。連結されたテキストの中に
		// 現れてはならない。
		if strings.Contains(string(runner.commands[0].Stdin), "bastion") {
			t.Errorf("%s put the alias into the script text", id)
		}
		if !slices.Contains(runner.commands[0].Arguments, "bastion") {
			t.Errorf("%s arguments = %#v", id, runner.commands[0].Arguments)
		}
	}
}

// custom が開けるのは、アプリケーションを探す場所として認めたディレクトリの
// 直下にあるバンドルだけである。手で書き換えられた設定はここで止まる。
func TestCustomTerminalOpensOnlyASelectableBundle(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.Terminal{
		Runner: runner, Open: "/usr/bin/open", Home: "/Users/example",
		Entries: disk(map[string][]string{"/Users/example/Applications": {"Term.app"}}),
	}

	chosen := platform.TerminalChoice{
		ID: platform.TerminalCustom, Application: "/Users/example/Applications/Term.app", Arguments: []string{"-e"},
	}
	if err := terminal.LaunchIn(context.Background(), chosen, "bastion"); err != nil {
		t.Fatal(err)
	}
	want := []string{"-n", "-a", "/Users/example/Applications/Term.app", "--args", "-e", "/usr/bin/ssh", "--", "bastion"}
	if !slices.Equal(runner.commands[0].Arguments, want) {
		t.Errorf("arguments = %#v, want %#v", runner.commands[0].Arguments, want)
	}

	refused := []platform.TerminalChoice{
		{ID: platform.TerminalCustom, Application: "/usr/bin/ssh"},
		{ID: platform.TerminalCustom, Application: "/Users/example/Applications/../../../bin/Evil.app"},
		{ID: platform.TerminalCustom, Application: "Term.app"},
		{ID: platform.TerminalCustom, Application: "/Users/example/Applications/Deep/Term.app"},
		{ID: platform.TerminalCustom, Application: "/Users/example/Applications/Term.app", Arguments: []string{"a b"}},
		{ID: platform.TerminalCustom, Application: "/Users/example/Applications/Term.app", Arguments: []string{"a\nb"}},
	}
	for _, choice := range refused {
		if err := terminal.LaunchIn(context.Background(), choice, "bastion"); !errors.Is(
			err, platform.ErrTerminalApplication) {
			t.Errorf("LaunchIn(%#v) = %v, want ErrTerminalApplication", choice, err)
		}
	}
	// 選べる場所にあっても、もう無いものは「開けなかった」ではなく「入っていない」。
	gone := platform.TerminalChoice{ID: platform.TerminalCustom, Application: "/Applications/Gone.app"}
	if err := terminal.LaunchIn(context.Background(), gone, "bastion"); !errors.Is(
		err, platform.ErrTerminalNotInstalled) {
		t.Errorf("a bundle that is no longer there = %v, want ErrTerminalNotInstalled", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("a refused choice reached open: %#v", runner.commands[1:])
	}
}

// 「入っていない」は「開けなかった」とは別の答えである。前者は選び直すか
// インストールすれば直る。
func TestAMissingTerminalIsReportedAsNotInstalled(t *testing.T) {
	terminal := macos.Terminal{
		Runner:  &terminalRunner{output: platform.Output{ExitCode: 1}},
		Open:    "/usr/bin/open",
		Program: "/usr/bin/osascript",
		Entries: disk(nil),
	}

	for _, id := range []platform.TerminalID{platform.TerminalKitty, platform.TerminalITerm2, platform.TerminalGhostty} {
		if err := terminal.LaunchIn(context.Background(), platform.TerminalChoice{ID: id}, "bastion"); !errors.Is(
			err, platform.ErrTerminalNotInstalled) {
			t.Errorf("%s = %v, want ErrTerminalNotInstalled", id, err)
		}
	}
	// 見つからなくても Launch Services には届く。場所を知らないことと、無いことは違う。
	elsewhere := macos.Terminal{Runner: &terminalRunner{}, Open: "/usr/bin/open", Entries: disk(nil)}
	if err := elsewhere.LaunchIn(context.Background(),
		platform.TerminalChoice{ID: platform.TerminalKitty}, "bastion"); err != nil {
		t.Errorf("kitty in an unusual place = %v", err)
	}
}

func TestTerminalsAndApplicationsReportWhatThisMachineHas(t *testing.T) {
	terminal := macos.Terminal{
		Runner: &terminalRunner{},
		Home:   "/Users/example",
		Entries: disk(map[string][]string{
			"/Applications":                  {"Safari.app", "kitty.app", "notes.txt"},
			"/System/Applications/Utilities": {"Terminal.app"},
			"/Users/example/Applications":    {"Ghostty.app"},
		}),
	}
	want := []platform.TerminalAvailability{
		// Terminal.app は OS の一部であり、置き場所を当てにしない。custom が
		// 開く先は選択が運ぶので、これも在庫では常に見つかったことにする。
		{ID: platform.TerminalApple, Installed: true},
		{ID: platform.TerminalITerm2, Installed: false},
		{ID: platform.TerminalKitty, Installed: true},
		{ID: platform.TerminalGhostty, Installed: true},
		{ID: platform.TerminalWezTerm, Installed: false},
		{ID: platform.TerminalCustom, Installed: true},
	}
	if got := terminal.Terminals(); !slices.Equal(got, want) {
		t.Errorf("Terminals() = %#v, want %#v", got, want)
	}

	applications := terminal.Applications()
	wantApplications := []platform.Application{
		{Name: "Ghostty", Path: "/Users/example/Applications/Ghostty.app"},
		{Name: "kitty", Path: "/Applications/kitty.app"},
		{Name: "Safari", Path: "/Applications/Safari.app"},
		{Name: "Terminal", Path: "/System/Applications/Utilities/Terminal.app"},
	}
	if !slices.Equal(applications, wantApplications) {
		t.Errorf("Applications() = %#v, want %#v", applications, wantApplications)
	}
}

func TestITermUsesTheSameArgumentBoundaryAsTerminal(t *testing.T) {
	runner := &terminalRunner{}
	terminal := macos.Terminal{
		Runner: runner, Program: "/usr/bin/osascript",
		Entries: disk(map[string][]string{"/Applications": {"iTerm.app"}}),
	}
	if err := terminal.LaunchIn(context.Background(),
		platform.TerminalChoice{ID: platform.TerminalITerm2}, "bastion"); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || string(runner.commands[0].Stdin) != macos.ITermScript {
		t.Fatalf("commands = %#v", runner.commands)
	}
	if !slices.Equal(runner.commands[0].Arguments, []string{"-", "bastion"}) {
		t.Errorf("arguments = %#v", runner.commands[0].Arguments)
	}
	// 動いていない iTerm2 では activate 自身がウィンドウを開く。そこへ重ねて
	// 作らないことが、頼んでいない二枚目を出さない条件である。
	for _, script := range []string{macos.ITermScript, macos.ITermPasswordScript} {
		if !strings.Contains(script, "set wasRunning to running of application") {
			t.Error("the script creates a window without asking whether iTerm2 was already running")
		}
		if strings.Contains(script, "tell current session of current window") {
			t.Error("the script writes into whichever window is in front, which may be the user's own")
		}
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
