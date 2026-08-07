package macos_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/platform"
	"sshc/internal/platform/macos"
)

// 本物のエージェントを読み込むテストはない。ランナーは launchctl が何を求められた
// はずかを記録するだけで、何もしない。
type recordingLaunchctl struct{ commands [][]string }

func (r *recordingLaunchctl) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	r.commands = append(r.commands, append([]string{command.Path}, command.Arguments...))
	return platform.Output{}, nil
}

func TestEnablingWritesAnAgentThatOpensNoBrowserAndLogsNothing(t *testing.T) {
	home := t.TempDir()
	runner := &recordingLaunchctl{}
	item := macos.LoginItem{Runner: runner, Home: home, Launchctl: "/bin/launchctl"}

	if item.Enabled() {
		t.Fatal("a fresh home reports the agent as registered")
	}
	if err := item.Enable(context.Background(), "/Users/tester/.local/bin/sshc"); err != nil {
		t.Fatalf("Enable = %v", err)
	}
	if !item.Enabled() {
		t.Error("after Enable it is not registered")
	}

	path := filepath.Join(home, "Library", "LaunchAgents", macos.LoginItemLabel+".plist")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("plist = %v, %v", info, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	written := string(body)
	// ログイン時には何も開かず、何もリダイレクトしない。これが表示する URL は有効な
	// ブートストラップトークンを運び、ログファイルはそれを置く場所ではない。
	if !strings.Contains(written, "<string>-open=false</string>") {
		t.Errorf("the agent would open a browser at login: %s", written)
	}
	for _, absent := range []string{"StandardOutPath", "StandardErrorPath"} {
		if strings.Contains(written, absent) {
			t.Errorf("the agent redirects %s, which is where the bootstrap URL would land", absent)
		}
	}
	if !strings.Contains(written, "/Users/tester/.local/bin/sshc") {
		t.Errorf("the agent does not name the program: %s", written)
	}

	// boot in の前に boot out するので、パスが変わったときは古いものが残らずに
	// 置き換わる。
	if len(runner.commands) != 2 ||
		runner.commands[0][1] != "bootout" || runner.commands[1][1] != "bootstrap" {
		t.Errorf("launchctl calls = %#v", runner.commands)
	}

	if err := item.Disable(context.Background()); err != nil {
		t.Fatalf("Disable = %v", err)
	}
	if item.Enabled() {
		t.Error("after Disable it is still registered")
	}
	// 二度無効にすることは、呼び出し側が求めた状態である。
	if err := item.Disable(context.Background()); err != nil {
		t.Errorf("Disable twice = %v", err)
	}
}

func TestEnablingRefusesAProgramLaunchdWouldHaveToFind(t *testing.T) {
	item := macos.LoginItem{Runner: &recordingLaunchctl{}, Home: t.TempDir()}
	if err := item.Enable(context.Background(), "sshc"); err == nil {
		t.Error("a relative program was accepted")
	}
}
