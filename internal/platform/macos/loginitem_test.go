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

// No test loads a real agent: the runner records what launchctl would have been
// asked to do and does nothing.
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
	// Nothing opens at login, and nothing is redirected: the URL this prints
	// carries a live bootstrap token, and a log file is not a place for one.
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

	// Booted out before being booted in, so a changed path replaces the old one
	// rather than leaving it loaded.
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
	// Disabling twice is the state the caller asked for.
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
