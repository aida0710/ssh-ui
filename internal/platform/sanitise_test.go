package platform_test

import (
	"strings"
	"testing"

	"sshc/internal/platform"
)

func TestSanitiseHomePathsReplacesEveryOccurrence(t *testing.T) {
	const home = "/Users/tester"
	// 本物の `ssh -v` の出力は、読み込んだ設定ファイルと identity ファイルを、
	// それぞれ絶対パスで名指しする。
	verbose := "debug1: Reading configuration data /Users/tester/.ssh/config\r\n" +
		"debug1: identity file /Users/tester/.ssh/id_ed25519 type 3\n" +
		"debug1: Authenticated to bastion ([203.0.113.10]:22).\n"

	sanitised := platform.SanitiseHomePaths(verbose, home)
	if strings.Contains(sanitised, home) {
		t.Fatalf("sanitised output still names the home directory: %q", sanitised)
	}
	if !strings.Contains(sanitised, "~/.ssh/config") || !strings.Contains(sanitised, "~/.ssh/id_ed25519") {
		t.Fatalf("sanitised = %q, want the paths rewritten to ~", sanitised)
	}
	if !strings.Contains(sanitised, "Authenticated to bastion") {
		t.Error("sanitising removed information the user needs")
	}
}

func TestSanitiseHomePathsLeavesTextAloneWhenThereIsNoHome(t *testing.T) {
	const text = "debug1: Connecting to 203.0.113.10 port 22.\n"

	if got := platform.SanitiseHomePaths(text, ""); got != text {
		t.Errorf("SanitiseHomePaths with no home = %q, want the text unchanged", got)
	}
	if got := platform.SanitiseHomePaths(text, "/"); got != text {
		t.Errorf("SanitiseHomePaths with a root home = %q, want the text unchanged", got)
	}
}
