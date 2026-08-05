package application

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateGroupNameRefusesEverythingThatIsNotASafeRelativeDirectory(t *testing.T) {
	accepted := []string{"work", "work/eu", "a-b_c.d", "Work", "x", strings.Repeat("a", 64)}
	for _, name := range accepted {
		if err := ValidateGroupName(name); err != nil {
			t.Errorf("ValidateGroupName(%q) = %v, want nil", name, err)
		}
	}

	refused := []string{
		"",             // a group must be named
		"/work",        // absolute
		"work/",        // empty trailing segment
		"work//eu",     // empty middle segment
		".",            // the connections directory itself
		"..",           // above it
		"work/..",      // and the same by traversal
		"work/../home", // which cleaning would hide
		"work\x00eu",   // a NUL never reaches a path
		".hidden",      // a leading dot is how ~/.ssh hides its own files
		"work/.hidden", // at any depth
		"ssh-ui",       // the engine's own state directory
		"SSH-UI",       // and the same file on a case-insensitive volume
		"Config",       // a name the application depends on
		"known_hosts",  //
		"authorized_keys",
		strings.Repeat("a", 65), // one segment longer than the limit
		"a/b/c/d/e/f/g",         // deeper than MaxGroupSegments
		"work/eu/../..",         //
	}
	for _, name := range refused {
		if err := ValidateGroupName(name); !errors.Is(err, ErrInvalidGroupName) {
			t.Errorf("ValidateGroupName(%q) = %v, want ErrInvalidGroupName", name, err)
		}
	}
}

// MaxGroupSegments exists because of a limit in another package, so the reason
// is asserted rather than left as a number somebody will later "tidy up".
func TestMaxGroupSegmentsStaysInsideTheKeyScannerDepth(t *testing.T) {
	// keys/<segments…>/<file> must stay within keys.maxScanDepth counted from
	// ~/.ssh, or the key is reported as depth_exceeded and drops out of the
	// inventory rather than being listed.
	const keyScannerDepth = 8
	if 1+MaxGroupSegments+1 > keyScannerDepth {
		t.Fatalf("a key %d directories deep exceeds the scanner's %d", 1+MaxGroupSegments+1, keyScannerDepth)
	}
}

func TestGroupOfPathReadsMembershipFromTheDirectory(t *testing.T) {
	cases := []struct {
		path    string
		name    string
		inGroup bool
	}{
		{"connections/work/web.conf", "work", true},
		{"connections/work/eu/lon.conf", "work/eu", true},
		// A file directly under connections/ belongs to no group: no Include is
		// generated for it, so nothing reads it, and inventing a fourth
		// precedence tier for it would be harder to state than it is worth.
		{"connections/loose.conf", "", false},
		{"conf.d/10.conf", "", false},
		{"config", "", false},
		{"ssh-ui/metadata.json", "", false},
		{"connections", "", false},
	}
	for _, testCase := range cases {
		name, inGroup := GroupOfPath(testCase.path)
		if name != testCase.name || inGroup != testCase.inGroup {
			t.Errorf("GroupOfPath(%q) = (%q, %v), want (%q, %v)",
				testCase.path, name, inGroup, testCase.name, testCase.inGroup)
		}
	}
}

func TestGroupOfKeyPathReadsTheKeyDirectory(t *testing.T) {
	cases := []struct {
		path    string
		name    string
		inGroup bool
	}{
		{"keys/work/id_ed25519", "work", true},
		{"keys/work/eu/id_ed25519.pub", "work/eu", true},
		{"keys/loose_key", "", false},
		{"id_ed25519", "", false},
		{"connections/work/web.conf", "", false},
	}
	for _, testCase := range cases {
		name, inGroup := GroupOfKeyPath(testCase.path)
		if name != testCase.name || inGroup != testCase.inGroup {
			t.Errorf("GroupOfKeyPath(%q) = (%q, %v), want (%q, %v)",
				testCase.path, name, inGroup, testCase.name, testCase.inGroup)
		}
	}
}

func TestGroupDirectoriesAreWorkspaceRelativeAndSlashSeparated(t *testing.T) {
	if got := GroupDirectory("work/eu"); got != "connections/work/eu" {
		t.Errorf("GroupDirectory = %q", got)
	}
	if got := GroupKeyDirectory("work/eu"); got != "keys/work/eu" {
		t.Errorf("GroupKeyDirectory = %q", got)
	}
	if got := GroupIncludePattern("work/eu"); got != "connections/work/eu/*.conf" {
		t.Errorf("GroupIncludePattern = %q", got)
	}
}

func TestParentGroupNameIsTheParentDirectory(t *testing.T) {
	if got := ParentGroupName("work/eu/lon"); got != "work/eu" {
		t.Errorf("ParentGroupName = %q, want work/eu", got)
	}
	if got := ParentGroupName("work"); got != "" {
		t.Errorf("ParentGroupName of a top-level group = %q, want empty", got)
	}
	if got := GroupDepth("work/eu"); got != 2 {
		t.Errorf("GroupDepth = %d, want 2", got)
	}
}

func TestGroupNameOrderPutsChildrenBeforeParents(t *testing.T) {
	// OpenSSH keeps the first value it reads, so the deeper group's Include has
	// to come first or a parent would beat its own child.
	ordered := GroupNameOrder([]string{"work", "work/eu", "home"}, nil)
	want := []string{"work/eu", "home", "work"}
	if len(ordered) != len(want) {
		t.Fatalf("GroupNameOrder = %#v", ordered)
	}
	for index := range want {
		if ordered[index] != want[index] {
			t.Fatalf("GroupNameOrder = %#v, want %#v", ordered, want)
		}
	}
}

func TestGroupNameOrderBreaksADepthTieByOrderThenName(t *testing.T) {
	ordered := GroupNameOrder([]string{"alpha", "beta", "gamma"}, map[string]int{"gamma": -1})
	want := []string{"gamma", "alpha", "beta"}
	for index := range want {
		if ordered[index] != want[index] {
			t.Fatalf("GroupNameOrder = %#v, want %#v", ordered, want)
		}
	}
}
