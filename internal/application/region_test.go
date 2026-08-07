package application

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/config"
)

// planAndApply is the whole of what a caller does, so the tests assert on the
// rendered bytes rather than on a plan struct nobody reads.
func planAndApply(t *testing.T, source string, groups []string) (string, error) {
	t.Helper()
	file := config.Parse([]byte(source))
	plan, err := PlanRegion(file, groups, DefaultGroupsFile)
	if err != nil {
		return "", err
	}
	if applyErr := ApplyRegion(file, plan); applyErr != nil {
		t.Fatalf("ApplyRegion error = %v", applyErr)
	}
	return string(file.Render()), nil
}

const expectedRegion = `# >>> sshc groups (generated). Child groups first: OpenSSH keeps the first value it reads.
# Edit through the UI; lines between these markers are replaced on the next save.
Include connections/work/eu/*.conf
Include connections/work/*.conf
Include connections/home/*.conf
Include groups.sshc.conf
# <<< sshc groups
`

func TestPlanRegionEmitsOneIncludePerGroupChildFirst(t *testing.T) {
	// One line per group, not one wildcard: '*' does not cross a separator, so
	// connections/work/*.conf can never reach connections/work/eu/lon.conf.
	rendered, err := planAndApply(t, "", []string{"work/eu", "work", "home"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if rendered != expectedRegion {
		t.Errorf("region =\n%s\nwant\n%s", rendered, expectedRegion)
	}
}

// An Include written below a Host line belongs to that block. OpenSSH parses
// the included file either way — the debug output says "Reading configuration
// data" for it — but applies its options only when the block matches. Checked
// against OpenSSH 10.2p1: a top-level Include applies, the same line moved
// under a Host line does not, and a blank line between them changes nothing.
//
// So there is exactly one position where the region declares anything: above
// every Host and Match line in the entry file. Anywhere else the groups are
// read when connecting to one unrelated host and at no other time, which is
// indistinguishable from not being declared.
func TestPlanRegionPutsTheRegionAboveEveryHostBlock(t *testing.T) {
	source := "# a banner\n\nHost bastion\n\tUser ops\n\nHost *\n\tServerAliveInterval 30\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	region := strings.Index(rendered, RegionStartMarker)
	firstHost := strings.Index(rendered, "Host ")
	if region < 0 {
		t.Fatalf("no region was written:\n%s", rendered)
	}
	if firstHost < region {
		t.Errorf("the region sits below a Host line, where its Includes are conditional:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Host bastion\n\tUser ops\n") || !strings.Contains(rendered, "Host *\n\tServerAliveInterval 30\n") {
		t.Errorf("the user's own blocks were disturbed:\n%s", rendered)
	}
}

// The region goes above the comment attached to the first block, not between
// the comment and the Host line it describes.
func TestPlanRegionDoesNotSeparateTheFirstBlockFromItsComment(t *testing.T) {
	source := "# the bastion, reachable from the office only\nHost bastion\n\tUser ops\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.HasSuffix(rendered, source) {
		t.Errorf("the comment was severed from its block:\n%s", rendered)
	}
}

func TestPlanRegionAppendsWhenTheFileDeclaresNoBlockAtAll(t *testing.T) {
	source := "# personal configuration\nInclude conf.d/*.conf\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.HasPrefix(rendered, source) {
		t.Errorf("the region did not go at the end:\n%s", rendered)
	}
	// With no Host or Match line anywhere, the end of the file is still the
	// global block, so appending is unconditional.
	if !strings.HasSuffix(rendered, RegionEndMarker+"\n") {
		t.Errorf("the region did not close at the end:\n%s", rendered)
	}
}

// A region written where its Include lines are conditional has to be moved, not
// replaced where it stands. This is the shape every workspace built by an
// earlier version is in: the region was appended to the end of the entry file,
// which put it inside the last Host block.
func TestPlanRegionMovesARegionThatSitsInsideAHostBlock(t *testing.T) {
	source := "Host bastion\n\tUser ops\n\n" + RegionStartMarker + "\n" +
		"Include connections/work/*.conf\nInclude groups.sshc.conf\n" + RegionEndMarker + "\n"

	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	region := strings.Index(rendered, RegionStartMarker)
	firstHost := strings.Index(rendered, "Host ")
	if region < 0 || firstHost < region {
		t.Errorf("the region was left where OpenSSH reads it conditionally:\n%s", rendered)
	}
	if strings.Count(rendered, RegionStartMarker) != 1 || strings.Count(rendered, RegionEndMarker) != 1 {
		t.Errorf("the region was duplicated rather than moved:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Host bastion\n\tUser ops\n") {
		t.Errorf("the block the region was sitting in was disturbed:\n%s", rendered)
	}
}

func TestPlanRegionRefusesWhenAnExistingIncludeAlreadyReachesTheConnectionsTree(t *testing.T) {
	source := "Include connections/work/*.conf\nHost *\n\tUser ops\n"
	file := config.Parse([]byte(source))

	if _, err := PlanRegion(file, []string{"work"}, DefaultGroupsFile); !errors.Is(err, ErrRegionIncludeAlreadyPresent) {
		t.Fatalf("PlanRegion error = %v, want ErrRegionIncludeAlreadyPresent", err)
	}
}

func TestPlanRegionIgnoresAConditionalIncludeOfTheGroupsFile(t *testing.T) {
	// An Include inside a Host block is read when connecting to that host and
	// at no other time. Counting it as present left the generated settings file
	// unreachable from everywhere else, which is what the previous planner did.
	source := "Host bastion\n\tInclude groups.sshc.conf\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.Contains(rendered, "\nInclude groups.sshc.conf\n") {
		t.Errorf("no top-level Include was planned:\n%s", rendered)
	}
}

func TestPlanRegionReplacesAnExistingRegionInPlace(t *testing.T) {
	first, err := planAndApply(t, "Host bastion\n\tUser ops\nHost *\n\tUser me\n", []string{"work"})
	if err != nil {
		t.Fatalf("first plan error = %v", err)
	}
	second, err := planAndApply(t, first, []string{"work/eu", "work"})
	if err != nil {
		t.Fatalf("second plan error = %v", err)
	}

	if !strings.Contains(second, "Include connections/work/eu/*.conf\nInclude connections/work/*.conf\n") {
		t.Errorf("the new group was not added in order:\n%s", second)
	}
	if strings.Count(second, RegionStartMarker) != 1 || strings.Count(second, RegionEndMarker) != 1 {
		t.Errorf("the region was duplicated:\n%s", second)
	}
	// The region now leads the file, so what must not change is everything
	// under it: a replacement rewrites the marked lines and nothing else.
	if !strings.HasSuffix(second, "Host bastion\n\tUser ops\nHost *\n\tUser me\n") {
		t.Errorf("bytes outside the region changed:\n%s", second)
	}
}

func TestFindRegionRefusesAHalfMarkedRegion(t *testing.T) {
	for _, source := range []string{
		RegionStartMarker + "\nInclude groups.sshc.conf\n",
		"Include groups.sshc.conf\n" + RegionEndMarker + "\n",
	} {
		if _, _, _, err := FindRegion(config.Parse([]byte(source))); !errors.Is(err, ErrRegionDamaged) {
			t.Errorf("FindRegion(%q) error = %v, want ErrRegionDamaged", source, err)
		}
	}
}

func TestPlanRegionPreservesCRLF(t *testing.T) {
	rendered, err := planAndApply(t, "Host bastion\r\n\tUser ops\r\n", []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if strings.Contains(strings.ReplaceAll(rendered, "\r\n", ""), "\n") {
		t.Errorf("a lone newline was introduced into a CRLF file: %q", rendered)
	}
}

func TestApplyRegionChangesNothingOutsideTheMarkers(t *testing.T) {
	// Every shape the parser preserves rather than normalises: a banner, a
	// key=value spelling, a run of spaces, an unbalanced quote kept verbatim.
	source := strings.Join([]string{
		"# hand written, do not reformat",
		"",
		"Host bastion",
		"\tHostName=203.0.113.10",
		"\tUser    ops",
		"\tProxyCommand \"unbalanced",
		"",
		"Host *",
		"\tServerAliveInterval 30",
		"",
	}, "\n")
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}

	start := strings.Index(rendered, RegionStartMarker)
	end := strings.Index(rendered, RegionEndMarker) + len(RegionEndMarker) + 1
	if start < 0 || end <= start {
		t.Fatalf("no region in:\n%s", rendered)
	}
	if rendered[:start]+rendered[end:] != source {
		t.Errorf("bytes outside the region changed:\n%q\nwant\n%q", rendered[:start]+rendered[end:], source)
	}
}
