package application

import (
	"errors"
	"strings"
	"testing"

	"ssh-ui/internal/config"
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

const expectedRegion = `# >>> ssh-ui groups (generated). Child groups first: OpenSSH keeps the first value it reads.
# Edit through the UI; lines between these markers are replaced on the next save.
Include connections/work/eu/*.conf
Include connections/work/*.conf
Include connections/home/*.conf
Include groups.ssh-ui.conf
# <<< ssh-ui groups
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

func TestPlanRegionPlacesTheRegionBeforeTheFirstCatchAll(t *testing.T) {
	source := "Host bastion\n\tUser ops\nHost *\n\tServerAliveInterval 30\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	want := "Host bastion\n\tUser ops\n" + strings.Replace(expectedRegion,
		"Include connections/work/eu/*.conf\nInclude connections/work/*.conf\nInclude connections/home/*.conf\n",
		"Include connections/work/*.conf\n", 1) + "Host *\n\tServerAliveInterval 30\n"
	if rendered != want {
		t.Errorf("rendered =\n%s\nwant\n%s", rendered, want)
	}
}

func TestPlanRegionAppendsWhenThereIsNoCatchAll(t *testing.T) {
	source := "Host bastion\n\tUser ops\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.HasPrefix(rendered, source) {
		t.Errorf("the region did not go at the end:\n%s", rendered)
	}
	if !strings.HasSuffix(rendered, RegionEndMarker+"\n") {
		t.Errorf("the region did not close at the end:\n%s", rendered)
	}
}

// The catch-all-at-the-top case. Inserting here would put the generated
// Includes above the user's own concrete blocks, so any alias declared in both
// places would change winner — silently, in a file the user did not edit.
func TestPlanRegionRefusesWhenAConcreteHostFollowsTheInsertionPoint(t *testing.T) {
	source := "Host *\n\tUser ops\nHost bastion\n\tUser root\n"
	file := config.Parse([]byte(source))

	if _, err := PlanRegion(file, []string{"work"}, DefaultGroupsFile); !errors.Is(err, ErrRegionPositionAmbiguous) {
		t.Fatalf("PlanRegion error = %v, want ErrRegionPositionAmbiguous", err)
	}
	if string(file.Render()) != source {
		t.Errorf("a refused plan changed the file")
	}
}

func TestPlanRegionAcceptsAWildcardBlockAfterTheInsertionPoint(t *testing.T) {
	// A second wildcard block declares no alias of its own, so it cannot be the
	// "declared in two places" case the refusal is about. Refusing here would
	// block the feature for a configuration that is not ambiguous at all.
	source := "Host *\n\tUser ops\nHost *.internal\n\tUser root\n"
	if _, err := planAndApply(t, source, []string{"work"}); err != nil {
		t.Fatalf("PlanRegion error = %v", err)
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
	source := "Host bastion\n\tInclude groups.ssh-ui.conf\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.Contains(rendered, "\nInclude groups.ssh-ui.conf\n") {
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
	if !strings.HasPrefix(second, "Host bastion\n\tUser ops\n") || !strings.HasSuffix(second, "Host *\n\tUser me\n") {
		t.Errorf("bytes outside the region changed:\n%s", second)
	}
}

func TestFindRegionRefusesAHalfMarkedRegion(t *testing.T) {
	for _, source := range []string{
		RegionStartMarker + "\nInclude groups.ssh-ui.conf\n",
		"Include groups.ssh-ui.conf\n" + RegionEndMarker + "\n",
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
