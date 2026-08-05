package application

import (
	"errors"
	"strings"

	"ssh-ui/internal/config"
)

// The generated region is delimited by two comment lines. They are ordinary
// OpenSSH comments, so a reader who has never heard of this application still
// sees what the block is and that editing it is pointless.
const (
	RegionStartMarker = "# >>> ssh-ui groups (generated). Child groups first: OpenSSH keeps the first value it reads."
	RegionEndMarker   = "# <<< ssh-ui groups"
	regionNote        = "# Edit through the UI; lines between these markers are replaced on the next save."
)

var (
	// ErrRegionDamaged reports a region with exactly one of its two markers.
	ErrRegionDamaged = errors.New("the generated group region has only one of its markers")
	// ErrRegionPositionAmbiguous reports an entry file whose own concrete Host
	// blocks sit after the position the region would take.
	ErrRegionPositionAmbiguous = errors.New("inserting the group region here would change which value wins")
	// ErrRegionIncludeAlreadyPresent reports an Include the user wrote that
	// already reaches the connections tree or the generated groups file.
	ErrRegionIncludeAlreadyPresent = errors.New("an existing Include already reaches the generated group files")
)

// Notice codes the region planner produces.
const (
	NoticeRegionPositionAmbiguous = "include_position_ambiguous"
	NoticeGroupIncludePresent     = "group_include_already_present"
	NoticeRegionDamaged           = "generated_region_damaged"
)

// RegionPlan describes the edit that installs the region.
//
// ReplaceFrom/ReplaceTo is a half-open range of existing lines when a region is
// already present; otherwise the lines are inserted at InsertAt.
type RegionPlan struct {
	InsertAt    int
	ReplaceFrom int
	ReplaceTo   int
	Replacing   bool
	Lines       []config.Line
}

// FindRegion locates the generated region by its markers.
//
// A file carrying exactly one marker is refused rather than repaired: knowing
// where a half-marked region ended means guessing, and guessing here rewrites
// lines the user wrote.
func FindRegion(file *config.File) (start, end int, found bool, err error) {
	start, end = -1, -1
	for index, line := range file.Lines {
		if line.Kind != config.LineComment {
			continue
		}
		switch strings.TrimSpace(line.Text) {
		case RegionStartMarker:
			if start < 0 {
				start = index
			}
		case RegionEndMarker:
			if end < 0 {
				end = index
			}
		}
	}
	switch {
	case start >= 0 && end > start:
		return start, end, true, nil
	case start < 0 && end < 0:
		return -1, -1, false, nil
	default:
		return -1, -1, false, ErrRegionDamaged
	}
}

// PlanRegion decides what the region should contain and where it belongs.
//
// groups are the declared group names in the order they must be read; the
// caller has already applied GroupNameOrder, so this function does not reorder
// them. groupsFile is the generated settings file, which is included last so a
// group setting can never beat a host's own value.
func PlanRegion(file *config.File, groups []string, groupsFile string) (RegionPlan, error) {
	start, end, found, err := FindRegion(file)
	if err != nil {
		return RegionPlan{}, err
	}

	ending := dominantEnding(file)
	lines := []config.Line{
		{Kind: config.LineComment, Text: RegionStartMarker, Ending: ending},
		{Kind: config.LineComment, Text: regionNote, Ending: ending},
	}
	for _, pattern := range append(groupPatterns(groups), groupsFile) {
		include, buildErr := buildLine("", "Include", []string{pattern}, ending)
		if buildErr != nil {
			return RegionPlan{}, buildErr
		}
		lines = append(lines, include)
	}
	lines = append(lines, config.Line{Kind: config.LineComment, Text: RegionEndMarker, Ending: ending})

	if found {
		return RegionPlan{ReplaceFrom: start, ReplaceTo: end + 1, Replacing: true, Lines: lines}, nil
	}
	insertAt, err := regionPosition(file, groups, groupsFile)
	if err != nil {
		return RegionPlan{}, err
	}
	return RegionPlan{InsertAt: insertAt, Lines: lines}, nil
}

func groupPatterns(groups []string) []string {
	patterns := make([]string, 0, len(groups))
	for _, group := range groups {
		patterns = append(patterns, GroupIncludePattern(group))
	}
	return patterns
}

// regionPosition computes where a fresh region belongs, and refuses when
// putting it there would change which value wins.
//
// The position is the one this application has always used for the groups
// Include: before the first Match block or the first Host block whose pattern
// list contains an exact '*', otherwise at the end of the file. That test is a
// heuristic and nothing more, which is why it is paired with a refusal: if any
// concrete Host block follows the computed position, the user's own blocks
// would end up being read after the generated ones, and an alias declared in
// both places would change winner. The application does not pick for them.
func regionPosition(file *config.File, groups []string, groupsFile string) (int, error) {
	if err := checkExistingIncludes(file, groups, groupsFile); err != nil {
		return 0, err
	}
	insertAt := len(file.Lines)
	found := false
	for index, line := range file.Lines {
		if line.Kind != config.LineDirective || found {
			continue
		}
		if config.EqualKeyword(line.Keyword, "Match") {
			insertAt, found = index, true
			continue
		}
		if !config.EqualKeyword(line.Keyword, "Host") {
			continue
		}
		for _, pattern := range line.Values() {
			if pattern == "*" {
				insertAt, found = index, true
				break
			}
		}
	}
	if !found {
		return insertAt, nil
	}
	for index := insertAt; index < len(file.Lines); index++ {
		line := file.Lines[index]
		if line.Kind != config.LineDirective || !config.EqualKeyword(line.Keyword, "Host") {
			continue
		}
		if declaresConcreteAlias(line.Values()) {
			return 0, ErrRegionPositionAmbiguous
		}
	}
	return insertAt, nil
}

// declaresConcreteAlias reports whether a Host line names a destination rather
// than a pattern. A wildcard or negated pattern matches many hosts and cannot
// be the "one alias declared in two places" the ambiguity check is about.
func declaresConcreteAlias(patterns []string) bool {
	for _, pattern := range patterns {
		if strings.ContainsAny(pattern, "*?!") {
			continue
		}
		return true
	}
	return false
}

// checkExistingIncludes refuses when the user already includes the files the
// region would include.
//
// A second Include of the same file is not harmless: OpenSSH applies the first
// read and the graph reports include_duplicate, so the region would silently
// become dead weight — or worse, change precedence. The Include the user wrote
// is named so they can replace it deliberately.
//
// Only a top-level Include counts. One written inside a Host or Match block is
// conditional: it is read when connecting to that host and at no other time,
// which is not the same statement at all. The previous planner did not consult
// the governing block and so was fooled by exactly that.
func checkExistingIncludes(file *config.File, groups []string, groupsFile string) error {
	claimed := make(map[string]bool, len(groups)+1)
	for _, pattern := range append(groupPatterns(groups), groupsFile) {
		claimed[pattern] = true
	}
	for index, line := range file.Lines {
		if line.Kind != config.LineDirective || !config.EqualKeyword(line.Keyword, "Include") {
			continue
		}
		if file.Condition(file.BlockAt(index)) != "" {
			continue
		}
		for _, value := range line.Values() {
			if claimed[value] || strings.HasPrefix(value, ConnectionsDirectory+"/") {
				return ErrRegionIncludeAlreadyPresent
			}
		}
	}
	return nil
}

// ApplyRegion writes the planned lines into the file, changing nothing outside
// the region.
func ApplyRegion(file *config.File, plan RegionPlan) error {
	if plan.Replacing {
		if plan.ReplaceFrom < 0 || plan.ReplaceTo > len(file.Lines) || plan.ReplaceFrom > plan.ReplaceTo {
			return ErrEditLineOutsideBlock
		}
		rest := append([]config.Line(nil), file.Lines[plan.ReplaceTo:]...)
		file.Lines = append(append(file.Lines[:plan.ReplaceFrom:plan.ReplaceFrom], plan.Lines...), rest...)
		return nil
	}
	if plan.InsertAt < 0 || plan.InsertAt > len(file.Lines) {
		return ErrEditLineOutsideBlock
	}
	for offset, line := range plan.Lines {
		insertLine(file, plan.InsertAt+offset, line)
	}
	return nil
}
