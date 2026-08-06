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
	// ErrRegionIncludeAlreadyPresent reports an Include the user wrote that
	// already reaches the connections tree or the generated groups file.
	ErrRegionIncludeAlreadyPresent = errors.New("an existing Include already reaches the generated group files")
)

// Notice codes the region planner produces.
const (
	NoticeGroupIncludePresent = "group_include_already_present"
	// NoticeRegionDamaged reports a generated region with one of its two
	// markers. It is its own fact and not a group problem: DeclaredGroups reads
	// the region, and a damaged one declares nothing, so without this notice
	// every declared group looks undeclared and the screen fills with "no
	// Include line names this directory" for directories whose Include lines
	// are right there and working.
	NoticeRegionDamaged = "generated_region_damaged"
)

// RegionPlan describes the edit that installs the region.
//
// ReplaceFrom/ReplaceTo is a half-open range of existing lines when a region is
// already present where it belongs. RemoveFrom/RemoveTo is the same range when
// the region has to be lifted out and written somewhere else; InsertAt is then
// an index into the file with that range already gone. Otherwise the lines are
// inserted at InsertAt.
type RegionPlan struct {
	InsertAt    int
	ReplaceFrom int
	ReplaceTo   int
	Replacing   bool
	RemoveFrom  int
	RemoveTo    int
	Removing    bool
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

// ClampToRegion shortens a block's half-open line range so that it stops at the
// generated region instead of swallowing it.
//
// A block's range runs to the next header, and the region is inserted
// immediately before the first catch-all — so in every entry file that declares
// a group, the region sits inside the range of the concrete block above it. The
// region is the file's own structure and belongs to no connection, so every
// path that treats a block's range as the block's own text has to stop here:
// otherwise moving or rewriting one unrelated connection carries away the
// Include lines that declare every group, and the entry file is left with a
// lone marker that FindRegion then refuses as damaged.
//
// The mirror case is clamped too. The run of comments above a header is read as
// that header's attached comment, so a block written directly under the region
// would claim the end marker as its own description.
func ClampToRegion(file *config.File, start, end int) (int, int) {
	regionStart, regionEnd, found, err := FindRegion(file)
	if err != nil || !found {
		return start, end
	}
	if regionStart > start && regionStart < end {
		end = regionStart
	}
	if regionEnd >= start && regionEnd < end {
		start = regionEnd + 1
	}
	return start, end
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
		if file.Condition(file.BlockAt(start)) == "" {
			return RegionPlan{ReplaceFrom: start, ReplaceTo: end + 1, Replacing: true, Lines: lines}, nil
		}
		// The region sits inside a Host or Match block, where its Include lines
		// are read only when connecting to that one host. Replacing it where it
		// stands would keep it there, so it is lifted out and written where it
		// declares something. The position is computed against the file without
		// it, both so the index is right and so its own Include lines cannot be
		// mistaken for ones the user wrote.
		without := withoutLines(file, start, end+1)
		insertAt, positionErr := regionPosition(without, groups, groupsFile)
		if positionErr != nil {
			return RegionPlan{}, positionErr
		}
		return RegionPlan{
			RemoveFrom: start, RemoveTo: end + 1, Removing: true,
			InsertAt: insertAt, Lines: lines,
		}, nil
	}
	insertAt, err := regionPosition(file, groups, groupsFile)
	if err != nil {
		return RegionPlan{}, err
	}
	return RegionPlan{InsertAt: insertAt, Lines: lines}, nil
}

// withoutLines copies a file with one half-open range removed.
func withoutLines(file *config.File, from, to int) *config.File {
	lines := make([]config.Line, 0, len(file.Lines)-(to-from))
	lines = append(lines, file.Lines[:from]...)
	lines = append(lines, file.Lines[to:]...)
	return &config.File{Lines: lines}
}

func groupPatterns(groups []string) []string {
	patterns := make([]string, 0, len(groups))
	for _, group := range groups {
		patterns = append(patterns, GroupIncludePattern(group))
	}
	return patterns
}

// regionPosition computes where the region belongs: above the first Host or
// Match line, or at the end of a file that has neither.
//
// There is no choice to make here. An Include is a directive like any other, so
// it belongs to the block it is written under, and OpenSSH applies an included
// file's options only when that block matches. The only lines that are read
// unconditionally are the ones above the first block header, so that is where a
// declaration has to go. A previous version put the region before the first
// catch-all instead, to keep the user's own blocks winning; the price was that
// the Includes landed inside whatever concrete block preceded the catch-all —
// or, in a file with no catch-all, inside the last block in the file — and
// declared the groups to that one host and to nothing else.
//
// The consequence is that the group files are read before the entry file's own
// blocks, so an alias written in both places resolves to the group file. That
// is not decided here and not guessed at.
//
// It is, however, currently under-reported, and this comment should not be read
// as saying otherwise. Only /api/v1/diagnostics/effective reports a cross-file
// duplicate today, and it names the losing block rather than both. The
// connections overview does not: ProjectHosts keys its duplicate check on the
// file's absolute path, so it only ever fires for two blocks in one file — the
// case that needs no help. Until that is fixed, a duplicate introduced across
// two files is silent on the screen where a user would notice it.
//
// The insertion point is the start of the first block's comment run, so the
// region goes above the comment rather than between it and the header it
// describes.
func regionPosition(file *config.File, groups []string, groupsFile string) (int, error) {
	if err := checkExistingIncludes(file, groups, groupsFile); err != nil {
		return 0, err
	}
	for index, line := range file.Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		if config.EqualKeyword(line.Keyword, "Host") || config.EqualKeyword(line.Keyword, "Match") {
			return file.CommentRun(index), nil
		}
	}
	return len(file.Lines), nil
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
	if plan.Removing {
		if plan.RemoveFrom < 0 || plan.RemoveTo > len(file.Lines) || plan.RemoveFrom > plan.RemoveTo {
			return ErrEditLineOutsideBlock
		}
		rest := append([]config.Line(nil), file.Lines[plan.RemoveTo:]...)
		file.Lines = append(file.Lines[:plan.RemoveFrom:plan.RemoveFrom], rest...)
	}
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
