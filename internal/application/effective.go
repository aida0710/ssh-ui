package application

import (
	"sort"
	"strconv"
	"strings"

	"ssh-ui/internal/config"
)

// cumulativeKeywords are the directives OpenSSH accumulates instead of keeping
// only the first value. Every other keyword follows first-value-wins.
var cumulativeKeywords = map[string]bool{
	"identityfile": true, "certificatefile": true, "localforward": true,
	"remoteforward": true, "dynamicforward": true, "sendenv": true, "setenv": true,
}

// Source is where a value came from.
type Source struct {
	Path      string `json:"path,omitempty"`
	Absolute  string `json:"absolute,omitempty"`
	Line      int    `json:"line,omitempty"`
	Condition string `json:"condition,omitempty"`
}

// EffectiveEntry is one explained value.
type EffectiveEntry struct {
	Keyword string   `json:"keyword"`
	Values  []string `json:"values"`
	Source  Source   `json:"source"`
}

// Effective is this engine's explanation of the values an alias receives.
//
// Approximate is always true: design §5.5 makes the installed OpenSSH's
// `ssh -G` the authority, and that evaluation belongs to a later subsystem
// because it can execute user commands. This view exists to show where a value
// comes from, and it says so instead of claiming to be the final answer.
type Effective struct {
	Alias       string           `json:"alias"`
	Approximate bool             `json:"approximate"`
	Entries     []EffectiveEntry `json:"entries"`
	Notices     []Notice         `json:"notices,omitempty"`
}

// declaresExactly reports whether a Host line names this alias outright rather
// than matching it through a pattern. A catch-all matches every alias and
// declares none, so it can never be the "two blocks claim this name" case.
func declaresExactly(patterns []config.Pattern, alias string) bool {
	for _, pattern := range patterns {
		if pattern.Negated || pattern.Wildcard {
			continue
		}
		if pattern.Value == alias {
			return true
		}
	}
	return false
}

// ComputeEffective walks the graph in reading order and records the first value
// for each keyword, accumulating the keywords OpenSSH accumulates. Match blocks
// are never evaluated, because `Match exec` can run the user's shell; their
// presence is reported as a complex external rule instead.
func ComputeEffective(graph *config.Graph, root, alias string) Effective {
	effective := Effective{Alias: alias, Approximate: true, Entries: []EffectiveEntry{}}
	effective.Notices = appendNotice(effective.Notices, Notice{Code: NoticeExplainedValuesOnly})
	seen := map[string]bool{}
	// Blocks that name this alias outright, keyed by where they are, because
	// the walk visits a block once per directive. A catch-all that happens to
	// match is not one of these: it is reported as a wildcard shadow, which is
	// a different statement. Two blocks declaring one alias is the case where
	// the values on screen are not the values the user gets, so the tab that
	// exists to answer "what do I actually get?" has to say it.
	declaring := map[string]bool{}

	WalkDirectives(graph, func(visit Visit) bool {
		if visit.Block.Header == visit.Index {
			return true
		}
		if config.EqualKeyword(visit.Line.Keyword, "Include") {
			return true
		}
		reference := NewFileRef(root, visit.Path)

		switch visit.Block.Kind {
		case config.BlockMatch:
			effective.Notices = appendNotice(effective.Notices, Notice{
				Code: NoticeMatchBlock, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
			})
			effective.Notices = appendNotice(effective.Notices, Notice{
				Code: NoticeComplexExternalRule, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
			})
			return true
		case config.BlockHost:
			if !MatchHostLine(visit.Block.Patterns, alias) {
				return true
			}
			if declaresExactly(visit.Block.Patterns, alias) {
				where := visit.Path + "\x00" + strconv.Itoa(visit.Block.Header)
				if !declaring[where] {
					declaring[where] = true
					if len(declaring) > 1 {
						effective.Notices = appendNotice(effective.Notices, Notice{
							Code: NoticeDuplicateAlias, Path: reference.Path,
							Line: visit.Block.Header + 1, Detail: alias,
						})
					}
				}
			}
			for _, pattern := range visit.Block.Patterns {
				if !pattern.Negated {
					continue
				}
				effective.Notices = appendNotice(effective.Notices, Notice{
					Code: NoticeNegatedPattern, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
				})
			}
		}

		lowered := strings.ToLower(visit.Line.Keyword)
		if seen[lowered] && !cumulativeKeywords[lowered] {
			return true
		}
		seen[lowered] = true
		effective.Entries = append(effective.Entries, EffectiveEntry{
			Keyword: visit.Line.Keyword,
			Values:  visit.Line.Values(),
			Source: Source{
				Path:      reference.Path,
				Absolute:  reference.Absolute,
				Line:      visit.Index + 1,
				Condition: visit.Condition,
			},
		})
		return true
	})

	sort.SliceStable(effective.Entries, func(first, second int) bool {
		return strings.ToLower(effective.Entries[first].Keyword) < strings.ToLower(effective.Entries[second].Keyword)
	})
	return effective
}

// EffectiveChange is one keyword whose explained value changes.
type EffectiveChange struct {
	Keyword       string   `json:"keyword"`
	Before        []string `json:"before"`
	After         []string `json:"after"`
	BeforeSources []Source `json:"beforeSources,omitempty"`
	AfterSources  []Source `json:"afterSources,omitempty"`
}

// EffectiveDiff is the before/after view design §5.4 requires before a group
// change is saved.
type EffectiveDiff struct {
	Alias   string            `json:"alias"`
	Changes []EffectiveChange `json:"changes"`
}

// DiffEffective compares two explanations keyword by keyword.
func DiffEffective(before, after Effective) EffectiveDiff {
	diff := EffectiveDiff{Alias: after.Alias, Changes: []EffectiveChange{}}
	if diff.Alias == "" {
		diff.Alias = before.Alias
	}
	beforeIndex := indexEffective(before)
	afterIndex := indexEffective(after)

	keywords := make([]string, 0, len(beforeIndex)+len(afterIndex))
	for keyword := range beforeIndex {
		keywords = append(keywords, keyword)
	}
	for keyword := range afterIndex {
		if _, ok := beforeIndex[keyword]; !ok {
			keywords = append(keywords, keyword)
		}
	}
	sort.Strings(keywords)

	for _, keyword := range keywords {
		beforeValues, beforeSources, display := renderEffective(beforeIndex[keyword])
		afterValues, afterSources, afterDisplay := renderEffective(afterIndex[keyword])
		if afterDisplay != "" {
			display = afterDisplay
		}
		if equalStrings(beforeValues, afterValues) && equalSources(beforeSources, afterSources) {
			continue
		}
		diff.Changes = append(diff.Changes, EffectiveChange{
			Keyword:       display,
			Before:        beforeValues,
			After:         afterValues,
			BeforeSources: beforeSources,
			AfterSources:  afterSources,
		})
	}
	return diff
}

func indexEffective(effective Effective) map[string][]EffectiveEntry {
	index := make(map[string][]EffectiveEntry, len(effective.Entries))
	for _, entry := range effective.Entries {
		lowered := strings.ToLower(entry.Keyword)
		index[lowered] = append(index[lowered], entry)
	}
	return index
}

func renderEffective(entries []EffectiveEntry) (values []string, sources []Source, display string) {
	values = []string{}
	sources = []Source{}
	for _, entry := range entries {
		if display == "" {
			display = entry.Keyword
		}
		values = append(values, strings.Join(entry.Values, " "))
		sources = append(sources, entry.Source)
	}
	return values, sources, display
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

// equalSources compares where two explanations got their values from, ignoring
// the line number. A value that kept its file and its governing block has not
// changed just because an edit elsewhere in that file pushed it down a line;
// reporting that as a change would fill the group preview with edits the user
// did not make. A value that genuinely moved to another file or another Host
// or Match block differs in Path, Absolute or Condition and is still reported.
func equalSources(first, second []Source) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if !equivalentSource(first[index], second[index]) {
			return false
		}
	}
	return true
}

func equivalentSource(first, second Source) bool {
	return first.Path == second.Path &&
		first.Absolute == second.Absolute &&
		first.Condition == second.Condition
}
