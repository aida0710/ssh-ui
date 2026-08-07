package effective

import (
	"strings"

	"sshc/internal/config"
)

// How confidently a source can be explained.
const (
	SourceExact    = "exact"
	SourceWildcard = "wildcard"
	SourceGlobal   = "global"
)

// Why a projection cannot be shown as one tidy inheritance chain.
const (
	ComplexityWildcardPattern   = "wildcard_pattern"
	ComplexityNegatedPattern    = "negated_pattern"
	ComplexityMatchBlock        = "match_block"
	ComplexityDuplicateAlias    = "duplicate_alias"
	ComplexityUnresolvedInclude = "unresolved_include"
	ComplexityJumpInvalid       = "jump_invalid"
	ComplexityJumpCycle         = "jump_cycle"
	ComplexityJumpDepth         = "jump_depth_exceeded"
)

// Source is one place a value came from. Winner marks the value OpenSSH keeps,
// because the first value read wins; the others are listed so a reader can see
// what is being shadowed.
type Source struct {
	Keyword   string
	Value     string
	Path      string
	Line      int
	Condition string
	Kind      string
	Winner    bool
}

// Complexity records a reason the engine refuses to present its projection as
// the whole truth. The UI shows these as complex external rules and defers to
// `ssh -G` for the authoritative value.
type Complexity struct {
	Code      string
	Path      string
	Line      int
	Condition string
	Detail    string
}

// Projection is the engine's own reading of the configuration for one alias.
type Projection struct {
	Alias        string
	Sources      []Source
	Complexities []Complexity
}

// Simple reports whether every value could be attributed without a caveat.
func (p Projection) Simple() bool { return len(p.Complexities) == 0 }

// Value returns the winning source for keyword.
func (p Projection) Value(keyword string) (Source, bool) {
	wanted := strings.ToLower(keyword)
	for _, source := range p.Sources {
		if source.Winner && strings.ToLower(source.Keyword) == wanted {
			return source, true
		}
	}
	return Source{}, false
}

// Project walks the configuration in load order and attributes each keyword to
// the first block that set it, which is what OpenSSH does.
//
// Load order is not file order. OpenSSH reads an Include at the point the line
// sits, so a block written below an Include is read after the whole of the
// included file — and first value wins, so the included file beats it. Walking
// the graph file by file would put every block of the entry file ahead of every
// included one, which reverses exactly the case the generated group region
// depends on: the Includes sit above the user's catch-all so a group's value
// beats the default, and file-order attribution would report the default.
//
// Match blocks never contribute a value: their criteria depend on state that
// only exists while connecting. A Match block anywhere in the graph is instead
// recorded as a complexity, because it can also shadow a value this projection
// attributes to a later Host block.
func Project(graph *config.Graph, alias string) Projection {
	projection := Projection{Alias: alias}
	if graph == nil {
		return projection
	}
	claimed := make(map[string]bool)
	matchedHostBlocks := 0
	kind, applies, condition := SourceGlobal, true, ""

	enterBlock := func(filePath string, file *config.File, block config.Block) {
		condition = file.Condition(block)
		kind, applies = blockApplies(block, alias)
		if block.Kind == config.BlockMatch {
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityMatchBlock,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "Match criteria are evaluated while connecting, so this block may override values shown here",
			})
			return
		}
		if !applies || block.Kind != config.BlockHost {
			return
		}
		matchedHostBlocks++
		if matchedHostBlocks > 1 {
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityDuplicateAlias,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "more than one Host block claims this alias",
			})
		}
		if kind == SourceWildcard {
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityWildcardPattern,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "this block matched through a wildcard pattern",
			})
		}
		for _, pattern := range block.Patterns {
			if !pattern.Negated {
				continue
			}
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityNegatedPattern,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "this block excludes hosts through " + pattern.Raw,
			})
			break
		}
	}

	directive := func(filePath string, index int, line config.Line) {
		if !applies {
			return
		}
		keyword := strings.ToLower(line.Keyword)
		projection.Sources = append(projection.Sources, Source{
			Keyword:   line.Keyword,
			Value:     argumentText(line),
			Path:      filePath,
			Line:      index + 1,
			Condition: condition,
			Kind:      kind,
			Winner:    !claimed[keyword],
		})
		claimed[keyword] = true
	}

	walkLoadOrder(graph, graph.Root, map[string]bool{}, enterBlock, directive)

	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Severity == config.SeverityInfo {
			continue
		}
		projection.Complexities = append(projection.Complexities, Complexity{
			Code:   ComplexityUnresolvedInclude,
			Path:   diagnostic.Path,
			Line:   diagnostic.Line,
			Detail: diagnostic.Code,
		})
	}
	return projection
}

// walkLoadOrder visits one file's blocks and directives in the order OpenSSH
// reads them, descending into each Include where its line sits.
//
// chain stops a cycle. A file included twice is walked twice, which is what
// OpenSSH does; the second read contributes nothing because the first value has
// already been claimed.
func walkLoadOrder(
	graph *config.Graph,
	filePath string,
	chain map[string]bool,
	enterBlock func(string, *config.File, config.Block),
	directive func(string, int, config.Line),
) {
	node := graph.Nodes[filePath]
	if node == nil || node.File == nil || chain[filePath] {
		return
	}
	chain[filePath] = true
	defer delete(chain, filePath)

	blocks := node.File.Blocks()
	position := 0
	enterBlock(filePath, node.File, blocks[0])
	for index, line := range node.File.Lines {
		if position+1 < len(blocks) && blocks[position+1].Header == index {
			position++
			enterBlock(filePath, node.File, blocks[position])
			continue
		}
		if line.Kind != config.LineDirective {
			continue
		}
		if config.EqualKeyword(line.Keyword, "Include") {
			for _, edge := range node.Includes {
				if edge.Line != index+1 {
					continue
				}
				for _, match := range edge.Matches {
					walkLoadOrder(graph, match, chain, enterBlock, directive)
				}
			}
			continue
		}
		directive(filePath, index, line)
	}
}

// blockApplies reports whether a block governs alias and how it matched.
func blockApplies(block config.Block, alias string) (kind string, applies bool) {
	switch block.Kind {
	case config.BlockGlobal:
		return SourceGlobal, true
	case config.BlockMatch:
		return "", false
	}
	for _, pattern := range block.Patterns {
		if pattern.Negated && MatchPattern(pattern.Value, alias) {
			return "", false
		}
	}
	for _, pattern := range block.Patterns {
		if pattern.Negated || !MatchPattern(pattern.Value, alias) {
			continue
		}
		if pattern.Wildcard {
			return SourceWildcard, true
		}
		return SourceExact, true
	}
	return "", false
}

// MatchPattern implements OpenSSH's match_pattern: '*' matches any sequence,
// '?' matches exactly one character, comparison is case-insensitive, and no
// other metacharacter is special.
func MatchPattern(pattern, value string) bool {
	loweredPattern := strings.ToLower(pattern)
	loweredValue := strings.ToLower(value)

	patternIndex, valueIndex := 0, 0
	starIndex, resumeIndex := -1, 0
	for valueIndex < len(loweredValue) {
		switch {
		case patternIndex < len(loweredPattern) &&
			(loweredPattern[patternIndex] == '?' || loweredPattern[patternIndex] == loweredValue[valueIndex]):
			patternIndex++
			valueIndex++
		case patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*':
			starIndex = patternIndex
			resumeIndex = valueIndex
			patternIndex++
		case starIndex >= 0:
			patternIndex = starIndex + 1
			resumeIndex++
			valueIndex = resumeIndex
		default:
			return false
		}
	}
	for patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(loweredPattern)
}
