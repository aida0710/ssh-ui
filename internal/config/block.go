package config

import "strings"

// BlockKind identifies which conditional construct owns a range of lines.
type BlockKind uint8

const (
	// BlockGlobal holds the lines before the first Host or Match line. It
	// always exists, even when it is empty.
	BlockGlobal BlockKind = iota
	BlockHost
	BlockMatch
)

// Pattern is one argument of a Host line.
type Pattern struct {
	Raw      string
	Value    string
	Negated  bool
	Wildcard bool
}

// Criterion is one attribute of a Match line.
type Criterion struct {
	Keyword  string
	Argument string
	Negated  bool
}

// Block is a half-open line range [Start, End) governed by one header line.
type Block struct {
	Kind     BlockKind
	Header   int
	Start    int
	End      int
	Patterns []Pattern
	Criteria []Criterion
}

// matchCriteriaWithArgument lists the Match attributes that consume the next
// token as their argument. all, canonical and final take no argument.
var matchCriteriaWithArgument = map[string]bool{
	"exec":         true,
	"host":         true,
	"localnetwork": true,
	"localuser":    true,
	"originalhost": true,
	"tagged":       true,
	"user":         true,
}

// Blocks returns every block in file order. The first entry is always the
// global block.
func (f *File) Blocks() []Block {
	blocks := []Block{{Kind: BlockGlobal, Header: -1, Start: 0}}
	for index, line := range f.Lines {
		if line.Kind != LineDirective {
			continue
		}
		switch {
		case EqualKeyword(line.Keyword, "Host"):
			blocks[len(blocks)-1].End = index
			blocks = append(blocks, Block{
				Kind:     BlockHost,
				Header:   index,
				Start:    index + 1,
				Patterns: parsePatterns(line.Values()),
			})
		case EqualKeyword(line.Keyword, "Match"):
			blocks[len(blocks)-1].End = index
			blocks = append(blocks, Block{
				Kind:     BlockMatch,
				Header:   index,
				Start:    index + 1,
				Criteria: parseCriteria(line.Values()),
			})
		}
	}
	blocks[len(blocks)-1].End = len(f.Lines)
	return blocks
}

// BlockAt returns the block that governs the given line index. A Host or Match
// header line belongs to the block it opens.
func (f *File) BlockAt(line int) Block {
	blocks := f.Blocks()
	found := blocks[0]
	for _, block := range blocks {
		if block.Header == line || (line >= block.Start && line < block.End) {
			found = block
		}
	}
	return found
}

// Condition returns the header text of a block for display, without indent or
// line ending. The global block has no condition.
func (f *File) Condition(block Block) string {
	if block.Header < 0 || block.Header >= len(f.Lines) {
		return ""
	}
	return strings.TrimSpace(f.Lines[block.Header].Render())
}

func parsePatterns(values []string) []Pattern {
	patterns := make([]Pattern, 0, len(values))
	for _, value := range values {
		pattern := Pattern{Raw: value, Value: value}
		if strings.HasPrefix(pattern.Value, "!") {
			pattern.Negated = true
			pattern.Value = pattern.Value[1:]
		}
		pattern.Wildcard = strings.ContainsAny(pattern.Value, "*?")
		patterns = append(patterns, pattern)
	}
	return patterns
}

func parseCriteria(values []string) []Criterion {
	criteria := make([]Criterion, 0, len(values))
	for index := 0; index < len(values); index++ {
		keyword := values[index]
		criterion := Criterion{}
		if strings.HasPrefix(keyword, "!") {
			criterion.Negated = true
			keyword = keyword[1:]
		}
		// OpenSSH's strdelim splits a Match attribute from its argument on
		// whitespace or a single '=', so both spellings must be accepted.
		name, argument, hasEquals := strings.Cut(keyword, "=")
		criterion.Keyword = strings.ToLower(name)
		if hasEquals {
			criterion.Argument = argument
			criteria = append(criteria, criterion)
			continue
		}
		if matchCriteriaWithArgument[criterion.Keyword] && index+1 < len(values) {
			index++
			criterion.Argument = values[index]
		}
		criteria = append(criteria, criterion)
	}
	return criteria
}
