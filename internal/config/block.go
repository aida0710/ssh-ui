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

// CommentRun reports the range of comment lines attached to the block whose
// header is at the given index, as a half-open interval [start, header).
//
// The attached comment is the run of contiguous LineComment lines immediately
// above the header. The run stops at a blank line, a directive, an
// unstructured line or the start of the file.
//
// A blank line separates deliberately. Without that rule a file's own banner —
// the "# Managed by hand since 2019" that sits at the top above an empty line —
// would be adopted by whichever Host block happens to come first, and editing
// that block's comment would rewrite the file's banner. Requiring adjacency is
// what makes the attachment a property of the text rather than a guess.
//
// The returned range is empty (start == header) when no comment is attached.
func (f *File) CommentRun(header int) (start int) {
	if header < 0 || header > len(f.Lines) {
		return header
	}
	start = header
	for start > 0 && f.Lines[start-1].Kind == LineComment {
		start--
	}
	return start
}

// CommentText returns the attached comment as text, with the leading '#' and a
// single following space removed from each line.
//
// The marker is stripped so the editor shows what the user wrote rather than
// the syntax carrying it, and re-added on the way back by RenderComment. A
// comment line that is only "#" becomes an empty line in the text, which is how
// a deliberate blank line inside a comment block survives the round trip.
func (f *File) CommentText(header int) string {
	start := f.CommentRun(header)
	if start == header {
		return ""
	}
	lines := make([]string, 0, header-start)
	for _, line := range f.Lines[start:header] {
		text := strings.TrimLeft(line.Text, " \t")
		text = strings.TrimSuffix(strings.TrimSuffix(text, "\n"), "\r")
		text = strings.TrimPrefix(text, "#")
		lines = append(lines, strings.TrimPrefix(text, " "))
	}
	return strings.Join(lines, "\n")
}

// RenderComment turns comment text back into configuration lines.
//
// Every line is prefixed with "# ", including an empty one, which is written as
// "#" alone rather than "# " so no trailing whitespace is introduced. Text that
// already begins with '#' is not double-marked: a user who types "## section"
// means that, and re-marking it would grow a marker on every save.
func RenderComment(text, indent, ending string) []Line {
	if text == "" {
		return nil
	}
	parts := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	lines := make([]Line, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimRight(part, " \t")
		var body string
		switch {
		case trimmed == "":
			body = "#"
		case strings.HasPrefix(trimmed, "#"):
			body = trimmed
		default:
			body = "# " + trimmed
		}
		lines = append(lines, Line{Kind: LineComment, Text: indent + body + ending})
	}
	return lines
}
