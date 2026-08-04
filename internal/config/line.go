package config

import "strings"

// LineKind classifies a physical line of an OpenSSH client configuration file.
type LineKind uint8

const (
	// LineBlank is an empty line or a line containing only whitespace.
	LineBlank LineKind = iota
	// LineComment is a line whose first non-whitespace character is '#'.
	LineComment
	// LineDirective is a keyword with zero or more arguments.
	LineDirective
	// LineUnstructured is a line the engine preserves verbatim because its
	// structure cannot be reproduced exactly. It is never rewritten.
	LineUnstructured
)

// Line is one physical line. For every kind except LineDirective the complete
// line text is kept in Text. For LineDirective the components satisfy
// Indent+Keyword+Separator+arguments+Trailing == the original line text.
type Line struct {
	Kind      LineKind
	Text      string
	Indent    string
	Keyword   string
	Separator string
	Arguments []Argument
	Trailing  string
	Ending    string
}

// Render returns the line exactly as it appeared in the source file.
func (l Line) Render() string {
	if l.Kind != LineDirective {
		return l.Text + l.Ending
	}
	var builder strings.Builder
	builder.WriteString(l.Indent)
	builder.WriteString(l.Keyword)
	builder.WriteString(l.Separator)
	for _, argument := range l.Arguments {
		builder.WriteString(argument.Lead)
		builder.WriteString(argument.Raw)
	}
	builder.WriteString(l.Trailing)
	builder.WriteString(l.Ending)
	return builder.String()
}

// Values returns the unquoted argument values of a directive line, stopping at
// the first unquoted '#' token because OpenSSH's argv_split terminates a
// configuration line's argument list at a comment. Arguments keeps the full
// tokenization so the line still renders byte-for-byte.
func (l Line) Values() []string {
	if l.Kind != LineDirective || len(l.Arguments) == 0 {
		return nil
	}
	values := make([]string, 0, len(l.Arguments))
	for _, argument := range l.Arguments {
		if strings.HasPrefix(argument.Raw, "#") {
			break
		}
		values = append(values, argument.Value)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

// EqualKeyword compares two directive keywords the way OpenSSH does, which is
// case-insensitively for ASCII keywords.
func EqualKeyword(first, second string) bool {
	return strings.EqualFold(first, second)
}
