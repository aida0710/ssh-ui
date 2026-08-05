package config

import (
	"errors"
	"strings"
)

// Argument is one directive argument together with the exact bytes that
// produced it. Lead holds the whitespace that precedes the argument so a
// parsed line can be rendered back byte-for-byte.
type Argument struct {
	Lead  string
	Raw   string
	Value string
}

// ErrUnquotableValue reports a value ssh_config cannot represent. OpenSSH has
// no backslash escape inside a quoted argument, so a value containing a double
// quote, a newline or a NUL has no spelling and is refused rather than mangled.
var ErrUnquotableValue = errors.New("value cannot be quoted for an OpenSSH configuration")

// RenderArgument writes one value using OpenSSH's quoting rules.
func RenderArgument(lead, value string) (Argument, error) {
	if strings.ContainsAny(value, "\n\r\x00\"") {
		return Argument{}, ErrUnquotableValue
	}
	raw := value
	if value == "" || strings.ContainsAny(value, " \t") || strings.HasPrefix(value, "#") {
		raw = `"` + value + `"`
	}
	return Argument{Lead: lead, Raw: raw, Value: value}, nil
}

// splitArguments splits the argument portion of a directive line.
//
// OpenSSH's argv_split treats a double quote that starts a token as the start
// of a quoted string that runs to the next double quote, and supports no
// backslash escapes. Input whose quoting cannot be reproduced under that rule
// is reported as unstructured (ok == false) so the caller keeps the line
// verbatim instead of guessing at its meaning.
func splitArguments(input string) (arguments []Argument, trailing string, ok bool) {
	index := 0
	for {
		leadStart := index
		for index < len(input) && isSpace(input[index]) {
			index++
		}
		lead := input[leadStart:index]
		if index == len(input) {
			return arguments, lead, true
		}

		rawStart := index
		var value string
		if input[index] == '"' {
			index++
			closing := strings.IndexByte(input[index:], '"')
			if closing < 0 {
				return nil, "", false
			}
			value = input[index : index+closing]
			index += closing + 1
			if index < len(input) && !isSpace(input[index]) {
				return nil, "", false
			}
		} else {
			for index < len(input) && !isSpace(input[index]) {
				if input[index] == '"' {
					return nil, "", false
				}
				index++
			}
			value = input[rawStart:index]
		}

		arguments = append(arguments, Argument{
			Lead:  lead,
			Raw:   input[rawStart:index],
			Value: value,
		})
	}
}

func isSpace(character byte) bool {
	return character == ' ' || character == '\t'
}
