package config

import "strings"

// Argument is one directive argument together with the exact bytes that
// produced it. Lead holds the whitespace that precedes the argument so a
// parsed line can be rendered back byte-for-byte.
type Argument struct {
	Lead  string
	Raw   string
	Value string
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
