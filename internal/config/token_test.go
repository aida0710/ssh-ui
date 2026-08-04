package config

import "testing"

func TestSplitArgumentsPreservesEveryByte(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		values   []string
		trailing string
	}{
		{"single", " example", []string{"example"}, ""},
		{"multiple with tabs", "\tone\ttwo  three", []string{"one", "two", "three"}, ""},
		{"quoted with spaces", ` "jump host" plain`, []string{"jump host", "plain"}, ""},
		{"empty quotes", ` ""`, []string{""}, ""},
		{"trailing whitespace", " value  \t", []string{"value"}, "  \t"},
		{"only whitespace", "   ", nil, "   "},
		{"empty", "", nil, ""},
		{"hash token is preserved", " 22 #trailing", []string{"22", "#trailing"}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments, trailing, ok := splitArguments(test.input)
			if !ok {
				t.Fatalf("splitArguments(%q) reported unstructured input", test.input)
			}
			if trailing != test.trailing {
				t.Errorf("trailing = %q, want %q", trailing, test.trailing)
			}
			if len(arguments) != len(test.values) {
				t.Fatalf("arguments = %#v, want %d values", arguments, len(test.values))
			}
			rendered := ""
			for index, argument := range arguments {
				if argument.Value != test.values[index] {
					t.Errorf("value[%d] = %q, want %q", index, argument.Value, test.values[index])
				}
				rendered += argument.Lead + argument.Raw
			}
			if rendered+trailing != test.input {
				t.Fatalf("re-rendered %q, want %q", rendered+trailing, test.input)
			}
		})
	}
}

func TestSplitArgumentsRejectsQuotingItCannotReproduce(t *testing.T) {
	for _, input := range []string{` "unterminated`, ` "closed"tail`, ` bare"quote`} {
		if _, _, ok := splitArguments(input); ok {
			t.Errorf("splitArguments(%q) accepted ambiguous quoting", input)
		}
	}
}
