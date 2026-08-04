package config

import (
	"errors"
	"testing"
)

func newTestResolver() Resolver {
	return Resolver{
		Home:   "/Users/tester",
		Root:   "/Users/tester/.ssh",
		Tokens: map[byte]string{'d': "/Users/tester", 'u': "tester", 'i': "501"},
	}
}

func TestExpandPatternFollowsOpenSSHRules(t *testing.T) {
	resolver := newTestResolver()
	tests := []struct {
		name     string
		argument string
		want     string
	}{
		{"relative resolves under the ssh directory", "conf.d/*.conf", "/Users/tester/.ssh/conf.d/*.conf"},
		{"absolute stays absolute", "/etc/ssh/ssh_config", "/etc/ssh/ssh_config"},
		{"tilde uses the home directory", "~/work/config", "/Users/tester/work/config"},
		{"bare tilde is the home directory", "~", "/Users/tester"},
		{"percent d is the home directory", "%d/.ssh/extra", "/Users/tester/.ssh/extra"},
		{"double percent is a literal percent", "weird%%name", "/Users/tester/.ssh/weird%name"},
		{"parent segments are cleaned", "conf.d/../other.conf", "/Users/tester/.ssh/other.conf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolver.expandPattern(test.argument)
			if err != nil {
				t.Fatalf("expandPattern(%q) error = %v", test.argument, err)
			}
			if got != test.want {
				t.Fatalf("expandPattern(%q) = %q, want %q", test.argument, got, test.want)
			}
		})
	}
}

func TestExpandPatternRefusesToGuess(t *testing.T) {
	resolver := newTestResolver()
	for _, argument := range []string{"~other/config", "%h/config", "%C.conf", ""} {
		if got, err := resolver.expandPattern(argument); !errors.Is(err, ErrUnsupportedExpansion) {
			t.Errorf("expandPattern(%q) = %q, %v; want ErrUnsupportedExpansion", argument, got, err)
		}
	}
}

func TestIncludeArgumentsIgnoreOtherDirectives(t *testing.T) {
	file := Parse([]byte("Include a.conf b.conf # note\ninclude\t\"c d.conf\"\nHostName example\n"))
	var collected []string
	for _, line := range file.Lines {
		if line.Kind == LineDirective && EqualKeyword(line.Keyword, "Include") {
			collected = append(collected, line.Values()...)
		}
	}
	want := []string{"a.conf", "b.conf", "c d.conf"}
	if len(collected) != len(want) {
		t.Fatalf("collected = %#v, want %#v", collected, want)
	}
	for index := range want {
		if collected[index] != want[index] {
			t.Fatalf("collected[%d] = %q, want %q", index, collected[index], want[index])
		}
	}
}
