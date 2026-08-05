package config

import (
	"bytes"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzParseRendersOriginalBytes(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("Host example\n  HostName 10.0.0.1\n"))
	f.Add([]byte("Host=a\r\n\t# comment\nInclude \"conf.d/*.conf\"\n"))
	f.Add([]byte("ProxyCommand \"unterminated\nPort 22"))
	f.Add([]byte(" \t\n\x00\xff=\"\"\n"))
	f.Fuzz(func(t *testing.T, source []byte) {
		file := Parse(source)
		rendered := file.Render()
		if !bytes.Equal(rendered, source) {
			t.Fatalf("round trip changed bytes: got %q, want %q", rendered, source)
		}
		for index, line := range file.Lines {
			if line.Kind == LineDirective && line.Keyword == "" {
				t.Fatalf("line %d is a directive without a keyword", index)
			}
		}
	})
}

// FuzzExpandIncludePattern fuzzes the step that turns an Include argument into
// a filesystem glob. It is the only place in the engine where text from a
// configuration file becomes a path, so a pattern that expanded to a relative
// path, to an uncleaned path, or to a home directory the engine had to guess
// would widen what the resolver reads.
func FuzzExpandIncludePattern(f *testing.F) {
	for _, seed := range []string{
		"conf.d/*.conf",
		"~/.ssh/extra hosts.conf",
		"%d/.ssh/config.d/*",
		"/etc/ssh/ssh_config",
		"~root/config",
		"~",
		"~/",
		"a%",
		"%%literal",
		"%h.conf",
		"../escape.conf",
		"./././x",
		"",
		"a\x00b",
		"a\nb",
	} {
		f.Add(seed)
	}
	// Seed from the committed golden fixture too, so the corpus starts from
	// arguments a real configuration actually contains.
	golden, err := os.ReadFile(filepath.Join("testdata", "golden", "realistic.conf"))
	if err != nil {
		f.Fatal(err)
	}
	for _, line := range Parse(golden).Lines {
		if line.Kind != LineDirective || !EqualKeyword(line.Keyword, "Include") {
			continue
		}
		for _, argument := range line.Arguments {
			f.Add(strings.Trim(argument.Raw, "\""))
		}
	}

	// Seeds that once broke an assertion in this target are kept permanently.
	// "~%d" expands its token first and only then reads as "~/...", which is a
	// reference to the home directory this resolver was given rather than to
	// some user's home it would have had to look up.
	f.Add("~%d")
	f.Add("%d")
	f.Add("~%%d")
	f.Add("%%~")

	resolver := Resolver{
		Home:   "/Users/tester",
		Root:   "/Users/tester/.ssh",
		Tokens: map[byte]string{'d': "/Users/tester"},
	}

	// A '~user' form needs a password database lookup this engine does not do,
	// so it is refused rather than guessed at. This is asserted directly rather
	// than as a rule inside the fuzz body, because expressing it there would
	// mean restating the order in which tokens and tildes are expanded, and a
	// test that restates the implementation checks nothing.
	for _, guessed := range []string{"~root/config", "~nobody", "~a/b"} {
		if _, err := resolver.expandPattern(guessed); !errors.Is(err, ErrUnsupportedExpansion) {
			f.Fatalf("expandPattern(%q) = %v, want ErrUnsupportedExpansion", guessed, err)
		}
	}

	f.Fuzz(func(t *testing.T, argument string) {
		expanded, err := resolver.expandPattern(argument)
		if err != nil {
			if expanded != "" {
				t.Fatalf("expandPattern(%q) returned %q alongside %v", argument, expanded, err)
			}
			return
		}
		if !path.IsAbs(expanded) {
			t.Fatalf("expandPattern(%q) = %q, which is not absolute", argument, expanded)
		}
		if cleaned := path.Clean(expanded); cleaned != expanded {
			t.Fatalf("expandPattern(%q) = %q, which is not cleaned (%q)", argument, expanded, cleaned)
		}
		// No percent token may survive unexpanded into a path the resolver will
		// glob. A literal percent can only come from the "%%" escape.
		//
		// There is deliberately no rule about tildes here. A leading tilde is
		// already excluded by the absoluteness check above, and a tilde
		// anywhere else is an ordinary character in a filename: "%%~" expands
		// to the literal name "%~", which OpenSSH would also treat literally.
		if strings.Contains(expanded, "%") && !strings.Contains(argument, "%%") {
			t.Fatalf("expandPattern(%q) = %q, which still contains an unexpanded token", argument, expanded)
		}
		again, againErr := resolver.expandPattern(argument)
		if againErr != nil || again != expanded {
			t.Fatalf("expandPattern(%q) is not deterministic: %q/%v then %q/%v", argument, expanded, err, again, againErr)
		}
	})
}
