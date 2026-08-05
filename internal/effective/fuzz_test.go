package effective

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseValues fuzzes the parser for `ssh -G` output.
//
// The bytes come from a program this application started but does not control,
// and the result decides what the UI reports as the effective configuration.
// The invariant is that the parse is total and lossless in the only sense that
// matters: every non-empty line contributes exactly one value, every keyword is
// listed once, in output order, lowercased, and First agrees with the first
// entry. A parser that dropped, duplicated or reordered a value would show the
// user a configuration OpenSSH is not going to use.
func FuzzParseValues(f *testing.F) {
	transcript, err := os.ReadFile(filepath.Join("testdata", "ssh-g-output.txt"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(transcript)
	for _, line := range strings.Split(string(transcript), "\n") {
		f.Add([]byte(line))
	}
	for _, seed := range []string{
		"",
		"\n",
		"\r\n",
		"hostname",
		"hostname ",
		"HostName 203.0.113.10",
		"identityfile ~/.ssh/id_a\nidentityfile ~/.ssh/id_b\n",
		"proxycommand /bin/sh -c \"nc %h %p\"\n",
		"user with spaces in the value\n",
		"a\x00b c\n",
		strings.Repeat("keyword value\n", 4096),
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, stdout []byte) {
		values := ParseValues(stdout)

		seen := make(map[string]bool, len(values.Keywords))
		parsed := 0
		for _, keyword := range values.Keywords {
			if seen[keyword] {
				t.Fatalf("keyword %q is listed twice in Keywords", keyword)
			}
			seen[keyword] = true
			if keyword != strings.ToLower(keyword) {
				t.Fatalf("keyword %q was not lowercased", keyword)
			}
			entries, ok := values.Entries[keyword]
			if !ok {
				t.Fatalf("keyword %q is in Keywords but not in Entries", keyword)
			}
			if len(entries) == 0 {
				t.Fatalf("keyword %q has an empty entry list", keyword)
			}
			if first := values.First(keyword); first != entries[0] {
				t.Fatalf("First(%q) = %q, want %q", keyword, first, entries[0])
			}
			if all := values.All(keyword); len(all) != len(entries) {
				t.Fatalf("All(%q) = %d entries, want %d", keyword, len(all), len(entries))
			}
			parsed += len(entries)
		}
		if len(seen) != len(values.Entries) {
			t.Fatalf("Entries has %d keywords but Keywords lists %d", len(values.Entries), len(seen))
		}

		expected := 0
		for _, raw := range strings.Split(string(stdout), "\n") {
			if strings.TrimRight(raw, "\r") != "" {
				expected++
			}
		}
		if parsed != expected {
			t.Fatalf("parsed %d values from %d non-empty lines", parsed, expected)
		}

		if missing := values.First("definitely-not-a-keyword"); missing != "" {
			t.Fatalf("First on an absent keyword = %q", missing)
		}
	})
}
