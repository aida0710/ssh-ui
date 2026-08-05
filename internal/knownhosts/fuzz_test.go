package knownhosts

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseKnownHostsRoundTrip fuzzes the known_hosts reader.
//
// The file is written by ssh, by ssh-keyscan and by hand, so it is the one
// artefact under ~/.ssh this application reads that it did not write. Two
// invariants matter: rendering an unmodified file returns the original bytes,
// because a deletion rewrites the whole file and every untouched line must
// survive; and a Line that claims to carry an Entry must carry a complete one,
// because the deletion path selects lines by their parsed identity.
func FuzzParseKnownHostsRoundTrip(f *testing.F) {
	sample, err := os.ReadFile(filepath.Join("testdata", "known_hosts.sample"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sample)
	for _, line := range bytes.Split(sample, []byte("\n")) {
		f.Add(line)
		f.Add(append(append([]byte(nil), line...), '\n'))
		f.Add(append(append([]byte(nil), line...), '\r', '\n'))
	}
	for _, seed := range []string{
		"",
		"\n",
		"\r\n",
		"   \t  \n",
		"# only a comment",
		"host",
		"host type",
		"host type key extra comment words",
		"|1|badsalt|badhash ssh-ed25519 AAAA",
		"@marker",
		"a\x00b ssh-ed25519 AAAA",
		strings.Repeat("h,", 4096) + "x ssh-ed25519 AAAA",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, contents []byte) {
		file := ParseFile(contents)
		if file == nil {
			t.Fatal("ParseFile returned nil")
		}
		if rendered := file.Render(); !bytes.Equal(rendered, contents) {
			t.Fatalf("round trip changed bytes:\n got %q\nwant %q", rendered, contents)
		}

		for _, line := range file.Lines {
			if line.Number <= 0 {
				t.Fatalf("line number %d is not 1-based", line.Number)
			}
			if line.Entry == nil {
				continue
			}
			entry := line.Entry
			if len(entry.Hosts) == 0 {
				t.Fatalf("line %d parsed an entry with no host", line.Number)
			}
			if entry.KeyType == "" || entry.Key == "" {
				t.Fatalf("line %d parsed an entry with no key: %#v", line.Number, entry)
			}
			if entry.Fingerprint != "" && !strings.HasPrefix(entry.Fingerprint, "SHA256:") {
				t.Fatalf("line %d fingerprint = %q", line.Number, entry.Fingerprint)
			}
			for _, host := range entry.Hosts {
				// A hashed entry cannot be matched by the literal it hashes, so
				// only the call itself is asserted: it must terminate and must
				// not panic on any host string the file contained.
				_ = entry.MatchesHost(host)
			}
		}

		if entries := file.Entries(); len(entries) > len(file.Lines) {
			t.Fatalf("Entries() = %d, more than the %d lines it came from", len(entries), len(file.Lines))
		}
		for _, query := range []string{"", "a", "SHA256:", "ssh-ed25519"} {
			for _, found := range Search(file, query) {
				if found.Entry == nil {
					t.Fatalf("Search(%q) returned a line with no entry", query)
				}
			}
		}
	})
}
