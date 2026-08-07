package knownhosts

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseKnownHostsRoundTrip は known_hosts のリーダーをファズする。
//
// このファイルは ssh が、ssh-keyscan が、そして人の手が書く。つまり、このアプリ
// ケーションが読む ~/.ssh 配下の成果物のうち、自分で書いたのではない唯一のもの
// である。重要な不変条件は二つ。変更していないファイルをレンダリングすると元の
// バイト列が返ること — 削除はファイル全体を書き直すので、触れていない行はすべて
// 生き残らなければならない — と、Entry を持つと主張する Line は完全なものを
// 持たなければならないこと。削除の経路は、解析された同一性で行を選ぶからである。
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
				// ハッシュ化されたエントリは、その元になったリテラルではマッチできない。
				// そこで表明するのは呼び出しそのものだけだ。ファイルに含まれていたどんな
				// ホスト文字列に対しても、終了し、panic しないこと。
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
