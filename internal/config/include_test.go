package config

import (
	"errors"
	"strings"
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

// 生成された領域の内側の Include が何にも一致しなかったことは報告しない。
//
// その行を書いたのはこのアプリケーション自身で、宣言されたグループごとに 1 本ずつ
// 置いている。宣言済みで中身が空のグループは、作った直後と最後の接続を出した後の
// 正常な状態であり、application 層は同じ事実を group_empty として持っていて、それを
// 注意としては出さないと決めている。engine が同じことを別の名前で言えば、片方を
// 黙らせた判断が無意味になる。
//
// 領域の外側の Include は引き続き報告する。そちらは人が書いた行であり、何にも
// 一致しないのは打ち間違いの可能性がある。
func TestNoMatchIsNotReportedInsideTheGeneratedRegion(t *testing.T) {
	const start = "# >>> generated"
	const end = "# <<< generated"
	source := start + "\nInclude declared/*.conf\n" + end + "\nInclude by-hand/*.conf\n"
	entry := "/home/u/.ssh/config"
	resolver := Resolver{
		Loader: fakeLoader{files: map[string]string{entry: source}},
		Home:   "/home/u",
		Root:   "/home/u/.ssh",
		GeneratedRegion: func(file *File) (int, int, bool) {
			first, last := -1, -1
			for index, line := range file.Lines {
				switch strings.TrimSpace(line.Text) {
				case start:
					first = index
				case end:
					last = index
				}
			}
			return first, last, first >= 0 && last > first
		},
	}

	graph, err := resolver.Resolve(entry)
	if err != nil {
		t.Fatal(err)
	}

	var reported []string
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Code == DiagnosticIncludeNoMatch {
			reported = append(reported, diagnostic.Detail)
		}
	}
	if len(reported) != 1 || !strings.Contains(reported[0], "by-hand") {
		t.Fatalf("include_no_match = %v, want only the hand-written include", reported)
	}
}
