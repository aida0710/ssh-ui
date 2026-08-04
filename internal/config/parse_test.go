package config

import (
	"bytes"
	"os"
	"testing"
)

func TestParseClassifiesLines(t *testing.T) {
	source := []byte("# comment\n\n  Host  example  \nHostName=10.0.0.1\n\tUnknownDirective \"a b\"\n\"quoted keyword\" x\n")
	file := Parse(source)
	if len(file.Lines) != 6 {
		t.Fatalf("lines = %d", len(file.Lines))
	}
	wantKinds := []LineKind{LineComment, LineBlank, LineDirective, LineDirective, LineDirective, LineUnstructured}
	for index, want := range wantKinds {
		if file.Lines[index].Kind != want {
			t.Errorf("line %d kind = %v, want %v", index, file.Lines[index].Kind, want)
		}
	}

	host := file.Lines[2]
	if host.Indent != "  " || host.Keyword != "Host" || host.Separator != "  " || host.Trailing != "  " {
		t.Errorf("host line = %#v", host)
	}
	if values := host.Values(); len(values) != 1 || values[0] != "example" {
		t.Errorf("host values = %#v", values)
	}

	hostName := file.Lines[3]
	if hostName.Keyword != "HostName" || hostName.Separator != "=" {
		t.Errorf("hostname line = %#v", hostName)
	}
	if values := file.Lines[4].Values(); len(values) != 1 || values[0] != "a b" {
		t.Errorf("unknown directive values = %#v", file.Lines[4].Values())
	}
}

func TestParseAndRenderRoundTripsExactBytes(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{"empty", ""},
		{"no trailing newline", "Host example"},
		{"crlf", "Host example\r\nHostName 10.0.0.1\r\n"},
		{"mixed endings", "Host a\nHost b\r\n\nHost c"},
		{"blank whitespace line", "Host a\n \t\nPort 22\n"},
		{"equals with spaces", "Host   =  example\n"},
		{"unterminated quote", "ProxyCommand \"broken\n"},
		{"invalid utf8", "Host \xff\xfe\n"},
		{"nul byte", "Host a\x00b\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rendered := Parse([]byte(test.source)).Render()
			if !bytes.Equal(rendered, []byte(test.source)) {
				t.Fatalf("render = %q, want %q", rendered, test.source)
			}
		})
	}
}

func TestGoldenFixtureRoundTripsExactBytes(t *testing.T) {
	source, err := os.ReadFile("testdata/golden/realistic.conf")
	if err != nil {
		t.Fatal(err)
	}
	if rendered := Parse(source).Render(); !bytes.Equal(rendered, source) {
		t.Fatalf("golden fixture did not round-trip")
	}
}

func TestEqualKeywordIgnoresCase(t *testing.T) {
	if !EqualKeyword("hostname", "HostName") || EqualKeyword("host", "hostname") {
		t.Fatal("EqualKeyword does not match OpenSSH case-insensitive keywords")
	}
}

func TestValuesStopAtCommentButRenderKeepsIt(t *testing.T) {
	source := []byte("Port 22 # inline note\n")
	file := Parse(source)
	if values := file.Lines[0].Values(); len(values) != 1 || values[0] != "22" {
		t.Fatalf("values = %#v, want [22]", file.Lines[0].Values())
	}
	if rendered := file.Render(); !bytes.Equal(rendered, source) {
		t.Fatalf("render = %q, want %q", rendered, source)
	}
}
