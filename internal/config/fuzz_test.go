package config

import (
	"bytes"
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
