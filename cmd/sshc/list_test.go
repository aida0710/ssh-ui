package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestListReadsConcreteAliasesFromConfigAndIncludes(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(ssh, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(ssh, filepath.FromSlash(name)), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config", "Host zeta second\n  HostName zeta.example\nInclude conf.d/*.conf\nHost *\n  User ops\n")
	write("conf.d/10-work.conf", "Host alpha !blocked web-* single-?\n  HostName alpha.example\nHost second\n")

	var stdout, stderr bytes.Buffer
	if code := runList(home, &stdout, &stderr); code != 0 {
		t.Fatalf("runList = %d, stderr = %q", code, stderr.String())
	}
	if got, want := stdout.String(), "alpha\nsecond\nzeta\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestListTreatsAMissingConfigAsAnEmptyList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runList(t.TempDir(), &stdout, &stderr); code != 0 {
		t.Fatalf("runList = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}
