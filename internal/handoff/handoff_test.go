package handoff_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/handoff"
)

func TestWritingTheHandoffAndTakingItAway(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sshc")
	secret, err := handoff.Mint(strings.NewReader(strings.Repeat("k", 64)))
	if err != nil {
		t.Fatalf("Mint = %v", err)
	}
	written, err := handoff.Write(directory, "http://127.0.0.1:52865", secret)
	if err != nil {
		t.Fatalf("Write = %v", err)
	}
	if len(written.Secret) < 32 {
		t.Errorf("the secret is %d characters, which is not one worth minting", len(written.Secret))
	}

	path := filepath.Join(directory, handoff.FileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the handoff was not written: %v", err)
	}
	// Readable by this user and nobody else, like everything else in ~/.ssh.
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}

	read, err := handoff.Read(directory)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if read.URL != written.URL || read.Secret != written.Secret {
		t.Errorf("read %+v, wrote %+v", read, written)
	}

	if err := handoff.Remove(directory); err != nil {
		t.Fatalf("Remove = %v", err)
	}
	if _, err := handoff.Read(directory); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Read after Remove = %v, want a missing file", err)
	}
	// Removing what is not there is the state the caller asked for.
	if err := handoff.Remove(directory); err != nil {
		t.Errorf("Remove twice = %v", err)
	}
}

// A second run replaces the first one's file rather than trusting it. The
// secret is per run, so a handoff left behind by a process that was killed
// points at a port nothing is listening on with a secret nothing accepts.
func TestASecondRunReplacesTheHandoff(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sshc")
	firstSecret, err := handoff.Mint(strings.NewReader(strings.Repeat("a", 64)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := handoff.Write(directory, "http://127.0.0.1:1", firstSecret)
	if err != nil {
		t.Fatal(err)
	}
	secondSecret, err := handoff.Mint(strings.NewReader(strings.Repeat("b", 64)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := handoff.Write(directory, "http://127.0.0.1:2", secondSecret)
	if err != nil {
		t.Fatal(err)
	}
	if first.Secret == second.Secret {
		t.Error("two runs minted the same secret")
	}
	read, err := handoff.Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	if read.Secret != second.Secret || read.URL != "http://127.0.0.1:2" {
		t.Errorf("the file still describes the first run: %+v", read)
	}
}
