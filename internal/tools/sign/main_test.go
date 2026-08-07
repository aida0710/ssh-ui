package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// What this writes is what the updater reads.
//
// The two live in different packages and are compiled into different programs,
// so nothing but a test connects them: a format decided twice is a format that
// can drift, and the way it would be discovered is a release nobody can
// install.
func TestWhatThisSignsIsWhatTheUpdaterVerifies(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	manifest := filepath.Join(directory, "checksums.txt")
	body := []byte("abc123  ssh-ui-darwin-arm64\n")
	if err := os.WriteFile(manifest, body, 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("go", "run", ".", manifest)
	command.Env = append(os.Environ(), "RELEASE_SIGNING_KEY="+base64.StdEncoding.EncodeToString(private))
	output, err := command.Output()
	if err != nil {
		t.Fatalf("sign = %v", err)
	}

	// The updater trims and base64-decodes exactly this, then verifies it over
	// the manifest's bytes.
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatalf("the signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, body, signature) {
		t.Error("the updater's key does not verify what this wrote")
	}
}

// A release built without the key is refused here rather than published
// unsigned, because an installation refuses an unsigned release anyway.
func TestSigningWithoutAKeyFails(t *testing.T) {
	command := exec.Command("go", "run", ".", "main.go")
	command.Env = append(os.Environ(), "RELEASE_SIGNING_KEY=")
	if err := command.Run(); err == nil {
		t.Error("signing with no key succeeded")
	}
}
