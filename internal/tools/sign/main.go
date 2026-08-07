// Command sign produces the detached signature a release publishes beside its
// checksum file.
//
// It is a tool rather than a step in the workflow's shell so that the format is
// decided in the same language that verifies it, and so that a mistake in it is
// a compile error rather than a release nobody can install.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sign <file>")
		os.Exit(2)
	}
	encoded := strings.TrimSpace(os.Getenv("RELEASE_SIGNING_KEY"))
	if encoded == "" {
		fmt.Fprintln(os.Stderr, "sign: RELEASE_SIGNING_KEY is not set; a release without one is a release nobody can install")
		os.Exit(1)
	}
	private, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "sign: RELEASE_SIGNING_KEY is not an Ed25519 private key")
		os.Exit(1)
	}
	body, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(private), body)))
}
