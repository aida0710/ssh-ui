// Package handoff is how the running application tells a command-line
// invocation of the same binary where to find it.
//
// It exists so that connecting from a terminal is `ssh-ui <alias>` rather than
// five environment variables and a flag. Those variables are the hand-written
// form of what the Terminal button already does for itself; nothing about them
// was ever meant to be typed.
//
// The file holds a URL and a secret minted for this run. Anyone who can read it
// can already read the vault's ciphertext and every private key — it lives in
// the same directory under the same permissions — so it moves no boundary. What
// it does move is the reach of a stale one: the secret is worthless the moment
// the run that minted it ends, so a file left behind by a process that was
// killed points at a port nothing is listening on with a secret nothing
// accepts.
package handoff

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// FileName is the handoff inside the application's state directory.
const FileName = "cli"

// secretLength is the number of random bytes behind the secret.
const secretLength = 32

// Handoff is where this run is listening and what proves a caller read the
// file rather than guessed at it.
type Handoff struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// HeaderName carries the secret on a request from the command line.
//
// A custom header is a request no web page can send cross-origin without a
// preflight, and this server answers no preflight, so the handoff route is
// unreachable from a browser however much it knows.
const HeaderName = "X-SSH-UI-CLI"

// Mint returns a secret for one run.
//
// It is separate from Write because the server has to be told the secret before
// it starts listening, and the file cannot be written until the URL is known.
func Mint(random io.Reader) (string, error) {
	raw := make([]byte, secretLength)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Write records where this run is listening and what proves a caller read the
// file, replacing whatever is there.
func Write(directory, url, secret string) (Handoff, error) {
	written := Handoff{URL: url, Secret: secret}
	body, err := json.Marshal(written)
	if err != nil {
		return Handoff{}, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Handoff{}, err
	}
	if err := os.WriteFile(filepath.Join(directory, FileName), body, 0o600); err != nil {
		return Handoff{}, err
	}
	return written, nil
}

// Read returns what the running application left behind.
func Read(directory string) (Handoff, error) {
	body, err := os.ReadFile(filepath.Join(directory, FileName))
	if err != nil {
		return Handoff{}, err
	}
	var read Handoff
	if err := json.Unmarshal(body, &read); err != nil {
		return Handoff{}, err
	}
	return read, nil
}

// Remove takes it away. A file that is not there is the state this asks for.
func Remove(directory string) error {
	err := os.Remove(filepath.Join(directory, FileName))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Random is the source Write draws from when a caller has no opinion.
var Random io.Reader = rand.Reader
