// Package selfupdate looks at the project's GitHub releases and, when asked,
// replaces this binary with a newer one.
//
// This is the only thing in this application that contacts a host other than
// itself, and the only thing that replaces the code it is running as. Both are
// deliberate and neither is automatic: nothing here runs unless somebody
// presses something.
//
// The checksum file is signed, and the public key is compiled into this binary.
// That is what stands behind the bytes: not TLS, and not the account that
// published them. An attacker who takes the GitHub account can publish anything
// they like and no installation will accept it, because they cannot produce a
// signature the key already in the binary verifies.
//
// The checksum itself only catches a truncated transfer — it comes from the
// same place as the binary — so it is worth nothing on its own. It is worth
// something once the file carrying it has been signed, which is the whole
// arrangement: sign the manifest, and let the manifest speak for the artefact.
//
// A release with no signature is refused rather than accepted with a warning.
// Accepting one would mean an attacker need only leave the signature out.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	// ErrNoRelease reports that the project has published none yet.
	ErrNoRelease = errors.New("no release has been published")
	// ErrAssetMissing reports a release with nothing this machine can run.
	ErrAssetMissing = errors.New("the release carries no build for this machine")
	// ErrChecksumMismatch reports a download that is not what the signed
	// checksum file says it is.
	ErrChecksumMismatch = errors.New("the download does not match the published checksum")
	// ErrUnsigned reports a release that published no signature. It is refused
	// rather than accepted, because otherwise an attacker need only leave the
	// signature out.
	ErrUnsigned = errors.New("the release is not signed")
	// ErrBadSignature reports a signature this binary's key does not verify.
	// Whoever published that release does not hold the key this was built with.
	ErrBadSignature = errors.New("the release signature is not from this project")
	// ErrNotWritable reports a binary this process may not replace.
	ErrNotWritable = errors.New("this binary is not in a place this process can replace")
)

// MaxDownloadBytes bounds what will be read from the network. A build of this
// application is tens of megabytes; anything far larger is not one.
const MaxDownloadBytes = 200 << 20

// Release is what the project published.
type Release struct {
	Version string
	// PageURL is where a person can read what changed and download it by hand,
	// which is the alternative to letting this replace anything.
	PageURL      string
	AssetURL     string
	ChecksumURL  string
	SignatureURL string
}

// Checker asks GitHub what the latest release is.
type Checker struct {
	// API is the releases endpoint, injected so no test reaches GitHub.
	API string
	// AssetName is the file in the release this machine can run.
	AssetName string
	// ChecksumName is the file listing the checksums of the others.
	ChecksumName string
	// SignatureName is the detached signature over that file.
	SignatureName string
	// PublicKey verifies it. An empty one accepts nothing: a build with no key
	// cannot tell an honest release from any other, and must not guess.
	PublicKey ed25519.PublicKey
	HTTP      *http.Client
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Draft   bool   `json:"draft"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (c Checker) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// Latest returns the newest published release.
func (c Checker) Latest(ctx context.Context) (Release, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.API, nil)
	if err != nil {
		return Release{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := c.client().Do(request)
	if err != nil {
		return Release{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return Release{}, ErrNoRelease
	}
	if response.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("the releases API answered %d", response.StatusCode)
	}

	var decoded githubRelease
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
		return Release{}, err
	}
	if decoded.Draft || decoded.TagName == "" {
		return Release{}, ErrNoRelease
	}
	release := Release{Version: decoded.TagName, PageURL: decoded.HTMLURL}
	for _, asset := range decoded.Assets {
		switch asset.Name {
		case c.AssetName:
			release.AssetURL = asset.URL
		case c.ChecksumName:
			release.ChecksumURL = asset.URL
		case c.SignatureName:
			release.SignatureURL = asset.URL
		}
	}
	if release.AssetURL == "" {
		return release, ErrAssetMissing
	}
	return release, nil
}

// Newer reports whether candidate is a later version than current.
//
// Versions are compared field by field as numbers, so 0.10.0 is newer than
// 0.9.0 — which a string comparison gets wrong, and getting it wrong here means
// offering an update that goes backwards. Anything unparseable compares as
// different rather than newer: a build that is not a release ("dev") should be
// told there is a release, and never told it is behind by some amount.
func Newer(current, candidate string) bool {
	if current == candidate {
		return false
	}
	currentParts, currentOK := parseVersion(current)
	candidateParts, candidateOK := parseVersion(candidate)
	if !currentOK || !candidateOK {
		return true
	}
	for index := range currentParts {
		if candidateParts[index] != currentParts[index] {
			return candidateParts[index] > currentParts[index]
		}
	}
	return false
}

func parseVersion(value string) ([3]int, bool) {
	var parts [3]int
	fields := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
	if len(fields) != 3 {
		return parts, false
	}
	for index, field := range fields {
		number, err := strconv.Atoi(field)
		if err != nil || number < 0 {
			return parts, false
		}
		parts[index] = number
	}
	return parts, true
}

// Apply downloads the release and replaces the binary at path.
//
// The new file is written beside the old one and renamed over it, so a transfer
// that fails part way leaves the working binary exactly where it was. The
// running process goes on running the old code: replacing a file does not
// replace what is already in memory, and this says so rather than pretending
// the update took effect.
func (c Checker) Apply(ctx context.Context, release Release, path string) error {
	directory := filepath.Dir(path)
	if err := writable(directory); err != nil {
		return err
	}

	if len(c.PublicKey) != ed25519.PublicKeySize {
		return ErrUnsigned
	}
	if release.ChecksumURL == "" || release.SignatureURL == "" {
		return ErrUnsigned
	}
	sums, err := c.download(ctx, release.ChecksumURL, 1<<20)
	if err != nil {
		return err
	}
	signature, err := c.download(ctx, release.SignatureURL, 1<<20)
	if err != nil {
		return err
	}
	// The signature is checked before the binary is even fetched, so a release
	// nobody signed costs one small download and stops there.
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || !ed25519.Verify(c.PublicKey, sums, decoded) {
		return ErrBadSignature
	}

	body, err := c.download(ctx, release.AssetURL, MaxDownloadBytes)
	if err != nil {
		return err
	}
	if err := verify(body, string(sums), c.AssetName); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(directory, ".ssh-ui-update-")
	if err != nil {
		return err
	}
	staged := temporary.Name()
	defer func() { _ = os.Remove(staged) }()
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return err
	}
	return os.Rename(staged, path)
}

func writable(directory string) error {
	probe, err := os.CreateTemp(directory, ".ssh-ui-probe-")
	if err != nil {
		return ErrNotWritable
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

func (c Checker) download(ctx context.Context, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client().Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the download answered %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, limit))
}

// verify compares the download against the line naming it in the checksum file.
func verify(body []byte, sums, name string) error {
	sum := hex.EncodeToString(hashOf(body))
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		if strings.EqualFold(fields[0], sum) {
			return nil
		}
		return ErrChecksumMismatch
	}
	return ErrChecksumMismatch
}

func hashOf(body []byte) []byte {
	sum := sha256.Sum256(body)
	return sum[:]
}
