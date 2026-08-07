// Package selfupdate looks at the project's GitHub releases and says whether
// there is a newer one.
//
// It looks, and that is all it does. It used to fetch the release and replace
// the binary it was running as, guarded by a signature over the checksum file
// with the public key compiled in — and that guard was worth very little,
// because the key had to live somewhere the release workflow could read it,
// which is somewhere anybody who controls the repository can read it. The
// defence and the attack had the same key.
//
// What is left is the useful half without the dangerous one: this says a newer
// version exists and where to read about it, and a person decides what to do.
// It is the only thing in this application that contacts a host other than
// itself, it is asked rather than scheduled, and it downloads nothing.
package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ErrNoRelease reports that the project has published none yet.
var ErrNoRelease = errors.New("no release has been published")

// Release is what the project published.
type Release struct {
	Version string
	// PageURL is where a person reads what changed and decides what to do,
	// which is the whole of what this offers.
	PageURL string
}

// Checker asks GitHub what the latest release is.
type Checker struct {
	// API is the releases endpoint, injected so no test reaches GitHub.
	API  string
	HTTP *http.Client
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Draft   bool   `json:"draft"`
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
	return Release{Version: decoded.TagName, PageURL: decoded.HTMLURL}, nil
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
