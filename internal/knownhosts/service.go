package knownhosts

import (
	"context"
	"crypto/subtle"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"ssh-ui/internal/storage"
)

var (
	ErrUnverifiedCandidate = errors.New("a scanned key needs a matching fingerprint or an explicit acknowledgement")
	ErrEntryChanged        = errors.New("the entry on disk is not the entry that was displayed")
	ErrNoSuchEntry         = errors.New("no such known_hosts entry")
	ErrUnsupportedKeyType  = errors.New("unsupported host key type")
)

// supportedKeyTypes is the set this application will write into known_hosts.
// Anything else is refused rather than copied through unchecked.
var supportedKeyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"rsa-sha2-256":                       true,
	"rsa-sha2-512":                       true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,3}$`)

// Target identifies one entry to remove. Digest is the hash of the exact line
// the user saw, so a file edited in the meantime cannot lose the wrong line.
type Target struct {
	Line   int
	Digest string
}

// Listing is the searchable view of the file.
type Listing struct {
	Path  string
	Lines []Line
}

// Service reads and edits known_hosts through the transaction manager.
type Service struct {
	Workspace *storage.Workspace
	Manager   *storage.Manager
	Scanner   Scanner
}

// NewService wires the production dependencies together.
func NewService(workspace *storage.Workspace, manager *storage.Manager, scanner Scanner) *Service {
	return &Service{Workspace: workspace, Manager: manager, Scanner: scanner}
}

// Path is the known_hosts file this service manages.
func (s *Service) Path() string { return filepath.Join(s.Workspace.Root(), "known_hosts") }

func (s *Service) read() ([]byte, error) {
	contents, err := s.Workspace.FileSystem().ReadFile(s.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return contents, err
}

// Listing returns the entries matching query.
func (s *Service) Listing(query string) (Listing, error) {
	contents, err := s.read()
	if err != nil {
		return Listing{}, err
	}
	return Listing{Path: s.Path(), Lines: Search(ParseFile(contents), query)}, nil
}

// Evidence is a digest of the current file. An action token for a known_hosts
// change is bound to it, so an external edit invalidates the confirmation.
func (s *Service) Evidence() (string, error) {
	contents, err := s.read()
	if err != nil {
		return "", err
	}
	return storage.Digest(contents), nil
}

// Scan asks ssh-keyscan for the keys of one host. The candidates it returns are
// never trusted by this call; Add decides that separately.
func (s *Service) Scan(ctx context.Context, host string, port int) ([]Candidate, error) {
	return s.Scanner.Scan(ctx, host, port)
}

// Delete removes the requested lines and leaves every other byte untouched.
//
// Each target carries the digest of the line the user was shown. A line that no
// longer hashes to it is refused, so a file edited between the confirmation and
// the request cannot lose a line nobody agreed to remove.
func (s *Service) Delete(targets []Target) (storage.Result, error) {
	contents, err := s.read()
	if err != nil {
		return storage.Result{}, err
	}
	file := ParseFile(contents)

	removing := make(map[int]bool, len(targets))
	for _, target := range targets {
		found := false
		for _, line := range file.Lines {
			if line.Number != target.Line {
				continue
			}
			found = true
			if storage.Digest([]byte(line.Raw)) != target.Digest {
				return storage.Result{}, ErrEntryChanged
			}
			removing[line.Number] = true
		}
		if !found {
			return storage.Result{}, ErrNoSuchEntry
		}
	}

	remaining := &File{}
	for _, line := range file.Lines {
		if removing[line.Number] {
			continue
		}
		remaining.Lines = append(remaining.Lines, line)
	}
	return s.commit("known_hosts.delete", contents, remaining.Render())
}

// Add appends one scanned key after the user proved it is the key they meant.
//
// Either expectedFingerprint matches the key's real fingerprint, or the user
// acknowledged explicitly that the key is unverified. The line is rebuilt from
// validated parts rather than trusting the text a client sent.
func (s *Service) Add(candidate Candidate, expectedFingerprint string, acknowledged bool) (storage.Result, error) {
	if !supportedKeyTypes[candidate.KeyType] {
		return storage.Result{}, ErrUnsupportedKeyType
	}
	if !base64Pattern.MatchString(candidate.Key) {
		return storage.Result{}, ErrInvalidKey
	}
	fingerprint, err := Fingerprint(candidate.Key)
	if err != nil {
		return storage.Result{}, err
	}
	switch {
	case expectedFingerprint != "":
		if subtle.ConstantTimeCompare([]byte(expectedFingerprint), []byte(fingerprint)) != 1 {
			return storage.Result{}, ErrUnverifiedCandidate
		}
	case !acknowledged:
		return storage.Result{}, ErrUnverifiedCandidate
	}

	hostField := candidate.Host
	if candidate.Port != 22 {
		hostField = "[" + candidate.Host + "]:" + strconv.Itoa(candidate.Port)
	}
	newLine := hostField + " " + candidate.KeyType + " " + candidate.Key

	contents, err := s.read()
	if err != nil {
		return storage.Result{}, err
	}
	file := ParseFile(contents)
	for _, line := range file.Lines {
		if strings.TrimSpace(line.Raw) == newLine {
			// Exact duplicate: nothing to write.
			return storage.Result{}, nil
		}
	}

	updated := string(contents)
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += newLine + "\n"
	return s.commit("known_hosts.add", contents, []byte(updated))
}

func (s *Service) commit(operation string, previous, updated []byte) (storage.Result, error) {
	if err := s.Workspace.EnsureDirectory(s.Workspace.Root()); err != nil {
		return storage.Result{}, err
	}
	return s.Manager.Commit(storage.Request{
		Operation: operation,
		Changes: []storage.Change{{
			Path:         s.Path(),
			Contents:     updated,
			Precondition: storage.Precondition{Exists: previous != nil, Digest: storage.Digest(previous)},
		}},
	})
}
