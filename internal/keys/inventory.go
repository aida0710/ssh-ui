package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"ssh-ui/internal/config"
	"ssh-ui/internal/storage"
)

// Kind classifies a file under ~/.ssh by what it contains, never by its name.
type Kind string

const (
	KindPrivateKey  Kind = "private_key"
	KindPublicKey   Kind = "public_key"
	KindCertificate Kind = "certificate"
	KindKnownHosts  Kind = "known_hosts"
	KindConfig      Kind = "config"
	KindOther       Kind = "other"
)

// Note codes are stable identifiers the UI maps to its own wording.
const (
	NoteSymbolicLink           = "symbolic_link"
	NoteFingerprintUnavailable = "fingerprint_unavailable"
	NoteEmptyFile              = "empty_file"
	NoteNotRegularFile         = "not_regular_file"
	NoteCommentNotPreserved    = "comment_not_preserved"
)

// Unreadable reason codes.
const (
	ReasonFileTooLarge  = "file_too_large"
	ReasonReadFailed    = "read_failed"
	ReasonDepthExceeded = "depth_exceeded"
	ReasonTooManyFiles  = "too_many_files"
)

const (
	// StateDirectoryName is the engine's own directory inside the workspace.
	// Everything below it — backups, trash, journal and history — is engine
	// state, so it never appears in the inventory, is never registered with an
	// agent and is never suggested as an IdentityFile.
	StateDirectoryName = "ssh-ui"

	maxScanDepth   = 8
	maxScanEntries = 4096
)

// CertificateInfo carries the parts of an OpenSSH certificate a user needs to
// decide whether it is still useful.
type CertificateInfo struct {
	KeyID                string
	Principals           []string
	ValidBefore          uint64
	SignedKeyType        string
	SignedKeyFingerprint string
}

// Item is one classified file inside the workspace.
type Item struct {
	ID             string
	RelativePath   string
	Kind           Kind
	Container      string
	Algorithm      Algorithm
	KeyType        string
	Bits           int
	Encrypted      bool
	Fingerprint    string
	Comment        string
	Permission     string
	PermissionRisk bool
	SizeBytes      int64
	Certificate    *CertificateInfo
	References     []Reference
	Notes          []string
}

// UnreadableFile is a file the scanner deliberately refused to interpret.
type UnreadableFile struct {
	RelativePath string
	Reason       string
}

// Inventory is the classified content of the workspace.
type Inventory struct {
	Items                []Item
	Unreadable           []UnreadableFile
	AgentDelegations     []Reference
	UnresolvedReferences []UnresolvedReference
}

// Find returns the item with the given identifier.
func (inventory *Inventory) Find(id string) (*Item, bool) {
	for index := range inventory.Items {
		if inventory.Items[index].ID == id {
			return &inventory.Items[index], true
		}
	}
	return nil, false
}

// Group returns the item together with the public key and certificate files
// that belong to the same key pair.
//
// Membership is decided by fingerprint alone. A file that merely shares a base
// name is never grouped, so a look-alike is never moved to the trash with a key
// it does not belong to. When the fingerprint of an encrypted private key is
// unavailable, the group is the item by itself.
func (inventory *Inventory) Group(item *Item) []Item {
	group := []Item{*item}
	if item.Kind != KindPrivateKey || item.Fingerprint == "" {
		return group
	}
	for _, candidate := range inventory.Items {
		if candidate.ID == item.ID {
			continue
		}
		switch candidate.Kind {
		case KindPublicKey:
			if candidate.Fingerprint == item.Fingerprint {
				group = append(group, candidate)
			}
		case KindCertificate:
			if candidate.Certificate != nil && candidate.Certificate.SignedKeyFingerprint == item.Fingerprint {
				group = append(group, candidate)
			}
		}
	}
	return group
}

// ItemID is the stable, path-free identifier the HTTP API uses for one file.
// It is derived from the workspace-relative path, so it survives a restart, it
// carries no path into a URL, and it cannot address a file that the current
// inventory does not contain.
func ItemID(relativePath string) string {
	sum := sha256.Sum256([]byte(relativePath))
	return hex.EncodeToString(sum[:16])
}

// Scanner walks the workspace through the storage filesystem seam.
type Scanner struct {
	workspace *storage.Workspace
}

func NewScanner(workspace *storage.Workspace) *Scanner {
	return &Scanner{workspace: workspace}
}

// Scan classifies every regular file below the workspace root except the
// engine's own state directory.
func (scanner *Scanner) Scan() (*Inventory, error) {
	inventory := &Inventory{}
	visited := 0
	if err := scanner.walk(inventory, scanner.workspace.Root(), 0, &visited); err != nil {
		return nil, err
	}
	sort.Slice(inventory.Items, func(first, second int) bool {
		return inventory.Items[first].RelativePath < inventory.Items[second].RelativePath
	})
	sort.Slice(inventory.Unreadable, func(first, second int) bool {
		return inventory.Unreadable[first].RelativePath < inventory.Unreadable[second].RelativePath
	})
	return inventory, nil
}

func (scanner *Scanner) walk(inventory *Inventory, directory string, depth int, visited *int) error {
	fileSystem := scanner.workspace.FileSystem()
	entries, err := fileSystem.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		absolute := filepath.Join(directory, entry.Name())
		if absolute == scanner.workspace.StateDir() {
			continue
		}
		relative := scanner.relativePath(absolute)
		if *visited >= maxScanEntries {
			inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonTooManyFiles})
			return nil
		}
		*visited++

		info, statErr := fileSystem.Lstat(absolute)
		if statErr != nil {
			inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonReadFailed})
			continue
		}
		mode := info.Mode()
		switch {
		case mode&fs.ModeSymlink != 0:
			inventory.Items = append(inventory.Items, Item{
				ID:           ItemID(relative),
				RelativePath: relative,
				Kind:         KindOther,
				Permission:   fmt.Sprintf("%04o", mode.Perm()),
				Notes:        []string{NoteSymbolicLink},
			})
		case mode.IsDir():
			if depth+1 > maxScanDepth {
				inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonDepthExceeded})
				continue
			}
			if err := scanner.walk(inventory, absolute, depth+1, visited); err != nil {
				return err
			}
		case mode.IsRegular():
			inventory.Items = append(inventory.Items, scanner.classifyFile(inventory, absolute, relative, info))
		default:
			inventory.Items = append(inventory.Items, Item{
				ID:           ItemID(relative),
				RelativePath: relative,
				Kind:         KindOther,
				Permission:   fmt.Sprintf("%04o", mode.Perm()),
				Notes:        []string{NoteNotRegularFile},
			})
		}
	}
	return nil
}

func (scanner *Scanner) relativePath(absolute string) string {
	relative, err := filepath.Rel(scanner.workspace.Root(), absolute)
	if err != nil {
		return absolute
	}
	return relative
}

func (scanner *Scanner) classifyFile(inventory *Inventory, absolute, relative string, info fs.FileInfo) Item {
	item := Item{
		ID:           ItemID(relative),
		RelativePath: relative,
		Kind:         KindOther,
		Permission:   fmt.Sprintf("%04o", info.Mode().Perm()),
		SizeBytes:    info.Size(),
	}
	contents, err := scanner.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		reason := ReasonReadFailed
		if errors.Is(err, storage.ErrFileTooLarge) {
			reason = ReasonFileTooLarge
		}
		inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: reason})
		return item
	}
	classify(&item, contents)
	if item.Kind == KindPrivateKey && info.Mode().Perm()&0o077 != 0 {
		item.PermissionRisk = true
	}
	return item
}

// classify decides what a file is from its bytes. The order matters: a private
// key is recognised first, then an authorized-keys line, then a known_hosts
// line, then configuration syntax. A known_hosts line would otherwise be
// mistaken for a public key with options.
func classify(item *Item, contents []byte) {
	if len(contents) == 0 {
		item.Notes = append(item.Notes, NoteEmptyFile)
		return
	}
	if material, err := InspectPrivateKey(contents); err == nil {
		item.Kind = KindPrivateKey
		item.Container = material.Container
		item.Encrypted = material.Encrypted
		item.Algorithm = material.Algorithm
		item.KeyType = material.KeyType
		item.Bits = material.Bits
		item.Fingerprint = material.Fingerprint
		if item.Fingerprint == "" {
			item.Notes = append(item.Notes, NoteFingerprintUnavailable)
		}
		return
	}

	line := firstMeaningfulLine(contents)
	if len(line) == 0 {
		return
	}
	fields := strings.Fields(string(line))
	if len(fields) >= 2 && looksLikeKeyType(fields[0]) {
		if info, err := InspectPublicKey(line); err == nil {
			item.Kind = KindPublicKey
			item.Algorithm = info.Algorithm
			item.KeyType = info.KeyType
			item.Bits = info.Bits
			item.Fingerprint = info.Fingerprint
			item.Comment = info.Comment
			if info.IsCertificate {
				item.Kind = KindCertificate
				item.Certificate = &CertificateInfo{
					KeyID:                info.CertificateKeyID,
					Principals:           info.CertificatePrincipals,
					ValidBefore:          info.CertificateValidBefore,
					SignedKeyType:        info.SignedKeyType,
					SignedKeyFingerprint: info.SignedKeyFingerprint,
				}
			}
			return
		}
	}
	if _, _, _, _, _, err := ssh.ParseKnownHosts(line); err == nil {
		item.Kind = KindKnownHosts
		return
	}
	if looksLikeConfiguration(contents) {
		item.Kind = KindConfig
	}
}

func firstMeaningfulLine(contents []byte) []byte {
	for _, raw := range strings.Split(string(contents), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return []byte(trimmed + "\n")
	}
	return nil
}

func looksLikeKeyType(field string) bool {
	prefixes := []string{"ssh-", "ecdsa-sha2-", "rsa-sha2-", "sk-ssh-", "sk-ecdsa-"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return false
}

var configurationKeywords = []string{
	"Host", "Match", "Include", "HostName", "IdentityFile", "ProxyJump", "User", "Port",
}

func looksLikeConfiguration(contents []byte) bool {
	for _, line := range config.Parse(contents).Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		for _, keyword := range configurationKeywords {
			if config.EqualKeyword(line.Keyword, keyword) {
				return true
			}
		}
	}
	return false
}
