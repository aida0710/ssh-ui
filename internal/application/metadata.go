package application

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"ssh-ui/internal/storage"
)

const (
	// MetadataSchemaVersion is the only version this build writes. A file
	// carrying a higher version is refused rather than silently downgraded.
	//
	// Version 2 dropped group membership. A group is a directory under
	// ~/.ssh/connections and the entry file's generated region declares which
	// groups exist, so neither hosts[].group nor groups[].parent has anything
	// left to say. A version 1 document decodes and simply loses those two
	// fields: json.Unmarshal ignores what the struct no longer has.
	MetadataSchemaVersion = 2
	// MetadataFileName lives in the workspace state directory, never in the
	// configuration tree, so it can never be read as SSH configuration.
	MetadataFileName = "metadata.json"
	// DefaultGroupsFile is the configuration file group inheritance compiles
	// into. It stays inside the configuration tree so it is ordinary, hand
	// editable OpenSSH configuration.
	DefaultGroupsFile = "groups.ssh-ui.conf"
)

var (
	ErrMetadataVersion = errors.New("metadata schema version is newer than this build supports")
	ErrMetadataSecret  = errors.New("metadata may not contain key material")
	ErrMetadataPath    = errors.New("metadata host path must be relative to the ssh directory")
	ErrMetadataGroup   = errors.New("metadata group definition is invalid")
)

// secretMarkers are substrings that indicate someone tried to store key
// material in a field meant for organisation. Metadata has no field for a key,
// so any occurrence is a mistake worth refusing loudly.
var secretMarkers = []string{"-----BEGIN", "PRIVATE KEY", "ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-"}

// HostIdentity is the UI identity of a host: the normalised configuration file
// path plus the concrete primary Host alias declared in it.
type HostIdentity struct {
	Path  string `json:"path"`
	Alias string `json:"alias"`
}

// NewHostIdentity normalises an absolute configuration path into an identity.
func NewHostIdentity(root, absolute, alias string) (HostIdentity, error) {
	relative, err := RelativePath(root, absolute)
	if err != nil {
		return HostIdentity{}, err
	}
	if alias == "" {
		return HostIdentity{}, ErrMetadataPath
	}
	return HostIdentity{Path: relative, Alias: alias}, nil
}

func (identity HostIdentity) IsZero() bool { return identity.Path == "" || identity.Alias == "" }

// Setting is one directive a group contributes to its members.
type Setting struct {
	Keyword string   `json:"keyword"`
	Values  []string `json:"values"`
}

// HostMetadata is the UI-only information attached to one host.
//
// It carries only what has no representation in the configuration itself.
// Group membership is the directory the file sits in, and a note is a comment
// above the Host line, so neither is here.
type HostMetadata struct {
	Identity  HostIdentity `json:"identity"`
	Tags      []string     `json:"tags,omitempty"`
	Colour    string       `json:"colour,omitempty"`
	Note      string       `json:"note,omitempty"`
	Favourite bool         `json:"favourite,omitempty"`
	Order     int          `json:"order,omitempty"`
	Orphan    bool         `json:"orphan,omitempty"`
}

func (host HostMetadata) Alias() string { return host.Identity.Alias }

// GroupMetadata is the presentation attached to one group name. The group
// itself is a directory and its hierarchy is its name; this is what a directory
// cannot carry. Settings are compiled into an ordinary Host block.
type GroupMetadata struct {
	Name     string    `json:"name"`
	Colour   string    `json:"colour,omitempty"`
	Note     string    `json:"note,omitempty"`
	Order    int       `json:"order,omitempty"`
	Settings []Setting `json:"settings,omitempty"`
}

// Metadata is the whole of ~/.ssh/ssh-ui/metadata.json.
type Metadata struct {
	SchemaVersion int             `json:"schemaVersion"`
	GroupsFile    string          `json:"groupsFile,omitempty"`
	Groups        []GroupMetadata `json:"groups,omitempty"`
	Hosts         []HostMetadata  `json:"hosts,omitempty"`
}

func NewMetadata() Metadata {
	return Metadata{SchemaVersion: MetadataSchemaVersion, GroupsFile: DefaultGroupsFile}
}

// GroupsPath returns the configured groups file, falling back to the default.
func (metadata Metadata) GroupsPath() string {
	if metadata.GroupsFile == "" {
		return DefaultGroupsFile
	}
	return metadata.GroupsFile
}

// DecodeMetadata parses metadata.json. Absent or empty contents produce a fresh
// document; a newer schema version is refused instead of being rewritten.
func DecodeMetadata(contents []byte) (Metadata, error) {
	if len(strings.TrimSpace(string(contents))) == 0 {
		return NewMetadata(), nil
	}
	var metadata Metadata
	if err := json.Unmarshal(contents, &metadata); err != nil {
		return Metadata{}, err
	}
	if metadata.SchemaVersion > MetadataSchemaVersion {
		return Metadata{}, ErrMetadataVersion
	}
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = MetadataSchemaVersion
	}
	if metadata.GroupsFile == "" {
		metadata.GroupsFile = DefaultGroupsFile
	}
	return metadata, nil
}

// EncodeMetadata validates and serialises metadata deterministically.
func EncodeMetadata(metadata Metadata) ([]byte, error) {
	metadata.SchemaVersion = MetadataSchemaVersion
	if metadata.GroupsFile == "" {
		metadata.GroupsFile = DefaultGroupsFile
	}
	if err := ValidateMetadata(metadata); err != nil {
		return nil, err
	}
	sorted := metadata
	sorted.Groups = append([]GroupMetadata(nil), metadata.Groups...)
	sorted.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	sort.SliceStable(sorted.Groups, func(first, second int) bool {
		return sorted.Groups[first].Name < sorted.Groups[second].Name
	})
	sort.SliceStable(sorted.Hosts, func(first, second int) bool {
		if sorted.Hosts[first].Identity.Path != sorted.Hosts[second].Identity.Path {
			return sorted.Hosts[first].Identity.Path < sorted.Hosts[second].Identity.Path
		}
		return sorted.Hosts[first].Identity.Alias < sorted.Hosts[second].Identity.Alias
	})
	encoded, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ValidateMetadata refuses documents that break the design's invariants.
func ValidateMetadata(metadata Metadata) error {
	if _, err := checkRelative(metadata.GroupsPath()); err != nil {
		return err
	}
	names := make(map[string]bool, len(metadata.Groups))
	for _, group := range metadata.Groups {
		// The name is a directory path, so it has to be one this application
		// would be willing to create. Refusing here keeps a hand-edited
		// metadata file from naming "../escape" and having it believed.
		if names[strings.ToLower(group.Name)] || ValidateGroupName(group.Name) != nil {
			return ErrMetadataGroup
		}
		// Case-insensitively, because two groups whose names differ only in
		// case are one directory on a default macOS volume.
		names[strings.ToLower(group.Name)] = true
		for _, setting := range group.Settings {
			if containsSecretMarker(setting.Keyword) {
				return ErrMetadataSecret
			}
			for _, value := range setting.Values {
				if containsSecretMarker(value) {
					return ErrMetadataSecret
				}
			}
		}
	}
	for _, host := range metadata.Hosts {
		if _, err := checkRelative(host.Identity.Path); err != nil {
			return err
		}
		if host.Identity.Alias == "" {
			return ErrMetadataPath
		}
		for _, text := range append([]string{host.Note, host.Colour}, host.Tags...) {
			if containsSecretMarker(text) {
				return ErrMetadataSecret
			}
		}
	}
	return nil
}

func checkRelative(candidate string) (string, error) {
	if candidate == "" || strings.HasPrefix(candidate, "/") {
		return "", ErrMetadataPath
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(candidate)))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", ErrMetadataPath
	}
	return cleaned, nil
}

func containsSecretMarker(text string) bool {
	for _, marker := range secretMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// MetadataStore reads and stages metadata.json inside the workspace state
// directory. It never writes directly: a change is committed by the same
// storage transaction that writes the configuration files it describes.
type MetadataStore struct {
	workspace *storage.Workspace
}

func NewMetadataStore(workspace *storage.Workspace) *MetadataStore {
	return &MetadataStore{workspace: workspace}
}

func (store *MetadataStore) Path() string {
	return filepath.Join(store.workspace.StateDir(), MetadataFileName)
}

// EnsureDirectory creates the state directory so a first metadata write can
// resolve its parent.
func (store *MetadataStore) EnsureDirectory() error {
	return store.workspace.EnsureDirectory(store.workspace.StateDir())
}

// Load reads the current document and the precondition a later commit needs.
func (store *MetadataStore) Load() (Metadata, storage.Precondition, error) {
	contents, err := store.workspace.FileSystem().ReadFile(store.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return NewMetadata(), storage.Precondition{}, nil
	}
	if err != nil {
		return Metadata{}, storage.Precondition{}, err
	}
	metadata, err := DecodeMetadata(contents)
	if err != nil {
		return Metadata{}, storage.Precondition{}, err
	}
	return metadata, storage.Precondition{Exists: true, Digest: storage.Digest(contents)}, nil
}

// Change turns metadata into one file change for a storage transaction.
func (store *MetadataStore) Change(metadata Metadata, precondition storage.Precondition) (storage.Change, error) {
	contents, err := EncodeMetadata(metadata)
	if err != nil {
		return storage.Change{}, err
	}
	return storage.Change{Path: store.Path(), Contents: contents, Precondition: precondition}, nil
}

// ReconcileMetadata marks entries whose host disappeared. It never re-points an
// entry at a different host: a vanished target becomes an orphan the user must
// re-associate deliberately.
func ReconcileMetadata(metadata Metadata, present []HostIdentity) (Metadata, []Notice) {
	known := make(map[HostIdentity]bool, len(present))
	for _, identity := range present {
		known[identity] = true
	}
	reconciled := metadata
	reconciled.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	var notices []Notice
	for index := range reconciled.Hosts {
		host := &reconciled.Hosts[index]
		host.Orphan = !known[host.Identity]
		if !host.Orphan {
			continue
		}
		notices = appendNotice(notices, Notice{
			Code:   NoticeOrphanMetadata,
			Path:   host.Identity.Path,
			Detail: host.Identity.Alias,
		})
	}
	return reconciled, notices
}

// ClearHostNote removes the note from one host's entry and leaves every other
// field and every other entry untouched.
//
// A note and a comment are the same thing written in two places, so saving a
// comment retires the note for that host in the same transaction. Doing it per
// host, as the user edits, converges without a migration that rewrites every
// file at once. An entry left with nothing but its identity is dropped, because
// an entry that says nothing is not worth keeping.
func ClearHostNote(metadata Metadata, identity HostIdentity) Metadata {
	cleared := metadata
	cleared.Hosts = make([]HostMetadata, 0, len(metadata.Hosts))
	for _, host := range metadata.Hosts {
		if host.Identity != identity {
			cleared.Hosts = append(cleared.Hosts, host)
			continue
		}
		host.Note = ""
		if len(host.Tags) == 0 && host.Colour == "" && !host.Favourite && host.Order == 0 {
			continue
		}
		cleared.Hosts = append(cleared.Hosts, host)
	}
	return cleared
}

// RenameHostIdentity moves the entry for one host and leaves every other entry
// untouched. The caller commits the result in the same transaction as the
// configuration change that performed the rename.
// RelocateHostIdentities rewrites the path of every entry declared in one file,
// keeping each alias. It is the file-level counterpart of RenameHostIdentity,
// which moves exactly one identity.
//
// Only an exact path match is rewritten. A prefix match would make renaming
// "work" eat "workshop"; a caller moving a directory passes each file.
func RelocateHostIdentities(metadata Metadata, fromPath, toPath string) Metadata {
	relocated := metadata
	relocated.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	for index := range relocated.Hosts {
		if relocated.Hosts[index].Identity.Path != fromPath {
			continue
		}
		relocated.Hosts[index].Identity.Path = toPath
		relocated.Hosts[index].Orphan = false
	}
	return relocated
}

func RenameHostIdentity(metadata Metadata, from, to HostIdentity) Metadata {
	renamed := metadata
	renamed.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	for index := range renamed.Hosts {
		if renamed.Hosts[index].Identity != from {
			continue
		}
		renamed.Hosts[index].Identity = to
		renamed.Hosts[index].Orphan = false
	}
	return renamed
}
