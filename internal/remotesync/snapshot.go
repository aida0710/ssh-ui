// Package remotesync carries a whole workspace to an object store and back.
//
// The package is named remotesync rather than sync because the standard
// library already owns that name, and a file here that needs a mutex should
// not have to alias one of the two.
//
// One object, one snapshot, one atomic PUT. A file per object would give
// per-file conflict detection for free and would be wrong, because a
// configuration is only meaningful as a set: ~/.ssh/config says
// "Include connections/work/*.conf", metadata.json names groups that must have
// directories, IdentityFile lines name key files. Uploading files
// independently leaves a window in which the remote holds a state that never
// existed on any machine — an Include reaching a file that is not there yet —
// and a machine pulling in that window gets a configuration that is not merely
// stale but incoherent.
package remotesync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// ManifestName is the first entry of every snapshot.
const ManifestName = "manifest.json"

// SchemaVersion is the version of the manifest document.
const SchemaVersion = 1

// MaxSnapshotBytes bounds what Read will decompress. A snapshot is a ~/.ssh;
// anything approaching this is a decompression bomb rather than a workspace.
const MaxSnapshotBytes = 64 << 20

// MaxEntries bounds how many files one snapshot may carry.
const MaxEntries = 4096

var (
	// ErrNotASnapshot reports bytes that are not a snapshot at all.
	ErrNotASnapshot = errors.New("these bytes are not an ssh-ui snapshot")
	// ErrUnsupportedVersion reports a snapshot from a newer build.
	ErrUnsupportedVersion = errors.New("this snapshot was written by a newer version of ssh-ui")
	// ErrUnsafePath reports an entry whose path would escape the workspace. A
	// snapshot is untrusted input and "../" in a tar is the oldest trick there
	// is.
	ErrUnsafePath = errors.New("a snapshot entry names a path outside the workspace")
	// ErrUnsafeMode reports an entry whose permission bits are not ones this
	// application writes. A snapshot must not be able to widen a private key.
	ErrUnsafeMode = errors.New("a snapshot entry has permissions this application does not write")
	// ErrSnapshotTooLarge reports a snapshot beyond the ceiling.
	ErrSnapshotTooLarge = errors.New("the snapshot is larger than this application will read")
	// ErrManifestMismatch reports a file whose digest does not match the
	// manifest, or a file the manifest does not list.
	ErrManifestMismatch = errors.New("the snapshot's files do not match its manifest")
)

// Entry describes one file in the snapshot.
type Entry struct {
	// Path is workspace-relative and forward-slashed, the vocabulary
	// storage.Workspace already uses.
	Path string `json:"path"`
	// SHA256 is the hex digest of the contents, so a pull can tell which files
	// differ without unpacking every one of them twice.
	SHA256 string `json:"sha256"`
	// Mode travels because a private key with the wrong bits is a private key
	// OpenSSH refuses. Only 0600 and 0700 are accepted.
	Mode string `json:"mode"`
	// Secret marks a private key, so a pull applies it with SkipBackup set.
	// That field exists in the storage layer for exactly this reason: the
	// design refuses to leave a second copy of key material in
	// ~/.ssh/ssh-ui/backups/, and a pull that ignored it would defeat that
	// decision from a new direction.
	Secret bool `json:"secret,omitempty"`
}

// Manifest is the snapshot's index.
type Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	CreatedAt     string `json:"createdAt"`
	// Origin identifies the installation that wrote this, so the interface can
	// say "this came from a different machine". It is an opaque id and never a
	// hostname: a hostname in an object anyone with the bucket can read is an
	// unnecessary disclosure.
	Origin string  `json:"origin"`
	Files  []Entry `json:"files"`
}

// Build packs the given files into a compressed archive.
//
// contents is keyed by workspace-relative path. The caller decides what
// belongs — this package refuses to guess, because "which files are part of
// the configuration" is a question the Include graph answers and this package
// cannot see it.
func Build(manifest Manifest, contents map[string][]byte) ([]byte, error) {
	manifest.SchemaVersion = SchemaVersion
	if len(manifest.Files) > MaxEntries {
		return nil, ErrSnapshotTooLarge
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	for _, entry := range manifest.Files {
		if err := checkPath(entry.Path); err != nil {
			return nil, err
		}
		if err := checkMode(entry.Mode); err != nil {
			return nil, err
		}
		if _, ok := contents[entry.Path]; !ok {
			return nil, ErrManifestMismatch
		}
	}

	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(zip)

	document, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if err := writeEntry(archive, ManifestName, document, 0o600); err != nil {
		return nil, err
	}
	for _, entry := range manifest.Files {
		if err := writeEntry(archive, entry.Path, contents[entry.Path], modeBits(entry.Mode)); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	if err := zip.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

// Read unpacks an archive and returns its manifest and contents.
//
// It treats every byte as hostile: the archive arrives from a bucket, and
// anyone who can write that bucket can choose what is in it.
func Read(archive []byte) (Manifest, map[string][]byte, error) {
	zip, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return Manifest{}, nil, ErrNotASnapshot
	}
	defer func() { _ = zip.Close() }()

	reader := tar.NewReader(io.LimitReader(zip, MaxSnapshotBytes+1))
	var manifest Manifest
	seenManifest := false
	contents := map[string][]byte{}
	total := 0

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, nil, ErrNotASnapshot
		}
		if header.Typeflag != tar.TypeReg {
			// A directory, a symlink or a device in this archive has no
			// meaning here and is not something to interpret charitably.
			return Manifest{}, nil, ErrUnsafePath
		}
		if len(contents) > MaxEntries {
			return Manifest{}, nil, ErrSnapshotTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(reader, MaxSnapshotBytes+1))
		if err != nil {
			return Manifest{}, nil, ErrNotASnapshot
		}
		total += len(body)
		if total > MaxSnapshotBytes {
			return Manifest{}, nil, ErrSnapshotTooLarge
		}

		if header.Name == ManifestName {
			if err := json.Unmarshal(body, &manifest); err != nil {
				return Manifest{}, nil, ErrNotASnapshot
			}
			seenManifest = true
			continue
		}
		if err := checkPath(header.Name); err != nil {
			return Manifest{}, nil, err
		}
		contents[header.Name] = body
	}

	if !seenManifest {
		return Manifest{}, nil, ErrNotASnapshot
	}
	if manifest.SchemaVersion > SchemaVersion {
		return Manifest{}, nil, ErrUnsupportedVersion
	}
	if len(manifest.Files) != len(contents) {
		return Manifest{}, nil, ErrManifestMismatch
	}
	for _, entry := range manifest.Files {
		if err := checkPath(entry.Path); err != nil {
			return Manifest{}, nil, err
		}
		if err := checkMode(entry.Mode); err != nil {
			return Manifest{}, nil, err
		}
		body, ok := contents[entry.Path]
		if !ok {
			return Manifest{}, nil, ErrManifestMismatch
		}
		if Digest(body) != entry.SHA256 {
			return Manifest{}, nil, ErrManifestMismatch
		}
	}
	return manifest, contents, nil
}

// checkPath refuses anything that is not a plain relative path inside the
// workspace. It is deliberately stricter than filepath.Clean: a path that
// needs cleaning is a path somebody constructed, and this is not the place to
// be charitable about it.
func checkPath(name string) error {
	if name == "" || name == "." {
		return ErrUnsafePath
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return ErrUnsafePath
	}
	if name != path.Clean(name) {
		return ErrUnsafePath
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrUnsafePath
		}
	}
	return nil
}

// checkMode accepts only the two permission sets this application writes.
// Anything else is refused rather than normalised, so a snapshot cannot widen
// a private key to something OpenSSH would still read but others could too.
func checkMode(mode string) error {
	if mode != "0600" && mode != "0700" {
		return ErrUnsafeMode
	}
	return nil
}

func modeBits(mode string) fs.FileMode {
	if mode == "0700" {
		return 0o700
	}
	return 0o600
}

func writeEntry(archive *tar.Writer, name string, body []byte, mode fs.FileMode) error {
	if err := archive.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     int64(mode),
		Size:     int64(len(body)),
		// No modification time, no owner, no group. A snapshot that carried
		// them would differ between machines for no reason and would disclose
		// a little about the machine that wrote it.
	}); err != nil {
		return err
	}
	_, err := archive.Write(body)
	return err
}
