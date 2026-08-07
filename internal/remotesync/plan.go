package remotesync

import (
	"errors"
	"path/filepath"
	"sort"

	"sshc/internal/storage"
)

// ErrNothingToApply reports that the remote snapshot already matches this
// disk. It is an answer, not a failure.
var ErrNothingToApply = errors.New("this workspace already matches the snapshot")

// Conflict is one file that changed on both sides since the last sync.
//
// It carries digests and never contents: a three-way view is assembled by the
// caller from files it can read, and a conflict record that carried a private
// key's bytes would be a copy of that key in a response body.
type Conflict struct {
	Path         string
	BaseDigest   string
	LocalDigest  string
	RemoteDigest string
}

// Plan turns a decrypted snapshot and the current workspace into the exact
// transaction that would make this machine match it — or into conflicts.
//
// This is the part of the design that costs least and buys most. A pull that
// could not be expressed as one storage.Request would be a pull that escapes
// every safety property this codebase has; because it can be, it inherits all
// of them for free: the Manager.Validate hook re-parses and re-resolves, so a
// snapshot that would break the Include graph is refused before a byte lands;
// every replaced file except the keys is backed up into a generation
// directory, so a bad pull is one click of the existing History screen away
// from being undone; the journal makes an interrupted pull completable; and
// the preview the user approves is the existing per-file diff.
//
//   - base is the manifest of the snapshot this machine last synced. A nil
//     base means this machine has never synced, so nothing can be called a
//     deletion and no file is removed.
//   - local maps workspace-relative path to the digest on this disk now.
//   - remote is the manifest just fetched, and contents its files.
func Plan(root string, base *Manifest, local map[string]string, remote Manifest, contents map[string][]byte) (storage.Request, []Conflict, error) {
	baseDigests := map[string]string{}
	if base != nil {
		for _, item := range base.Files {
			baseDigests[item.Path] = item.SHA256
		}
	}
	remoteDigests := map[string]string{}
	for _, item := range remote.Files {
		remoteDigests[item.Path] = item.SHA256
	}

	request := storage.Request{Operation: "sync.pull"}
	var conflicts []Conflict

	for _, item := range remote.Files {
		localDigest, present := local[item.Path]
		if present && localDigest == item.SHA256 {
			continue
		}
		baseDigest, hadBase := baseDigests[item.Path]
		if present && hadBase && localDigest != baseDigest {
			// Changed here and changed there. There is no correct automatic
			// answer — a merge of two ssh_config files that both changed the
			// same Host block would violate the byte-preservation promise the
			// parser exists to keep — so this is reported, never guessed.
			conflicts = append(conflicts, Conflict{
				Path: item.Path, BaseDigest: baseDigest,
				LocalDigest: localDigest, RemoteDigest: item.SHA256,
			})
			continue
		}
		if present && !hadBase {
			// It exists on both sides, differs, and this machine has never
			// synced it. Nothing here knows which is newer.
			conflicts = append(conflicts, Conflict{
				Path: item.Path, LocalDigest: localDigest, RemoteDigest: item.SHA256,
			})
			continue
		}
		precondition := storage.Precondition{}
		if present {
			precondition = storage.Precondition{Exists: true, Digest: localDigest}
		}
		request.Changes = append(request.Changes, storage.Change{
			Path:         filepath.Join(root, filepath.FromSlash(item.Path)),
			Contents:     contents[item.Path],
			Precondition: precondition,
			// A private key this pull overwrites keeps a backup like anything
			// else. It used to keep none, because the copy would have been the
			// key in the clear; the backups are sealed with the master password
			// now, and a pull replacing a local key is exactly the case where
			// the previous one is what somebody wants back.
		})
	}

	// A file present locally and absent from the snapshot is either "deleted
	// on the other machine" or "created here since the last sync". The
	// last-synced manifest is the only thing that can tell them apart:
	// present in the base and absent from the remote means deleted; absent
	// from both means new here, and it is left alone.
	for path, localDigest := range local {
		if _, stillRemote := remoteDigests[path]; stillRemote {
			continue
		}
		baseDigest, hadBase := baseDigests[path]
		if !hadBase {
			continue
		}
		if localDigest != baseDigest {
			// Deleted there, edited here.
			conflicts = append(conflicts, Conflict{
				Path: path, BaseDigest: baseDigest, LocalDigest: localDigest,
			})
			continue
		}
		request.Removals = append(request.Removals, storage.Removal{
			Path:         filepath.Join(root, filepath.FromSlash(path)),
			Precondition: storage.Precondition{Exists: true, Digest: localDigest},
		})
	}

	sort.Slice(request.Changes, func(i, j int) bool { return request.Changes[i].Path < request.Changes[j].Path })
	sort.Slice(request.Removals, func(i, j int) bool { return request.Removals[i].Path < request.Removals[j].Path })
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].Path < conflicts[j].Path })

	if len(conflicts) == 0 && len(request.Changes) == 0 && len(request.Removals) == 0 {
		return storage.Request{}, nil, ErrNothingToApply
	}
	return request, conflicts, nil
}
