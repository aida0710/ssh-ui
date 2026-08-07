package keys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTrashService(t *testing.T) (*Service, string) {
	t.Helper()
	service, workspace := newTestService(t, newQueryRunner())
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	return service, workspace.Root()
}

func TestTrashMovesTheWholeKeyPairAndKeepsItsPermissions(t *testing.T) {
	service, root := newTrashService(t)
	if err := os.Chmod(filepath.Join(root, "id_work"), 0o400); err != nil {
		t.Fatalf("tighten permissions: %v", err)
	}

	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("files = %#v, want the private and public key", result.Files)
	}
	for _, name := range []string{"id_work", "id_work.pub"} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s is still in the workspace: %v", name, statErr)
		}
	}

	entryDirectory := filepath.Join(root, StateDirectoryName, "trash", result.EntryID)
	directoryInfo, err := os.Lstat(entryDirectory)
	if err != nil {
		t.Fatalf("trash entry missing: %v", err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Errorf("trash directory permission = %04o, want 0700", directoryInfo.Mode().Perm())
	}
	keyInfo, err := os.Lstat(filepath.Join(entryDirectory, "id_work"))
	if err != nil {
		t.Fatalf("trashed key missing: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o400 {
		t.Errorf("trashed key permission = %04o, want the original 0400", keyInfo.Mode().Perm())
	}

	backups := filepath.Join(root, StateDirectoryName, "backups")
	if err := filepath.WalkDir(backups, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(contents), "OPENSSH PRIVATE KEY") {
			t.Fatalf("key material was copied into the backup directory: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk backups: %v", err)
	}

	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 1 || entries[0].ID != result.EntryID {
		t.Fatalf("entries = %#v", entries)
	}
	if !entries[0].Restorable || len(entries[0].Blockers) != 0 {
		t.Fatalf("entry = %#v, want a restorable entry", entries[0])
	}
	if entries[0].Stale {
		t.Errorf("a key deleted moments ago was marked stale")
	}
}

func TestListTrashShowsAgeAndNeverDeletesAnything(t *testing.T) {
	service, root := newTrashService(t)
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	manifestPath := filepath.Join(root, StateDirectoryName, "trash", result.EntryID, "manifest.json")
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest["deletedAt"] = time.Now().UTC().Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	aged, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, aged, 0o600); err != nil {
		t.Fatalf("write aged manifest: %v", err)
	}

	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].AgeDays < TrashRetentionDays {
		t.Errorf("AgeDays = %d, want at least %d", entries[0].AgeDays, TrashRetentionDays)
	}
	if !entries[0].Stale {
		t.Errorf("Stale = false, want true for a 40-day-old entry")
	}
	if _, statErr := os.Lstat(filepath.Join(root, StateDirectoryName, "trash", result.EntryID, "id_work")); statErr != nil {
		t.Fatalf("listing the trash deleted a key: %v", statErr)
	}
}

func TestRestoreRefusesWhenItWouldHaveToGuess(t *testing.T) {
	service, root := newTrashService(t)
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	// いまはその元のパスを別のファイルが占めている。
	if err := os.WriteFile(filepath.Join(root, "id_work"), []byte("something else\n"), 0o600); err != nil {
		t.Fatalf("occupy the original path: %v", err)
	}
	restored, err := service.Restore(result.EntryID)
	if !errors.Is(err, ErrRestoreBlocked) {
		t.Fatalf("Restore error = %v, want ErrRestoreBlocked", err)
	}
	if len(restored.Blockers) == 0 || !strings.HasPrefix(restored.Blockers[0], BlockerPathOccupied) {
		t.Fatalf("blockers = %#v, want a path-occupied blocker", restored.Blockers)
	}
	if contents, readErr := os.ReadFile(filepath.Join(root, "id_work")); readErr != nil || string(contents) != "something else\n" {
		t.Fatalf("a blocked restore overwrote the occupying file: %q, %v", contents, readErr)
	}

	if err := os.Remove(filepath.Join(root, "id_work")); err != nil {
		t.Fatalf("clear the original path: %v", err)
	}
	if _, err := service.Restore("../escape"); !errors.Is(err, ErrUnknownTrashEntry) {
		t.Fatalf("traversal identifier = %v, want ErrUnknownTrashEntry", err)
	}

	success, err := service.Restore(result.EntryID)
	if err != nil {
		t.Fatalf("Restore error = %v", err)
	}
	if len(success.Restored) != 2 {
		t.Fatalf("restored = %#v, want two files", success.Restored)
	}
	for _, name := range []string{"id_work", "id_work.pub"} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); statErr != nil {
			t.Fatalf("%s was not restored: %v", name, statErr)
		}
	}
	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %#v, want an empty trash after a restore", entries)
	}
}

func TestRestoreRefusesWhenAnIdenticalKeyIsAlreadyPresent(t *testing.T) {
	service, root := newTrashService(t)
	original, err := os.ReadFile(filepath.Join(root, "id_work"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "id_copy"), original, 0o600); err != nil {
		t.Fatalf("write duplicate key: %v", err)
	}

	restored, err := service.Restore(result.EntryID)
	if !errors.Is(err, ErrRestoreBlocked) {
		t.Fatalf("Restore error = %v, want ErrRestoreBlocked", err)
	}
	found := false
	for _, blocker := range restored.Blockers {
		if strings.HasPrefix(blocker, BlockerFingerprintPresent) {
			found = true
		}
	}
	if !found {
		t.Fatalf("blockers = %#v, want a fingerprint-present blocker", restored.Blockers)
	}
}

func TestPurgeRemovesEveryFileAndCannotBeUndone(t *testing.T) {
	service, root := newTrashService(t)
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	purged, err := service.Purge(result.EntryID)
	if err != nil {
		t.Fatalf("Purge error = %v", err)
	}
	if len(purged.Removed) != 2 {
		t.Fatalf("removed = %#v, want two files", purged.Removed)
	}
	entryDirectory := filepath.Join(root, StateDirectoryName, "trash", result.EntryID)
	for _, name := range []string{"id_work", "id_work.pub", "manifest.json"} {
		if _, statErr := os.Lstat(filepath.Join(entryDirectory, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s survived the purge: %v", name, statErr)
		}
	}
	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %#v, want an empty trash", entries)
	}
	if _, err := service.Purge(result.EntryID); !errors.Is(err, ErrUnknownTrashEntry) {
		t.Fatalf("second purge = %v, want ErrUnknownTrashEntry", err)
	}
}
