package storage

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	moment := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		moment = moment.Add(time.Second)
		return moment
	}
}

func newTestManager(t *testing.T) (*Manager, *Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	return NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096))), workspace
}

func writeWorkspaceFile(t *testing.T, workspace *Workspace, name, contents string, permission fs.FileMode) string {
	t.Helper()
	path := filepath.Join(workspace.Root(), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), permission); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCommitWritesEveryChangeAndRecordsHistory(t *testing.T) {
	manager, workspace := newTestManager(t)
	config := writeWorkspaceFile(t, workspace, "config", "Host old\n", 0o644)
	extra := filepath.Join(workspace.Root(), "conf.d", "new.conf")
	if err := os.MkdirAll(filepath.Dir(extra), 0o700); err != nil {
		t.Fatal(err)
	}

	result, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: config, Contents: []byte("Host new\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host old\n"))}},
			{Path: extra, Contents: []byte("Host extra\n")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Written) != 2 || result.ID == "" {
		t.Fatalf("result = %#v", result)
	}

	for path, want := range map[string]string{config: "Host new\n", extra: "Host extra\n"} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != FilePermission {
			t.Fatalf("%s permission = %v, want %v", path, info.Mode().Perm(), FilePermission)
		}
	}

	backup, err := os.ReadFile(filepath.Join(result.BackupDir, "config"))
	if err != nil || string(backup) != "Host old\n" {
		t.Fatalf("backup = %q, %v", backup, err)
	}
	if _, err := os.Stat(filepath.Join(result.BackupDir, "conf.d", "new.conf")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a file that did not exist was backed up")
	}

	journalEntries, err := os.ReadDir(filepath.Join(workspace.StateDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if len(journalEntries) != 0 {
		t.Fatalf("journal still holds %d entries", len(journalEntries))
	}
	historyEntries, err := os.ReadDir(filepath.Join(workspace.StateDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	if len(historyEntries) != 1 || !strings.HasSuffix(historyEntries[0].Name(), ".json") {
		t.Fatalf("history = %#v", historyEntries)
	}

	staged, err := os.ReadDir(workspace.Root())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range staged {
		if strings.HasPrefix(entry.Name(), ".ssh-ui-") {
			t.Fatalf("temporary file %q was left behind", entry.Name())
		}
	}
}

func TestCommitPreservesStricterPermissions(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "strict.conf", "Host old\n", 0o400)
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path, Contents: []byte("Host new\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host old\n"))}}},
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("permission = %v, want 0400", info.Mode().Perm())
	}
}

func TestCommitRejectsExternalChangesWithThreeWayData(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host disk\n", 0o600)

	_, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path, Contents: []byte("Host ui\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host base\n"))}}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
	if conflict.Path != path || string(conflict.Current) != "Host disk\n" {
		t.Fatalf("conflict = %#v", conflict)
	}
	if conflict.Expected == conflict.Actual {
		t.Fatal("conflict does not distinguish the two versions")
	}
	if strings.Contains(conflict.Error(), "Host disk") {
		t.Fatal("conflict error message leaks file contents")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "Host disk\n" {
		t.Fatalf("file changed during a rejected commit: %q", contents)
	}
}

func TestCommitRejectsCreationWhenTheFileAlreadyExists(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host disk\n", 0o600)
	_, err := manager.Commit(Request{
		Operation: "config.create",
		Changes:   []Change{{Path: path, Contents: []byte("Host ui\n")}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
}

func TestCommitRejectsInvalidRequests(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := filepath.Join(workspace.Root(), "config")

	if _, err := manager.Commit(Request{Operation: "config.save"}); !errors.Is(err, ErrNoChanges) {
		t.Errorf("empty request error = %v", err)
	}
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path}, {Path: path}},
	}); !errors.Is(err, ErrDuplicatePath) {
		t.Errorf("duplicate path error = %v", err)
	}
	outside := filepath.Join(filepath.Dir(workspace.Root()), "outside.conf")
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: outside}},
	}); !errors.Is(err, ErrOutsideWorkspace) {
		t.Errorf("outside path error = %v", err)
	}
}

func TestCommitLeavesRecoverableJournalWhenRenameFails(t *testing.T) {
	workspace := newTestWorkspace(t)
	first := writeWorkspaceFile(t, workspace, "first.conf", "Host first\n", 0o600)
	second := writeWorkspaceFile(t, workspace, "second.conf", "Host second\n", 0o600)
	failure := errors.New("injected rename failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "rename" && path == second {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))

	_, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: first, Contents: []byte("Host first changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host first\n"))}},
			{Path: second, Contents: []byte("Host second changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host second\n"))}},
		},
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want the injected failure", err)
	}

	if contents, readErr := os.ReadFile(first); readErr != nil || string(contents) != "Host first changed\n" {
		t.Fatalf("first file = %q, %v", contents, readErr)
	}
	if contents, readErr := os.ReadFile(second); readErr != nil || string(contents) != "Host second\n" {
		t.Fatalf("second file = %q, %v", contents, readErr)
	}
	journalEntries, readErr := os.ReadDir(filepath.Join(workspace.StateDir(), "journal"))
	if readErr != nil || len(journalEntries) != 1 {
		t.Fatalf("journal = %#v, %v", journalEntries, readErr)
	}
}

func TestCommitRunsTheInjectedValidatorBeforeTouchingDisk(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host old\n", 0o600)
	rejected := errors.New("syntax error at line 1")
	manager.Validate = func(request Request) error {
		if len(request.Changes) != 1 || request.Operation != "config.save" {
			t.Fatalf("validator received %#v", request)
		}
		return rejected
	}

	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path, Contents: []byte("Host new\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host old\n"))}}},
	}); !errors.Is(err, rejected) {
		t.Fatalf("error = %v, want the validator's error", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "Host old\n" {
		t.Fatalf("file changed despite validation failure: %q", contents)
	}
	if _, err := os.Stat(workspace.StateDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a rejected request created state directories")
	}
}

func TestCommitFailureWhileStagingLeavesEveryFileUntouched(t *testing.T) {
	workspace := newTestWorkspace(t)
	first := writeWorkspaceFile(t, workspace, "first.conf", "Host first\n", 0o600)
	second := writeWorkspaceFile(t, workspace, "conf.d/second.conf", "Host second\n", 0o600)
	failure := errors.New("injected staging failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "writeTemp" && path == filepath.Dir(second) {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))

	_, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: first, Contents: []byte("Host first changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host first\n"))}},
			{Path: second, Contents: []byte("Host second changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host second\n"))}},
		},
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want the injected failure", err)
	}
	for path, want := range map[string]string{first: "Host first\n", second: "Host second\n"} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, readErr)
		}
	}
	journalEntries, readErr := os.ReadDir(filepath.Join(workspace.StateDir(), "journal"))
	if readErr != nil || len(journalEntries) != 1 {
		t.Fatalf("journal = %#v, %v", journalEntries, readErr)
	}
	// Nothing was renamed, so the recovery test in Task 7 can roll this back
	// without restoring any file.
}

// faultyFileSystem injects one failure into an otherwise real filesystem so a
// test can interrupt a transaction at a chosen stage.
type faultyFileSystem struct {
	FileSystem
	failOn func(operation, path string) error
}

func (f faultyFileSystem) Rename(oldPath, newPath string) error {
	if err := f.failOn("rename", newPath); err != nil {
		return err
	}
	return f.FileSystem.Rename(oldPath, newPath)
}

func (f faultyFileSystem) WriteTemp(directory, prefix string, permission fs.FileMode, contents []byte) (string, error) {
	if err := f.failOn("writeTemp", directory); err != nil {
		return "", err
	}
	return f.FileSystem.WriteTemp(directory, prefix, permission, contents)
}

func (f faultyFileSystem) SyncDir(path string) error {
	if err := f.failOn("syncDir", path); err != nil {
		return err
	}
	return f.FileSystem.SyncDir(path)
}

func (f faultyFileSystem) Remove(path string) error {
	if err := f.failOn("remove", path); err != nil {
		return err
	}
	return f.FileSystem.Remove(path)
}

// A private key must never be duplicated into the generational backup
// directory, so a caller that replaces key material opts out of the backup and
// accepts that the change cannot be rolled back afterwards.
func TestCommitSkipsTheGenerationalBackupWhenTheCallerOptsOut(t *testing.T) {
	manager, workspace := newTestManager(t)
	secret := writeWorkspaceFile(t, workspace, "id_work", "PRIVATE KEY BYTES\n", 0o600)

	result, err := manager.Commit(Request{
		Operation: "key.passphrase",
		Changes: []Change{{
			Path:         secret,
			Contents:     []byte("RE-ENCRYPTED KEY BYTES\n"),
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("PRIVATE KEY BYTES\n"))},
			SkipBackup:   true,
		}},
	})
	if err != nil {
		t.Fatalf("Commit error = %v", err)
	}

	contents, err := os.ReadFile(secret)
	if err != nil || string(contents) != "RE-ENCRYPTED KEY BYTES\n" {
		t.Fatalf("contents = %q, %v", contents, err)
	}
	if entries, readErr := os.ReadDir(result.BackupDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("a change that opted out of the backup still wrote one: %#v", entries)
	}

	history, err := manager.History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	if len(history) != 1 || history[0].Operation != "key.passphrase" {
		t.Fatalf("history = %#v", history)
	}
}
