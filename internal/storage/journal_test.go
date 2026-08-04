package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// interruptedCommit runs a two-file commit whose second rename fails and
// returns the workspace with a healthy filesystem restored.
func interruptedCommit(t *testing.T) (*Manager, *Workspace, string, string) {
	t.Helper()
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
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: first, Contents: []byte("Host first changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host first\n"))}},
			{Path: second, Contents: []byte("Host second changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host second\n"))}},
		},
	}); !errors.Is(err, failure) {
		t.Fatalf("commit error = %v, want the injected failure", err)
	}
	workspace.fileSystem = OSFileSystem{}
	return manager, workspace, first, second
}

func TestPendingDescribesTheInterruptedTransaction(t *testing.T) {
	manager, _, first, second := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %#v", pending)
	}
	item := pending[0]
	if item.Committed != 1 || item.Status != statusStaged || !item.CanComplete {
		t.Fatalf("pending item = %#v", item)
	}
	if len(item.Entries) != 2 {
		t.Fatalf("entries = %#v", item.Entries)
	}
	if item.Entries[0].Path != first || !item.Entries[0].Committed || !item.Entries[0].HasBackup {
		t.Errorf("entry 0 = %#v", item.Entries[0])
	}
	if item.Entries[1].Path != second || item.Entries[1].Committed || !item.Entries[1].HasStaged {
		t.Errorf("entry 1 = %#v", item.Entries[1])
	}
}

func TestCompleteFinishesTheRemainingRenames(t *testing.T) {
	manager, workspace, first, second := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Complete(pending[0].ID); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{first: "Host first changed\n", second: "Host second changed\n"} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, readErr)
		}
	}
	remaining, err := manager.Pending()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("pending after completion = %#v, %v", remaining, err)
	}
	history, err := manager.History()
	if err != nil || len(history) != 1 || history[0].Status != statusCompleted {
		t.Fatalf("history = %#v, %v", history, err)
	}
	assertNoTemporaryFiles(t, workspace.Root())
}

func TestRollbackRestoresEveryCommittedFile(t *testing.T) {
	manager, workspace, first, second := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(pending[0].ID); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{first: "Host first\n", second: "Host second\n"} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, readErr)
		}
	}
	history, err := manager.History()
	if err != nil || len(history) != 1 || history[0].Status != statusRolledBack {
		t.Fatalf("history = %#v, %v", history, err)
	}
	assertNoTemporaryFiles(t, workspace.Root())
}

func TestRollbackRemovesFilesTheTransactionCreated(t *testing.T) {
	workspace := newTestWorkspace(t)
	created := filepath.Join(workspace.Root(), "created.conf")
	existing := writeWorkspaceFile(t, workspace, "existing.conf", "Host existing\n", 0o600)
	failure := errors.New("injected rename failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "rename" && path == existing {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: created, Contents: []byte("Host created\n")},
			{Path: existing, Contents: []byte("Host changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host existing\n"))}},
		},
	}); !errors.Is(err, failure) {
		t.Fatalf("commit error = %v", err)
	}
	workspace.fileSystem = OSFileSystem{}

	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(pending[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created file still exists: %v", err)
	}
	contents, err := os.ReadFile(existing)
	if err != nil || string(contents) != "Host existing\n" {
		t.Fatalf("existing file = %q, %v", contents, err)
	}
}

func TestCompleteRefusesAlteredStagedContents(t *testing.T) {
	manager, _, _, _ := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	staged := stagedPathFor(t, manager, pending[0].ID, 1)
	if err := os.WriteFile(staged, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Complete(pending[0].ID); !errors.Is(err, ErrCannotComplete) {
		t.Fatalf("Complete error = %v, want ErrCannotComplete", err)
	}
	refreshed, err := manager.Pending()
	if err != nil || len(refreshed) != 1 || refreshed[0].CanComplete {
		t.Fatalf("pending = %#v, %v", refreshed, err)
	}
}

func TestPendingAndHistoryAreEmptyForAFreshWorkspace(t *testing.T) {
	manager, _ := newTestManager(t)
	pending, err := manager.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	history, err := manager.History()
	if err != nil || len(history) != 0 {
		t.Fatalf("history = %#v, %v", history, err)
	}
	if err := manager.Complete("../escape"); !errors.Is(err, ErrUnknownTransaction) {
		t.Fatalf("Complete(traversal) error = %v", err)
	}
	if err := manager.Rollback("missing"); !errors.Is(err, ErrUnknownTransaction) {
		t.Fatalf("Rollback(missing) error = %v", err)
	}
}

func stagedPathFor(t *testing.T, manager *Manager, identifier string, index int) string {
	t.Helper()
	record, _, err := manager.loadPending(identifier)
	if err != nil {
		t.Fatal(err)
	}
	if record.Entries[index].Temp == "" {
		t.Fatalf("entry %d has no staged file", index)
	}
	return record.Entries[index].Temp
}

func assertNoTemporaryFiles(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(temporaryPrefix) && entry.Name()[:len(temporaryPrefix)] == temporaryPrefix {
			t.Fatalf("temporary file %q was left behind", entry.Name())
		}
	}
}
