package storage

import (
	"bytes"
	"testing"
)

func TestHistoryListsNewestFirstWithoutFileContents(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host one\n", 0o600)
	for _, step := range []struct{ previous, next string }{
		{"Host one\n", "Host two\n"},
		{"Host two\n", "Host three\n"},
	} {
		if _, err := manager.Commit(Request{
			Operation: "config.save",
			Changes:   []Change{{Path: path, Contents: []byte(step.next), Precondition: Precondition{Exists: true, Digest: Digest([]byte(step.previous))}}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	history, err := manager.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("history = %#v", history)
	}
	if !history[0].StartedAt.After(history[1].StartedAt) {
		t.Fatalf("history is not newest first: %v then %v", history[0].StartedAt, history[1].StartedAt)
	}
	if history[0].Operation != "config.save" || len(history[0].Paths) != 1 || history[0].Paths[0] != path {
		t.Fatalf("record = %#v", history[0])
	}
	if history[0].FinishedAt.IsZero() || history[0].BackupDir == "" {
		t.Fatalf("record = %#v", history[0])
	}

	backup, err := manager.workspace.FileSystem().ReadFile(history[0].BackupDir + "/config")
	if err != nil || !bytes.Equal(backup, []byte("Host two\n")) {
		t.Fatalf("backup = %q, %v", backup, err)
	}
}
