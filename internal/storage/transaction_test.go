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
		if strings.HasPrefix(entry.Name(), ".sshc-") {
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
	// 何も rename されなかったので、Task 7 の復旧テストは、ファイルをひとつも復元
	// せずにこれを巻き戻せる。
}

// faultyFileSystem は、それ以外は本物のファイルシステムに失敗をひとつ注入する。
// これによりテストは、選んだ段階でトランザクションを中断できる。
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

func TestCommitMovesAFileWithoutCopyingItsBytes(t *testing.T) {
	manager, workspace := newTestManager(t)
	source := writeWorkspaceFile(t, workspace, "id_work", "PRIVATE KEY BYTES\n", 0o400)
	destinationDirectory := filepath.Join(workspace.StateDir(), "trash", "entry-1")
	if err := workspace.EnsureDirectory(destinationDirectory); err != nil {
		t.Fatalf("EnsureDirectory error = %v", err)
	}
	destination := filepath.Join(destinationDirectory, "id_work")

	result, err := manager.Commit(Request{
		Operation: "key.trash",
		Moves: []Move{{
			From:         source,
			To:           destination,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("PRIVATE KEY BYTES\n"))},
		}},
	})
	if err != nil {
		t.Fatalf("Commit error = %v", err)
	}

	if _, statErr := os.Lstat(source); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("source still exists: %v", statErr)
	}
	moved, err := os.Lstat(destination)
	if err != nil {
		t.Fatalf("destination missing: %v", err)
	}
	if moved.Mode().Perm() != 0o400 {
		t.Errorf("destination permission = %04o, want 0400", moved.Mode().Perm())
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "PRIVATE KEY BYTES\n" {
		t.Fatalf("destination contents = %q, %v", contents, err)
	}

	if entries, readErr := os.ReadDir(result.BackupDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("a move copied bytes into the backup directory: %#v", entries)
	}

	history, err := manager.History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	if len(history) != 1 || history[0].Operation != "key.trash" {
		t.Fatalf("history = %#v", history)
	}
}

func TestCommitRejectsAMoveOntoAnExistingFileOrAChangedSource(t *testing.T) {
	manager, workspace := newTestManager(t)
	source := writeWorkspaceFile(t, workspace, "id_work", "ORIGINAL\n", 0o600)
	occupied := writeWorkspaceFile(t, workspace, "taken", "ALREADY HERE\n", 0o600)

	if _, err := manager.Commit(Request{
		Operation: "key.trash",
		Moves: []Move{{
			From:         source,
			To:           occupied,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("ORIGINAL\n"))},
		}},
	}); !errors.Is(err, ErrMoveTargetExists) {
		t.Fatalf("error = %v, want ErrMoveTargetExists", err)
	}

	_, err := manager.Commit(Request{
		Operation: "key.trash",
		Moves: []Move{{
			From:         source,
			To:           filepath.Join(workspace.Root(), "moved"),
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("SOMETHING ELSE\n"))},
		}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want a ConflictError", err)
	}
	if conflict.Current != nil {
		t.Fatalf("a conflict on a move carried file contents, which may be key material")
	}
	if contents, readErr := os.ReadFile(source); readErr != nil || string(contents) != "ORIGINAL\n" {
		t.Fatalf("source changed after a rejected move: %q, %v", contents, readErr)
	}
}

func TestCommitRemovesAFileWithoutWritingABackup(t *testing.T) {
	manager, workspace := newTestManager(t)
	target := writeWorkspaceFile(t, workspace, "sshc/trash/entry-1/id_work", "PRIVATE KEY BYTES\n", 0o600)

	result, err := manager.Commit(Request{
		Operation: "key.purge",
		Removals: []Removal{{
			Path:         target,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("PRIVATE KEY BYTES\n"))},
		}},
	})
	if err != nil {
		t.Fatalf("Commit error = %v", err)
	}
	if _, statErr := os.Lstat(target); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("removed file still exists: %v", statErr)
	}
	if entries, readErr := os.ReadDir(result.BackupDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("a permanent delete wrote a backup: %#v", entries)
	}
}

func TestNoteRecordsAnAuditFactWithoutFileContents(t *testing.T) {
	manager, workspace := newTestManager(t)
	target := writeWorkspaceFile(t, workspace, "id_work", "PRIVATE KEY BYTES\n", 0o600)

	if _, err := manager.Note("key.reveal", []string{target}); err != nil {
		t.Fatalf("Note error = %v", err)
	}

	history, err := manager.History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	if len(history) != 1 || history[0].Operation != "key.reveal" {
		t.Fatalf("history = %#v", history)
	}
	if len(history[0].Paths) != 1 || history[0].Paths[0] != target {
		t.Fatalf("history paths = %#v", history[0].Paths)
	}
	if contents, readErr := os.ReadFile(target); readErr != nil || string(contents) != "PRIVATE KEY BYTES\n" {
		t.Fatalf("Note changed the file it recorded: %q, %v", contents, readErr)
	}
	if journalEntries, readErr := os.ReadDir(filepath.Join(workspace.StateDir(), "journal")); readErr == nil && len(journalEntries) != 0 {
		t.Fatalf("Note left a pending journal: %#v", journalEntries)
	}

	records, err := os.ReadDir(filepath.Join(workspace.StateDir(), "history"))
	if err != nil {
		t.Fatalf("read history directory: %v", err)
	}
	for _, entry := range records {
		document, readErr := os.ReadFile(filepath.Join(workspace.StateDir(), "history", entry.Name()))
		if readErr != nil {
			t.Fatalf("read history record: %v", readErr)
		}
		if strings.Contains(string(document), "PRIVATE KEY BYTES") {
			t.Fatalf("the audit record contains file contents")
		}
	}
}

// 秘密鍵が世代バックアップのディレクトリへ複製されることは決してあってはならない。
// そこで、鍵素材を置き換える呼び出し側はバックアップを取らないことを選び、その
// 変更があとから巻き戻せないことを受け入れる。
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

func TestCommitCreatesADirectoryAndTheFileInsideItInOneTransaction(t *testing.T) {
	// これがなかった頃は、呼び出し側はジャーナルの外で EnsureDirectory を呼び、
	// mkdir とコミットのあいだでクラッシュすれば空のディレクトリが残ることを
	// 受け入れるしかなかった。
	manager, workspace := newTestManager(t)
	nested := filepath.Join(workspace.Root(), "connections", "work", "eu")

	result, err := manager.Commit(Request{
		Operation:   "test.directory",
		Directories: []DirectoryCreate{{Path: nested}},
		Changes: []Change{{
			Path:     filepath.Join(nested, "lon.conf"),
			Contents: []byte("Host lon-1\n"),
		}},
	})
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}
	if result.ID == "" {
		t.Error("no transaction id")
	}

	info, err := os.Stat(nested)
	if err != nil || !info.IsDir() {
		t.Fatalf("the directory was not created: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %v, want 0700", info.Mode().Perm())
	}
	body, err := os.ReadFile(filepath.Join(nested, "lon.conf"))
	if err != nil || string(body) != "Host lon-1\n" {
		t.Errorf("file = %q, %v", body, err)
	}
}

func TestCommitRemovesAnEmptyDirectoryAndRefusesAFullOne(t *testing.T) {
	// 再帰的な削除は、トランザクションが一度も読んでいない内容を復元しない限り
	// 巻き戻せない。だから消えるのは空のディレクトリだけである。
	manager, workspace := newTestManager(t)
	full := filepath.Join(workspace.Root(), "connections", "work")
	if err := os.MkdirAll(full, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "lon.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := manager.Commit(Request{
		Operation:         "test.directory",
		RemoveDirectories: []DirectoryRemoval{{Path: full}},
	})
	if !errors.Is(err, ErrDirectoryNotEmpty) {
		t.Fatalf("removing a full directory = %v, want ErrDirectoryNotEmpty", err)
	}
	if _, err := os.Stat(filepath.Join(full, "lon.conf")); err != nil {
		t.Errorf("the refused removal touched the contents: %v", err)
	}

	if err := os.Remove(filepath.Join(full, "lon.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Commit(Request{
		Operation:         "test.directory",
		RemoveDirectories: []DirectoryRemoval{{Path: full}},
	}); err != nil {
		t.Fatalf("removing an empty directory = %v", err)
	}
	if _, err := os.Stat(full); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory is still there: %v", err)
	}
}

func TestRemovingADirectoryThatIsAlreadyGoneIsNotAnError(t *testing.T) {
	// これは呼び出し側が求めた状態である。すでに残骸が片付けられているグループ名の
	// 変更が、次のトランザクションを失敗させてはならない。
	manager, workspace := newTestManager(t)

	if _, err := manager.Commit(Request{
		Operation: "test.directory",
		Changes: []Change{{
			Path: filepath.Join(workspace.Root(), "marker"), Contents: []byte("x"),
		}},
		RemoveDirectories: []DirectoryRemoval{
			{Path: filepath.Join(workspace.Root(), "never-existed")},
		},
	}); err != nil {
		t.Fatalf("Commit = %v", err)
	}
}

func TestARefusedDirectoryRequestCreatesNothing(t *testing.T) {
	// バリデータは、ディレクトリが計画されたあと、そのどれかが作られる前に走る。
	// したがって拒否されたリクエストは、ディスクに手を触れずに終わらねばならない。
	manager, workspace := newTestManager(t)
	manager.Validate = func(Request) error { return errors.New("refused") }
	nested := filepath.Join(workspace.Root(), "connections", "work")

	if _, err := manager.Commit(Request{
		Operation:   "test.directory",
		Directories: []DirectoryCreate{{Path: nested}},
	}); err == nil {
		t.Fatal("the validator was ignored")
	}
	if _, err := os.Stat(nested); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused request created the directory: %v", err)
	}
}

func TestADirectoryOutsideTheWorkspaceIsRefused(t *testing.T) {
	manager, _ := newTestManager(t)

	for _, path := range []string{"/etc/ssh", "relative/path", "/"} {
		if _, err := manager.Commit(Request{
			Operation:   "test.directory",
			Directories: []DirectoryCreate{{Path: path}},
		}); err == nil {
			t.Errorf("creating %q was allowed", path)
		}
	}
}

func TestARemovalCanKeepABackupSoHistoryCanRestoreIt(t *testing.T) {
	// ユーザーがエクスプローラから削除した設定ファイルは鍵素材ではないし、この
	// アプリケーションが行う他のすべての変更は History から取り消せる。世代コピーは、
	// 削除を同じ土俵に載せるものだ。Restore が読むのは、まさにこのファイルで
	// ある。
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "conf.d/10-home.conf", "Host nas\n\tUser aida\n", 0o600)

	result, err := manager.Commit(Request{
		Operation: "config.file_delete",
		Removals: []Removal{{
			Path:         path,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host nas\n\tUser aida\n"))},
			Backup:       true,
		}},
	})
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the file is still there: %v", err)
	}

	backup := filepath.Join(result.BackupDir, "conf.d", "10-home.conf")
	kept, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("the removal kept no backup: %v", err)
	}
	if string(kept) != "Host nas\n\tUser aida\n" {
		t.Errorf("backup = %q", kept)
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %v, want the mode the file had", info.Mode().Perm())
	}
}

func TestAPurgeStillCopiesNothingIntoTheBackupDirectory(t *testing.T) {
	// 恒久的な鍵の削除こそ、削除が既定では何も残さない理由である。鍵素材を
	// バックアップディレクトリへコピーすれば、ユーザーがそのために与えた二度の
	// 確認を台無しにしてしまう。
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "keys/id_ed25519", "PRIVATE", 0o600)

	result, err := manager.Commit(Request{
		Operation: "key.purge",
		Removals: []Removal{{
			Path:         path,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("PRIVATE"))},
		}},
	})
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.BackupDir, "keys", "id_ed25519")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the purge wrote the key into the backup directory: %v", err)
	}
}

// バックアップは暗号文であり、それを知っているのはマネージャだけである。
//
// ほかにバックアップディレクトリを直接読むものはない。巻き戻しも復元もここへ
// 戻ってくるので、それらのバイト列が何であるかを知る場所はひとつだけであり、
// それを忘れうる呼び出し側は存在しない。
func TestBackupsAreSealedAndReadBackThroughTheManager(t *testing.T) {
	manager, workspace := newTestManager(t)
	manager.Seal = sealForTest
	manager.Unseal = unsealForTest

	path := filepath.Join(workspace.Root(), "config")
	if err := os.WriteFile(path, []byte("Host bastion\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{{
			Path:         path,
			Contents:     []byte("Host bastion\n\tPort 2222\n"),
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host bastion\n"))},
		}},
	})
	if err != nil {
		t.Fatalf("Commit = %v", err)
	}

	backup := filepath.Join(result.BackupDir, "config")
	onDisk, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read the backup: %v", err)
	}
	if bytes.Equal(onDisk, []byte("Host bastion\n")) {
		t.Error("the backup is the previous contents in the clear")
	}
	restored, err := manager.ReadBackup(backup)
	if err != nil {
		t.Fatalf("ReadBackup = %v", err)
	}
	if string(restored) != "Host bastion\n" {
		t.Errorf("ReadBackup = %q, want the previous contents", restored)
	}
}

// sealForTest は vault の鍵の代役である。可逆であり、かつ明らかに恒等写像では
// ない。ディスク上のバイト列は入ってきたバイト列と違わねばならず、さもなければ
// バックアップを鍵素材で grep する検査が平文の上を素通りしてしまう。
func sealForTest(plaintext []byte) ([]byte, error) {
	sealed := make([]byte, 0, len(plaintext)+len(testSealMarker))
	sealed = append(sealed, testSealMarker...)
	for _, b := range plaintext {
		sealed = append(sealed, b^0x5a)
	}
	return sealed, nil
}

func unsealForTest(sealed []byte) ([]byte, error) {
	if !bytes.HasPrefix(sealed, testSealMarker) {
		return nil, errors.New("that backup was not sealed")
	}
	body := sealed[len(testSealMarker):]
	plaintext := make([]byte, 0, len(body))
	for _, b := range body {
		plaintext = append(plaintext, b^0x5a)
	}
	return plaintext, nil
}

var testSealMarker = []byte("sealed:")

// このリクエスト自身が空にするディレクトリは、このリクエストで取り除ける。
//
// 以前は現状のディスクに対して検査していたので、呼び出し側は一方のトランザクション
// でファイルを外へ移し、次のトランザクションでディレクトリを取り除かねばならな
// かった — つまりグループ名の変更が自分で始めたことを終えられず、二つのあいだで
// クラッシュすれば空の抜け殻が残った。いまは、このリクエストが残すことになる
// ディスクの状態に対して検査する。
func TestADirectoryEmptiedByTheSameRequestIsRemoved(t *testing.T) {
	manager, workspace := newTestManager(t)
	from := writeWorkspaceFile(t, workspace, "connections/work/web.conf", "Host web\n", 0o600)
	nested := writeWorkspaceFile(t, workspace, "connections/work/eu/lon.conf", "Host lon\n", 0o600)

	if _, err := manager.Commit(Request{
		Operation: "config.group_rename",
		Directories: []DirectoryCreate{
			{Path: filepath.Join(workspace.Root(), "connections", "client-a", "eu")},
		},
		Moves: []Move{
			{
				From:         from,
				To:           filepath.Join(workspace.Root(), "connections", "client-a", "web.conf"),
				Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host web\n"))},
			},
			{
				From:         nested,
				To:           filepath.Join(workspace.Root(), "connections", "client-a", "eu", "lon.conf"),
				Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host lon\n"))},
			},
		},
		// 意図して親を先に列挙している。成立する順序は深いものからであり、呼び出し側が
		// それを知っている必要はない。
		RemoveDirectories: []DirectoryRemoval{
			{Path: filepath.Join(workspace.Root(), "connections", "work")},
			{Path: filepath.Join(workspace.Root(), "connections", "work", "eu")},
		},
	}); err != nil {
		t.Fatalf("Commit = %v", err)
	}

	for _, gone := range []string{"connections/work/eu", "connections/work"} {
		if _, err := os.Stat(filepath.Join(workspace.Root(), filepath.FromSlash(gone))); !os.IsNotExist(err) {
			t.Errorf("%s is still there: %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(workspace.Root(), "connections", "client-a", "eu", "lon.conf")); err != nil {
		t.Errorf("the nested file did not arrive: %v", err)
	}
}

// このリクエストが触れない何かを保持しているディレクトリは、やはり拒否される。
// 変わったのは何をもって空とするかであって、空であることが重要かどうかではない。
func TestADirectoryHoldingSomethingElseIsStillRefused(t *testing.T) {
	manager, workspace := newTestManager(t)
	from := writeWorkspaceFile(t, workspace, "connections/work/web.conf", "Host web\n", 0o600)
	writeWorkspaceFile(t, workspace, "connections/work/notes.txt", "not ours\n", 0o600)

	_, err := manager.Commit(Request{
		Operation: "config.group_rename",
		Directories: []DirectoryCreate{
			{Path: filepath.Join(workspace.Root(), "connections", "client-a")},
		},
		Moves: []Move{{
			From:         from,
			To:           filepath.Join(workspace.Root(), "connections", "client-a", "web.conf"),
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host web\n"))},
		}},
		RemoveDirectories: []DirectoryRemoval{
			{Path: filepath.Join(workspace.Root(), "connections", "work")},
		},
	})
	if !errors.Is(err, ErrDirectoryNotEmpty) {
		t.Fatalf("Commit = %v, want ErrDirectoryNotEmpty", err)
	}
	// 何かが起きる前に拒否された。
	if _, statErr := os.Stat(from); statErr != nil {
		t.Errorf("the file moved despite the refusal: %v", statErr)
	}
}
