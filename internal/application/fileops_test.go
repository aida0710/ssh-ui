package application

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/storage"
)

// newFileOpsService builds a workspace whose entry file names one included file
// literally and reaches another through a glob. The two are the whole reason
// these operations are not a simple rename: a literal Include has to travel
// with the file it names, and a glob must be left exactly as it is.
func newFileOpsService(t *testing.T) (*Service, string) {
	t.Helper()
	service, workspace := newTestService(t)
	entry := "# personal configuration\n" +
		"Include conf.d/*.conf\n" +
		"Include work/lon.conf\n" +
		"\n" +
		"Host bastion\n\tHostName 203.0.113.10\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := workspace.EnsureDirectory(filepath.Join(workspace.Root(), "work")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(workspace.Root(), "work", "lon.conf"),
		[]byte("Host lon\n\tHostName 198.51.100.7\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	return service, workspace.Root()
}

func readWorkspace(t *testing.T, root, relative string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return string(body)
}

func TestRenamingAFileCarriesTheIncludeThatNamedIt(t *testing.T) {
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "work/lon.conf")

	result, err := service.Save(EditRequest{
		Kind: EditFileRename, Path: "work/lon.conf", Base: base,
		DestinationPath: "work/london.conf",
	})
	if err != nil {
		t.Fatalf("Save = %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "work", "lon.conf")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the old file is still there: %v", err)
	}
	// Byte for byte: a rename moves a file, it does not reformat one.
	if got := readWorkspace(t, root, "work/london.conf"); got != base {
		t.Errorf("moved contents = %q, want %q", got, base)
	}
	entry := readWorkspace(t, root, "config")
	if !strings.Contains(entry, "Include work/london.conf") {
		t.Errorf("the Include was not carried:\n%s", entry)
	}
	if strings.Contains(entry, "work/lon.conf") {
		t.Errorf("the old Include is still there:\n%s", entry)
	}
	// The glob was never about this file, so it is untouched.
	if !strings.Contains(entry, "Include conf.d/*.conf") {
		t.Errorf("the unrelated glob was disturbed:\n%s", entry)
	}
	if len(result.Written) == 0 {
		t.Error("the result named nothing written")
	}
}

func TestDeletingAFileRemovesTheIncludeThatNamedIt(t *testing.T) {
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "work/lon.conf")

	if _, err := service.Save(EditRequest{
		Kind: EditFileDelete, Path: "work/lon.conf", Base: base,
	}); err != nil {
		t.Fatalf("Save = %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "work", "lon.conf")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the file is still there: %v", err)
	}
	entry := readWorkspace(t, root, "config")
	if strings.Contains(entry, "lon.conf") {
		t.Errorf("an Include still names the deleted file:\n%s", entry)
	}
	// An Include naming a file that is not there is a diagnostic ssh prints on
	// every connection. Removing the line is the point of doing this here
	// rather than with rm.
	if !strings.Contains(entry, "Host bastion") {
		t.Errorf("the rest of the entry file did not survive:\n%s", entry)
	}
}

func TestADeletedFileCanBeRestoredFromHistory(t *testing.T) {
	// Every other change this application makes can be undone. A delete that
	// could not would be the one irreversible thing in an application whose
	// whole promise is that nothing is.
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "work/lon.conf")

	result, err := service.Save(EditRequest{Kind: EditFileDelete, Path: "work/lon.conf", Base: base})
	if err != nil {
		t.Fatalf("Save = %v", err)
	}

	history, err := service.History()
	if err != nil {
		t.Fatal(err)
	}
	var restorable []string
	for _, entry := range history {
		if entry.ID == result.TransactionID {
			restorable = entry.Restorable
		}
	}
	found := false
	for _, path := range restorable {
		if path == "work/lon.conf" {
			found = true
		}
	}
	if !found {
		t.Fatalf("History does not offer the deleted file back: %#v", restorable)
	}

	if _, err := service.Restore(result.TransactionID, "work/lon.conf"); err != nil {
		t.Fatalf("Restore = %v", err)
	}
	if got := readWorkspace(t, root, "work/lon.conf"); got != base {
		t.Errorf("restored contents = %q, want %q", got, base)
	}
}

func TestTheEntryFileIsNotRenamedOrDeletedHere(t *testing.T) {
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "config")

	for name, request := range map[string]EditRequest{
		"rename": {Kind: EditFileRename, Path: "config", Base: base, DestinationPath: "config.old"},
		"delete": {Kind: EditFileDelete, Path: "config", Base: base},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Save(request); !errors.Is(err, ErrCannotTouchEntryFile) {
				t.Fatalf("Save = %v, want ErrCannotTouchEntryFile", err)
			}
			if got := readWorkspace(t, root, "config"); got != base {
				t.Error("the entry file changed anyway")
			}
		})
	}
}

func TestARenameOntoAnExistingFileIsRefusedAndWritesNothing(t *testing.T) {
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "work/lon.conf")
	existing := readWorkspace(t, root, "conf.d/10-home.conf")

	if _, err := service.Save(EditRequest{
		Kind: EditFileRename, Path: "work/lon.conf", Base: base,
		DestinationPath: "conf.d/10-home.conf",
	}); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("Save = %v, want ErrDestinationExists", err)
	}
	if got := readWorkspace(t, root, "conf.d/10-home.conf"); got != existing {
		t.Error("the destination was overwritten by a refused rename")
	}
	if got := readWorkspace(t, root, "work/lon.conf"); got != base {
		t.Error("the source was disturbed by a refused rename")
	}
}

func TestARenameWhoseBaseIsStaleIsAConflict(t *testing.T) {
	service, root := newFileOpsService(t)
	_ = root

	var conflict *ConflictError
	_, err := service.Save(EditRequest{
		Kind: EditFileRename, Path: "work/lon.conf",
		Base:            "something else entirely\n",
		DestinationPath: "work/london.conf",
	})
	if !errors.As(err, &conflict) {
		t.Fatalf("Save = %v, want a conflict", err)
	}
}

func TestRenamingOutOfAGlobsReachIsReported(t *testing.T) {
	// conf.d/10-home.conf is reached by conf.d/*.conf. Moving it to the
	// workspace root leaves it on disk and out of the configuration, which ssh
	// reports as nothing at all.
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "conf.d/10-home.conf")

	preview, err := service.Preview(EditRequest{
		Kind: EditFileRename, Path: "conf.d/10-home.conf", Base: base,
		DestinationPath: "10-home.conf",
	})
	if err != nil {
		t.Fatalf("Preview = %v", err)
	}
	codes := map[string]bool{}
	for _, notice := range preview.Notices {
		codes[notice.Code] = true
	}
	if !codes[NoticeIncludeNoLongerMatches] && !codes[NoticeIncludeNowUnreached] {
		t.Errorf("nothing warned that the file leaves the configuration: %#v", preview.Notices)
	}
}

func TestRenamingWithinAGlobsReachIsNotReported(t *testing.T) {
	// The same glob still covers the new name, so there is nothing to warn
	// about and a warning here would teach the user to ignore them.
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "conf.d/10-home.conf")

	preview, err := service.Preview(EditRequest{
		Kind: EditFileRename, Path: "conf.d/10-home.conf", Base: base,
		DestinationPath: "conf.d/20-home.conf",
	})
	if err != nil {
		t.Fatalf("Preview = %v", err)
	}
	for _, notice := range preview.Notices {
		if notice.Code == NoticeIncludeNoLongerMatches || notice.Code == NoticeIncludeNowUnreached {
			t.Errorf("a rename the glob still covers was reported: %#v", preview.Notices)
		}
	}
}

func TestPreviewOfADeleteWritesNothing(t *testing.T) {
	service, root := newFileOpsService(t)
	base := readWorkspace(t, root, "work/lon.conf")
	entry := readWorkspace(t, root, "config")

	preview, err := service.Preview(EditRequest{Kind: EditFileDelete, Path: "work/lon.conf", Base: base})
	if err != nil {
		t.Fatalf("Preview = %v", err)
	}
	if len(preview.Diffs) < 2 {
		t.Errorf("the preview showed %d diffs, want the file and the Include", len(preview.Diffs))
	}
	if got := readWorkspace(t, root, "work/lon.conf"); got != base {
		t.Error("Preview deleted the file")
	}
	if got := readWorkspace(t, root, "config"); got != entry {
		t.Error("Preview edited the entry file")
	}
}

// The explorer can make a directory, journalled like everything else.
func TestDirectoryCreateMakesOneAndRefusesAnExistingPath(t *testing.T) {
	service, workspace := newTestService(t)

	if _, err := service.Save(EditRequest{Kind: EditDirectoryCreate, Path: "conf.d/eu"}); err != nil {
		t.Fatalf("Save = %v", err)
	}
	info, err := os.Stat(filepath.Join(workspace.Root(), "conf.d", "eu"))
	if err != nil || !info.IsDir() {
		t.Fatalf("the directory is not there: %v", err)
	}
	if _, err := service.Save(EditRequest{Kind: EditDirectoryCreate, Path: "conf.d/eu"}); !errors.Is(err, ErrDestinationExists) {
		t.Errorf("creating it twice = %v, want ErrDestinationExists", err)
	}
}

// An empty directory goes; one holding a configuration file does not, because
// the files have a delete of their own that rewrites the Include lines naming
// them and this one looks at nothing.
func TestDirectoryDeleteTakesAnEmptyOneAndRefusesAFullOne(t *testing.T) {
	service, workspace := newTestService(t)
	if err := os.MkdirAll(filepath.Join(workspace.Root(), "conf.d", "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace.Root(), "conf.d", "full"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "full", "a.conf"), []byte("Host a\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Save(EditRequest{Kind: EditDirectoryDelete, Path: "conf.d/empty"}); err != nil {
		t.Fatalf("Save = %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace.Root(), "conf.d", "empty")); !os.IsNotExist(err) {
		t.Errorf("the empty directory is still there: %v", err)
	}

	if _, err := service.Save(EditRequest{Kind: EditDirectoryDelete, Path: "conf.d/full"}); !errors.Is(err, storage.ErrDirectoryNotEmpty) {
		t.Errorf("deleting a full directory = %v, want ErrDirectoryNotEmpty", err)
	}
	if _, err := os.Stat(filepath.Join(workspace.Root(), "conf.d", "full", "a.conf")); err != nil {
		t.Errorf("the file inside was touched: %v", err)
	}
}

// A declared group is refused here and named, so the interface can send the
// user where that operation lives. Deleting one moves its connections,
// rewrites the generated region, the group settings and the metadata; two
// screens calling it would be two places for it to drift.
func TestDirectoryDeleteRefusesADeclaredGroupAndSaysWhichOne(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeGroupFile(t, workspace, "work", "web.conf", "Host web-1\n")

	_, err := service.Save(EditRequest{Kind: EditDirectoryDelete, Path: "connections/work"})
	var declared *GroupDeclaredError
	if !errors.As(err, &declared) {
		t.Fatalf("deleting a declared group = %v, want GroupDeclaredError", err)
	}
	if declared.Group != "work" {
		t.Errorf("group = %q, want work", declared.Group)
	}
	if _, statErr := os.Stat(filepath.Join(workspace.Root(), "connections", "work")); statErr != nil {
		t.Errorf("the group directory was touched: %v", statErr)
	}
}
