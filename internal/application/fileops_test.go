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

// newFileOpsService は、エントリファイルが 1 つの include 対象ファイルをリテラルに
// 名指しし、もう 1 つを glob で参照するワークスペースを構築する。この 2 つが、
// これらの操作が単純な名前変更ではない理由のすべてである。リテラルな Include は
// 名指しするファイルと共に移動しなければならず、glob はそのまま残さなければならない。
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
	// 1 バイトも変えない: 名前変更はファイルを移動するのであって、整形し直すのではない。
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
	// glob はもともとこのファイルについてのものではなかったので、変更されない。
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
	// 存在しないファイルを名指しする Include は、ssh が接続の
	// たびに出す診断である。その行を削除することこそ、rm ではなく
	// ここでこれを行う意味である。
	if !strings.Contains(entry, "Host bastion") {
		t.Errorf("the rest of the entry file did not survive:\n%s", entry)
	}
}

func TestADeletedFileCanBeRestoredFromHistory(t *testing.T) {
	// このアプリケーションが行う他のすべての変更は取り消せる。
	// 取り消せない削除があれば、それは「何も取り消し不能ではない」
	// ことを約束するアプリケーションの中で唯一の不可逆なものになってしまう。
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
	// conf.d/10-home.conf は conf.d/*.conf によって届く。それを
	// ワークスペースのルートへ移動すると、ディスク上には残るが
	// 設定からは外れ、ssh はそれを何も無かったかのように報告する。
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
	// 同じ glob が新しい名前も引き続きカバーするので、警告すべき
	// ことは何もなく、ここで警告すればユーザーに警告を無視することを教えてしまう。
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

// explorer は、他のすべてと同様にジャーナル記録しつつディレクトリを作れる。
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

// 空のディレクトリは削除されるが、設定ファイルを保持する
// ディレクトリは削除されない。ファイルにはそれを名指しする
// Include 行を書き換える専用の削除があり、こちらは何も見ないからだ。
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

// 宣言済みグループはここで拒否され、名指しされる。インター
// フェースがその操作の本来の場所へユーザーを送れるようにする
// ためである。グループの削除はその connections を移動させ、生成領域、グループ
// 設定、metadata を書き換える。2 つの画面がそれを呼べば、食い違う場所が 2 つできてしまう。
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
