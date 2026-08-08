package application

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/storage"
)

// groupRenameFixture は、名前変更が本当に問題にしている状況を
// 構築する: 内部にネストしたグループを持つグループ、両方にある connections、
// グループの鍵ディレクトリの中の鍵、そしてその鍵を名指しする設定ファイルである。
func groupRenameFixture(t *testing.T) (*Service, *storage.Workspace) {
	t.Helper()
	service, workspace := newTestService(t)
	declareGroup(t, service, "work", "work/eu")
	writeGroupFile(t, workspace, "work", "web.conf", "Host web-1\n\tHostName 203.0.113.10\n")
	writeGroupFile(t, workspace, "work/eu", "lon.conf", "Host lon-1\n\tHostName 203.0.113.11\n")
	writeKeyPair(t, workspace, "keys/work/id_work")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"),
		[]byte("Host web-1\n\tIdentityFile ~/.ssh/keys/work/id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return service, workspace
}

func TestGroupRenameMovesEveryFileAndRewritesEveryLineThatNamedIt(t *testing.T) {
	service, workspace := groupRenameFixture(t)

	result, err := service.RenameGroup(keyInventory(t, workspace), "work", "client-a")
	if err != nil {
		t.Fatalf("RenameGroup error = %v", err)
	}
	wantRelocations := map[string]string{
		"keys/work/id_work":     "keys/client-a/id_work",
		"keys/work/id_work.pub": "keys/client-a/id_work.pub",
	}
	for _, relocation := range result.KeyRelocations {
		if wantRelocations[relocation.From] == relocation.To {
			delete(wantRelocations, relocation.From)
		}
	}
	if len(wantRelocations) != 0 {
		t.Errorf("KeyRelocations omitted %#v: %#v", wantRelocations, result.KeyRelocations)
	}

	// すべてのファイルが移動した。ネストしたグループはその親と共に…
	for _, name := range []string{
		"connections/client-a/web.conf",
		"connections/client-a/eu/lon.conf",
		"keys/client-a/id_work",
		"keys/client-a/id_work.pub",
	} {
		if _, err := os.Lstat(filepath.Join(workspace.Root(), filepath.FromSlash(name))); err != nil {
			t.Errorf("%s is not there: %v", name, err)
		}
	}
	// …region は新しい名前を、子を先に宣言し…
	entry := readFile(t, workspace, "config")
	if !strings.Contains(entry, "Include connections/client-a/eu/*.conf\nInclude connections/client-a/*.conf\n") {
		t.Errorf("entry region = %q", entry)
	}
	if strings.Contains(entry, "connections/work") {
		t.Errorf("the old group is still declared: %q", entry)
	}
	// …そして IdentityFile はそれが名指しする鍵に追従した。
	if got := readFile(t, workspace, "conf.d/30-keys.conf"); got != "Host web-1\n\tIdentityFile ~/.ssh/keys/client-a/id_work\n" {
		t.Errorf("key reference = %q", got)
	}
}

func TestGroupRenameCarriesTheMetadataIdentityAndPresentation(t *testing.T) {
	service, workspace := groupRenameFixture(t)
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{
		{Name: "work", Colour: "#f97316"},
		{Name: "work/eu"},
	}
	metadata.Hosts = []HostMetadata{{
		Identity:  HostIdentity{Path: "connections/work/web.conf", Alias: "web-1"},
		Colour:    "#22d3ee",
		Favourite: true,
	}}
	if _, err := service.Save(EditRequest{Kind: EditMetadata, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.RenameGroup(keyInventory(t, workspace), "work", "client-a"); err != nil {
		t.Fatalf("RenameGroup error = %v", err)
	}

	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, group := range stored.Groups {
		names[group.Name] = group.Colour
	}
	if names["client-a"] != "#f97316" {
		t.Errorf("groups = %#v, want the presentation carried to the new name", stored.Groups)
	}
	if _, stale := names["work"]; stale {
		t.Errorf("the old group name survived: %#v", stored.Groups)
	}
	if len(stored.Hosts) != 1 {
		t.Fatalf("hosts = %#v", stored.Hosts)
	}
	// identity はパスと共に変わったので、そのエントリはユーザーが
	// 手作業で再関連付けしなければならない孤児にはならない。
	if stored.Hosts[0].Identity.Path != "connections/client-a/web.conf" || stored.Hosts[0].Orphan {
		t.Errorf("identity = %#v", stored.Hosts[0])
	}
	if !stored.Hosts[0].Favourite || stored.Hosts[0].Colour != "#22d3ee" {
		t.Errorf("presentation lost on the way: %#v", stored.Hosts[0])
	}
}

// 名前変更が空にするディレクトリは、同じトランザクションで一緒に削除される。
//
// かつてはそれらは置き去りにされ、報告されていた。ディレクトリの削除は復旧記録を
// 持たないファイルシステム効果だったからだ。ジャーナルは今やディレクトリ削除を
// 持つので、操作は始めたことを終えられる: 旧グループの空の抜け殻を残す
// 名前変更は、半端にしか動かなかったように見えてしまう。
func TestGroupRenameTakesTheDirectoriesItEmpties(t *testing.T) {
	service, workspace := groupRenameFixture(t)

	result, err := service.RenameGroup(keyInventory(t, workspace), "work", "client-a")
	if err != nil {
		t.Fatalf("RenameGroup error = %v", err)
	}
	if hasNotice(result.Preview.Notices, NoticeGroupDirectoryLeftover, "work") {
		t.Errorf("it still reports a leftover it now removes: %#v", result.Preview.Notices)
	}
	for _, name := range []string{"connections/work/eu", "connections/work", "keys/work"} {
		if _, err := os.Stat(filepath.Join(workspace.Root(), filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Errorf("%s is still there: %v", name, err)
		}
	}
}

// この操作が触れなかった何かを保持するディレクトリはそのまま残される。
//
// グループのファイルは、このアプリケーションが置いたのでない
// ものも含めて、グループと共に移動する。宣言済みグループでない
// ディレクトリは移動しない: 何もそれを宣言していないので、
// どこへ行くべきか誰も知らないからだ。したがってその上のグループ
// ディレクトリは空にならず、それでも削除すればユーザーが中に残したものを壊してしまう。
func TestGroupRenameLeavesADirectoryThatStillHoldsSomething(t *testing.T) {
	service, workspace := groupRenameFixture(t)
	stray := filepath.Join(workspace.Root(), "connections", "work", "scratch")
	if err := os.MkdirAll(stray, 0o700); err != nil {
		t.Fatal(err)
	}

	result, err := service.RenameGroup(keyInventory(t, workspace), "work", "client-a")
	if err != nil {
		t.Fatalf("RenameGroup error = %v", err)
	}
	if !hasNotice(result.Preview.Notices, NoticeGroupDirectoryLeftover, "work") {
		t.Errorf("notices = %#v, want group_directory_leftover", result.Preview.Notices)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("the file the user left there is gone: %v", err)
	}
	// ネストしたグループは他に何も保持していなかったので、消えた。
	if _, err := os.Stat(filepath.Join(workspace.Root(), "connections", "work", "eu")); !os.IsNotExist(err) {
		t.Errorf("connections/work/eu is still there: %v", err)
	}
}

func TestGroupRenameOntoAnExistingGroupIsRefused(t *testing.T) {
	service, workspace := groupRenameFixture(t)
	declareGroup(t, service, "work", "work/eu", "client-a")

	_, err := service.RenameGroup(keyInventory(t, workspace), "work", "client-a")
	if !errors.Is(err, ErrGroupExists) {
		t.Fatalf("RenameGroup error = %v, want ErrGroupExists", err)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "connections", "work", "web.conf")); statErr != nil {
		t.Errorf("a refused rename moved a file: %v", statErr)
	}
}

func TestGroupRenameRefusesWhenAKeyReferenceCannotBeRewritten(t *testing.T) {
	service, workspace := groupRenameFixture(t)
	// 同じベース名を名指しする相対 IdentityFile はこの鍵かもしれず、
	// エンジンはそうでないと証明できない。半端にしか適用できない
	// 名前変更は丸ごと拒否される。鍵の relocation が適用するのと同じ規則である。
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "40-relative.conf"),
		[]byte("Host other\n\tIdentityFile id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var blocked *GroupBlockedError
	_, err := service.RenameGroup(keyInventory(t, workspace), "work", "client-a")
	if !errors.As(err, &blocked) {
		t.Fatalf("RenameGroup error = %v, want *GroupBlockedError", err)
	}
	if len(blocked.Blockers) == 0 || !strings.HasPrefix(blocked.Blockers[0], BlockerKeyUnresolved) {
		t.Errorf("blockers = %#v", blocked.Blockers)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "keys", "work", "id_work")); statErr != nil {
		t.Errorf("a blocked rename moved the key: %v", statErr)
	}
}

func TestGroupRenameLeavesEveryByteOutsideTheRegionAlone(t *testing.T) {
	service, workspace := groupRenameFixture(t)
	entry := readFile(t, workspace, "config")
	const external = "\nHost added-by-hand\n\tHostName 192.0.2.99\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(entry+external), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := service.RenameGroup(keyInventory(t, workspace), "work", "client-a"); err != nil {
		t.Fatalf("RenameGroup error = %v", err)
	}

	// 名前変更は region だけを書き換えるので、ユーザーがその下に
	// 追加したブロックは 1 バイトも変わらずそこにある。
	if !strings.HasSuffix(readFile(t, workspace, "config"), external) {
		t.Errorf("the hand-written block was disturbed:\n%s", readFile(t, workspace, "config"))
	}
}

func TestDeleteGroupRelocatesItsConnectionsAndNeverDeletesAFile(t *testing.T) {
	service, workspace := groupRenameFixture(t)
	declareGroup(t, service, "work", "work/eu", "archive")

	if _, err := service.DeleteGroup(keyInventory(t, workspace), "work", "archive"); err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}

	// 両方のファイルが destination に到着した — 削除は平坦化する。
	// 「このグループは無くなる」はその下の階層を保てないからだ。
	for _, name := range []string{"connections/archive/web.conf", "connections/archive/lon.conf"} {
		if _, err := os.Lstat(filepath.Join(workspace.Root(), filepath.FromSlash(name))); err != nil {
			t.Errorf("%s is not there: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(workspace.Root(), "keys", "archive", "id_work")); err != nil {
		t.Errorf("the group's key did not follow: %v", err)
	}
	entry := readFile(t, workspace, "config")
	if strings.Contains(entry, "connections/work") {
		t.Errorf("the deleted group is still declared: %q", entry)
	}
	if !strings.Contains(entry, "Include connections/archive/*.conf") {
		t.Errorf("the destination is not declared: %q", entry)
	}
}

func TestDeleteGroupRefusesADestinationThatIsNotDeclared(t *testing.T) {
	service, workspace := groupRenameFixture(t)

	if _, err := service.DeleteGroup(keyInventory(t, workspace), "work", "archive"); !errors.Is(err, ErrGroupNotDeclared) {
		t.Fatalf("DeleteGroup error = %v, want ErrGroupNotDeclared", err)
	}
	if _, err := service.DeleteGroup(keyInventory(t, workspace), "marketing", ""); !errors.Is(err, ErrGroupNotDeclared) {
		t.Fatalf("DeleteGroup of an undeclared group = %v, want ErrGroupNotDeclared", err)
	}
}

func TestGroupOperationsRefuseANameThatIsNotASafeDirectory(t *testing.T) {
	service, workspace := groupRenameFixture(t)
	inventory := keyInventory(t, workspace)

	for _, name := range []string{"../escape", "", "sshc"} {
		if _, err := service.RenameGroup(inventory, "work", name); !errors.Is(err, ErrInvalidGroupName) {
			t.Errorf("RenameGroup to %q = %v, want ErrInvalidGroupName", name, err)
		}
	}
	if _, err := service.RenameGroup(inventory, "work", "work/inside"); !errors.Is(err, ErrGroupSelfNesting) {
		t.Errorf("nesting a group inside itself was allowed")
	}
}

// destination なしでグループを削除すると、その connections は
// どの Include も名指ししない connections/ の直下に残る。
// 操作自体は意図的だが、その沈黙は意図的ではなかった。
func TestDeleteGroupWarnsThatItsConnectionsWillBeUnreached(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeGroupFile(t, workspace, "work", "hosts.conf", "Host inwork\n\tUser aida\n")

	result, err := service.DeleteGroup(keyInventory(t, workspace), "work", "")
	if err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	found := false
	for _, notice := range result.Preview.Notices {
		if notice.Code == NoticeGroupFileUnreached {
			found = true
		}
	}
	if !found {
		t.Errorf("notices = %#v, want group_file_unreached", result.Preview.Notices)
	}
}

func TestDeleteGroupIntoAnotherGroupDoesNotWarn(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work", "keep")
	writeGroupFile(t, workspace, "work", "hosts.conf", "Host inwork\n\tUser aida\n")

	result, err := service.DeleteGroup(keyInventory(t, workspace), "work", "keep")
	if err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	for _, notice := range result.Preview.Notices {
		if notice.Code == NoticeGroupFileUnreached {
			t.Errorf("a connection that stayed inside a group was called unreached: %#v", notice)
		}
	}
}

// 鍵を保持するグループは destination を名指ししなければ
// 削除できなかった: 鍵はワークスペースのルートへ向けられ、
// そのディレクトリは "." であり、path ヘルパーはそれがルート
// 自体だという理由で拒否する。その拒否は "path is outside the
// ssh directory" として届き、原因もユーザーの行為も何も説明していなかった。
//
// 鍵は connection と同じ場所へ行く: それぞれ自身のツリーの
// 直下、鍵は keys/、connection は connections/ であり、両方とも
// インベントリと explorer が引き続き見える場所にとどまる。
func TestDeleteGroupHoldingAKeyNeedsNoDestination(t *testing.T) {
	service, workspace := groupRenameFixture(t)

	if _, err := service.DeleteGroup(keyInventory(t, workspace), "work", ""); err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	for _, name := range []string{"keys/id_work", "keys/id_work.pub", "connections/web.conf"} {
		if _, err := os.Lstat(filepath.Join(workspace.Root(), filepath.FromSlash(name))); err != nil {
			t.Errorf("%s is not there: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(workspace.Root(), "id_work")); err == nil {
		t.Error("the key was left loose in the workspace root")
	}
}
