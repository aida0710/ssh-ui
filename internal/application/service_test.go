package application

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshc/internal/storage"
)

const serviceMainConfig = `# personal configuration
Include conf.d/*.conf

Host bastion
	HostName 203.0.113.10
	User ops
	Port 22

Host *
	ServerAliveInterval 30
`

func newTestService(t *testing.T) (*Service, *storage.Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	if err := workspace.EnsureDirectory(filepath.Join(workspace.Root(), "conf.d")); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"config":              serviceMainConfig,
		"conf.d/10-home.conf": "Host nas\n\tUser aida\t# personal\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(workspace.Root(), filepath.FromSlash(name)), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager := storage.NewManager(workspace, time.Now, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	return NewService(workspace, manager), workspace
}

// writeGroupFile は、そのグループが示す場所に connection ファイルを置く。
func writeGroupFile(t *testing.T, workspace *storage.Workspace, group, name, contents string) string {
	t.Helper()
	relative := GroupDirectory(group) + "/" + name
	absolute := filepath.Join(workspace.Root(), filepath.FromSlash(relative))
	if err := workspace.EnsureDirectory(filepath.Dir(absolute)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return relative
}

func readFile(t *testing.T, workspace *storage.Workspace, relative string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(workspace.Root(), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestOverviewListsIncludeTreeHostsAndDiagnostics(t *testing.T) {
	service, _ := newTestService(t)

	overview, err := service.Overview()
	if err != nil {
		t.Fatal(err)
	}
	if overview.Entry.Path != "config" || len(overview.Files) != 2 {
		t.Fatalf("overview files = %#v", overview.Files)
	}
	if overview.Files[0].File.Path != "config" || len(overview.Files[0].Includes) != 1 {
		t.Fatalf("entry node = %#v", overview.Files[0])
	}
	if overview.Files[0].Includes[0].Matches[0].Path != "conf.d/10-home.conf" {
		t.Fatalf("include matches = %#v", overview.Files[0].Includes[0].Matches)
	}
	aliases := []string{}
	for _, host := range overview.Hosts {
		aliases = append(aliases, host.Identity.Alias)
	}
	if len(aliases) != 3 || aliases[0] != "nas" || aliases[1] != "bastion" || aliases[2] != "" {
		t.Fatalf("aliases = %#v", aliases)
	}
	if overview.Metadata.SchemaVersion != MetadataSchemaVersion {
		t.Fatalf("metadata = %#v", overview.Metadata)
	}
	if len(overview.Pending) != 0 {
		t.Fatalf("pending = %#v", overview.Pending)
	}
}

func TestSaveHostFieldsWritesOnlyTheEditedFile(t *testing.T) {
	service, workspace := newTestService(t)

	preview, err := service.Preview(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Diffs) != 1 || preview.Diffs[0].Path != "config" {
		t.Fatalf("preview = %#v", preview)
	}
	changed := 0
	for _, line := range preview.Diffs[0].Lines {
		if line.Op != DiffContext {
			changed++
		}
	}
	if changed != 2 {
		t.Fatalf("preview changed %d lines, want one delete and one insert", changed)
	}
	if readFile(t, workspace, "config") != serviceMainConfig {
		t.Fatal("preview must not write to disk")
	}

	result, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TransactionID == "" || len(result.Written) != 1 || result.Written[0] != "config" {
		t.Fatalf("result = %#v", result)
	}
	want := bytes.Replace([]byte(serviceMainConfig), []byte("Port 22\n"), []byte("Port 2222\n"), 1)
	if readFile(t, workspace, "config") != string(want) {
		t.Fatalf("config = %q", readFile(t, workspace, "config"))
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "Host nas\n\tUser aida\t# personal\n" {
		t.Fatal("an unrelated file changed during the commit")
	}
}

// TestFieldEditLineNumbersAreOneBasedAcrossTheServiceBoundary は、
// service が担う唯一の変換を固定する。config 側の index は 0-based であり、
// この境界を越えるすべての行番号は 1-based である。このテストは、
// service 自身が報告した行番号をそのまま編集として送り返すので、変換を落とすかそれを
// 二重に適用すると、User ではなく HostName や Port を書き換えてしまい失敗する。
func TestFieldEditLineNumbersAreOneBasedAcrossTheServiceBoundary(t *testing.T) {
	service, workspace := newTestService(t)

	detail, err := service.HostDetail("config", "bastion")
	if err != nil {
		t.Fatal(err)
	}
	var userField FormField
	for _, field := range detail.Form.Fields {
		if field.Keyword == "User" {
			userField = field
		}
	}
	if userField.Line != 6 {
		t.Fatalf("reported User line = %d, want the 1-based line 6", userField.Line)
	}

	if _, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: userField.Line, Values: []string{"root"}}},
	}); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(serviceMainConfig, "\tUser ops\n", "\tUser root\n", 1)
	if got := readFile(t, workspace, "config"); got != want {
		t.Fatalf("config = %q, want %q", got, want)
	}
}

func TestSaveRejectsAStaleBaseWithAThreeWayReport(t *testing.T) {
	service, workspace := newTestService(t)
	externallyChanged := serviceMainConfig + "\nHost added-elsewhere\n\tUser other\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(externallyChanged), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *ConflictError", err)
	}
	if conflict.Report.Path != "config" || len(conflict.Report.ExternalChange) == 0 || len(conflict.Report.LocalChange) == 0 {
		t.Fatalf("report = %#v", conflict.Report)
	}
	if readFile(t, workspace, "config") != externallyChanged {
		t.Fatal("a conflicting save must not write")
	}
}

func TestSaveRejectsRawTextThatBreaksQuotingAndWritesNothing(t *testing.T) {
	service, workspace := newTestService(t)

	_, err := service.Save(EditRequest{
		Kind: EditFileRaw,
		Path: "conf.d/10-home.conf",
		Base: "Host nas\n\tUser aida\t# personal\n",
		Raw:  "Host nas\n\tUser \"unbalanced\n",
	})
	var syntax *SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("error = %v, want *SyntaxError", err)
	}
	if syntax.Path != "conf.d/10-home.conf" || syntax.Line != 2 || syntax.Column == 0 {
		t.Fatalf("syntax error = %#v", syntax)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "Host nas\n\tUser aida\t# personal\n" {
		t.Fatal("a rejected raw save must not write")
	}
}

func TestSaveRejectsAnEditThatIntroducesAnIncludeCycle(t *testing.T) {
	service, workspace := newTestService(t)

	_, err := service.Save(EditRequest{
		Kind: EditFileRaw,
		Path: "conf.d/10-home.conf",
		Base: "Host nas\n\tUser aida\t# personal\n",
		Raw:  "Include config\nHost nas\n\tUser aida\n",
	})
	var graphError *GraphError
	if !errors.As(err, &graphError) {
		t.Fatalf("error = %v, want *GraphError", err)
	}
	if len(graphError.Diagnostics) == 0 || graphError.Diagnostics[0].Severity != "error" {
		t.Fatalf("diagnostics = %#v", graphError.Diagnostics)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "Host nas\n\tUser aida\t# personal\n" {
		t.Fatal("a rejected save must not write")
	}
}

// TestSaveIsBlockedOnlyByBreakageItIntroduces は、validation 規則の
// 両半分を証明する。既存の壊れ——SeverityError の diagnostic である
// Include cycle と、parser が分解できない行——は、無関係な save を
// 妨げてはならない。壊れたファイルを引き継いだユーザーは、それでも
// 1 回の編集ずつ直せなければならないからである。編集それ自体が
// 加える壊れは拒否されなければならない。
func TestSaveIsBlockedOnlyByBreakageItIntroduces(t *testing.T) {
	service, workspace := newTestService(t)
	const broken = "Include config\nHost nas\n\tUser aida\n\tSendEnv \"broken\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "10-home.conf"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	// 半分の 1 つ目。graph が終始 SeverityError の cycle を抱えているにも
	// かかわらず、既に壊れている graph へ何も新しいものを持ち込まない save は成功する。
	if _, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2022"}}},
	}); err != nil {
		t.Fatalf("pre-existing breakage blocked an unrelated save: %v", err)
	}
	if !strings.Contains(readFile(t, workspace, "config"), "\tPort 2022\n") {
		t.Fatalf("config = %q", readFile(t, workspace, "config"))
	}

	// 依然として半分の 1 つ目、今度は壊れたファイル自体を編集する。
	// 既存の parse できない行を残したまま別の行を変更することは許される。
	const keptBroken = "Include config\nHost nas\n\tUser root\n\tSendEnv \"broken\n"
	if _, err := service.Save(EditRequest{
		Kind: EditFileRaw,
		Path: "conf.d/10-home.conf",
		Base: broken,
		Raw:  keptBroken,
	}); err != nil {
		t.Fatalf("keeping a pre-existing unparsable line was refused: %v", err)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != keptBroken {
		t.Fatalf("conf.d/10-home.conf = %q", readFile(t, workspace, "conf.d/10-home.conf"))
	}

	// 半分の 2 つ目。同じファイル、同じ既存の壊れに加えて、新たに parse できなくなった
	// 1 行がある。拒否されるのはその新しい行だけであり、何も書き込まれない。
	_, err := service.Save(EditRequest{
		Kind: EditFileRaw,
		Path: "conf.d/10-home.conf",
		Base: keptBroken,
		Raw:  keptBroken + "\tSetEnv \"another\n",
	})
	var syntax *SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("error = %v, want *SyntaxError for the newly broken line", err)
	}
	if syntax.Line != 5 {
		t.Fatalf("syntax error = %#v, want the newly added line 5", syntax)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != keptBroken {
		t.Fatal("a rejected save must not write")
	}
}

func TestSaveGroupsWritesConfigurationAndMetadataInOneTransaction(t *testing.T) {
	service, workspace := newTestService(t)
	// membership はファイルが置かれている場所なので、ホストはそこに
	// 置かれなければならない——そしてそこにだけ。2 個のブロックが 1 個の
	// alias を宣言するのは別の状況であり、それ専用の通知を持つ。この
	// save が書き込む生成領域こそが、connections/home/*.conf をそもそも読ませているものである。
	if err := os.Remove(filepath.Join(workspace.Root(), "conf.d", "10-home.conf")); err != nil {
		t.Fatal(err)
	}
	writeGroupFile(t, workspace, "home", "nas.conf", "Host nas\n\tUser aida\t# personal\n")
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{
		Name:     "home",
		Settings: []Setting{{Keyword: "Port", Values: []string{"2222"}}},
	}}

	preview, err := service.Preview(EditRequest{Kind: EditGroups, Metadata: &metadata})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Diffs) != 3 {
		t.Fatalf("group preview diffs = %#v", preview.Diffs)
	}
	if len(preview.Effective) != 1 || preview.Effective[0].Alias != "nas" {
		t.Fatalf("effective preview = %#v", preview.Effective)
	}
	// 1 個ではなく 2 個の変更。この save こそが connections/home を読める
	// ようにするものなので、ホストそれ自身の User がグループの Port と同じ瞬間に到着する。
	// "Port changed"とだけ言うことは、この save が行っていることの半分を隠してしまう。
	changed := map[string]string{}
	for _, change := range preview.Effective[0].Changes {
		changed[change.Keyword] = strings.Join(change.After, " ")
	}
	if changed["Port"] != "2222" || changed["User"] != "aida" {
		t.Fatalf("effective changes = %#v", preview.Effective[0].Changes)
	}

	if _, err := service.Save(EditRequest{Kind: EditGroups, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}
	groups := readFile(t, workspace, DefaultGroupsFile)
	if !bytes.Contains([]byte(groups), []byte("Host nas\n\tPort 2222\n")) {
		t.Fatalf("groups file = %q", groups)
	}
	entry := readFile(t, workspace, "config")
	// 宣言済みグループごとに 1 本の Include、それに続く settings ファイル、
	// それらすべてが生成領域の内側にある。
	for _, want := range []string{
		RegionStartMarker,
		"Include " + GroupIncludePattern("home") + "\n",
		"Include " + DefaultGroupsFile + "\n",
		RegionEndMarker,
	} {
		if !bytes.Contains([]byte(entry), []byte(want)) {
			t.Fatalf("entry config = %q, want it to contain %q", entry, want)
		}
	}
	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Groups) != 1 || stored.Groups[0].Name != "home" {
		t.Fatalf("stored metadata = %#v", stored)
	}

	detail, err := service.HostDetail(GroupDirectory("home")+"/nas.conf", "nas")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range detail.Effective.Entries {
		if entry.Keyword == "Port" && entry.Values[0] == "2222" && entry.Source.Path == DefaultGroupsFile {
			found = true
		}
	}
	if !found {
		t.Fatalf("effective entries = %#v", detail.Effective.Entries)
	}
}

func TestSaveRenameUpdatesTheHostLineAndMetadataTogether(t *testing.T) {
	service, workspace := newTestService(t)
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "keep me"}}
	if _, err := service.Save(EditRequest{Kind: EditMetadata, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Save(EditRequest{
		Kind:     EditRename,
		Path:     "config",
		Base:     serviceMainConfig,
		Alias:    "bastion",
		NewAlias: "jump",
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(readFile(t, workspace, "config")), []byte("Host jump\n")) {
		t.Fatalf("config = %q", readFile(t, workspace, "config"))
	}
	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Hosts) != 1 || stored.Hosts[0].Identity.Alias != "jump" || stored.Hosts[0].Note != "keep me" || stored.Hosts[0].Orphan {
		t.Fatalf("stored metadata = %#v", stored.Hosts)
	}
}

func TestHistoryListsCommitsAndRestoreRevertsOneFile(t *testing.T) {
	service, workspace := newTestService(t)
	if _, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	}); err != nil {
		t.Fatal(err)
	}

	history, err := service.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Operation != "config.host_fields" || len(history[0].Restorable) != 1 {
		t.Fatalf("history = %#v", history)
	}
	if _, err := service.Restore(history[0].ID, "config"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, workspace, "config") != serviceMainConfig {
		t.Fatalf("config after restore = %q", readFile(t, workspace, "config"))
	}
	if _, err := service.Restore("no-such-transaction", "config"); !errors.Is(err, storage.ErrUnknownTransaction) {
		t.Fatalf("unknown restore error = %v", err)
	}
}

// snapshotConfigFiles は、ワークスペース内のすべての設定ファイルを読むが、
// journal、history、backup が commit のたびに変化することが期待される sshc の状態ディレク
// トリはスキップする。これは、move が他の何にも触れないことを証明するために存在する。
func snapshotConfigFiles(t *testing.T, workspace *storage.Workspace) map[string]string {
	t.Helper()
	files := map[string]string{}
	root := workspace.Root()
	stateDir := workspace.StateDir()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path == stateDir {
				return filepath.SkipDir
			}
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files[filepath.ToSlash(relative)] = string(contents)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSaveMoveCommitsBothFilesAndMetadataInOneTransaction(t *testing.T) {
	service, workspace := newTestService(t)
	const untouched = "Host work\n\tUser ops\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "20-work.conf"), []byte(untouched), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "keep me"}}
	if _, err := service.Save(EditRequest{Kind: EditMetadata, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}

	before := snapshotConfigFiles(t, workspace)

	const homeConfig = "Host nas\n\tUser aida\t# personal\n"
	request := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "conf.d/10-home.conf",
		DestinationBase: homeConfig,
	}

	preview, err := service.Preview(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Diffs) != 3 {
		t.Fatalf("move preview diffs = %#v", preview.Diffs)
	}
	if len(preview.Effective) != 1 || preview.Effective[0].Alias != "bastion" {
		t.Fatalf("move preview effective = %#v", preview.Effective)
	}
	// そのブロックが運ぶすべてのディレクティブは値を保ったまま新しい source
	// ファイルを報告する。それこそがユーザーが見る必要のある並び替え
	// である。ServerAliveInterval は依然としてエントリファイルの Host *
	// ブロックから、同じ値と同じ governing condition で来ている。変わったのはその行番号だけ
	// であり、それは上にあったブロックが去ったためであって、純粋な行のずれは変更ではない。
	wantSourceFile := map[string]string{
		"HostName": "conf.d/10-home.conf",
		"Port":     "conf.d/10-home.conf",
		"User":     "conf.d/10-home.conf",
	}
	if len(preview.Effective[0].Changes) != len(wantSourceFile) {
		t.Fatalf("effective changes = %#v", preview.Effective[0].Changes)
	}
	for _, change := range preview.Effective[0].Changes {
		if !equalStrings(change.Before, change.After) {
			t.Fatalf("moving a block must not change a value: %#v", change)
		}
		want, known := wantSourceFile[change.Keyword]
		if !known {
			t.Fatalf("unexpected changed keyword: %#v", change)
		}
		if change.BeforeSources[0].Path != "config" || change.AfterSources[0].Path != want {
			t.Fatalf("%s source = %#v -> %#v, want it to end in %q", change.Keyword, change.BeforeSources[0], change.AfterSources[0], want)
		}
	}

	result, err := service.Save(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Written) != 3 {
		t.Fatalf("written = %#v", result.Written)
	}

	const wantSourceContents = "# personal configuration\nInclude conf.d/*.conf\n\nHost *\n\tServerAliveInterval 30\n"
	if got := readFile(t, workspace, "config"); got != wantSourceContents {
		t.Fatalf("source = %q", got)
	}
	wantDestination := homeConfig + "\nHost bastion\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 22\n\n"
	if got := readFile(t, workspace, "conf.d/10-home.conf"); got != wantDestination {
		t.Fatalf("destination = %q", got)
	}

	// 設定 tree の他の何も、1 バイトたりとも動いていないはずである。
	after := snapshotConfigFiles(t, workspace)
	if len(after) != len(before) {
		t.Fatalf("the move added or removed a file: before %v, after %v", before, after)
	}
	touched := map[string]bool{"config": true, "conf.d/10-home.conf": true}
	for path, contents := range after {
		if touched[path] {
			continue
		}
		if contents != before[path] {
			t.Fatalf("%s changed during the move: %q -> %q", path, before[path], contents)
		}
	}
	if after["conf.d/20-work.conf"] != untouched {
		t.Fatalf("an untouched file changed: %q", after["conf.d/20-work.conf"])
	}

	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Hosts) != 1 {
		t.Fatalf("stored hosts = %#v", stored.Hosts)
	}
	if stored.Hosts[0].Identity.Path != "conf.d/10-home.conf" || stored.Hosts[0].Note != "keep me" || stored.Hosts[0].Orphan {
		t.Fatalf("metadata after the move = %#v", stored.Hosts[0])
	}

	if _, err := service.HostDetail("conf.d/10-home.conf", "bastion"); err != nil {
		t.Fatalf("the moved host is not readable at its new path: %v", err)
	}
}

func TestSaveMoveRefusesADuplicateAliasAndANonEditableDestination(t *testing.T) {
	service, workspace := newTestService(t)
	const homeConfig = "Host nas\n\tUser aida\t# personal\n"

	duplicate := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "conf.d/10-home.conf",
		DestinationBase: homeConfig + "Host bastion\n\tUser other\n",
	}
	if _, err := service.Save(duplicate); !errors.Is(err, ErrDuplicateDestinationAlias) {
		t.Fatalf("duplicate alias error = %v", err)
	}

	outside := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "../.bashrc",
		DestinationBase: "",
	}
	if _, err := service.Save(outside); !errors.Is(err, ErrExternalPath) {
		t.Fatalf("outside destination error = %v", err)
	}

	same := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "config",
		DestinationBase: serviceMainConfig,
	}
	if _, err := service.Save(same); !errors.Is(err, ErrSameFileMove) {
		t.Fatalf("same file error = %v", err)
	}

	if got := readFile(t, workspace, "config"); got != serviceMainConfig {
		t.Fatal("a refused move must write nothing")
	}
	if got := readFile(t, workspace, "conf.d/10-home.conf"); got != homeConfig {
		t.Fatal("a refused move must write nothing")
	}
}

func TestSaveMoveReportsAStaleDestinationBase(t *testing.T) {
	service, workspace := newTestService(t)
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "10-home.conf"), []byte("Host nas\n\tUser changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stale := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "conf.d/10-home.conf",
		DestinationBase: "Host nas\n\tUser aida\t# personal\n",
	}

	// Preview は Commit に決して到達しないので、ここでは古くなった destination を捉えられるのは
	// planner 自身の事前条件チェックだけである。Save だけについて assert
	// すると、storage 層のチェックを通ってしまい、planner については何も証明しない。
	_, previewErr := service.Preview(stale)
	var previewConflict *ConflictError
	if !errors.As(previewErr, &previewConflict) {
		t.Fatalf("preview error = %v, want *ConflictError", previewErr)
	}
	if previewConflict.Report.Path != "conf.d/10-home.conf" {
		t.Fatalf("preview conflict report = %#v", previewConflict.Report)
	}

	_, err := service.Save(stale)
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *ConflictError", err)
	}
	if conflict.Report.Path != "conf.d/10-home.conf" {
		t.Fatalf("conflict report = %#v", conflict.Report)
	}
	if got := readFile(t, workspace, "config"); got != serviceMainConfig {
		t.Fatal("a conflicting move must write nothing")
	}
}

func TestSaveMoveReportsAStaleSourceBase(t *testing.T) {
	service, workspace := newTestService(t)
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(serviceMainConfig+"\nHost later\n\tUser other\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stale := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "conf.d/10-home.conf",
		DestinationBase: "Host nas\n\tUser aida\t# personal\n",
	}

	_, previewErr := service.Preview(stale)
	var previewConflict *ConflictError
	if !errors.As(previewErr, &previewConflict) {
		t.Fatalf("preview error = %v, want *ConflictError", previewErr)
	}
	if previewConflict.Report.Path != "config" {
		t.Fatalf("a stale source must name the source file in preview: %#v", previewConflict.Report)
	}

	_, err := service.Save(stale)
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *ConflictError", err)
	}
	if conflict.Report.Path != "config" {
		t.Fatalf("a stale source must name the source file: %#v", conflict.Report)
	}
	if got := readFile(t, workspace, "conf.d/10-home.conf"); got != "Host nas\n\tUser aida\t# personal\n" {
		t.Fatal("a conflicting move must write nothing")
	}
}

func TestSaveMoveWarnsWhenNoIncludeReachesTheDestination(t *testing.T) {
	service, workspace := newTestService(t)
	const orphanFile = "# not reached by any Include\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "detached.conf"), []byte(orphanFile), 0o600); err != nil {
		t.Fatal(err)
	}

	preview, err := service.Preview(EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "detached.conf",
		DestinationBase: orphanFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, notice := range preview.Notices {
		if notice.Code == NoticeDestinationNotIncluded && notice.Path == "detached.conf" {
			found = true
		}
	}
	if !found {
		t.Fatalf("notices = %#v, want a destination_not_included notice", preview.Notices)
	}
}

// declareGroup は、グループが存在するように生成領域をエントリファイルに書き込む。
// 宣言することが、ディレクトリをグループにしているものである。move はそれを副作用として
// 行うことを拒否するので、move するテストは先に宣言しなければならない。
func declareGroup(t *testing.T, service *Service, names ...string) {
	t.Helper()
	metadata := NewMetadata()
	for _, name := range names {
		metadata.Groups = append(metadata.Groups, GroupMetadata{Name: name})
	}
	if _, err := service.Save(EditRequest{Kind: EditGroups, Metadata: &metadata}); err != nil {
		t.Fatalf("declare %v: %v", names, err)
	}
}

func TestMoveHostIntoAGroupDerivesTheDestinationPath(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")

	const homeConfig = "Host nas\n\tUser aida\t# personal\n"
	if _, err := service.Save(EditRequest{
		Kind:             EditMove,
		Path:             "conf.d/10-home.conf",
		Base:             homeConfig,
		Alias:            "nas",
		DestinationGroup: "work",
	}); err != nil {
		t.Fatalf("Save error = %v", err)
	}

	// ファイルは自分自身の名前を保ったままディレクトリを変える。それは
	// shell においてもグループ間の move がそういうものであるのと同じである。
	moved := readFile(t, workspace, "connections/work/10-home.conf")
	if moved != homeConfig {
		t.Errorf("moved block = %q, want the bytes it had", moved)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "" {
		t.Errorf("the source still declares the host")
	}
}

// エントリファイルは、グループ化されていないすべての connection が始まる場所であり、
// そこから 1 個を移動することが、ワークスペースが行う最初の move である。そのファイル名は
// "config"であり、これは"connections/<group>/*.conf"に match しないので、そこから逐語的に
// 導出された destination は書き込まれた後で決して読まれることがなくなる。両方のファイル
// がディスク上では正しく見えているのに、connection は OpenSSH が見る設定から消えてしまう。
func TestMoveHostFromTheEntryFileIntoAGroupLandsWhereTheIncludeReadsIt(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")

	if _, err := service.Save(EditRequest{
		Kind:             EditMove,
		Path:             "config",
		Base:             readFile(t, workspace, "config"),
		Alias:            "bastion",
		DestinationGroup: "work",
	}); err != nil {
		t.Fatalf("Save error = %v", err)
	}

	overview, err := service.Overview()
	if err != nil {
		t.Fatal(err)
	}
	var moved *HostEntry
	for index := range overview.Hosts {
		if overview.Hosts[index].Identity.Alias == "bastion" {
			moved = &overview.Hosts[index]
		}
	}
	if moved == nil {
		t.Fatal("the moved connection is not read back: no Include reaches where it was written")
	}
	if moved.Group != "work" {
		t.Errorf("group = %q, want work", moved.Group)
	}
}

// この通知は、Include を追加するまで OpenSSH がそのブロックを読まないことを
// ユーザーに伝える。宣言済みのグループは既にそれを持っており、destination は
// match するように名指されているので、ここで別のことを言うと、それが真であるまさに
// その 1 つのケースで、ユーザーに警告をクリックして通り過ぎることを訓練してしまう。
func TestMoveHostIntoADeclaredGroupDoesNotWarnThatNoIncludeReachesIt(t *testing.T) {
	service, _ := newTestService(t)
	declareGroup(t, service, "work")

	preview, err := service.Preview(EditRequest{
		Kind:             EditMove,
		Path:             "conf.d/10-home.conf",
		Base:             "Host nas\n\tUser aida\t# personal\n",
		Alias:            "nas",
		DestinationGroup: "work",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, notice := range preview.Notices {
		if notice.Code == NoticeDestinationNotIncluded {
			t.Fatalf("the group's Include reaches the destination: %#v", preview.Notices)
		}
	}
}

func TestMoveHostIntoAGroupUpdatesTheMetadataIdentityInTheSameTransaction(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")

	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{Name: "work"}}
	metadata.Hosts = []HostMetadata{{
		Identity:  HostIdentity{Path: "conf.d/10-home.conf", Alias: "nas"},
		Tags:      []string{"personal"},
		Colour:    "#22d3ee",
		Favourite: true,
		Order:     3,
	}}
	if _, err := service.Save(EditRequest{Kind: EditMetadata, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Save(EditRequest{
		Kind:             EditMove,
		Path:             "conf.d/10-home.conf",
		Base:             "Host nas\n\tUser aida\t# personal\n",
		Alias:            "nas",
		DestinationGroup: "work",
	}); err != nil {
		t.Fatalf("Save error = %v", err)
	}

	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Hosts) != 1 {
		t.Fatalf("hosts = %#v", stored.Hosts)
	}
	host := stored.Hosts[0]
	// path が変わったので identity も変わり、entry が運んでいたすべての
	// ものは、orphan になるのではなくそれと共に移動した。
	if host.Identity.Path != "connections/work/10-home.conf" || host.Orphan {
		t.Errorf("identity = %#v", host)
	}
	if host.Colour != "#22d3ee" || !host.Favourite || host.Order != 3 || len(host.Tags) != 1 {
		t.Errorf("the entry lost presentation on the way: %#v", host)
	}

	overview, err := service.Overview()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range overview.Hosts {
		if entry.Identity.Alias == "nas" && entry.Group != "work" {
			t.Errorf("projected group = %q, want work", entry.Group)
		}
	}
	_ = workspace
}

func TestMoveHostIntoAnUndeclaredGroupIsRefusedAndLeavesNoDirectory(t *testing.T) {
	service, workspace := newTestService(t)

	_, err := service.Save(EditRequest{
		Kind:             EditMove,
		Path:             "conf.d/10-home.conf",
		Base:             "Host nas\n\tUser aida\t# personal\n",
		Alias:            "nas",
		DestinationGroup: "marketing",
	})
	if !errors.Is(err, ErrGroupNotDeclared) {
		t.Fatalf("Save error = %v, want ErrGroupNotDeclared", err)
	}
	// 拒否は何も後に残してはならない、それが必要としていた
	// はずのディレクトリでさえも。
	if _, statErr := os.Stat(filepath.Join(workspace.Root(), "connections")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a refused move created the connections directory: %v", statErr)
	}
}

func TestMoveHostRefusesBothADestinationGroupAndAPath(t *testing.T) {
	service, _ := newTestService(t)
	declareGroup(t, service, "work")

	_, err := service.Save(EditRequest{
		Kind:             EditMove,
		Path:             "conf.d/10-home.conf",
		Base:             "Host nas\n\tUser aida\t# personal\n",
		Alias:            "nas",
		DestinationGroup: "work",
		DestinationPath:  "conf.d/20-work.conf",
	})
	if !errors.Is(err, ErrAmbiguousDestination) {
		t.Fatalf("Save error = %v, want ErrAmbiguousDestination", err)
	}
}

func TestASecondConnectionCanBeMovedIntoAGroupThatAlreadyHoldsOne(t *testing.T) {
	// 実際のワークスペースから報告された bug。グループへの最初の connection
	// は成功し、それ以降のものはすべて"this file was changed outside
	// the application"で失敗し、起きてもいない外部編集を名指していた。
	//
	// グループを名指す move は destination ファイルを名指さないので、
	// クライアントはそれを読んだことがなく、そのバイト列を送ることも
	// できなかった。代わりに送った空の base は、その時点で最初の
	// connection を既に保持していたディスク上のグループファイルと比較された——つまり比較は
	// "nothing"と"このアプリケーションがたった今自分で行った作業"の間で行われたのである。
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")

	const both = "Host nas\n\tUser aida\n\nHost printer\n\tHostName 198.51.100.30\n"
	if err := os.WriteFile(
		filepath.Join(workspace.Root(), filepath.FromSlash("conf.d/10-home.conf")), []byte(both), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Save(EditRequest{
		Kind: EditMove, Path: "conf.d/10-home.conf", Base: both,
		Alias: "nas", DestinationGroup: "work",
	}); err != nil {
		t.Fatalf("the first move = %v", err)
	}

	remaining := readFile(t, workspace, "conf.d/10-home.conf")
	if _, err := service.Save(EditRequest{
		Kind: EditMove, Path: "conf.d/10-home.conf", Base: remaining,
		Alias: "printer", DestinationGroup: "work",
	}); err != nil {
		t.Fatalf("the second move into the same group = %v", err)
	}

	// 両方ともグループファイルの中にあり、最初のものが 2 番目のもので
	// 上書きされることはなかった——それが、これが"fixed"にされ得たもう 1 つのやり方である。
	moved := readFile(t, workspace, "connections/work/10-home.conf")
	if !strings.Contains(moved, "Host nas") || !strings.Contains(moved, "Host printer") {
		t.Errorf("the group file holds %q, want both connections", moved)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "" {
		t.Errorf("the source still holds something: %q", readFile(t, workspace, "conf.d/10-home.conf"))
	}
}

func TestAGroupMoveStillRefusesAFileThatChangedUnderIt(t *testing.T) {
	// クライアントが決して持っていなかった base を信用するのではなく
	// destination を読むことは、"write regardless"になってはならない。
	// source 側の base は依然としてクライアントのものであり依然としてチェックされ、
	// destination のために読まれる digest は、storage が commit 中に検証する事前条件である。
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")

	const both = "Host nas\n\tUser aida\n\nHost printer\n\tHostName 198.51.100.30\n"
	if err := os.WriteFile(
		filepath.Join(workspace.Root(), filepath.FromSlash("conf.d/10-home.conf")), []byte(both), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Save(EditRequest{
		Kind: EditMove, Path: "conf.d/10-home.conf", Base: both,
		Alias: "nas", DestinationGroup: "work",
	}); err != nil {
		t.Fatalf("the first move = %v", err)
	}

	// 2 回目の move は、最初の move より前の base を運んでいる。それは
	// 2 番目の browser tab が送るであろうものである。
	var conflict *ConflictError
	_, err := service.Save(EditRequest{
		Kind: EditMove, Path: "conf.d/10-home.conf", Base: both,
		Alias: "printer", DestinationGroup: "work",
	})
	if !errors.As(err, &conflict) {
		t.Fatalf("Save = %v, want a conflict on the stale source", err)
	}
	if conflict.Report.Path != "conf.d/10-home.conf" {
		t.Errorf("the conflict names %q, want the source", conflict.Report.Path)
	}
}

// 何か他のものが既に宣言している alias に着地する rename は、第 2 の
// ホストを作るわけではない。それは 1 個の名前への第 2 の主張を作り、
// OpenSSH はその名前を最初に読んだブロックへ与える。move path は
// 書かれたときからこれを拒否してきた。rename はそれを受け入れ、書き込み、何も言わなかった
// ので、rename は生きている alias をそれを所有していたホストから奪ってしまい得た。
func TestRenameOntoAnAliasAnotherFileDeclaresIsRefused(t *testing.T) {
	service, workspace := newTestService(t)
	before := readFile(t, workspace, "conf.d/10-home.conf")

	_, err := service.Save(EditRequest{
		Kind:     EditRename,
		Path:     "conf.d/10-home.conf",
		Base:     before,
		Alias:    "nas",
		NewAlias: "bastion", // エントリファイルによって宣言されている
	})
	if !errors.Is(err, ErrAliasAlreadyDeclared) {
		t.Fatalf("Save error = %v, want ErrAliasAlreadyDeclared", err)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != before {
		t.Error("a refused rename changed the file")
	}
}

func TestRenameOntoAnAliasTheSameFileDeclaresIsRefused(t *testing.T) {
	service, workspace := newTestService(t)
	const two = "Host nas\n\tUser aida\n\nHost attic\n\tUser aida\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "10-home.conf"),
		[]byte(two), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := service.Save(EditRequest{
		Kind: EditRename, Path: "conf.d/10-home.conf", Base: two,
		Alias: "nas", NewAlias: "attic",
	})
	if !errors.Is(err, ErrAliasAlreadyDeclared) {
		t.Fatalf("Save error = %v, want ErrAliasAlreadyDeclared", err)
	}
}

func TestRenameToAFreeAliasStillWorks(t *testing.T) {
	service, workspace := newTestService(t)
	before := readFile(t, workspace, "conf.d/10-home.conf")

	if _, err := service.Save(EditRequest{
		Kind: EditRename, Path: "conf.d/10-home.conf", Base: before,
		Alias: "nas", NewAlias: "attic",
	}); err != nil {
		t.Fatalf("Save error = %v", err)
	}
	if got := readFile(t, workspace, "conf.d/10-home.conf"); !strings.Contains(got, "Host attic") {
		t.Errorf("file = %q, want the renamed alias", got)
	}
}

// connections/配下にあってどの Include も名指していない.conf ファイルは、
// 誰にも読まれない。グループ delete は、destination を与えられなかったとき、interface
// がそれを報告するという明言された理解の下で、意図的にファイルをそこに置く。
// 何も報告しなかったので、connection は一言も言われることなく設定から抜け落ちてしまい得た。
func TestOverviewReportsAConnectionFileNothingIncludes(t *testing.T) {
	service, workspace := newTestService(t)
	if err := workspace.EnsureDirectory(filepath.Join(workspace.Root(), "connections")); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(workspace.Root(), "connections", "orphan.conf")
	if err := os.WriteFile(stray, []byte("Host nowhere\n\tUser nobody\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	overview, err := service.Overview()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, notice := range overview.Notices {
		if notice.Code == NoticeGroupFileUnreached && notice.Path == "connections/orphan.conf" {
			found = true
		}
	}
	if !found {
		t.Errorf("notices = %#v, want group_file_unreached for connections/orphan.conf", overview.Notices)
	}
}

func TestOverviewDoesNotCallAReachedGroupFileUnreached(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeGroupFile(t, workspace, "work", "hosts.conf", "Host inwork\n\tUser aida\n")

	overview, err := service.Overview()
	if err != nil {
		t.Fatal(err)
	}
	for _, notice := range overview.Notices {
		if notice.Code == NoticeGroupFileUnreached {
			t.Errorf("a file a group Include reaches was called unreached: %#v", notice)
		}
	}
}
