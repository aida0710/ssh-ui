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

// writeGroupFile puts a connection file where its group says it lives.
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

// TestFieldEditLineNumbersAreOneBasedAcrossTheServiceBoundary pins the one
// conversion the service owns: config indices are 0-based, every line number
// crossing this boundary is 1-based. The test feeds a line number the service
// itself reported straight back as an edit, so dropping the conversion or
// applying it twice rewrites HostName or Port instead of User and fails.
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

// TestSaveIsBlockedOnlyByBreakageItIntroduces proves both halves of the
// validation rule. Pre-existing breakage — an Include cycle that is a
// SeverityError diagnostic, and a line the parser cannot decompose — must not
// block an unrelated save, because a user who inherited a broken file must
// still be able to fix it one edit at a time. Breakage the edit itself adds
// must be refused.
func TestSaveIsBlockedOnlyByBreakageItIntroduces(t *testing.T) {
	service, workspace := newTestService(t)
	const broken = "Include config\nHost nas\n\tUser aida\n\tSendEnv \"broken\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "10-home.conf"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	// Half one: a save into an already-broken graph that introduces nothing new
	// succeeds, even though the graph carries a SeverityError cycle throughout.
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

	// Still half one, now editing the broken file itself: keeping the existing
	// unparsable line while changing another line is allowed.
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

	// Half two: the same file, the same pre-existing breakage, plus one newly
	// unparsable line. Only the new line is refused, and nothing is written.
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
	// Membership is where the file sits, so the host has to sit there — and
	// only there: two blocks declaring one alias is a different situation with
	// its own notice. The region this save writes is what makes
	// connections/home/*.conf read at all.
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
	// Two changes, not one: this save is what makes connections/home readable,
	// so the host's own User arrives at the same moment as the group's Port.
	// Saying only "Port changed" would hide half of what the save does.
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
	// One Include per declared group, then the settings file, all inside the
	// generated region.
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

// snapshotConfigFiles reads every configuration file in the workspace, skipping
// the sshc state directory whose journal, history and backups are expected to
// change on every commit. It exists to prove a move touches nothing else.
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
	// Every directive the block carries keeps its value and reports a new source
	// file, which is the reordering the user needs to see. ServerAliveInterval
	// still comes from the entry file's Host * block with the same value and the
	// same governing condition; only its line number shifted because the block
	// above it left, and a pure line shift is not a change.
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

	// Nothing else in the configuration tree may have moved a byte.
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

	// Preview never reaches Commit, so only the planner's own precondition check
	// can catch a stale destination here. Asserting on Save alone would pass on
	// the storage layer's check and prove nothing about the planner.
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

// declareGroup writes the region into the entry file so the group exists.
// Declaring is what makes a directory a group; the move refuses to do it as a
// side effect, so a test that moves has to declare first.
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

	// The file keeps its own name and changes directory, which is what a move
	// between groups is in a shell too.
	moved := readFile(t, workspace, "connections/work/10-home.conf")
	if moved != homeConfig {
		t.Errorf("moved block = %q, want the bytes it had", moved)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "" {
		t.Errorf("the source still declares the host")
	}
}

// The entry file is where every ungrouped connection starts, so moving one out
// of it is the first move a workspace makes. Its base name is "config", which
// "connections/<group>/*.conf" does not match, so a destination derived from it
// verbatim is written and then never read: the connection disappears from the
// configuration OpenSSH sees while both files look correct on disk.
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

// The notice tells the user OpenSSH will not read the block until they add an
// Include. A declared group already has one, and the destination is named so
// that it matches, so saying otherwise here trains the user to click past the
// warning in the one case where it is true.
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
	// The identity changed because the path did, and everything the entry
	// carried travelled with it rather than being orphaned.
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
	// A refusal must leave nothing behind, not even the directory it would
	// have needed.
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
	// The bug, reported from a real workspace: the first connection into a
	// group worked and every one after it failed with "this file was changed
	// outside the application", naming an external edit that had not happened.
	//
	// A move that names a group does not name a destination file, so the client
	// never read one and could not send its bytes. The empty base it sent
	// instead was compared against the group file on disk, which by then held
	// the first connection — so the comparison was between "nothing" and "the
	// work this application had just done itself".
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

	// Both are in the group file, and the first was not overwritten by the
	// second — which is the other way this could have been "fixed".
	moved := readFile(t, workspace, "connections/work/10-home.conf")
	if !strings.Contains(moved, "Host nas") || !strings.Contains(moved, "Host printer") {
		t.Errorf("the group file holds %q, want both connections", moved)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "" {
		t.Errorf("the source still holds something: %q", readFile(t, workspace, "conf.d/10-home.conf"))
	}
}

func TestAGroupMoveStillRefusesAFileThatChangedUnderIt(t *testing.T) {
	// Reading the destination rather than trusting a base the client never had
	// must not become "write regardless". The source base is still the client's
	// and is still checked, and the digest read for the destination is the
	// precondition storage verifies while committing.
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

	// The second move carries the base from before the first one, which is what
	// a second browser tab would send.
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

// A rename that lands on an alias something else already declares does not
// create a second host: it creates a second claim on one name, and OpenSSH
// gives the name to whichever block it reads first. The move path has refused
// this since it was written; rename accepted it, wrote it, and said nothing,
// so a rename could take a live alias away from the host that owned it.
func TestRenameOntoAnAliasAnotherFileDeclaresIsRefused(t *testing.T) {
	service, workspace := newTestService(t)
	before := readFile(t, workspace, "conf.d/10-home.conf")

	_, err := service.Save(EditRequest{
		Kind:     EditRename,
		Path:     "conf.d/10-home.conf",
		Base:     before,
		Alias:    "nas",
		NewAlias: "bastion", // declared by the entry file
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

// A .conf file under connections/ that no Include names is read by nobody. The
// group delete puts one there deliberately when it is given no destination, on
// the stated understanding that the interface reports it; nothing did, so a
// connection could leave the configuration without a word being said about it.
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
