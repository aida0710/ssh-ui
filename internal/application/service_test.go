package application

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssh-ui/internal/storage"
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
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{
		Name:     "home",
		Settings: []Setting{{Keyword: "Port", Values: []string{"2222"}}},
	}}
	metadata.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "conf.d/10-home.conf", Alias: "nas"}, Group: "home"}}

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
	if len(preview.Effective[0].Changes) != 1 || preview.Effective[0].Changes[0].Keyword != "Port" {
		t.Fatalf("effective changes = %#v", preview.Effective[0].Changes)
	}

	if _, err := service.Save(EditRequest{Kind: EditGroups, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}
	groups := readFile(t, workspace, DefaultGroupsFile)
	if !bytes.Contains([]byte(groups), []byte("Host nas\n\tPort 2222\n")) {
		t.Fatalf("groups file = %q", groups)
	}
	if !bytes.Contains([]byte(readFile(t, workspace, "config")), []byte("Include "+DefaultGroupsFile+"\n")) {
		t.Fatalf("entry config = %q", readFile(t, workspace, "config"))
	}
	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Groups) != 1 || stored.Groups[0].Name != "home" {
		t.Fatalf("stored metadata = %#v", stored)
	}

	detail, err := service.HostDetail("conf.d/10-home.conf", "nas")
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
