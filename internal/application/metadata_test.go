package application

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/storage"
)

func newTestWorkspace(t *testing.T) *storage.Workspace {
	t.Helper()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := workspace.EnsureDirectory(workspace.Root()); err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestDecodeMetadataAcceptsAnAbsentFileAndRejectsAFutureSchema(t *testing.T) {
	empty, err := DecodeMetadata(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.SchemaVersion != MetadataSchemaVersion || len(empty.Hosts) != 0 || len(empty.Groups) != 0 {
		t.Fatalf("empty metadata = %#v", empty)
	}
	if _, err := DecodeMetadata([]byte(`{"schemaVersion":99}`)); !errors.Is(err, ErrMetadataVersion) {
		t.Fatalf("future schema error = %v, want ErrMetadataVersion", err)
	}
	if _, err := DecodeMetadata([]byte(`{"schemaVersion":1,`)); err == nil {
		t.Fatal("truncated metadata was accepted")
	}
}

func TestValidateMetadataRefusesKeyMaterialAndUnknownPaths(t *testing.T) {
	withNote := NewMetadata()
	withNote.Hosts = []HostMetadata{{
		Identity: HostIdentity{Path: "config", Alias: "bastion"},
		Note:     "-----BEGIN OPENSSH PRIVATE KEY-----",
	}}
	if err := ValidateMetadata(withNote); !errors.Is(err, ErrMetadataSecret) {
		t.Fatalf("note error = %v, want ErrMetadataSecret", err)
	}

	withTag := NewMetadata()
	withTag.Hosts = []HostMetadata{{
		Identity: HostIdentity{Path: "config", Alias: "bastion"},
		Tags:     []string{"ssh-rsa AAAAB3NzaC1yc2EAAAA"},
	}}
	if err := ValidateMetadata(withTag); !errors.Is(err, ErrMetadataSecret) {
		t.Fatalf("tag error = %v, want ErrMetadataSecret", err)
	}

	withAbsolutePath := NewMetadata()
	withAbsolutePath.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "/etc/ssh/ssh_config", Alias: "x"}}}
	if err := ValidateMetadata(withAbsolutePath); !errors.Is(err, ErrMetadataPath) {
		t.Fatalf("path error = %v, want ErrMetadataPath", err)
	}

	// A group name is a directory path, so a document that names one this
	// application would refuse to create must not be believed either.
	for _, name := range []string{"../escape", "", "sshc", "work/"} {
		withBadGroup := NewMetadata()
		withBadGroup.Groups = []GroupMetadata{{Name: name}}
		if err := ValidateMetadata(withBadGroup); !errors.Is(err, ErrMetadataGroup) {
			t.Errorf("group %q error = %v, want ErrMetadataGroup", name, err)
		}
	}

	// Two groups whose names differ only in case are one directory on a default
	// macOS volume, so the document that declares both is refused.
	withCaseClash := NewMetadata()
	withCaseClash.Groups = []GroupMetadata{{Name: "work"}, {Name: "Work"}}
	if err := ValidateMetadata(withCaseClash); !errors.Is(err, ErrMetadataGroup) {
		t.Errorf("case clash error = %v, want ErrMetadataGroup", err)
	}
}

func TestMetadataCarriesOnlyPresentation(t *testing.T) {
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{Name: "work", Colour: "#f97316", Note: "the office", Order: 2}}
	metadata.Hosts = []HostMetadata{{
		Identity: HostIdentity{Path: "connections/work/web.conf", Alias: "web-1"},
		Tags:     []string{"prod"},
		Colour:   "#22d3ee",
	}}

	encoded, err := EncodeMetadata(metadata)
	if err != nil {
		t.Fatalf("EncodeMetadata error = %v", err)
	}
	// Membership is the directory and a note is a comment, so neither has a
	// key here. Asserting on the bytes is what stops one creeping back.
	for _, absent := range []string{`"group"`, `"parent"`} {
		if strings.Contains(string(encoded), absent) {
			t.Errorf("encoded metadata still carries %s:\n%s", absent, encoded)
		}
	}
	if !strings.Contains(string(encoded), `"schemaVersion": 2`) {
		t.Errorf("encoded metadata is not version 2:\n%s", encoded)
	}
}

func TestDecodeMetadataDropsGroupMembershipFromAnOlderDocument(t *testing.T) {
	// A version 1 document decodes and simply loses the two fields that no
	// longer mean anything. The directory is authoritative now, and a v1
	// document's group names a layout that does not exist on disk yet.
	const document = `{"schemaVersion":1,"groups":[{"name":"work","parent":"company"}],` +
		`"hosts":[{"identity":{"path":"config","alias":"bastion"},"group":"work","colour":"#f97316"}]}`

	metadata, err := DecodeMetadata([]byte(document))
	if err != nil {
		t.Fatalf("DecodeMetadata error = %v", err)
	}
	if len(metadata.Hosts) != 1 || metadata.Hosts[0].Colour != "#f97316" {
		t.Fatalf("hosts = %#v, want the presentation kept", metadata.Hosts)
	}
	encoded, err := EncodeMetadata(metadata)
	if err != nil {
		t.Fatalf("EncodeMetadata error = %v", err)
	}
	if strings.Contains(string(encoded), "company") {
		t.Errorf("the parent survived re-encoding:\n%s", encoded)
	}
}

func TestMetadataStoreRoundTripsThroughOneTransaction(t *testing.T) {
	workspace := newTestWorkspace(t)
	store := NewMetadataStore(workspace)

	loaded, precondition, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if precondition.Exists {
		t.Fatalf("precondition for an absent file = %#v", precondition)
	}
	loaded.Groups = []GroupMetadata{{Name: "home", Settings: []Setting{{Keyword: "User", Values: []string{"aida"}}}}}
	loaded.Hosts = []HostMetadata{{
		Identity:  HostIdentity{Path: "config", Alias: "bastion"},
		Tags:      []string{"personal"},
		Colour:    "#22d3ee",
		Note:      "office jump host",
		Favourite: true,
		Order:     1,
	}}

	change, err := store.Change(loaded, precondition)
	if err != nil {
		t.Fatal(err)
	}
	if change.Path != store.Path() || change.Precondition.Exists {
		t.Fatalf("change = %#v", change)
	}
	if err := store.EnsureDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(change.Path, change.Contents, 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, reloadedPrecondition, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reloadedPrecondition.Exists || reloadedPrecondition.Digest != storage.Digest(change.Contents) {
		t.Fatalf("reloaded precondition = %#v", reloadedPrecondition)
	}
	if len(reloaded.Hosts) != 1 || reloaded.Hosts[0].Alias() != "bastion" || !reloaded.Hosts[0].Favourite {
		t.Fatalf("reloaded hosts = %#v", reloaded.Hosts)
	}
	if got := string(change.Contents); !strings.HasSuffix(got, "\n") {
		t.Fatal("encoded metadata must end with a newline")
	}
	if store.Path() != filepath.Join(workspace.StateDir(), MetadataFileName) {
		t.Fatalf("store path = %q", store.Path())
	}
}

func TestReconcileMetadataMarksVanishedTargetsAsOrphansWithoutGuessing(t *testing.T) {
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{
		{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "kept"},
		{Identity: HostIdentity{Path: "conf.d/10-home.conf", Alias: "nas"}, Note: "vanished"},
	}
	present := []HostIdentity{
		{Path: "config", Alias: "bastion"},
		{Path: "conf.d/10-home.conf", Alias: "nas-new"},
	}

	reconciled, notices := ReconcileMetadata(metadata, present)
	if reconciled.Hosts[0].Orphan {
		t.Fatalf("present host became an orphan: %#v", reconciled.Hosts[0])
	}
	if !reconciled.Hosts[1].Orphan || reconciled.Hosts[1].Note != "vanished" {
		t.Fatalf("orphan entry = %#v", reconciled.Hosts[1])
	}
	if reconciled.Hosts[1].Identity.Alias != "nas" {
		t.Fatal("an orphan must keep its original identity instead of being re-pointed")
	}
	if len(notices) != 1 || notices[0].Code != NoticeOrphanMetadata || notices[0].Path != "conf.d/10-home.conf" {
		t.Fatalf("notices = %#v", notices)
	}
}

func TestRenameHostIdentityMovesExactlyOneEntry(t *testing.T) {
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{
		{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "renamed"},
		{Identity: HostIdentity{Path: "config", Alias: "nas"}, Note: "untouched"},
	}
	renamed := RenameHostIdentity(metadata,
		HostIdentity{Path: "config", Alias: "bastion"},
		HostIdentity{Path: "config", Alias: "jump"},
	)
	if renamed.Hosts[0].Identity.Alias != "jump" || renamed.Hosts[0].Note != "renamed" || renamed.Hosts[0].Orphan {
		t.Fatalf("renamed entry = %#v", renamed.Hosts[0])
	}
	if renamed.Hosts[1].Identity.Alias != "nas" {
		t.Fatalf("second entry = %#v", renamed.Hosts[1])
	}
	if metadata.Hosts[0].Identity.Alias != "bastion" {
		t.Fatal("RenameHostIdentity must not mutate its input")
	}
}

// Hidden is presentation, like Colour and Order: this engine carries it and
// never acts on it. A group whose purpose is to hold other groups has nothing
// of its own to show in the connections tree, and this takes its heading out of
// it — while leaving the Include line, the directory and every answer ssh gives
// exactly as they were.
func TestGroupMetadataCarriesTheHiddenFlagThroughARoundTrip(t *testing.T) {
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{Name: "dubguild", Hidden: true}, {Name: "dubguild/mdx"}}

	encoded, err := EncodeMetadata(metadata)
	if err != nil {
		t.Fatalf("EncodeMetadata error = %v", err)
	}
	if !strings.Contains(string(encoded), `"hidden": true`) {
		t.Errorf("encoded metadata lost the hidden flag:\n%s", encoded)
	}

	decoded, err := DecodeMetadata(encoded)
	if err != nil {
		t.Fatalf("DecodeMetadata error = %v", err)
	}
	if len(decoded.Groups) != 2 || !decoded.Groups[0].Hidden || decoded.Groups[1].Hidden {
		t.Errorf("groups = %#v, want only dubguild hidden", decoded.Groups)
	}
}

// A group that is not hidden writes no key at all, so an untouched workspace's
// metadata does not grow a field for every group the moment this ships.
func TestAGroupThatIsNotHiddenWritesNoHiddenKey(t *testing.T) {
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{Name: "work"}}

	encoded, err := EncodeMetadata(metadata)
	if err != nil {
		t.Fatalf("EncodeMetadata error = %v", err)
	}
	if strings.Contains(string(encoded), "hidden") {
		t.Errorf("encoded metadata carries a hidden key it did not need:\n%s", encoded)
	}
}
