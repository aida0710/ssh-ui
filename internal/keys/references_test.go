package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssh-ui/internal/storage"
)

func TestBuildReferenceIndexFindsHostsThatNameAKey(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, publicKey, _ := newKeyPairFixture(t, "")
	writeFixture(t, workspace, "work", privateKey, 0o600)
	writeFixture(t, workspace, "work.pub", publicKey, 0o644)
	writeFixture(t, workspace, "work-cert.pub", publicKey, 0o644)
	writeFixture(t, workspace, "config", []byte(""+
		"Host build-*\n"+
		"  IdentityFile ~/.ssh/work\n"+
		"  CertificateFile ~/.ssh/work-cert.pub\n"+
		"\n"+
		"Host agent-only\n"+
		"  IdentityAgent SSH_AUTH_SOCK\n"+
		"\n"+
		"Host unknown-token\n"+
		"  IdentityFile ~/.ssh/%h.key\n"+
		"\n"+
		"Host external\n"+
		"  IdentityFile /etc/ssh/shared\n"), 0o600)

	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	index := BuildReferenceIndex(graph, workspace)

	identityReferences := index.For("work")
	if len(identityReferences) != 1 {
		t.Fatalf("references for work = %#v, want one", identityReferences)
	}
	reference := identityReferences[0]
	if reference.Directive != "IdentityFile" {
		t.Errorf("Directive = %q, want IdentityFile", reference.Directive)
	}
	if reference.Line != 2 {
		t.Errorf("Line = %d, want 2", reference.Line)
	}
	if len(reference.HostPatterns) != 1 || reference.HostPatterns[0] != "build-*" {
		t.Errorf("HostPatterns = %#v, want [build-*]", reference.HostPatterns)
	}
	if reference.Condition != "Host build-*" {
		t.Errorf("Condition = %q, want %q", reference.Condition, "Host build-*")
	}

	if got := index.For("work-cert.pub"); len(got) != 1 || got[0].Directive != "CertificateFile" {
		t.Errorf("certificate references = %#v", got)
	}
	if got := index.AgentDelegations(); len(got) != 1 || got[0].Directive != "IdentityAgent" {
		t.Errorf("agent delegations = %#v", got)
	}

	reasons := make(map[string]string, len(index.Unresolved()))
	for _, unresolved := range index.Unresolved() {
		reasons[unresolved.Value] = unresolved.Reason
	}
	if reasons["~/.ssh/%h.key"] != ReasonUnsupportedToken {
		t.Errorf("token reason = %q, want %q", reasons["~/.ssh/%h.key"], ReasonUnsupportedToken)
	}
	if reasons["/etc/ssh/shared"] != ReasonOutsideWorkspace {
		t.Errorf("external reason = %q, want %q", reasons["/etc/ssh/shared"], ReasonOutsideWorkspace)
	}
}

func TestAttachReferencesNeverPointsAtEngineState(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, _, _ := newKeyPairFixture(t, "")
	writeFixture(t, workspace, "work", privateKey, 0o600)
	writeFixture(t, workspace, "ssh-ui/trash/20260805T090000.000-aabbccdd/work", privateKey, 0o600)
	writeFixture(t, workspace, "config", []byte(""+
		"Host live\n"+
		"  IdentityFile ~/.ssh/work\n"+
		"\n"+
		"Host stale\n"+
		"  IdentityFile ~/.ssh/ssh-ui/trash/20260805T090000.000-aabbccdd/work\n"), 0o600)

	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	inventory.AttachReferences(BuildReferenceIndex(graph, workspace))

	item, ok := inventory.Find(ItemID("work"))
	if !ok {
		t.Fatalf("work missing from the inventory")
	}
	if len(item.References) != 1 || item.References[0].HostPatterns[0] != "live" {
		t.Fatalf("references = %#v, want the live Host only", item.References)
	}
	for _, candidate := range inventory.Items {
		if strings.HasPrefix(candidate.RelativePath, StateDirectoryName+string(filepath.Separator)) {
			t.Fatalf("engine state was inventoried: %s", candidate.RelativePath)
		}
	}
}

// A home directory reached through a symbolic link is the shape this
// application says it supports: "a user who keeps ~/.ssh on another volume
// still works". It is also the shape every macOS temporary directory has, and
// the ordinary shape for anyone whose ~/.ssh is a link into a dotfiles
// checkout.
//
// Workspace resolves its root through EvalSymlinks and leaves Home as it was
// given, so the two live in different path spaces. expandKeyPath builds from
// Home and Contains compares against Root, so on such a machine every
// IdentityFile ~/.ssh/… is filed as pointing outside the workspace: the key
// screen reports the whole configuration as unresolved, and a key rename
// rewrites none of the directives that name it, silently, because a reference
// judged to be outside cannot be the key being moved.
//
// The workspace here is built from the link, exactly as cmd/ssh-ui builds one
// from os.UserHomeDir. Every other test in this package resolves the temporary
// directory first, which is why none of them sees this.
func TestBuildReferenceIndexResolvesAKeyUnderASymlinkedHome(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real-home")
	if err := os.MkdirAll(filepath.Join(real, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "linked-home")
	if err := os.Symlink(real, home); err != nil {
		t.Skipf("this filesystem does not support symbolic links: %v", err)
	}

	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatalf("new workspace: %v", err)
	}
	privateKey, publicKey, _ := newKeyPairFixture(t, "")
	writeFixture(t, workspace, "work", privateKey, 0o600)
	writeFixture(t, workspace, "work.pub", publicKey, 0o644)
	writeFixture(t, workspace, "config", []byte(
		"Host build\n  IdentityFile ~/.ssh/work\n  CertificateFile %d/.ssh/work.pub\n"), 0o600)

	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	index := BuildReferenceIndex(graph, workspace)

	if got := len(index.For("work")); got != 1 {
		t.Errorf("references for work = %d, want the IdentityFile line", got)
	}
	if got := len(index.For("work.pub")); got != 1 {
		t.Errorf("references for work.pub = %d, want the CertificateFile line", got)
	}
	for _, unresolved := range index.Unresolved() {
		t.Errorf("reported as unresolvable: %#v", unresolved)
	}
}
