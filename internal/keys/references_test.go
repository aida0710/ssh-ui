package keys

import (
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
