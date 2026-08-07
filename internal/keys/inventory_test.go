package keys

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/storage"
)

// newTestWorkspace builds an isolated ~/.ssh under t.TempDir(). No test in this
// package ever touches the developer's real home directory.
//
// The temporary directory is resolved with EvalSymlinks first because macOS
// puts t.TempDir() under /var, which is a symbolic link to /private/var.
// Workspace resolves its root the same way, so an unresolved home would make
// Workspace.Home() and Workspace.Root() disagree and every '~' expansion would
// look like a path outside the workspace.
func newTestWorkspace(t *testing.T) *storage.Workspace {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary home: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("create ssh directory fixture: %v", err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatalf("new workspace: %v", err)
	}
	return workspace
}

func writeFixture(t *testing.T, workspace *storage.Workspace, relativePath string, contents []byte, permission os.FileMode) {
	t.Helper()
	absolute := filepath.Join(workspace.Root(), relativePath)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatalf("create fixture directory for %s: %v", relativePath, err)
	}
	if err := os.WriteFile(absolute, contents, permission); err != nil {
		t.Fatalf("write fixture %s: %v", relativePath, err)
	}
}

func newKeyPairFixture(t *testing.T, passphrase string) (privateKey []byte, publicKey []byte, fingerprint string) {
	t.Helper()
	generated, err := GeneratePrivateKey(AlgorithmEd25519, 0, rand.Reader)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	privateKey, err = EncodePrivateKey(generated, "fixture@test", []byte(passphrase))
	if err != nil {
		t.Fatalf("encode fixture private key: %v", err)
	}
	publicKey, err = EncodePublicKey(generated, "fixture@test")
	if err != nil {
		t.Fatalf("encode fixture public key: %v", err)
	}
	info, err := InspectPublicKey(publicKey)
	if err != nil {
		t.Fatalf("inspect fixture public key: %v", err)
	}
	return privateKey, publicKey, info.Fingerprint
}

func TestScanClassifiesByContentNotByFileName(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, publicKey, fingerprint := newKeyPairFixture(t, "correct horse")

	// Deliberately misleading names: the private key is called "notes.txt" and
	// a plain text file is called "id_ed25519".
	writeFixture(t, workspace, "notes.txt", privateKey, 0o600)
	writeFixture(t, workspace, "notes.txt.pub", publicKey, 0o644)
	writeFixture(t, workspace, "id_ed25519", []byte("this is not a key at all\n"), 0o600)
	writeFixture(t, workspace, "config", []byte("Host example\n  HostName example.test\n"), 0o600)
	writeFixture(t, workspace, "known_hosts", []byte("example.test "+string(publicKey)), 0o600)
	writeFixture(t, workspace, "exposed", privateKey, 0o644)
	writeFixture(t, workspace, "sshc/trash/20260805T090000.000-aabbccdd/secret", privateKey, 0o600)
	writeFixture(t, workspace, "sshc/backups/20260805T090000.000-aabbccdd/config", []byte("Host old\n"), 0o600)
	writeFixture(t, workspace, "sshc/journal/20260805T090000.000-aabbccdd.json", []byte("{}\n"), 0o600)

	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	byPath := make(map[string]*Item, len(inventory.Items))
	for index := range inventory.Items {
		byPath[inventory.Items[index].RelativePath] = &inventory.Items[index]
	}

	tests := []struct {
		relativePath   string
		wantKind       Kind
		wantEncrypted  bool
		wantPermission string
	}{
		{"notes.txt", KindPrivateKey, true, "0600"},
		{"notes.txt.pub", KindPublicKey, false, "0644"},
		{"id_ed25519", KindOther, false, "0600"},
		{"config", KindConfig, false, "0600"},
		{"known_hosts", KindKnownHosts, false, "0600"},
		{"exposed", KindPrivateKey, true, "0644"},
	}
	for _, test := range tests {
		t.Run(test.relativePath, func(t *testing.T) {
			item, ok := byPath[test.relativePath]
			if !ok {
				t.Fatalf("%s missing from the inventory", test.relativePath)
			}
			if item.Kind != test.wantKind {
				t.Errorf("Kind = %q, want %q", item.Kind, test.wantKind)
			}
			if item.Encrypted != test.wantEncrypted {
				t.Errorf("Encrypted = %v, want %v", item.Encrypted, test.wantEncrypted)
			}
			if item.Permission != test.wantPermission {
				t.Errorf("Permission = %q, want %q", item.Permission, test.wantPermission)
			}
			if item.ID != ItemID(test.relativePath) {
				t.Errorf("ID = %q, want %q", item.ID, ItemID(test.relativePath))
			}
		})
	}

	if !byPath["exposed"].PermissionRisk {
		t.Errorf("a world-readable private key was not flagged")
	}
	if byPath["notes.txt"].PermissionRisk {
		t.Errorf("a 0600 private key was flagged as risky")
	}
	if byPath["notes.txt"].Fingerprint != fingerprint {
		t.Errorf("Fingerprint = %q, want %q", byPath["notes.txt"].Fingerprint, fingerprint)
	}
	if byPath["notes.txt"].Bits != 256 || byPath["notes.txt"].Algorithm != AlgorithmEd25519 {
		t.Errorf("algorithm detail = %q/%d", byPath["notes.txt"].Algorithm, byPath["notes.txt"].Bits)
	}

	for path := range byPath {
		if strings.HasPrefix(path, StateDirectoryName+string(filepath.Separator)) {
			t.Fatalf("engine state leaked into the inventory: %s", path)
		}
	}
}

func TestScanShowsSymbolicLinksWithoutFollowingThem(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, _, _ := newKeyPairFixture(t, "")
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(outside, privateKey, 0o600); err != nil {
		t.Fatalf("write external key: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace.Root(), "linked")); err != nil {
		t.Fatalf("create symbolic link: %v", err)
	}

	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	var found *Item
	for index := range inventory.Items {
		if inventory.Items[index].RelativePath == "linked" {
			found = &inventory.Items[index]
		}
	}
	if found == nil {
		t.Fatalf("symbolic link was hidden from the inventory")
	}
	if found.Kind != KindOther {
		t.Errorf("Kind = %q, want %q", found.Kind, KindOther)
	}
	if found.Fingerprint != "" {
		t.Errorf("Fingerprint = %q, want empty; the link must not be followed", found.Fingerprint)
	}
	if !hasNote(found.Notes, NoteSymbolicLink) {
		t.Errorf("Notes = %#v, want %q", found.Notes, NoteSymbolicLink)
	}
}

func TestGroupMatchesSiblingsByFingerprintOnly(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, publicKey, _ := newKeyPairFixture(t, "")
	_, strangerPublicKey, _ := newKeyPairFixture(t, "")

	writeFixture(t, workspace, "work", privateKey, 0o600)
	writeFixture(t, workspace, "work.pub", publicKey, 0o644)
	// Same base name, different key: it must not be grouped with "work".
	writeFixture(t, workspace, "work-old.pub", strangerPublicKey, 0o644)

	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	item, ok := inventory.Find(ItemID("work"))
	if !ok {
		t.Fatalf("private key missing from the inventory")
	}
	group := inventory.Group(item)
	if len(group) != 2 {
		t.Fatalf("group = %d members, want 2", len(group))
	}
	names := map[string]bool{group[0].RelativePath: true, group[1].RelativePath: true}
	if !names["work"] || !names["work.pub"] {
		t.Fatalf("group = %#v, want work and work.pub", names)
	}
}

func hasNote(notes []string, wanted string) bool {
	for _, note := range notes {
		if note == wanted {
			return true
		}
	}
	return false
}
