package application

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/keys"
	"sshc/internal/storage"
)

// A real Ed25519 key pair, generated once and kept as a constant. Building one
// per test would be the only slow thing in this package, and the bytes are what
// make the scanner classify the file as a private key rather than as "other".
const (
	relocateTestPrivate = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBLBQZBkOLcHOKZDGnDlOfyJTPuKQpVE5MOZaSNPWy5xQAAAJBhMS0aYTEt
GgAAAAtzc2gtZWQyNTUxOQAAACBLBQZBkOLcHOKZDGnDlOfyJTPuKQpVE5MOZaSNPWy5xQ
AAAEBGD9wRSuRSCLDMHTmDzJqJDBNPo5Y6dCLLIsG6UhTKWksFBkGQ4twc4pkMacOU5/Il
M+4pClUTkw5lpI09bLnFAAAADWFpZGFAZXhhbXBsZQECAwQ=
-----END OPENSSH PRIVATE KEY-----
`
	relocateTestPublic = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEsFBkGQ4twc4pkMacOU5/IlM+4pClUTkw5lpI09bLnF aida@example\n"
)

// keyInventory reads the workspace the way the key vault does, so a relocation
// test exercises the same classification the running application uses.
func keyInventory(t *testing.T, workspace *storage.Workspace) *keys.Inventory {
	t.Helper()
	service := keys.NewService(keys.ServiceOptions{
		Workspace:    workspace,
		Transactions: storage.NewManager(workspace, nil, rand.Reader),
		Resolver:     storage.NewResolver(workspace),
	})
	inventory, err := service.Inventory()
	if err != nil {
		t.Fatalf("Inventory error = %v", err)
	}
	return inventory
}

func writeKeyPair(t *testing.T, workspace *storage.Workspace, relative string) {
	t.Helper()
	absolute := filepath.Join(workspace.Root(), filepath.FromSlash(relative))
	if err := workspace.EnsureDirectory(filepath.Dir(absolute)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, []byte(relocateTestPrivate), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute+".pub", []byte(relocateTestPublic), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stringPointer(value string) *string { return &value }

func TestRelocateKeyRewritesEveryDirectiveThatNamesIt(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// Two files, three spellings, one of them with a trailing comment: every
	// byte except the path itself has to survive.
	const source = "Host build\n\tIdentityFile ~/.ssh/id_work  # the build key\n" +
		"Host deploy\n\tIdentityFile=%d/.ssh/id_work\n\tCertificateFile ~/.ssh/id_work.pub\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if result.RelativePath != "keys/work/id_work" || result.Group != "work" {
		t.Errorf("result = %#v", result)
	}

	for _, name := range []string{"keys/work/id_work", "keys/work/id_work.pub"} {
		if _, statErr := os.Lstat(filepath.Join(workspace.Root(), filepath.FromSlash(name))); statErr != nil {
			t.Errorf("%s was not created: %v", name, statErr)
		}
	}
	// The spelling the user wrote is what OpenSSH resolves and what they
	// recognise, so only the part below ~/.ssh changed.
	want := strings.ReplaceAll(source, "/.ssh/id_work", "/.ssh/keys/work/id_work")
	if got := readFile(t, workspace, "conf.d/30-keys.conf"); got != want {
		t.Errorf("configuration =\n%q\nwant\n%q", got, want)
	}
	if len(result.References) != 3 {
		t.Errorf("references = %#v, want all three directives", result.References)
	}
}

func TestRelocateKeyRenamesWithoutChangingGroup(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"),
		[]byte("Host build\n\tIdentityFile ~/.ssh/id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work"),
		NewName: stringPointer("id_build"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if result.RelativePath != "id_build" {
		t.Errorf("relative path = %q, want id_build", result.RelativePath)
	}
	if got := readFile(t, workspace, "conf.d/30-keys.conf"); got != "Host build\n\tIdentityFile ~/.ssh/id_build\n" {
		t.Errorf("configuration = %q", got)
	}
	// A passphrase in the login Keychain is filed under the old absolute path
	// and macOS owns that entry, so the result says so every time.
	if len(result.Notes) != 1 || result.Notes[0] != NoteKeychainEntryStale {
		t.Errorf("notes = %#v, want the Keychain warning", result.Notes)
	}
}

func TestRelocateKeyMovesTheWholeFingerprintGroupAndLeavesALookAlike(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// Same key, a name the user chose. It is not "id_work" plus a suffix, so
	// moving it would be this application deciding what that name meant.
	if err := os.WriteFile(filepath.Join(workspace.Root(), "backup_copy.pub"), []byte(relocateTestPublic), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if len(result.Files) != 2 {
		t.Errorf("files = %#v, want the private key and its public half", result.Files)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "backup_copy.pub" {
		t.Errorf("skipped = %#v", result.Skipped)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "backup_copy.pub")); statErr != nil {
		t.Errorf("the look-alike was moved: %v", statErr)
	}
}

func TestRelocateKeyRefusesAnUndeclaredGroup(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("marketing"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerKeyGroupNotDeclared) {
		t.Errorf("blockers = %#v", result.Blockers)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "keys")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a refused relocation created the keys directory: %v", statErr)
	}
}

func TestRelocateKeyRefusesWhileADirectiveCannotBeResolved(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// A relative IdentityFile is resolved by ssh against its own working
	// directory, which this application cannot know. It names "id_work", so it
	// may well be this key.
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"),
		[]byte("Host build\n\tIdentityFile id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerKeyUnresolved) {
		t.Errorf("blockers = %#v", result.Blockers)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "id_work")); statErr != nil {
		t.Errorf("a blocked relocation moved the key: %v", statErr)
	}
}

func TestRelocateKeyRefusesADestinationAnIncludeWouldRead(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// A hand-written Include reaching under keys/ would make the destination a
	// configuration file. A private key parsed as ssh_config is the worst
	// outcome available, so this refuses rather than warns.
	entry := readFile(t, workspace, "config")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"),
		[]byte("Include keys/work/*\n"+entry), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	found := false
	for _, blocker := range result.Blockers {
		if strings.HasPrefix(blocker, BlockerKeyDestinationRead) {
			found = true
		}
	}
	if !found {
		t.Errorf("blockers = %#v, want key_destination_is_config", result.Blockers)
	}
}

func TestRelocateKeyRefusesADestinationThatIsOccupied(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "id_build.pub"), []byte("occupied\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work"),
		NewName: stringPointer("id_build"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerKeyTargetOccupied) {
		t.Errorf("blockers = %#v", result.Blockers)
	}
}

func TestRelocateKeyRefusesHalfOfAPairAndTheNameItAlreadyHas(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")
	inventory := keyInventory(t, workspace)

	if _, err := service.RelocateKey(inventory, KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work.pub"),
		NewName: stringPointer("id_build"),
	}); !errors.Is(err, ErrKeyRelocateNotSupported) {
		t.Errorf("public half error = %v, want ErrKeyRelocateNotSupported", err)
	}
	if _, err := service.RelocateKey(inventory, KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work"),
		NewName: stringPointer("id_work"),
	}); !errors.Is(err, ErrKeyRelocateUnchanged) {
		t.Errorf("unchanged error = %v, want ErrKeyRelocateUnchanged", err)
	}
}

func TestRelocateKeyIsOneTransactionThatCopiesNoKeyMaterial(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	if err := os.Chmod(filepath.Join(workspace.Root(), "id_work"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"),
		[]byte("Host build\n\tIdentityFile ~/.ssh/id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if result.TransactionID == "" {
		t.Fatal("the relocation reported no transaction")
	}

	// A move is a rename(2): the bytes never travel through this process, so
	// the mode survives and no copy reaches the generational backup directory.
	info, err := os.Lstat(filepath.Join(workspace.Root(), "keys", "work", "id_work"))
	if err != nil {
		t.Fatalf("relocated key missing: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("permission = %04o, want the original 0400", info.Mode().Perm())
	}
	backups := filepath.Join(workspace.StateDir(), "backups")
	err = filepath.WalkDir(backups, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(contents), "OPENSSH PRIVATE KEY") {
			t.Fatalf("key material was copied into the backup directory: %s", path)
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("walk backups: %v", err)
	}
}
