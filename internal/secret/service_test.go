package secret_test

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ssh-ui/internal/secret"
	"ssh-ui/internal/storage"
)

func newService(t *testing.T) (*secret.Service, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader)), home
}

func vaultPath(home string) string {
	return filepath.Join(home, ".ssh", filepath.FromSlash(secret.WorkspacePath))
}

func TestNothingIsReadableUntilTheVaultIsUnlocked(t *testing.T) {
	service, _ := newService(t)

	if service.Unlocked() {
		t.Fatal("a new service reports itself unlocked")
	}
	if err := service.Set("bastion", "hunter2"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Set while locked = %v, want ErrLocked", err)
	}
	if err := service.Remove("bastion"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Remove while locked = %v, want ErrLocked", err)
	}
	if _, err := service.IssueToken("bastion"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("IssueToken while locked = %v, want ErrLocked", err)
	}
	if service.Has("bastion") {
		t.Error("Has reported true while locked")
	}
	if service.Aliases() != nil {
		t.Error("Aliases returned something while locked")
	}
}

func TestInitialiseWritesASealedFileAndUnlockReadsItBack(t *testing.T) {
	service, home := newService(t)

	if err := service.Initialise(passphrase); err != nil {
		t.Fatalf("Initialise = %v", err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatalf("Set = %v", err)
	}

	sealed, err := os.ReadFile(vaultPath(home))
	if err != nil {
		t.Fatalf("the vault was not written: %v", err)
	}
	if strings.Contains(string(sealed), "hunter2") || strings.Contains(string(sealed), "bastion") {
		t.Error("the written file contains the password or the alias in clear")
	}

	// A second service over the same workspace is a second run of the
	// application, which is the case that matters.
	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock = %v", err)
	}
	if !reopened.Has("bastion") {
		t.Error("the reopened vault has no password for bastion")
	}
}

func mustReopen(t *testing.T, home string) *secret.Service {
	t.Helper()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader))
}

func TestInitialiseRefusesToReplaceAnExistingVault(t *testing.T) {
	// Replacing it would destroy every stored password, and an encrypted file
	// whose key is gone has no recovery path.
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	second := mustReopen(t, home)
	if err := second.Initialise("a completely different passphrase"); !errors.Is(err, secret.ErrAlreadyExists) {
		t.Fatalf("Initialise = %v, want ErrAlreadyExists", err)
	}

	third := mustReopen(t, home)
	if err := third.Unlock(passphrase); err != nil {
		t.Fatalf("the original vault no longer opens: %v", err)
	}
	if !third.Has("bastion") {
		t.Error("the stored password is gone")
	}
}

func TestUnlockReportsNoVaultRatherThanAWrongPassphrase(t *testing.T) {
	service, _ := newService(t)
	if err := service.Unlock(passphrase); !errors.Is(err, secret.ErrNoVault) {
		t.Fatalf("Unlock = %v, want ErrNoVault", err)
	}
}

func TestUnlockRefusesTheWrongPassphraseAndStaysLocked(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	second := mustReopen(t, home)
	if err := second.Unlock(passphrase + "x"); !errors.Is(err, secret.ErrWrongPassphrase) {
		t.Fatalf("Unlock = %v, want ErrWrongPassphrase", err)
	}
	if second.Unlocked() {
		t.Error("a failed unlock left the service unlocked")
	}
}

func TestLockForgetsTheKeyAndEveryPendingToken(t *testing.T) {
	// A token outliving the lock would let a connection started before it
	// still collect a password afterwards.
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}

	service.Lock()

	if service.Unlocked() {
		t.Error("Lock left the service unlocked")
	}
	if _, err := service.Redeem(token, "bastion", "x's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Redeem after Lock = %v, want ErrLocked", err)
	}
}

func alwaysAnswerable(string) bool { return true }
func neverAnswerable(string) bool  { return false }

func TestATokenIsSpentByItsFirstUse(t *testing.T) {
	service := unlockedWithPassword(t)

	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}
	password, err := service.Redeem(token, "bastion", "ops@h's password: ", alwaysAnswerable)
	if err != nil {
		t.Fatalf("Redeem = %v", err)
	}
	if password != "hunter2" {
		t.Errorf("password = %q", password)
	}

	if _, err := service.Redeem(token, "bastion", "ops@h's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatalf("the second Redeem = %v, want ErrUnknownToken", err)
	}
}

func TestATokenIsBoundToItsAlias(t *testing.T) {
	// A stolen token must be worth at most the one host the user just chose to
	// connect to, not the whole vault.
	service := unlockedWithPassword(t)
	if err := service.Set("nas", "other-secret"); err != nil {
		t.Fatal(err)
	}

	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Redeem(token, "nas", "ops@h's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatalf("Redeem for another alias = %v, want ErrUnknownToken", err)
	}
}

func TestRedeemAppliesThePromptRuleAndSpendsTheTokenAnyway(t *testing.T) {
	// The server side of the rule cannot be replaced by recompiling the
	// helper. And a token that survived a refused prompt could be retried with
	// an acceptable one, which would make the rule advisory.
	service := unlockedWithPassword(t)

	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Redeem(token, "bastion", "continue connecting?", neverAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatalf("Redeem with a refused prompt = %v", err)
	}
	if _, err := service.Redeem(token, "bastion", "ops@h's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatal("the token survived a refused prompt and was reusable")
	}
}

func TestAnUnknownTokenIsRefused(t *testing.T) {
	service := unlockedWithPassword(t)
	if _, err := service.IssueToken("bastion"); err != nil {
		t.Fatal(err)
	}

	for _, presented := range []string{"", "not-a-token", strings.Repeat("A", 43)} {
		if _, err := service.Redeem(presented, "bastion", "x's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
			t.Errorf("Redeem(%q) = %v, want ErrUnknownToken", presented, err)
		}
	}
}

func TestNoTokenIsIssuedForAHostWithNoStoredPassword(t *testing.T) {
	service := unlockedWithPassword(t)
	if _, err := service.IssueToken("nas"); !errors.Is(err, secret.ErrNoPassword) {
		t.Fatalf("IssueToken = %v, want ErrNoPassword", err)
	}
}

func TestRemoveWritesTheVaultBack(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := service.Remove("bastion"); err != nil {
		t.Fatalf("Remove = %v", err)
	}

	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	if reopened.Has("bastion") {
		t.Error("the password came back after a restart")
	}
}

func TestRenameCarriesThePasswordThroughAWrite(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := service.Rename("bastion", "edge"); err != nil {
		t.Fatalf("Rename = %v", err)
	}
	if err := service.Rename("absent", "elsewhere"); err != nil {
		t.Errorf("renaming a host with no password = %v, want nil", err)
	}

	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	if reopened.Has("bastion") || !reopened.Has("edge") {
		t.Errorf("aliases after rename = %#v", reopened.Aliases())
	}
}

func TestTheVaultIsNotCopiedIntoTheBackupDirectory(t *testing.T) {
	// A store of passwords is not something whose old generations anyone wants
	// kept, and every change would otherwise leave one more copy of the
	// ciphertext behind. The key vault applies the same rule to private keys.
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"first", "second", "third"} {
		if err := service.Set("bastion", password); err != nil {
			t.Fatal(err)
		}
	}

	backups := filepath.Join(home, ".ssh", "ssh-ui", "backups")
	found := 0
	_ = filepath.Walk(backups, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil //nolint:nilerr // a missing backup directory is the passing case
		}
		if strings.Contains(filepath.ToSlash(path), "secrets") {
			found++
		}
		return nil
	})
	if found != 0 {
		t.Errorf("%d copies of the vault are in the backup directory", found)
	}
}

func unlockedWithPassword(t *testing.T) *secret.Service {
	t.Helper()
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	return service
}

// The service's credential surface, which is what every screen and every route
// goes through. A locked vault answers ErrLocked rather than an empty list,
// because "we cannot see" and "there is none" are different facts.
func TestCredentialsThroughTheService(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	if err := service.SetCredential(secret.KindPassword, "office", "s3cret"); err != nil {
		t.Fatalf("SetCredential = %v", err)
	}
	if err := service.AssignCredential(secret.KindPassword, "web-1", "office"); err != nil {
		t.Fatalf("AssignCredential = %v", err)
	}
	if err := service.AssignCredential(secret.KindPassword, "web-2", "office"); err != nil {
		t.Fatal(err)
	}

	listed, err := service.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := listed[secret.KindPassword]["office"]
	if !ok || !slices.Equal(entry, []string{"web-1", "web-2"}) {
		t.Fatalf("credentials = %#v, want office used by both", listed)
	}

	// The whole point of a name: one entry, rotated once, for both machines.
	if err := service.SetCredential(secret.KindPassword, "office", "rotated"); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"web-1", "web-2"} {
		if got := service.PasswordFor(alias); got != "rotated" {
			t.Errorf("%s reads %q after one rotation", alias, got)
		}
	}

	if err := service.DeleteCredential(secret.KindPassword, "office"); !errors.Is(err, secret.ErrCredentialInUse) {
		t.Errorf("DeleteCredential of a used name = %v, want ErrCredentialInUse", err)
	}

	service.Lock()
	if _, err := service.Credentials(); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Credentials while locked = %v, want ErrLocked", err)
	}
	if err := service.SetCredential(secret.KindPassword, "x", "y"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SetCredential while locked = %v, want ErrLocked", err)
	}
}

// The separation, again at the service, because a route reaches this and not
// the vault directly.
func TestTheServiceWillNotCrossTheNamespaces(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	_ = service.SetCredential(secret.KindKeyPassphrase, "build", "phrase")

	if err := service.AssignCredential(secret.KindPassword, "web-1", "build"); err == nil {
		t.Error("a host was pointed at a key passphrase through the service")
	}
}
