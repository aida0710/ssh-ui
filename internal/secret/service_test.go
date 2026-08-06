package secret_test

import (
	"bytes"
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
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now), home
}

// newClockedService owns time, so an idle day can be a line of test rather
// than a day of waiting.
func newClockedService(t *testing.T, now func() time.Time) (*secret.Service, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), now), home
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
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now)
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

// The vault keeps generations like every other file, and every one of them is
// unreadable.
//
// It used to keep none, on the reasoning that old copies of a password store
// are not something anyone wants left behind. What that cost was the undo: a
// vault damaged by an accident had nothing to go back to. The backups are
// sealed with this vault's own key now, so an old generation discloses nothing
// a copy of the live file does not.
func TestTheVaultKeepsGenerationsAndNoneOfThemIsReadable(t *testing.T) {
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
			return nil //nolint:nilerr // a missing backup directory fails below
		}
		if !strings.Contains(filepath.ToSlash(path), "secrets") {
			return nil
		}
		found++
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			return nil
		}
		for _, plain := range []string{"first", "second", "bastion", passphrase} {
			if strings.Contains(string(contents), plain) {
				t.Errorf("%s carries %q in the clear", path, plain)
			}
		}
		return nil
	})
	if found == 0 {
		t.Error("the vault kept no generation, so an accident to it cannot be undone")
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

// The object store's settings are sealed with the same master password and kept
// beside the vault, not inside it. The vault travels — remotesync.Collect names
// ssh-ui/secrets outright — and the key to the bucket must not be in the bucket.
func TestSyncSettingsAreSealedBesideTheVaultAndNotInIt(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	settings := secret.SyncSettings{
		Endpoint: "https://s3.example", Bucket: "b", Region: "auto",
		AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s3cret-key", Direction: "both",
	}
	if err := service.SetSyncSettings(settings); err != nil {
		t.Fatalf("SetSyncSettings = %v", err)
	}

	read, err := service.SyncSettings()
	if err != nil {
		t.Fatalf("SyncSettings = %v", err)
	}
	if read != settings {
		t.Errorf("settings = %#v, want %#v", read, settings)
	}

	// Not in the vault, and not readable from either file.
	vault, err := os.ReadFile(vaultPath(home))
	if err != nil {
		t.Fatal(err)
	}
	sealedSettings, err := os.ReadFile(filepath.Join(home, ".ssh", filepath.FromSlash(secret.SettingsPath)))
	if err != nil {
		t.Fatalf("the settings file is not there: %v", err)
	}
	for _, absent := range []string{"AKIAEXAMPLE", "s3cret-key", "s3.example"} {
		if strings.Contains(string(vault), absent) {
			t.Errorf("the vault carries %q", absent)
		}
		if strings.Contains(string(sealedSettings), absent) {
			t.Errorf("the settings file carries %q in the clear", absent)
		}
	}
}

// Never configured is a state, not a failure: a machine that has not been given
// settings answers the zero value so the screen can show an empty form rather
// than an error.
func TestSyncSettingsAnswerEmptyBeforeTheyAreEverSet(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	settings, err := service.SyncSettings()
	if err != nil {
		t.Fatalf("SyncSettings = %v", err)
	}
	if settings != (secret.SyncSettings{}) {
		t.Errorf("settings = %#v, want the zero value", settings)
	}
}

func TestSyncSettingsRefuseAShutVault(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	service.Lock()

	if _, err := service.SyncSettings(); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SyncSettings while locked = %v, want ErrLocked", err)
	}
	if err := service.SetSyncSettings(secret.SyncSettings{Bucket: "b"}); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SetSyncSettings while locked = %v, want ErrLocked", err)
	}
}

// A vault that stays open for the life of the process is a vault that is open
// while the laptop is in a bag. Nothing is asked at startup, so the cost of
// shutting it is one master password on the next use, and the reach of leaving
// it open is every password and every key passphrase.
func TestAVaultLeftUntouchedShutsItself(t *testing.T) {
	clock := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	service, _ := newClockedService(t, func() time.Time { return clock })
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(secret.IdleTimeout + time.Minute)
	if service.Unlocked() {
		t.Error("the vault is still open after a whole idle day")
	}
	if _, err := service.IssueToken("bastion"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("IssueToken after the idle timeout = %v, want ErrLocked", err)
	}
	// And it is the master password that opens it again, not merely asking.
	if err := service.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock = %v", err)
	}
	if !service.Has("bastion") {
		t.Error("the reopened vault lost what it held")
	}
}

func TestUsingASecretPutsTheClockBackToZero(t *testing.T) {
	clock := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	service, _ := newClockedService(t, func() time.Time { return clock })
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	// Three quarters of the way there, four times over: a working day of use
	// is not an idle day, however long it adds up to.
	for range 4 {
		clock = clock.Add(secret.IdleTimeout - secret.IdleTimeout/4)
		if got := service.PasswordFor("bastion"); got != "hunter2" {
			t.Fatalf("PasswordFor = %q after %v, want the password", got, clock)
		}
	}
	if !service.Unlocked() {
		t.Error("a vault used all day shut itself anyway")
	}
}

// An open browser tab reads the status every time a screen mounts. If that
// counted as use, one forgotten tab would hold the vault open for as long as
// the machine is on, which is the thing the timeout exists to stop.
func TestReadingTheStatusDoesNotHoldTheVaultOpen(t *testing.T) {
	clock := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	service, _ := newClockedService(t, func() time.Time { return clock })
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	for range 4 {
		clock = clock.Add(secret.IdleTimeout - secret.IdleTimeout/4)
		service.Unlocked()
		service.Aliases()
		service.Has("bastion")
	}
	if service.Unlocked() {
		t.Error("polling the status held the vault open")
	}
}

// Verify answers "is this the master password?" without changing anything.
//
// It is what lets the snapshot use the master password instead of a second one:
// a typed password can be checked before it is used as a key, so a typo becomes
// a refusal here rather than an archive nobody can open.
func TestVerifyAnswersWhetherThatIsTheMasterPassword(t *testing.T) {
	service, _ := newService(t)
	if _, err := service.Verify(passphrase); !errors.Is(err, secret.ErrNoVault) {
		t.Errorf("Verify with no vault = %v, want ErrNoVault", err)
	}

	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	ok, err := service.Verify(passphrase)
	if err != nil || !ok {
		t.Errorf("Verify with the right password = %v, %v", ok, err)
	}
	ok, err = service.Verify("not the master password at all")
	if err != nil || ok {
		t.Errorf("Verify with the wrong password = %v, %v, want false and no error", ok, err)
	}

	// And it answers from the file, so a shut vault can still be asked. The
	// screen that asks is the one that has just been told the vault is shut.
	service.Lock()
	if ok, err := service.Verify(passphrase); err != nil || !ok {
		t.Errorf("Verify on a locked vault = %v, %v", ok, err)
	}
}

// Every generational backup is ciphertext, and the vault is what opens it.
//
// A backup of a private key used to be a copy of that key sitting in
// ~/.ssh/ssh-ui/backups/, which is why the writes that could produce one asked
// for no backup at all and could therefore never be undone. Sealing them is
// what buys back the undo.
func TestBackupsAreSealedWithTheMasterPasswordAndOpenedWithIt(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	plain := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot really\n")
	sealed, err := service.SealBackup(plain)
	if err != nil {
		t.Fatalf("SealBackup = %v", err)
	}
	if bytes.Contains(sealed, []byte("BEGIN OPENSSH")) {
		t.Error("the sealed backup carries the key in the clear")
	}

	opened, err := service.OpenBackup(sealed)
	if err != nil {
		t.Fatalf("OpenBackup = %v", err)
	}
	if !bytes.Equal(opened, plain) {
		t.Errorf("OpenBackup returned %q", opened)
	}

	// A shut vault seals nothing and opens nothing. The application is behind
	// the master password precisely so this cannot happen while anything is
	// being written, and it fails loudly rather than writing in the clear.
	service.Lock()
	if _, err := service.SealBackup(plain); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SealBackup while shut = %v, want ErrLocked", err)
	}
	if _, err := service.OpenBackup(sealed); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("OpenBackup while shut = %v, want ErrLocked", err)
	}
}
