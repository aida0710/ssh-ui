package secret_test

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"ssh-ui/internal/envelope"
	"ssh-ui/internal/secret"
)

const passphrase = "correct horse battery staple"

func sealedVault(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	for alias, password := range entries {
		// "store a password for this host" is a credential named after the
		// alias, plus the alias pointing at it.
		if err := vault.Set(secret.KindPassword, alias, password); err != nil {
			t.Fatalf("Set(%q) = %v", alias, err)
		}
		if err := vault.Assign(secret.KindPassword, alias, alias); err != nil {
			t.Fatalf("Assign(%q) = %v", alias, err)
		}
	}
	sealed, err := vault.Seal()
	if err != nil {
		t.Fatalf("Seal = %v", err)
	}
	return sealed
}

func TestSealThenOpenRoundTrips(t *testing.T) {
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2 ", "nas": "p@ss word"})

	vault, err := secret.Open(sealed, passphrase)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	// A password may legitimately end in a space. Nothing here may trim it.
	if got, ok := vault.SecretFor(secret.KindPassword, "bastion"); !ok || got != "hunter2 " {
		t.Errorf("Password(bastion) = %q, %v", got, ok)
	}
	if got, _ := vault.SecretFor(secret.KindPassword, "nas"); got != "p@ss word" {
		t.Errorf("Password(nas) = %q", got)
	}
	if !slices.Equal(vault.Subjects(secret.KindPassword), []string{"bastion", "nas"}) {
		t.Errorf("Aliases = %#v", vault.Subjects(secret.KindPassword))
	}
}

func TestSealedBytesContainNoPasswordAndNoAlias(t *testing.T) {
	// The file syncs. An observer who obtains it must not learn which hosts
	// have a stored password, let alone what it is.
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	for _, plaintext := range []string{"hunter2", "bastion", "passwords", "schemaVersion"} {
		if bytes.Contains(sealed, []byte(plaintext)) {
			t.Errorf("the sealed vault contains %q in clear", plaintext)
		}
	}
}

func TestOpenRefusesTheWrongPassphrase(t *testing.T) {
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	_, err := secret.Open(sealed, passphrase+"x")
	if !errors.Is(err, secret.ErrWrongPassphrase) {
		t.Fatalf("Open = %v, want ErrWrongPassphrase", err)
	}
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Error("the error carries the plaintext")
	}
}

func TestOpenRefusesATamperedFileIncludingItsHeader(t *testing.T) {
	// The header carries the KDF cost. If it were not authenticated, an
	// attacker could rewrite it to the cheapest possible parameters and attack
	// the passphrase at that cost instead of the one it was sealed with.
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	// Byte 27 is the salt length, 28 is the first salt byte, and the last byte
	// is inside the tag. The cost fields have their own test above, because
	// they are refused before any key is derived rather than by the AEAD.
	for _, index := range []int{27, 28, 31, len(sealed) - 1} {
		tampered := slices.Clone(sealed)
		tampered[index] ^= 0x01
		if _, err := secret.Open(tampered, passphrase); err == nil {
			t.Errorf("a vault with byte %d flipped opened successfully", index)
		}
	}
}

func TestSealUsesAFreshNonceEveryTime(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	if err := vault.Set(secret.KindPassword, "bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for range 50 {
		sealed, err := vault.Seal()
		if err != nil {
			t.Fatalf("Seal = %v", err)
		}
		key := string(sealed)
		if seen[key] {
			t.Fatal("two seals of the same content produced the same bytes")
		}
		seen[key] = true
	}
}

func TestOpenRefusesSomethingThatIsNotAVault(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"short":        []byte("ssh-ui"),
		"wrong magic":  append([]byte("not-an-ssh-ui-en"), make([]byte, 64)...),
		"zero cost":    zeroCostVault(t),
		"truncated":    sealedVault(t, map[string]string{"a": "b"})[:20],
		"only header":  headerOf(t),
		"random bytes": bytes.Repeat([]byte{0xAB}, 128),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := secret.Open(input, passphrase); err == nil {
				t.Fatal("Open succeeded")
			}
		})
	}
}

func TestOpenRefusesAHeaderDemandingAbsurdWork(t *testing.T) {
	// This file arrives from other machines. A header claiming time=65539 over
	// 64 MiB asks for about ninety minutes of one core per attempt, so an
	// unlock would simply never return. Found by this package's own tamper
	// test, which hung for five minutes before anyone looked.
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	expensiveTime := slices.Clone(sealed)
	expensiveTime[19] = 0x01 // time becomes 65539
	if _, err := secret.Open(expensiveTime, passphrase); !errors.Is(err, secret.ErrCostRefused) {
		t.Fatalf("Open = %v, want ErrCostRefused", err)
	}

	expensiveMemory := slices.Clone(sealed)
	expensiveMemory[22] = 0xFF // memory becomes about 4 TiB
	if _, err := secret.Open(expensiveMemory, passphrase); !errors.Is(err, secret.ErrCostRefused) {
		t.Fatalf("Open = %v, want ErrCostRefused", err)
	}

	manyThreads := slices.Clone(sealed)
	manyThreads[26] = 0xFF
	if _, err := secret.Open(manyThreads, passphrase); !errors.Is(err, secret.ErrCostRefused) {
		t.Fatalf("Open = %v, want ErrCostRefused", err)
	}
}

func TestOpenSaysUpgradeRatherThanCorruptForAFutureFile(t *testing.T) {
	// "Your data is gone" and "this build is too old" are different messages
	// and a user must not be shown the first when the second is true.
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})
	future := slices.Clone(sealed)
	future[16] = 99 // envelope version

	if _, err := secret.Open(future, passphrase); !errors.Is(err, secret.ErrUnsupportedVersion) {
		t.Fatalf("Open = %v, want ErrUnsupportedVersion", err)
	}

	futureKDF := slices.Clone(sealed)
	futureKDF[17] = 99 // KDF id
	if _, err := secret.Open(futureKDF, passphrase); !errors.Is(err, secret.ErrUnsupportedVersion) {
		t.Fatalf("Open = %v, want ErrUnsupportedVersion", err)
	}
}

func TestCreateRefusesAShortPassphrase(t *testing.T) {
	// This file can be copied off the machine and attacked offline for as long
	// as anyone likes. Length is the only thing that makes that expensive.
	if _, err := secret.Create("short"); !errors.Is(err, secret.ErrWeakPassphrase) {
		t.Fatalf("Create = %v, want ErrWeakPassphrase", err)
	}
	if _, err := secret.Create(strings.Repeat("あ", secret.MinPassphraseLength)); err != nil {
		t.Errorf("a passphrase of %d runes was refused: %v", secret.MinPassphraseLength, err)
	}
}

func TestSetRefusesAnUnsafeAliasAndAnEmptyPassword(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	// The alias rule moved with the thing it describes. A credential is named
	// after what it is for — "the office VMs" is a fine name — so Set no longer
	// judges aliases; Assign does, because that is where an alias appears.
	if err := vault.Set(secret.KindPassword, "shared", "x"); err != nil {
		t.Fatalf("Set = %v", err)
	}
	for _, alias := range []string{"", "has space", "has\nnewline", "-U"} {
		if err := vault.Assign(secret.KindPassword, alias, "shared"); !errors.Is(err, secret.ErrUnsafeName) {
			t.Errorf("Assign(%q) = %v, want ErrUnsafeName", alias, err)
		}
	}
	if err := vault.Set(secret.KindPassword, "bastion", ""); !errors.Is(err, secret.ErrEmptySecret) {
		t.Errorf("Set with an empty password = %v, want ErrEmptySecret", err)
	}
}

func TestRenameCarriesThePasswordAndLeavesNothingBehind(t *testing.T) {
	// A host rename that left the password filed under the old alias would
	// orphan it: nothing would ever ask for that name again, and the user
	// would see the password silently stop working.
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Set(secret.KindPassword, "bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Assign(secret.KindPassword, "bastion", "bastion"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Rename(secret.KindPassword, "bastion", "edge"); err != nil {
		t.Fatalf("Rename = %v", err)
	}

	if func() bool { _, ok := vault.SecretFor(secret.KindPassword, "bastion"); return ok }() {
		t.Error("the old alias still has a password")
	}
	if got, ok := vault.SecretFor(secret.KindPassword, "edge"); !ok || got != "hunter2" {
		t.Errorf("Password(edge) = %q, %v", got, ok)
	}
	if err := vault.Rename(secret.KindPassword, "absent", "elsewhere"); err != nil {
		t.Errorf("renaming an alias with no password = %v, want nil", err)
	}
}

func TestPackageImportsNoLogger(t *testing.T) {
	// Every password in the application passes through this package. A log
	// statement here, however well meant, is the one thing that could put one
	// in a file, and a comment asking people not to add one is not a guard.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	forbidden := []string{`"log"`, `"log/slog"`}
	set := token.NewFileSet()
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(set, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imported := range file.Imports {
			if slices.Contains(forbidden, imported.Path.Value) {
				t.Errorf("%s imports %s", name, imported.Path.Value)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no package file was checked, so this assertion proves nothing")
	}
}

func zeroCostVault(t *testing.T) []byte {
	t.Helper()
	sealed := sealedVault(t, map[string]string{"a": "b"})
	zeroed := slices.Clone(sealed)
	// memory = 0, which would make the KDF free.
	zeroed[22], zeroed[23], zeroed[24], zeroed[25] = 0, 0, 0, 0
	return zeroed
}

func headerOf(t *testing.T) []byte {
	t.Helper()
	sealed := sealedVault(t, map[string]string{"a": "b"})
	return sealed[:44]
}

// One namespace would let a host's password picker offer a key's passphrase,
// and picking it would send that passphrase to a remote host as a login
// password. The separation is asserted rather than commented, because a comment
// cannot refuse anything.
func TestVaultKeepsTheTwoNamespacesApart(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Set(secret.KindPassword, "office", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Set(secret.KindKeyPassphrase, "build", "phrase"); err != nil {
		t.Fatal(err)
	}

	if err := vault.Assign(secret.KindPassword, "web-1", "build"); err == nil {
		t.Error("a host referenced a key passphrase")
	}
	if err := vault.Assign(secret.KindKeyPassphrase, "keys/id_work", "office"); err == nil {
		t.Error("a key referenced an account password")
	}
	if err := vault.Assign(secret.KindPassword, "web-1", "office"); err != nil {
		t.Errorf("a host could not reference an account password: %v", err)
	}
	if err := vault.Assign(secret.KindKeyPassphrase, "keys/id_work", "build"); err != nil {
		t.Errorf("a key could not reference a key passphrase: %v", err)
	}
}

// The point of naming a secret is that twenty machines share one entry, so the
// one entry cannot be removed while any of them still points at it.
func TestVaultRefusesToDeleteACredentialInUseAndSaysWhatUsesIt(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	_ = vault.Set(secret.KindPassword, "office", "s3cret")
	_ = vault.Assign(secret.KindPassword, "web-1", "office")
	_ = vault.Assign(secret.KindPassword, "web-2", "office")

	err = vault.Delete(secret.KindPassword, "office")
	if !errors.Is(err, secret.ErrCredentialInUse) {
		t.Fatalf("Delete error = %v, want ErrCredentialInUse", err)
	}
	if uses := vault.Uses(secret.KindPassword, "office"); !slices.Equal(uses, []string{"web-1", "web-2"}) {
		t.Errorf("uses = %#v, want both aliases", uses)
	}

	vault.Unassign(secret.KindPassword, "web-1")
	vault.Unassign(secret.KindPassword, "web-2")
	if err := vault.Delete(secret.KindPassword, "office"); err != nil {
		t.Errorf("Delete of an unused credential = %v", err)
	}
}

// A version 1 document held a password per alias and no names. There is at most
// one in the world; a migration would be larger than the thing it migrates, so
// it is refused with an error the screen can turn into "set them again".
func TestAVersionOneDocumentIsRefused(t *testing.T) {
	key, err := envelope.Derive(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte(`{"schemaVersion":1,"passwords":{"web-1":"s3cret"}}`))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := secret.Open(sealed, passphrase); !errors.Is(err, secret.ErrOldVault) {
		t.Fatalf("Open error = %v, want ErrOldVault", err)
	}
}

func TestSealedBytesCarryNothingFromEitherNamespace(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	_ = vault.Set(secret.KindPassword, "office-vm", "s3cret-password")
	_ = vault.Assign(secret.KindPassword, "web-1", "office-vm")
	_ = vault.Set(secret.KindKeyPassphrase, "build-key", "s3cret-phrase")
	_ = vault.Assign(secret.KindKeyPassphrase, "keys/id_work", "build-key")
	sealed, err := vault.Seal()
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{
		"office-vm", "s3cret-password", "web-1",
		"build-key", "s3cret-phrase", "keys/id_work",
	} {
		if bytes.Contains(sealed, []byte(absent)) {
			t.Errorf("the sealed file carries %q", absent)
		}
	}
}
