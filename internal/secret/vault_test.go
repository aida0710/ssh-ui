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
		if err := vault.Set(alias, password); err != nil {
			t.Fatalf("Set(%q) = %v", alias, err)
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
	if got, ok := vault.Password("bastion"); !ok || got != "hunter2 " {
		t.Errorf("Password(bastion) = %q, %v", got, ok)
	}
	if got, _ := vault.Password("nas"); got != "p@ss word" {
		t.Errorf("Password(nas) = %q", got)
	}
	if !slices.Equal(vault.Aliases(), []string{"bastion", "nas"}) {
		t.Errorf("Aliases = %#v", vault.Aliases())
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
	if err := vault.Set("bastion", "hunter2"); err != nil {
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
	for _, alias := range []string{"", "has space", "has\nnewline", "-U"} {
		if err := vault.Set(alias, "x"); !errors.Is(err, secret.ErrUnsafeName) {
			t.Errorf("Set(%q) = %v, want ErrUnsafeName", alias, err)
		}
	}
	if err := vault.Set("bastion", ""); !errors.Is(err, secret.ErrEmptySecret) {
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
	if err := vault.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Rename("bastion", "edge"); err != nil {
		t.Fatalf("Rename = %v", err)
	}

	if vault.Has("bastion") {
		t.Error("the old alias still has a password")
	}
	if got, ok := vault.Password("edge"); !ok || got != "hunter2" {
		t.Errorf("Password(edge) = %q, %v", got, ok)
	}
	if err := vault.Rename("absent", "elsewhere"); err != nil {
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
