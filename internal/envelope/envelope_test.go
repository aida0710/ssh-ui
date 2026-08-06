package envelope_test

import (
	"errors"
	"testing"

	"ssh-ui/internal/envelope"
)

// Seal works from a key alone, and opening is its mirror. A caller that already
// holds the key — the vault, which keeps the key and deliberately not the
// passphrase — can seal a second file beside its own and read it back without
// asking the user again.
func TestAKeyOpensWhatItSealed(t *testing.T) {
	key, err := envelope.Derive("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte("the object store settings"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := key.Open(sealed)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	if string(plaintext) != "the object store settings" {
		t.Errorf("plaintext = %q", plaintext)
	}
}

func TestAnotherKeyCannotOpenIt(t *testing.T) {
	mine, err := envelope.Derive("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := envelope.Derive("a different master password")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := mine.Seal([]byte("the object store settings"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := theirs.Open(sealed); !errors.Is(err, envelope.ErrWrongPassphrase) {
		t.Errorf("Open with another key = %v, want ErrWrongPassphrase", err)
	}
}

func TestAKeyRefusesTamperedBytes(t *testing.T) {
	key, err := envelope.Derive("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte("the object store settings"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff

	if _, err := key.Open(sealed); err == nil {
		t.Error("a flipped bit was accepted")
	}
}
