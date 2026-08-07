package envelope_test

import (
	"errors"
	"sync"
	"testing"

	"sshc/internal/envelope"
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

// Deriving a key is deliberately expensive, so how many can run at once is a
// number this decides rather than one a caller does.
//
// Unlocking, pushing and pulling all derive, and all three are ordinary
// requests: a page with a few tabs, or a script, can otherwise ask for dozens
// at 64 MiB apiece. The wait this adds is nothing — a local interface where one
// person is pressing things — and the memory it does not allocate is gigabytes.
func TestDerivationsDoNotAllRunAtOnce(t *testing.T) {
	const attempts = 8
	var running, peak int64
	var mutex sync.Mutex
	var group sync.WaitGroup

	envelope.OnDerive = func(step func()) {
		mutex.Lock()
		running++
		if running > peak {
			peak = running
		}
		mutex.Unlock()
		step()
		mutex.Lock()
		running--
		mutex.Unlock()
	}
	t.Cleanup(func() { envelope.OnDerive = nil })

	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := envelope.Derive("a passphrase long enough"); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if peak > envelope.MaxConcurrentDerivations {
		t.Errorf("%d derivations ran at once, want at most %d", peak, envelope.MaxConcurrentDerivations)
	}
}

// An envelope that arrived over a network is held to a tighter ceiling than one
// this installation wrote. The parameters in it were chosen by whoever wrote
// it, and opening is where the cost is paid.
func TestARemoteEnvelopeMayNotAskForWhatALocalOneMay(t *testing.T) {
	// Sealed with parameters this installation would accept locally.
	key, err := envelope.Derive("a passphrase long enough")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte("a snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := envelope.OpenWithin(sealed, "a passphrase long enough", envelope.AcceptedFromRemote); err != nil {
		t.Fatalf("what Derive writes must open under the remote ceiling: %v", err)
	}

	// A ceiling below what Derive writes refuses rather than spending the cost.
	tiny := envelope.Limits{Time: 1, MemoryKiB: 1024, Threads: 1}
	if _, _, err := envelope.OpenWithin(sealed, "a passphrase long enough", tiny); !errors.Is(err, envelope.ErrCostRefused) {
		t.Errorf("OpenWithin under a tiny ceiling = %v, want ErrCostRefused", err)
	}
}
