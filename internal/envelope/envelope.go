// Package envelope encrypts a blob with a passphrase.
//
// It exists because two things in this application need exactly the same
// answer to "put these bytes somewhere they can be read from another machine
// and nowhere else": the stored-password vault, and the snapshot the remote
// sync uploads. Two implementations of that would be two cost ceilings, two
// header formats and two chances to get the additional data wrong.
//
// The format is deliberately self-describing, because a sealed blob outlives
// the build that wrote it and has to be readable by a build that did not exist
// when it was written:
//
//	magic 16 | envelope 1 | kdf 1 | time 4 | memory 4 | threads 1 | saltLen 1 | salt | nonce 12 | AES-256-GCM(…)
//	└──────────────────────── authenticated as additional data ──────────────────────┘
//
// The header is the AEAD's additional data, so its parameters cannot be
// rewritten down and replayed: change one byte and the open fails rather than
// deriving a cheaper key.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"slices"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrWrongPassphrase reports that the blob could not be opened with the
	// passphrase given. It is deliberately the same error for "wrong
	// passphrase" and "tampered blob", because AES-GCM cannot tell them apart
	// and pretending otherwise would be a guess.
	ErrWrongPassphrase = errors.New("the passphrase did not open this data")
	// ErrNotAnEnvelope reports that the bytes are not a sealed blob at all.
	ErrNotAnEnvelope = errors.New("these bytes are not an sshc envelope")
	// ErrUnsupportedVersion reports a blob written by a newer build. It is a
	// distinct error because "this build is too old" and "your data is gone"
	// are different things to tell someone.
	ErrUnsupportedVersion = errors.New("this data was written by a newer version of sshc")
	// ErrCostRefused reports a header demanding more work than any envelope
	// this application writes could need.
	ErrCostRefused = errors.New("this data demands an unreasonable amount of work to open")
	// ErrWeakPassphrase rejects a passphrase below MinPassphraseLength.
	ErrWeakPassphrase = errors.New("the passphrase is too short")
)

// MinPassphraseLength is the shortest passphrase this package will seal with.
//
// It is a blunt rule and it is the only one: no character-class requirements,
// which push people towards short passphrases they cannot remember. A sealed
// blob can be copied off the machine and attacked offline for as long as
// anyone likes, and length is what makes that expensive.
const MinPassphraseLength = 12

// Argon2id parameters. They are written into every header, so raising them
// later leaves old blobs readable and new ones stronger.
const (
	kdfArgon2id      = 1
	defaultTime      = 3
	defaultMemoryKiB = 64 * 1024
	defaultThreads   = 4
	derivedKeyLength = 32
	saltLength       = 16
	nonceLength      = 12
	magicLength      = 16
	envelopeVersion  = 1
)

// Cost ceilings.
//
// The header states how much work opening costs, and a sealed blob arrives:
// from another machine, from a bucket, from a restore. Nothing may derive a
// key from parameters it has not first agreed are sane.
//
// Without these, a header claiming time=65539 over 64 MiB asks for roughly
// ninety minutes of one core per attempt, and the open never returns. That is
// not hypothetical — it is what the first run of the vault's own tamper test
// did, by flipping one bit in the cost field, and it hung for five minutes
// before anyone looked.
//
// Refusing high parameters is not a weakening. The header is authenticated, so
// an attacker cannot lower the real cost and have the blob still open; these
// limits only stop work being started that will never be worth finishing.
const (
	maxKDFTime      = 16
	maxKDFMemoryKiB = 1 << 20 // 1 GiB
	maxKDFThreads   = 16
	maxSaltLength   = 64
)

// Limits are the parameters an envelope may ask for.
//
// There are two sets, because there are two kinds of envelope and only one of
// them is ours. A file this installation wrote asks for what Derive chose; a
// snapshot fetched from a bucket asks for whatever whoever wrote it chose, and
// that is a number a stranger picked. The ceiling for the second is close to
// what we would have written, so a snapshot cannot make this machine spend a
// gigabyte and sixteen threads before finding out the passphrase is wrong.
type Limits struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// Accepted is what an envelope this installation wrote may ask for.
var Accepted = Limits{Time: maxKDFTime, MemoryKiB: maxKDFMemoryKiB, Threads: maxKDFThreads}

// AcceptedFromRemote is what an envelope that arrived over a network may ask
// for: a little above what Derive writes, and no more.
var AcceptedFromRemote = Limits{Time: 8, MemoryKiB: 256 << 10, Threads: 8}

var magic = [magicLength]byte{'s', 's', 'h', '-', 'u', 'i', '-', 'e', 'n', 'v', 'e', 'l', 'o', 'p', 'e', 0}

// Params are the key-derivation parameters of one sealed blob.
type Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Salt    []byte
}

// Key is a derived key. It is held rather than the passphrase so that a change
// can be re-sealed without asking for the passphrase again.
type Key struct {
	material []byte
	params   Params
}

// Derive stretches passphrase into a key with fresh parameters.
func Derive(passphrase string) (Key, error) {
	if len([]rune(passphrase)) < MinPassphraseLength {
		return Key{}, ErrWeakPassphrase
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return Key{}, err
	}
	params := Params{Time: defaultTime, Memory: defaultMemoryKiB, Threads: defaultThreads, Salt: salt}
	return Key{material: derive(passphrase, params), params: params}, nil
}

// MaxConcurrentDerivations is how many key derivations may run at once.
//
// Each one is deliberately expensive — tens of megabytes and several threads —
// and every unlock, push and pull performs one. Without a bound, a page with a
// few tabs asks for dozens at once and the process allocates gigabytes for no
// reason. Two is enough that nobody waiting on one notices, because this is a
// local interface with one person pressing things.
const MaxConcurrentDerivations = 2

var derivations = make(chan struct{}, MaxConcurrentDerivations)

// OnDerive wraps each derivation. It exists for the test that counts how many
// run at once and is nil everywhere else.
var OnDerive func(step func())

func derive(passphrase string, params Params) []byte {
	derivations <- struct{}{}
	defer func() { <-derivations }()

	var key []byte
	step := func() {
		key = argon2.IDKey([]byte(passphrase), params.Salt, params.Time, params.Memory, params.Threads, derivedKeyLength)
	}
	if OnDerive != nil {
		OnDerive(step)
	} else {
		step()
	}
	return key
}

// Seal encrypts plaintext under key. Each call uses a fresh nonce, so two
// seals of the same content are different bytes and neither reveals that they
// are the same.
func (k Key) Seal(plaintext []byte) ([]byte, error) {
	if len(k.material) != derivedKeyLength {
		return nil, ErrNotAnEnvelope
	}
	gcm, err := newGCM(k.material)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := writeHeader(k.params)
	sealed := make([]byte, 0, len(header)+nonceLength+len(plaintext)+gcm.Overhead())
	sealed = append(sealed, header...)
	sealed = append(sealed, nonce...)
	return gcm.Seal(sealed, nonce, plaintext, header), nil
}

// Open decrypts sealed with a key already held, which is the mirror of Seal:
// that works from a key alone and this does too.
//
// It exists for the caller that keeps the key and deliberately not the
// passphrase — the vault — so it can seal a second file beside its own and read
// it back without asking the user again. The header is authenticated data, so a
// key that does not match fails the tag rather than being detected separately.
func (k Key) Open(sealed []byte) ([]byte, error) {
	if len(k.material) != derivedKeyLength {
		return nil, ErrNotAnEnvelope
	}
	header, _, rest, err := readHeader(sealed)
	if err != nil {
		return nil, err
	}
	if len(rest) < nonceLength {
		return nil, ErrNotAnEnvelope
	}
	nonce, ciphertext := rest[:nonceLength], rest[nonceLength:]
	gcm, err := newGCM(k.material)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return plaintext, nil
}

// Open decrypts sealed with passphrase and returns the plaintext along with
// the key, so the caller can re-seal without deriving again.
func Open(sealed []byte, passphrase string) ([]byte, Key, error) {
	return OpenWithin(sealed, passphrase, Accepted)
}

// OpenWithin is Open with the ceiling named, for a caller that did not write
// the envelope it is opening.
func OpenWithin(sealed []byte, passphrase string, limits Limits) ([]byte, Key, error) {
	header, params, rest, err := readHeader(sealed)
	if err != nil {
		return nil, Key{}, err
	}
	if params.Time > limits.Time || params.Memory > limits.MemoryKiB || params.Threads > limits.Threads {
		return nil, Key{}, ErrCostRefused
	}
	if len(rest) < nonceLength {
		return nil, Key{}, ErrNotAnEnvelope
	}
	nonce, ciphertext := rest[:nonceLength], rest[nonceLength:]

	material := derive(passphrase, params)
	gcm, err := newGCM(material)
	if err != nil {
		return nil, Key{}, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, Key{}, ErrWrongPassphrase
	}
	return plaintext, Key{material: material, params: params}, nil
}

func newGCM(material []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func writeHeader(params Params) []byte {
	header := make([]byte, 0, magicLength+12+len(params.Salt))
	header = append(header, magic[:]...)
	header = append(header, envelopeVersion, kdfArgon2id)
	header = binary.BigEndian.AppendUint32(header, params.Time)
	header = binary.BigEndian.AppendUint32(header, params.Memory)
	header = append(header, params.Threads, byte(len(params.Salt)))
	return append(header, params.Salt...)
}

func readHeader(sealed []byte) (header []byte, params Params, rest []byte, err error) {
	const fixed = magicLength + 12
	if len(sealed) < fixed {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	if [magicLength]byte(sealed[:magicLength]) != magic {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	if sealed[magicLength] > envelopeVersion {
		return nil, Params{}, nil, ErrUnsupportedVersion
	}
	if sealed[magicLength+1] != kdfArgon2id {
		// An unknown KDF is a blob from a future build, not a corrupt one.
		return nil, Params{}, nil, ErrUnsupportedVersion
	}
	params.Time = binary.BigEndian.Uint32(sealed[magicLength+2:])
	params.Memory = binary.BigEndian.Uint32(sealed[magicLength+6:])
	params.Threads = sealed[magicLength+10]
	saltLen := int(sealed[magicLength+11])
	if params.Time == 0 || params.Memory == 0 || params.Threads == 0 || saltLen == 0 {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	if params.Time > maxKDFTime || params.Memory > maxKDFMemoryKiB ||
		params.Threads > maxKDFThreads || saltLen > maxSaltLength {
		return nil, Params{}, nil, ErrCostRefused
	}
	if len(sealed) < fixed+saltLen {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	params.Salt = slices.Clone(sealed[fixed : fixed+saltLen])
	return slices.Clone(sealed[:fixed+saltLen]), params, sealed[fixed+saltLen:], nil
}
