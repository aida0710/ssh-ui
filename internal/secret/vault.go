// Package secret holds the passwords this application can hand to OpenSSH.
//
// They live in one encrypted file inside the workspace, ~/.ssh/ssh-ui/secrets,
// and not in the macOS Keychain. That is a deliberate choice with one reason:
// a Keychain item belongs to a machine, and these have to travel. The
// workspace is what syncs, so anything that must arrive on a second machine
// has to be a file in it.
//
// The consequence is that the file is at rest on disk in a place any process
// running as the user can read, so it is encrypted before it is written, with
// a key derived from a passphrase this application never stores. Nothing here
// can decrypt anything without that passphrase being supplied.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"golang.org/x/crypto/argon2"

	"ssh-ui/internal/platform"
)

// WorkspacePath is where the sealed file lives, relative to the workspace
// root. It has no extension that invites an editor to open it and no name that
// suggests it can be read.
const WorkspacePath = "ssh-ui/secrets"

// SchemaVersion is the version of the plaintext document, inside the
// encryption. The header carries its own version for the envelope.
const SchemaVersion = 1

var (
	// ErrWrongPassphrase reports that the file could not be opened with the
	// passphrase given. It is deliberately the same error for "wrong
	// passphrase" and "tampered file", because AES-GCM cannot tell them apart
	// and pretending otherwise would be a guess.
	ErrWrongPassphrase = errors.New("the vault could not be opened with that passphrase")
	// ErrNotAVault reports that the bytes are not a sealed vault at all.
	ErrNotAVault = errors.New("this file is not an ssh-ui vault")
	// ErrUnsupportedVersion reports a file written by a newer build.
	ErrUnsupportedVersion = errors.New("this vault was written by a newer version of ssh-ui")
	// ErrCostRefused reports a header demanding more work than any vault this
	// application writes could need. See the limits below.
	ErrCostRefused = errors.New("this vault demands an unreasonable amount of work to open")
	// ErrUnsafeName rejects an alias that is not a safe alias.
	ErrUnsafeName = errors.New("that is not a safe host alias")
	// ErrEmptySecret rejects an empty password, which is indistinguishable at
	// the prompt from a wrong one.
	ErrEmptySecret = errors.New("the password is empty")
	// ErrWeakPassphrase rejects a vault passphrase below the minimum length.
	ErrWeakPassphrase = errors.New("the vault passphrase is too short")
)

// MinPassphraseLength is the shortest vault passphrase this will accept.
//
// It is a blunt rule and it is the only one: no character-class requirements,
// which push people towards short passphrases they cannot remember. This file
// can be copied off the machine and attacked offline for as long as someone
// likes, and length is what makes that expensive.
const MinPassphraseLength = 12

// Argon2id parameters. They are written into every file's header, so raising
// them later leaves old files readable and new files stronger.
const (
	kdfArgon2id       = 1
	defaultTime       = 3
	defaultMemoryKiB  = 64 * 1024
	defaultThreads    = 4
	derivedKeyLength  = 32
	saltLength        = 16
	nonceLength       = 12
	headerMagicLength = 15
)

// Cost ceilings.
//
// The header states how much work opening the file takes, and this file now
// travels: it arrives from another machine, from a bucket, from a restore.
// Nothing may derive a key from parameters it has not first agreed are sane.
//
// Without these, a header claiming time=65539 over 64 MiB asks for roughly
// ninety minutes of one core per attempt, and the unlock never returns. That
// is not a hypothetical — it is what the first run of this package's own
// tamper test did, by flipping one bit in the cost field.
//
// Refusing high parameters is not a weakening. The header is authenticated as
// additional data, so an attacker cannot lower the real cost and have the file
// still open; these limits only stop work being started that will never be
// worth finishing.
const (
	maxKDFTime      = 16
	maxKDFMemoryKiB = 1 << 20 // 1 GiB
	maxKDFThreads   = 16
	maxSaltLength   = 64
)

var headerMagic = [headerMagicLength]byte{'s', 's', 'h', '-', 'u', 'i', '-', 's', 'e', 'c', 'r', 'e', 't', 's', 0}

// envelopeVersion is the version of the file format, not of the document.
const envelopeVersion = 1

// document is the plaintext, and never leaves this package in this form.
type document struct {
	SchemaVersion int               `json:"schemaVersion"`
	Passwords     map[string]string `json:"passwords"`
}

// Vault is an opened secrets file.
//
// It holds the derived key rather than the passphrase, so a change can be
// re-sealed without asking again, and the passphrase is not kept anywhere
// after Open returns.
type Vault struct {
	key       []byte
	params    kdfParams
	passwords map[string]string
}

type kdfParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Salt    []byte
}

func defaultParams() (kdfParams, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return kdfParams{}, err
	}
	return kdfParams{Time: defaultTime, Memory: defaultMemoryKiB, Threads: defaultThreads, Salt: salt}, nil
}

func derive(passphrase string, params kdfParams) []byte {
	return argon2.IDKey([]byte(passphrase), params.Salt, params.Time, params.Memory, params.Threads, derivedKeyLength)
}

// Create returns an empty vault sealed by passphrase.
func Create(passphrase string) (*Vault, error) {
	if len([]rune(passphrase)) < MinPassphraseLength {
		return nil, ErrWeakPassphrase
	}
	params, err := defaultParams()
	if err != nil {
		return nil, err
	}
	return &Vault{key: derive(passphrase, params), params: params, passwords: map[string]string{}}, nil
}

// Open decrypts sealed with passphrase.
func Open(sealed []byte, passphrase string) (*Vault, error) {
	header, params, rest, err := readHeader(sealed)
	if err != nil {
		return nil, err
	}
	if len(rest) < nonceLength {
		return nil, ErrNotAVault
	}
	nonce, ciphertext := rest[:nonceLength], rest[nonceLength:]

	key := derive(passphrase, params)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	// The header is authenticated as additional data, so the KDF parameters
	// cannot be weakened by an attacker and replayed: changing one byte of the
	// header makes the open fail rather than derive a cheaper key.
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, ErrWrongPassphrase
	}

	var parsed document
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return nil, ErrWrongPassphrase
	}
	if parsed.SchemaVersion > SchemaVersion {
		return nil, ErrUnsupportedVersion
	}
	if parsed.Passwords == nil {
		parsed.Passwords = map[string]string{}
	}
	return &Vault{key: key, params: params, passwords: parsed.Passwords}, nil
}

// Seal encrypts the vault for writing. Each call uses a fresh nonce, so two
// seals of the same content are different bytes and neither reveals that they
// are the same.
func (v *Vault) Seal() ([]byte, error) {
	plaintext, err := json.Marshal(document{SchemaVersion: SchemaVersion, Passwords: v.passwords})
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(v.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := writeHeader(v.params)
	sealed := make([]byte, 0, len(header)+nonceLength+len(plaintext)+gcm.Overhead())
	sealed = append(sealed, header...)
	sealed = append(sealed, nonce...)
	return gcm.Seal(sealed, nonce, plaintext, header), nil
}

// Password returns the stored password for alias.
func (v *Vault) Password(alias string) (string, bool) {
	value, ok := v.passwords[alias]
	return value, ok
}

// Has reports whether a password is stored, without reading it.
func (v *Vault) Has(alias string) bool {
	_, ok := v.passwords[alias]
	return ok
}

// Aliases returns the aliases that have a stored password, sorted. The set of
// names is not itself a secret; the values are.
func (v *Vault) Aliases() []string {
	return slices.Sorted(maps.Keys(v.passwords))
}

// Set stores a password.
func (v *Vault) Set(alias, password string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return ErrUnsafeName
	}
	if password == "" {
		return ErrEmptySecret
	}
	v.passwords[alias] = password
	return nil
}

// Remove forgets a password. A missing alias is not an error.
func (v *Vault) Remove(alias string) {
	delete(v.passwords, alias)
}

// Rename carries a stored password to a new alias, which is what a host rename
// has to do or the password is silently orphaned under a name nothing asks
// for.
func (v *Vault) Rename(from, to string) error {
	password, ok := v.passwords[from]
	if !ok {
		return nil
	}
	if err := platform.ValidateAlias(to); err != nil {
		return ErrUnsafeName
	}
	delete(v.passwords, from)
	v.passwords[to] = password
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// The header is fixed-width except for the salt, and every field it carries is
// needed to derive the key again on another machine with another build.
//
//	magic   15 | envelope 1 | kdf 1 | time 4 | memory 4 | threads 1 | saltLen 1 | salt
func writeHeader(params kdfParams) []byte {
	header := make([]byte, 0, headerMagicLength+12+len(params.Salt))
	header = append(header, headerMagic[:]...)
	header = append(header, envelopeVersion, kdfArgon2id)
	header = binary.BigEndian.AppendUint32(header, params.Time)
	header = binary.BigEndian.AppendUint32(header, params.Memory)
	header = append(header, params.Threads, byte(len(params.Salt)))
	return append(header, params.Salt...)
}

func readHeader(sealed []byte) (header []byte, params kdfParams, rest []byte, err error) {
	const fixed = headerMagicLength + 12
	if len(sealed) < fixed {
		return nil, kdfParams{}, nil, ErrNotAVault
	}
	if [headerMagicLength]byte(sealed[:headerMagicLength]) != headerMagic {
		return nil, kdfParams{}, nil, ErrNotAVault
	}
	if sealed[headerMagicLength] > envelopeVersion {
		return nil, kdfParams{}, nil, ErrUnsupportedVersion
	}
	if sealed[headerMagicLength+1] != kdfArgon2id {
		// An unknown KDF is a file from a future build, not a corrupt one, and
		// saying so is the difference between "upgrade" and "your data is
		// gone".
		return nil, kdfParams{}, nil, ErrUnsupportedVersion
	}
	params.Time = binary.BigEndian.Uint32(sealed[headerMagicLength+2:])
	params.Memory = binary.BigEndian.Uint32(sealed[headerMagicLength+6:])
	params.Threads = sealed[headerMagicLength+10]
	saltLen := int(sealed[headerMagicLength+11])
	if params.Time == 0 || params.Memory == 0 || params.Threads == 0 || saltLen == 0 {
		return nil, kdfParams{}, nil, ErrNotAVault
	}
	if params.Time > maxKDFTime || params.Memory > maxKDFMemoryKiB ||
		params.Threads > maxKDFThreads || saltLen > maxSaltLength {
		return nil, kdfParams{}, nil, ErrCostRefused
	}
	if len(sealed) < fixed+saltLen {
		return nil, kdfParams{}, nil, ErrNotAVault
	}
	params.Salt = slices.Clone(sealed[fixed : fixed+saltLen])
	return slices.Clone(sealed[:fixed+saltLen]), params, sealed[fixed+saltLen:], nil
}
