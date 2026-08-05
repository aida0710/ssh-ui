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
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"ssh-ui/internal/envelope"
	"ssh-ui/internal/platform"
)

// WorkspacePath is where the sealed file lives, relative to the workspace
// root. It has no extension that invites an editor to open it and no name that
// suggests it can be read.
const WorkspacePath = "ssh-ui/secrets"

// SchemaVersion is the version of the plaintext document, inside the
// encryption. The header carries its own version for the envelope.
const SchemaVersion = 1

// The envelope's errors are re-exported so a caller handling a vault does not
// have to know which package sealed it.
var (
	ErrWrongPassphrase    = envelope.ErrWrongPassphrase
	ErrNotAVault          = envelope.ErrNotAnEnvelope
	ErrUnsupportedVersion = envelope.ErrUnsupportedVersion
	ErrCostRefused        = envelope.ErrCostRefused
	ErrWeakPassphrase     = envelope.ErrWeakPassphrase
)

var (
	// ErrUnsafeName rejects an alias that is not a safe alias.
	ErrUnsafeName = errors.New("that is not a safe host alias")
	// ErrEmptySecret rejects an empty password, which is indistinguishable at
	// the prompt from a wrong one.
	ErrEmptySecret = errors.New("the password is empty")
)

// MinPassphraseLength is the shortest vault passphrase this will accept.
const MinPassphraseLength = envelope.MinPassphraseLength

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
	key       envelope.Key
	passwords map[string]string
}

// Create returns an empty vault sealed by passphrase.
func Create(passphrase string) (*Vault, error) {
	key, err := envelope.Derive(passphrase)
	if err != nil {
		return nil, err
	}
	return &Vault{key: key, passwords: map[string]string{}}, nil
}

// Open decrypts sealed with passphrase.
func Open(sealed []byte, passphrase string) (*Vault, error) {
	plaintext, key, err := envelope.Open(sealed, passphrase)
	if err != nil {
		return nil, err
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
	return &Vault{key: key, passwords: parsed.Passwords}, nil
}

// Seal encrypts the vault for writing.
func (v *Vault) Seal() ([]byte, error) {
	plaintext, err := json.Marshal(document{SchemaVersion: SchemaVersion, Passwords: v.passwords})
	if err != nil {
		return nil, err
	}
	return v.key.Seal(plaintext)
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
