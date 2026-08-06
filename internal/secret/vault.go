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
	"strings"

	"ssh-ui/internal/envelope"
	"ssh-ui/internal/platform"
)

// WorkspacePath is where the sealed file lives, relative to the workspace
// root. It has no extension that invites an editor to open it and no name that
// suggests it can be read.
const WorkspacePath = "ssh-ui/secrets"

// SettingsPath is the object store's settings, sealed with the same master
// password and kept beside the vault rather than inside it.
//
// The vault travels: remotesync.Collect names ssh-ui/secrets outright. Putting
// the access key inside it would put the key to the bucket inside the bucket,
// and someone who obtained one snapshot by any means, along with its
// passphrase, would gain the live bucket and every snapshot after it rather
// than the one they already had. Collect lists what it takes, so this file is
// excluded by construction and not by a rule anyone has to remember.
const SettingsPath = "ssh-ui/sync-settings"

// SchemaVersion is the version of the plaintext document, inside the
// encryption. The header carries its own version for the envelope.
const SchemaVersion = 2

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
	// ErrOldVault reports a document from before secrets had names. There is at
	// most one in the world and a migration would be larger than what it
	// migrates, so it is refused and the screen offers to start again.
	ErrOldVault = errors.New("this vault predates named credentials and cannot be read")
	// ErrUnknownKind rejects a namespace that is neither of the two.
	ErrUnknownKind = errors.New("that is not a credential kind")
	// ErrUnknownCredential rejects a reference to a name that does not exist in
	// that namespace — which is also how a host is stopped from referencing a
	// key's passphrase.
	ErrUnknownCredential = errors.New("no credential of that kind has that name")
	// ErrCredentialInUse refuses to remove a secret something still points at.
	ErrCredentialInUse = errors.New("something still uses this credential")
)

// MinPassphraseLength is the shortest vault passphrase this will accept.
const MinPassphraseLength = envelope.MinPassphraseLength

// Kind names a credential namespace.
//
// A host may reference only KindPassword and a key only KindKeyPassphrase. One
// namespace would let a host's password picker offer a key's passphrase, and
// picking it would send that passphrase to a remote host as a login password.
// Two make that impossible to express rather than merely unlikely.
//
// They differ in what they protect as well: an account password admits you to
// one account, and a key passphrase unlocks a key that may admit you to many
// machines. Sharing is ordinary within each and meaningless across them.
type Kind string

const (
	KindPassword      Kind = "password"
	KindKeyPassphrase Kind = "key_passphrase"
)

// ValidKind reports whether a value names a namespace. It is the one place the
// set is decided, so a route and a form cannot disagree about it.
func ValidKind(kind Kind) bool {
	return kind == KindPassword || kind == KindKeyPassphrase
}

// SyncSettings is what the object store needs.
//
// It is sealed with the same master password as the vault and kept in its own
// file, because the vault travels: Collect names ssh-ui/secrets outright, and
// putting the access key inside the vault would put the key to the bucket
// inside the bucket. Someone who obtained one snapshot by any means, and its
// passphrase, would gain the live bucket and every future snapshot rather than
// the one they already had.
type SyncSettings struct {
	Endpoint string `json:"endpoint,omitempty"`
	Bucket   string `json:"bucket,omitempty"`
	// Path is the prefix every object goes under, empty for the bucket root.
	Path            string `json:"path,omitempty"`
	Region          string `json:"region,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	Direction       string `json:"direction,omitempty"`
}

// document is the plaintext, and never leaves this package in this form.
//
// Two credential maps, and one reference map per kind: hosts are keyed by alias
// and keys by workspace-relative path. A named secret is stored once however
// many subjects point at it, which is the whole reason for the shape — twenty
// machines sharing a password rotate it in one place.
type document struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Passwords      map[string]string `json:"passwords"`
	KeyPassphrases map[string]string `json:"keyPassphrases"`
	Hosts          map[string]string `json:"hosts"`
	Keys           map[string]string `json:"keys"`
}

// Vault is an opened secrets file.
//
// It holds the derived key rather than the passphrase, so a change can be
// re-sealed without asking again, and the passphrase is not kept anywhere
// after Open returns.
type Vault struct {
	key      envelope.Key
	secrets  map[Kind]map[string]string
	subjects map[Kind]map[string]string
}

func newMaps() (map[Kind]map[string]string, map[Kind]map[string]string) {
	return map[Kind]map[string]string{KindPassword: {}, KindKeyPassphrase: {}},
		map[Kind]map[string]string{KindPassword: {}, KindKeyPassphrase: {}}
}

// Create returns an empty vault sealed by passphrase.
func Create(passphrase string) (*Vault, error) {
	key, err := envelope.Derive(passphrase)
	if err != nil {
		return nil, err
	}
	secrets, subjects := newMaps()
	return &Vault{key: key, secrets: secrets, subjects: subjects}, nil
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
	// A version 1 document held a password per alias and no names at all. There
	// is at most one in the world, and a migration for it would be larger than
	// the thing it migrates, so it is refused with an error the screen turns
	// into "set them again" rather than silently reshaped.
	if parsed.SchemaVersion < SchemaVersion {
		return nil, ErrOldVault
	}
	secrets, subjects := newMaps()
	for kind, stored := range map[Kind]map[string]string{
		KindPassword:      parsed.Passwords,
		KindKeyPassphrase: parsed.KeyPassphrases,
	} {
		for name, value := range stored {
			secrets[kind][name] = value
		}
	}
	for kind, stored := range map[Kind]map[string]string{
		KindPassword:      parsed.Hosts,
		KindKeyPassphrase: parsed.Keys,
	} {
		for subject, name := range stored {
			subjects[kind][subject] = name
		}
	}
	return &Vault{key: key, secrets: secrets, subjects: subjects}, nil
}

// SealSettings encrypts the object store settings with the vault's own key, for
// the file beside it. Same master password, different file: this one does not
// travel.
func (v *Vault) SealSettings(settings SyncSettings) ([]byte, error) {
	plaintext, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return v.key.Seal(plaintext)
}

// OpenSettings decrypts the file SealSettings wrote.
func (v *Vault) OpenSettings(sealed []byte) (SyncSettings, error) {
	plaintext, err := v.key.Open(sealed)
	if err != nil {
		return SyncSettings{}, err
	}
	var settings SyncSettings
	if err := json.Unmarshal(plaintext, &settings); err != nil {
		return SyncSettings{}, ErrWrongPassphrase
	}
	return settings, nil
}

// Seal encrypts the vault for writing.
// Rekey derives a fresh key from passphrase and adopts it.
//
// The contents are untouched; what changes is what opens them. Everything the
// old key sealed has to be re-sealed by the caller in the same breath, which is
// why this is a method on the vault rather than a new vault: the caller needs
// both keys at once.
func (v *Vault) Rekey(passphrase string) (envelope.Key, error) {
	key, err := envelope.Derive(passphrase)
	if err != nil {
		return envelope.Key{}, err
	}
	previous := v.key
	v.key = key
	return previous, nil
}

// SealBytes seals arbitrary bytes with this vault's key.
//
// It is what turns the generational backup directory from a pile of previous
// file contents — including, for the writes that used to refuse a backup
// entirely, previous private keys — into a pile of ciphertext.
func (v *Vault) SealBytes(plaintext []byte) ([]byte, error) {
	return v.key.Seal(plaintext)
}

// OpenBytes is its inverse, for a rollback or a restore.
func (v *Vault) OpenBytes(sealed []byte) ([]byte, error) {
	return v.key.Open(sealed)
}

func (v *Vault) Seal() ([]byte, error) {
	plaintext, err := json.Marshal(document{
		SchemaVersion:  SchemaVersion,
		Passwords:      v.secrets[KindPassword],
		KeyPassphrases: v.secrets[KindKeyPassphrase],
		Hosts:          v.subjects[KindPassword],
		Keys:           v.subjects[KindKeyPassphrase],
	})
	if err != nil {
		return nil, err
	}
	return v.key.Seal(plaintext)
}

// Names returns the credential names of one kind, sorted. A name is not itself
// a secret; the value it stands for is.
func (v *Vault) Names(kind Kind) []string {
	return slices.Sorted(maps.Keys(v.secrets[kind]))
}

// Secret returns the value a name stands for.
func (v *Vault) Secret(kind Kind, name string) (string, bool) {
	value, ok := v.secrets[kind][name]
	return value, ok
}

// Set stores a credential under a name, creating it or replacing its value.
func (v *Vault) Set(kind Kind, name, value string) error {
	if !ValidKind(kind) {
		return ErrUnknownKind
	}
	if !validCredentialName(name) {
		return ErrUnsafeName
	}
	if value == "" {
		return ErrEmptySecret
	}
	v.secrets[kind][name] = value
	return nil
}

// Delete forgets a credential, and refuses while anything still points at it.
//
// The point of naming a secret is that many subjects share one entry, so
// removing the entry from under them would break every one of them at once,
// later, somewhere else.
func (v *Vault) Delete(kind Kind, name string) error {
	if len(v.Uses(kind, name)) > 0 {
		return ErrCredentialInUse
	}
	delete(v.secrets[kind], name)
	return nil
}

// Uses lists the subjects referencing a credential, sorted.
func (v *Vault) Uses(kind Kind, name string) []string {
	var uses []string
	for subject, referenced := range v.subjects[kind] {
		if referenced == name {
			uses = append(uses, subject)
		}
	}
	slices.Sort(uses)
	return uses
}

// Assign points a subject at a credential of the same kind.
//
// The kind is the whole guard: a host names an alias and may reference only an
// account password, a key names a workspace-relative path and may reference
// only a key passphrase. Crossing them is not refused by a check that could be
// forgotten — there is no map in which the other kind's names appear.
func (v *Vault) Assign(kind Kind, subject, name string) error {
	if !ValidKind(kind) {
		return ErrUnknownKind
	}
	if kind == KindPassword {
		if err := platform.ValidateAlias(subject); err != nil {
			return ErrUnsafeName
		}
	} else if subject == "" || strings.ContainsAny(subject, "\x00") {
		return ErrUnsafeName
	}
	if _, ok := v.secrets[kind][name]; !ok {
		return ErrUnknownCredential
	}
	v.subjects[kind][subject] = name
	return nil
}

// Unassign forgets a subject's reference. A missing subject is not an error.
func (v *Vault) Unassign(kind Kind, subject string) {
	delete(v.subjects[kind], subject)
}

// Assigned returns the credential a subject references.
func (v *Vault) Assigned(kind Kind, subject string) (string, bool) {
	name, ok := v.subjects[kind][subject]
	return name, ok
}

// Subjects returns every subject of one kind that references a credential.
func (v *Vault) Subjects(kind Kind) []string {
	return slices.Sorted(maps.Keys(v.subjects[kind]))
}

// SecretFor resolves a subject to the value it should be given.
func (v *Vault) SecretFor(kind Kind, subject string) (string, bool) {
	name, ok := v.subjects[kind][subject]
	if !ok {
		return "", false
	}
	return v.Secret(kind, name)
}

// Rename carries a subject's reference to a new name, which is what a host
// rename has to do or the reference is silently orphaned under a name nothing
// asks for.
func (v *Vault) Rename(kind Kind, from, to string) error {
	name, ok := v.subjects[kind][from]
	if !ok {
		return nil
	}
	if kind == KindPassword {
		if err := platform.ValidateAlias(to); err != nil {
			return ErrUnsafeName
		}
	}
	delete(v.subjects[kind], from)
	v.subjects[kind][to] = name
	return nil
}

// validCredentialName accepts a name a person would type and a screen can show.
// It is not an alias: a credential is named after what it is for, which may be
// "the office VMs" rather than a hostname.
func validCredentialName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	return !strings.ContainsAny(name, "\x00\r\n")
}
