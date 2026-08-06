package secret

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"ssh-ui/internal/envelope"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/storage"
)

var (
	// ErrLocked reports that no passphrase has been supplied this session.
	ErrLocked = errors.New("the password vault is locked")
	// ErrAlreadyExists reports that Initialise was called for a workspace that
	// already has a vault. Overwriting it would destroy every stored password
	// with no way back.
	ErrAlreadyExists = errors.New("this workspace already has a password vault")
	// ErrNoVault reports that nothing has been created yet.
	ErrNoVault = errors.New("this workspace has no password vault yet")
	// ErrUnknownToken reports an askpass token that was never issued, has
	// already been spent, has expired, or was issued for a different alias.
	ErrUnknownToken = errors.New("that askpass token is not valid for this request")
	// ErrNoPassword reports that nothing is stored for that alias.
	ErrNoPassword = errors.New("no password is stored for that host")
)

// TokenTTL is how long an askpass token stays usable.
//
// It is the same two minutes as a session action token, and for the same
// reason: it is the gap between a user clicking a button and OpenSSH reaching
// the password prompt, not a window anyone should be able to plan around.
const TokenTTL = 2 * time.Minute

// MaxPendingTokens bounds how many unspent tokens can be held at once, so a
// user who opens many terminals cannot grow this map without limit.
const MaxPendingTokens = 32

// IdleTimeout is how long an open vault survives without being used.
//
// A vault that stayed open for the life of the process would be open while the
// laptop is in a bag, and it holds every password and every key passphrase.
// Eight hours is a working day: someone who uses it in the morning is not asked
// again in the afternoon, and someone who stops for the night is.
const IdleTimeout = 8 * time.Hour

type pendingToken struct {
	alias   string
	expires time.Time
}

// Service owns the opened vault for the life of the process.
//
// The derived key lives in this struct and nowhere else. It is never written,
// never logged and never returned; the only thing that leaves is one password,
// to one askpass request, holding one token this service issued.
type Service struct {
	workspace    *storage.Workspace
	transactions *storage.Manager
	now          func() time.Time

	// sleep is how a refusal waits. Injected so a test can watch the backoff
	// without spending it.
	sleep func(time.Duration)

	mu    sync.Mutex
	vault *Vault
	// refusals counts consecutive wrong master passwords, and is what makes
	// each one answered more slowly than the last.
	refusals int
	tokens   map[string]pendingToken
	// used is when a secret was last read or written. Reading the status is
	// deliberately not use: an open browser tab asks for it whenever a screen
	// mounts, and one forgotten tab must not hold the vault open for as long as
	// the machine is on.
	used time.Time
}

// NewService returns a locked service. Nothing can be read until Unlock.
func NewService(workspace *storage.Workspace, transactions *storage.Manager, now func() time.Time) *Service {
	return &Service{
		workspace:    workspace,
		transactions: transactions,
		now:          now,
		tokens:       map[string]pendingToken{},
	}
}

// open returns the vault, shutting it first if it has gone untouched for longer
// than IdleTimeout.
//
// Every method that touches a secret goes through here rather than testing
// s.vault itself, so there is one place that decides whether the vault is open
// and no method can be written that forgets to ask.
func (s *Service) open() *Vault {
	if s.vault == nil {
		return nil
	}
	if s.now().Sub(s.used) >= IdleTimeout {
		s.vault = nil
		s.tokens = map[string]pendingToken{}
		return nil
	}
	return s.vault
}

// use returns the vault and puts the idle clock back to zero. It is what a
// method calls when it is about to read or write a secret, as opposed to
// reporting whether there is one.
func (s *Service) use() *Vault {
	vault := s.open()
	if vault != nil {
		s.used = s.now()
	}
	return vault
}

func (s *Service) path() string {
	return filepath.Join(s.workspace.Root(), filepath.FromSlash(WorkspacePath))
}

// Exists reports whether a vault file is present, which is a different
// question from whether it is unlocked.
func (s *Service) Exists() (bool, error) {
	_, err := s.workspace.FileSystem().ReadFile(s.path())
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// Unlocked reports whether a passphrase has been supplied this session.
func (s *Service) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open() != nil
}

// Initialise creates a vault for a workspace that has none.
//
// It refuses when one already exists rather than replacing it: an accidental
// re-initialise would destroy every stored password, and there is no recovery
// path for an encrypted file whose key is gone.
func (s *Service) Initialise(passphrase string) error {
	exists, err := s.Exists()
	if err != nil {
		return err
	}
	if exists {
		return ErrAlreadyExists
	}
	vault, err := Create(passphrase)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.vault = vault
	s.used = s.now()
	s.mu.Unlock()
	return s.write()
}

// Verify reports whether passphrase is this workspace's master password.
//
// It answers from the file and changes nothing, so a shut vault can still be
// asked and a screen can find out whether what the user typed is the master
// password before using it as one. That is what lets the snapshot be sealed
// with the master password rather than a second one: a typo becomes a refusal
// here instead of an archive nobody can ever open.
//
// It costs one derivation, which is the same cost as unlocking, and it is only
// ever reached by an action a person asked for.
func (s *Service) Verify(passphrase string) (bool, error) {
	sealed, err := s.workspace.FileSystem().ReadFile(s.path())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, ErrNoVault
		}
		return false, err
	}
	if _, err := Open(sealed, passphrase); err != nil {
		if errors.Is(err, ErrWrongPassphrase) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// MaxUnlockDelay is how long a refusal will ever wait.
//
// The vault file can be copied and attacked offline, so this is not what stands
// between an attacker and its contents — Argon2id is. What it stops is the
// cheap case: a local process trying passwords against a running application as
// fast as it can answer them.
const MaxUnlockDelay = 4 * time.Second

// SetSleep installs how a refusal waits. It is for the test that watches the
// backoff rather than spending it.
func (s *Service) SetSleep(sleep func(time.Duration)) { s.sleep = sleep }

// refuse waits for as long as this run's consecutive refusals have earned.
func (s *Service) refuse() {
	s.mu.Lock()
	s.refusals++
	count := s.refusals
	s.mu.Unlock()

	delay := time.Duration(count) * 250 * time.Millisecond
	if delay > MaxUnlockDelay {
		delay = MaxUnlockDelay
	}
	sleep := s.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	sleep(delay)
}

// Unlock opens the vault with passphrase.
func (s *Service) Unlock(passphrase string) error {
	sealed, err := s.workspace.FileSystem().ReadFile(s.path())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNoVault
		}
		return err
	}
	vault, err := Open(sealed, passphrase)
	if err != nil {
		if errors.Is(err, ErrWrongPassphrase) {
			s.refuse()
		}
		return err
	}

	s.mu.Lock()
	s.vault = vault
	s.used = s.now()
	// A password that worked clears what the wrong ones built up.
	s.refusals = 0
	s.mu.Unlock()
	return nil
}

// Lock forgets the derived key and every pending token.
//
// The tokens go with it because a token outliving the unlock would let a
// connection started before the lock still collect a password after it.
func (s *Service) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vault = nil
	s.tokens = map[string]pendingToken{}
}

// Has reports whether a password is stored for alias. It answers false rather
// than an error while locked, because "we cannot see" and "there is none" look
// the same from outside and the interface says which state it is in
// separately.
func (s *Service) Has(alias string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.open()
	if vault == nil {
		return false
	}
	_, ok := vault.SecretFor(KindPassword, alias)
	return ok
}

// Set stores a password for one alias and writes the vault.
//
// The credential takes the alias as its name, which is what "just store a
// password for this host" means now that secrets have names. Sharing one across
// several hosts is done by assigning an existing name instead.
func (s *Service) Set(alias, password string) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := vault.Set(KindPassword, alias, password); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := vault.Assign(KindPassword, alias, alias); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// Remove forgets a password and writes the vault.
func (s *Service) Remove(alias string) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	// The reference goes; the credential stays if anything else points at it,
	// and goes with it when nothing does.
	vault.Unassign(KindPassword, alias)
	_ = vault.Delete(KindPassword, alias)
	s.mu.Unlock()
	return s.write()
}

// Rename carries a stored password to a new alias. A host rename that left it
// behind would file the password under a name nothing ever asks for again.
func (s *Service) Rename(from, to string) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if _, ok := vault.Assigned(KindPassword, from); !ok {
		s.mu.Unlock()
		return nil
	}
	if err := vault.Rename(KindPassword, from, to); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// Credentials lists every credential name of both kinds with what uses it.
//
// Names and uses, never values. This is what the screens read, and a screen
// that could read a secret would be a screen a compromised browser could read
// it from.
func (s *Service) Credentials() (map[Kind]map[string][]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.open()
	if vault == nil {
		return nil, ErrLocked
	}
	listed := map[Kind]map[string][]string{}
	for _, kind := range []Kind{KindPassword, KindKeyPassphrase} {
		listed[kind] = map[string][]string{}
		for _, name := range vault.Names(kind) {
			uses := vault.Uses(kind, name)
			if uses == nil {
				uses = []string{}
			}
			listed[kind][name] = uses
		}
	}
	return listed, nil
}

// SetCredential creates a credential or replaces its value.
//
// Replacing is how a shared secret is rotated: every subject pointing at the
// name reads the new value, which is the whole reason names exist.
func (s *Service) SetCredential(kind Kind, name, value string) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := vault.Set(kind, name, value); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// DeleteCredential forgets a credential, refusing while anything points at it.
func (s *Service) DeleteCredential(kind Kind, name string) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := vault.Delete(kind, name); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// AssignCredential points a subject at a credential of the same kind. The kind
// is the guard: there is no map in which the other kind's names appear.
func (s *Service) AssignCredential(kind Kind, subject, name string) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := vault.Assign(kind, subject, name); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// UnassignCredential forgets a subject's reference, leaving the credential.
func (s *Service) UnassignCredential(kind Kind, subject string) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	vault.Unassign(kind, subject)
	s.mu.Unlock()
	return s.write()
}

// AssignedCredential reports the name a subject references.
func (s *Service) AssignedCredential(kind Kind, subject string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.open()
	if vault == nil {
		return "", false
	}
	return vault.Assigned(kind, subject)
}

// PasswordFor resolves an alias to the value it should be given, or "" when
// there is none and when the vault is shut. The caller that matters — the
// askpass answer — distinguishes the two through Redeem's errors.
func (s *Service) PasswordFor(alias string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.use()
	if vault == nil {
		return ""
	}
	value, _ := vault.SecretFor(KindPassword, alias)
	return value
}

// KeyPassphraseFor resolves a key's workspace-relative path to its stored
// passphrase. It is what lets a key be added to the agent in one action rather
// than two, and it is injected into the key vault rather than imported by it.
func (s *Service) KeyPassphraseFor(relativePath string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.use()
	if vault == nil {
		return "", false
	}
	return vault.SecretFor(KindKeyPassphrase, relativePath)
}

// SealBackup seals one generational backup, and OpenBackup opens it.
//
// They are handed to the storage layer rather than imported by it: where a
// secret lives belongs to this package, and the transaction manager must not
// have to know. A shut vault seals nothing and opens nothing — the application
// is behind the master password so that cannot happen while anything is being
// written, and failing here is the right answer if it somehow does, because the
// alternative is a copy of a private key in the clear.
func (s *Service) SealBackup(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.use()
	if vault == nil {
		return nil, ErrLocked
	}
	return vault.SealBytes(plaintext)
}

func (s *Service) OpenBackup(sealed []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.use()
	if vault == nil {
		return nil, ErrLocked
	}
	return vault.OpenBytes(sealed)
}

// settingsPath is the sealed object store settings beside the vault.
func (s *Service) settingsPath() string {
	return filepath.Join(s.workspace.Root(), filepath.FromSlash(SettingsPath))
}

// SyncSettings returns the object store settings, secrets included.
//
// Only the caller that builds a client asks for these; the screen is answered
// from the fields that are not secret. A machine that has never been given them
// answers the zero value and no error, because "not configured yet" is a state
// and not a failure.
func (s *Service) SyncSettings() (SyncSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.use()
	if vault == nil {
		return SyncSettings{}, ErrLocked
	}
	sealed, err := s.workspace.FileSystem().ReadFile(s.settingsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return SyncSettings{}, nil
	}
	if err != nil {
		return SyncSettings{}, err
	}
	return vault.OpenSettings(sealed)
}

// SetSyncSettings replaces the object store settings.
func (s *Service) SetSyncSettings(settings SyncSettings) error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	sealed, err := vault.SealSettings(settings)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := s.workspace.EnsureDirectory(s.workspace.StateDir()); err != nil {
		return err
	}
	current, readErr := s.workspace.FileSystem().ReadFile(s.settingsPath())
	precondition := storage.Precondition{}
	if readErr == nil {
		precondition = storage.Precondition{Exists: true, Digest: storage.Digest(current)}
	}
	_, err = s.transactions.Commit(storage.Request{
		Operation: "sync.settings",
		Changes: []storage.Change{{
			Path: s.settingsPath(), Contents: sealed, Precondition: precondition,
		}},
	})
	return err
}

// IssueToken mints a single-use token for one alias.
//
// It is issued when the user asks to open a terminal and is spent by the
// askpass request that connection makes. Nothing else can obtain one.
func (s *Service) IssueToken(alias string) (string, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return "", ErrUnsafeName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.use()
	if vault == nil {
		return "", ErrLocked
	}
	if _, ok := vault.SecretFor(KindPassword, alias); !ok {
		return "", ErrNoPassword
	}
	s.expireLocked()
	if len(s.tokens) >= MaxPendingTokens {
		return "", ErrUnknownToken
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.tokens[token] = pendingToken{alias: alias, expires: s.now().Add(TokenTTL)}
	return token, nil
}

// Redeem spends a token and returns the password for its alias.
//
// The prompt is checked here as well as in the helper, because this is the
// side that cannot be replaced: a helper compiled by someone else, or the same
// helper invoked with a different argument, still gets no answer to a question
// this application has not agreed to answer. The token is spent whether or not
// the prompt is acceptable, so a wrong prompt cannot be retried with a right
// one.
func (s *Service) Redeem(token, alias, prompt string, answerable func(alias, prompt string) bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.use()
	if vault == nil {
		return "", ErrLocked
	}
	s.expireLocked()

	pending, ok := s.lookupTokenLocked(token)
	if !ok || pending.alias != alias {
		return "", ErrUnknownToken
	}
	delete(s.tokens, token)

	if !answerable(alias, prompt) {
		return "", ErrUnknownToken
	}
	password, ok := vault.SecretFor(KindPassword, alias)
	if !ok {
		return "", ErrNoPassword
	}
	return password, nil
}

// lookupTokenLocked compares in constant time against every live token.
//
// A map lookup would be the obvious thing and would leak, through timing,
// whether a guessed prefix was getting closer. The set is bounded at
// MaxPendingTokens, so sweeping it costs nothing worth measuring.
func (s *Service) lookupTokenLocked(presented string) (pendingToken, bool) {
	var found pendingToken
	matched := false
	for token, pending := range s.tokens {
		if len(token) == len(presented) && subtle.ConstantTimeCompare([]byte(token), []byte(presented)) == 1 {
			found = pending
			matched = true
		}
	}
	return found, matched
}

func (s *Service) expireLocked() {
	now := s.now()
	for token, pending := range s.tokens {
		if now.After(pending.expires) {
			delete(s.tokens, token)
		}
	}
}

// write seals the vault and commits it through the transaction manager, so a
// half-written secrets file is not a state this application can reach.
//
// A generation is kept, like every other write. The backups are themselves
// sealed with this vault's key, so an old generation of the vault discloses
// nothing a copy of the live file does not — and an accident here is one of the
// few that cannot be undone any other way.
func (s *Service) write() error {
	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	sealed, err := vault.Seal()
	s.mu.Unlock()
	if err != nil {
		return err
	}

	if err := s.workspace.EnsureDirectory(s.workspace.StateDir()); err != nil {
		return err
	}
	current, readErr := s.workspace.FileSystem().ReadFile(s.path())
	precondition := storage.Precondition{}
	if readErr == nil {
		precondition = storage.Precondition{Exists: true, Digest: storage.Digest(current)}
	} else if !errors.Is(readErr, fs.ErrNotExist) {
		return readErr
	}

	_, err = s.transactions.Commit(storage.Request{
		Operation: "secret.vault",
		Changes: []storage.Change{{
			Path:         s.path(),
			Contents:     sealed,
			Precondition: precondition,
		}},
	})
	return err
}

// Aliases returns the hosts with a stored password, or nothing while locked.
func (s *Service) Aliases() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	vault := s.open()
	if vault == nil {
		return nil
	}
	return vault.Subjects(KindPassword)
}

// ChangeMasterPassword re-derives the key and re-seals everything it held.
//
// The vault, the sealed object store settings and every generational backup are
// sealed with a key derived from the master password. A change that replaced
// only the vault would leave the rest openable by a password nobody uses any
// more, which is the same as losing them: the backups exist to be restored
// from, and a backup nobody can open is not a backup.
//
// One transaction. It keeps no generational copies of what it replaces, and
// that is the one place SkipBackup is still right: a copy of the old vault
// sealed with the old key would be unopenable the moment this finishes.
// Everything is staged in the journal, so an interruption can be completed;
// what it cannot be is rolled back, and Rollback says so rather than pretending.
//
// The remote snapshot is not this function's to re-seal — it belongs to the
// object store and this package does not import it. The caller pushes.
func (s *Service) ChangeMasterPassword(current, next string) error {
	if ok, err := s.Verify(current); err != nil {
		return err
	} else if !ok {
		return ErrWrongPassphrase
	}

	s.mu.Lock()
	vault := s.use()
	if vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	previous, err := vault.Rekey(next)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	// From here the vault holds the new key, so anything it seals is sealed
	// with it and anything sealed before is opened with the old one.
	changes, buildErr := s.reSealed(vault, previous)
	if buildErr != nil {
		// Put the old key back: nothing has been written, so the vault in
		// memory must go on matching the vault on disk.
		vault.key = previous
		s.mu.Unlock()
		return buildErr
	}
	sealed, sealErr := vault.Seal()
	s.mu.Unlock()
	if sealErr != nil {
		return sealErr
	}

	previousVault, readErr := s.workspace.FileSystem().ReadFile(s.path())
	if readErr != nil {
		return readErr
	}
	changes = append(changes, storage.Change{
		Path: s.path(), Contents: sealed, SkipBackup: true,
		Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(previousVault)},
	})
	if _, err := s.transactions.Commit(storage.Request{
		Operation: "secret.rekey",
		Changes:   changes,
	}); err != nil {
		return err
	}
	return nil
}

// reSealed reads every file the old key sealed and seals it with the new one.
//
// The backups are read directly rather than through the manager, because the
// manager opens them with the key the service currently holds — which is the
// new one by the time this runs.
func (s *Service) reSealed(vault *Vault, previous envelope.Key) ([]storage.Change, error) {
	changes := make([]storage.Change, 0, 8)

	settings, err := s.workspace.FileSystem().ReadFile(s.settingsPath())
	switch {
	case err == nil:
		plaintext, openErr := previous.Open(settings)
		if openErr != nil {
			return nil, openErr
		}
		resealed, sealErr := vault.SealBytes(plaintext)
		if sealErr != nil {
			return nil, sealErr
		}
		changes = append(changes, storage.Change{
			Path: s.settingsPath(), Contents: resealed, SkipBackup: true,
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(settings)},
		})
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, err
	}

	backups := filepath.Join(s.workspace.StateDir(), storage.BackupDirectoryName)
	walkErr := filepath.WalkDir(backups, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if entry.IsDir() {
			return nil
		}
		body, readErr := s.workspace.FileSystem().ReadFile(path)
		if readErr != nil {
			return readErr
		}
		plaintext, openErr := previous.Open(body)
		if openErr != nil {
			// A backup written before the backups were sealed at all is not
			// this function's to convert, and refusing the whole change over
			// one is worse than leaving it as it was.
			return nil
		}
		resealed, sealErr := vault.SealBytes(plaintext)
		if sealErr != nil {
			return sealErr
		}
		changes = append(changes, storage.Change{
			Path: path, Contents: resealed, SkipBackup: true,
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(body)},
		})
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.ErrNotExist) {
		return nil, walkErr
	}
	return changes, nil
}
