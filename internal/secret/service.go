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

	mu     sync.Mutex
	vault  *Vault
	tokens map[string]pendingToken
}

// NewService returns a locked service. Nothing can be read until Unlock.
func NewService(workspace *storage.Workspace, transactions *storage.Manager) *Service {
	return &Service{
		workspace:    workspace,
		transactions: transactions,
		now:          time.Now,
		tokens:       map[string]pendingToken{},
	}
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
	return s.vault != nil
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
	s.mu.Unlock()
	return s.write()
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
		return err
	}

	s.mu.Lock()
	s.vault = vault
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
	if s.vault == nil {
		return false
	}
	_, ok := s.vault.SecretFor(KindPassword, alias)
	return ok
}

// Set stores a password for one alias and writes the vault.
//
// The credential takes the alias as its name, which is what "just store a
// password for this host" means now that secrets have names. Sharing one across
// several hosts is done by assigning an existing name instead.
func (s *Service) Set(alias, password string) error {
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := s.vault.Set(KindPassword, alias, password); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := s.vault.Assign(KindPassword, alias, alias); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// Remove forgets a password and writes the vault.
func (s *Service) Remove(alias string) error {
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	// The reference goes; the credential stays if anything else points at it,
	// and goes with it when nothing does.
	s.vault.Unassign(KindPassword, alias)
	_ = s.vault.Delete(KindPassword, alias)
	s.mu.Unlock()
	return s.write()
}

// Rename carries a stored password to a new alias. A host rename that left it
// behind would file the password under a name nothing ever asks for again.
func (s *Service) Rename(from, to string) error {
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if _, ok := s.vault.Assigned(KindPassword, from); !ok {
		s.mu.Unlock()
		return nil
	}
	if err := s.vault.Rename(KindPassword, from, to); err != nil {
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
	if s.vault == nil {
		return nil, ErrLocked
	}
	listed := map[Kind]map[string][]string{}
	for _, kind := range []Kind{KindPassword, KindKeyPassphrase} {
		listed[kind] = map[string][]string{}
		for _, name := range s.vault.Names(kind) {
			uses := s.vault.Uses(kind, name)
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
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := s.vault.Set(kind, name, value); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// DeleteCredential forgets a credential, refusing while anything points at it.
func (s *Service) DeleteCredential(kind Kind, name string) error {
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := s.vault.Delete(kind, name); err != nil {
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
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if err := s.vault.Assign(kind, subject, name); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return s.write()
}

// UnassignCredential forgets a subject's reference, leaving the credential.
func (s *Service) UnassignCredential(kind Kind, subject string) error {
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	s.vault.Unassign(kind, subject)
	s.mu.Unlock()
	return s.write()
}

// AssignedCredential reports the name a subject references.
func (s *Service) AssignedCredential(kind Kind, subject string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return "", false
	}
	return s.vault.Assigned(kind, subject)
}

// PasswordFor resolves an alias to the value it should be given, or "" when
// there is none and when the vault is shut. The caller that matters — the
// askpass answer — distinguishes the two through Redeem's errors.
func (s *Service) PasswordFor(alias string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return ""
	}
	value, _ := s.vault.SecretFor(KindPassword, alias)
	return value
}

// KeyPassphraseFor resolves a key's workspace-relative path to its stored
// passphrase. It is what lets a key be added to the agent in one action rather
// than two, and it is injected into the key vault rather than imported by it.
func (s *Service) KeyPassphraseFor(relativePath string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return "", false
	}
	return s.vault.SecretFor(KindKeyPassphrase, relativePath)
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
	if s.vault == nil {
		return SyncSettings{}, ErrLocked
	}
	sealed, err := s.workspace.FileSystem().ReadFile(s.settingsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return SyncSettings{}, nil
	}
	if err != nil {
		return SyncSettings{}, err
	}
	return s.vault.OpenSettings(sealed)
}

// SetSyncSettings replaces the object store settings.
func (s *Service) SetSyncSettings(settings SyncSettings) error {
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	sealed, err := s.vault.SealSettings(settings)
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
			// The settings are a secret, so no generational copy is kept: the
			// vault's own writes make none either.
			SkipBackup: true,
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
	if s.vault == nil {
		return "", ErrLocked
	}
	if _, ok := s.vault.SecretFor(KindPassword, alias); !ok {
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
func (s *Service) Redeem(token, alias, prompt string, answerable func(string) bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return "", ErrLocked
	}
	s.expireLocked()

	pending, ok := s.lookupTokenLocked(token)
	if !ok || pending.alias != alias {
		return "", ErrUnknownToken
	}
	delete(s.tokens, token)

	if !answerable(prompt) {
		return "", ErrUnknownToken
	}
	password, ok := s.vault.SecretFor(KindPassword, alias)
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
// SkipBackup is set. The file is already encrypted, so a backup would not
// disclose anything a copy of the live file does not — but it would leave one
// more copy of the ciphertext for every change, and a store of passwords is
// not something whose old generations anyone wants kept. The same reasoning
// the key vault applies to private keys.
func (s *Service) write() error {
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	sealed, err := s.vault.Seal()
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
			SkipBackup:   true,
		}},
	})
	return err
}

// Aliases returns the hosts with a stored password, or nothing while locked.
func (s *Service) Aliases() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return nil
	}
	return s.vault.Subjects(KindPassword)
}
