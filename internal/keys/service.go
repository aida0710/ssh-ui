package keys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"ssh-ui/internal/config"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/storage"
)

var (
	ErrUnknownKey                  = errors.New("no key with that identifier is in the inventory")
	ErrInvalidFileName             = errors.New("file name is not a safe single path segment")
	ErrInvalidComment              = errors.New("comment contains characters this application will not put in a command line")
	ErrConflictingPassphraseChoice = errors.New("a passphrase was supplied together with the unencrypted flag")
)

// fileNamePattern accepts one safe path segment. A leading dot, a slash and a
// '..' segment are all impossible under this pattern, so a request cannot name
// a file outside ~/.ssh even before Workspace.ResolveForWrite sees it.
var fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// commentPattern accepts only characters that need no shell quoting, because a
// comment is shown inside a copyable ssh-keygen command line.
var commentPattern = regexp.MustCompile(`^[A-Za-z0-9@._+=:,/-]{0,127}$`)

// safeArgumentPattern is the final check applied to every element of a command
// line this application displays.
var safeArgumentPattern = regexp.MustCompile(`^[A-Za-z0-9@%_+=:,./-]+$`)

// ValidateFileName rejects anything that is not a safe single path segment.
func ValidateFileName(name string) error {
	if !fileNamePattern.MatchString(name) {
		return ErrInvalidFileName
	}
	if strings.HasSuffix(name, ".pub") || name == StateDirectoryName {
		return ErrInvalidFileName
	}
	if reservedFileNames[strings.ToLower(name)] {
		return ErrInvalidFileName
	}
	return nil
}

// reservedFileNames are the names OpenSSH and this application already give a
// meaning inside ~/.ssh.
//
// Writing a key to one of them would not merely be confusing: generating a key
// called "config" into an empty workspace would create the entry configuration
// file and fill it with a private key. An existing file is protected by the
// transaction precondition, so only a fresh workspace is exposed, but the name
// policy should refuse a name the application itself depends on rather than
// rely on something already occupying it. The comparison is case-insensitive
// because macOS filesystems are case-insensitive by default, so "Config" and
// "config" are the same file.
var reservedFileNames = map[string]bool{
	"config":           true,
	"known_hosts":      true,
	"known_hosts2":     true,
	"authorized_keys":  true,
	"authorized_keys2": true,
	"environment":      true,
	"rc":               true,
	"ssh-ui":           true,
}

// ValidateComment rejects a comment this application would have to quote.
func ValidateComment(comment string) error {
	if !commentPattern.MatchString(comment) {
		return ErrInvalidComment
	}
	return nil
}

// Service is the key vault use-case layer. It owns no HTTP and no UI concern,
// reads only through the storage filesystem seam, and writes only through the
// journalled transaction manager.
type Service struct {
	workspace    *storage.Workspace
	transactions *storage.Manager
	resolver     config.Resolver
	catalogue    CatalogueReader
	agent        platform.KeyAgent
	now          func() time.Time
	random       io.Reader
}

type ServiceOptions struct {
	Workspace    *storage.Workspace
	Transactions *storage.Manager
	Resolver     config.Resolver
	Catalogue    CatalogueReader
	Agent        platform.KeyAgent
	Now          func() time.Time
	Random       io.Reader
}

func NewService(options ServiceOptions) *Service {
	return &Service{
		workspace:    options.Workspace,
		transactions: options.Transactions,
		resolver:     options.Resolver,
		catalogue:    options.Catalogue,
		agent:        options.Agent,
		now:          options.Now,
		random:       options.Random,
	}
}

// entryPath is the user configuration file the Include graph starts from.
func (service *Service) entryPath() string {
	return filepath.Join(service.workspace.Root(), "config")
}

func (service *Service) absolutePath(relativePath string) string {
	return filepath.Join(service.workspace.Root(), relativePath)
}

// Inventory classifies the workspace and attaches the Hosts that name each file.
func (service *Service) Inventory() (*Inventory, error) {
	inventory, err := NewScanner(service.workspace).Scan()
	if err != nil {
		return nil, err
	}
	graph, err := service.resolver.Resolve(service.entryPath())
	if err != nil {
		return inventory, nil
	}
	inventory.AttachReferences(BuildReferenceIndex(graph, service.workspace))
	return inventory, nil
}

// Algorithms reports the variants the installed OpenSSH supports.
func (service *Service) Algorithms(ctx context.Context) Catalogue {
	return service.catalogue.Read(ctx)
}

// HardwareCommand returns the ssh-keygen argument list for a hardware method.
func (service *Service) HardwareCommand(algorithm Algorithm, fileName, comment string) ([]string, error) {
	return HardwareCommand(algorithm, fileName, comment, service.workspace.Root())
}

// GenerateRequest is one in-process key generation.
//
// Unencrypted must be set explicitly for an empty passphrase, so an accidentally
// blank field can never silently produce an unprotected key.
type GenerateRequest struct {
	Algorithm   Algorithm
	Bits        int
	FileName    string
	Comment     string
	Passphrase  []byte
	Unencrypted bool
}

type GenerateResult struct {
	ID                 string
	RelativePath       string
	PublicRelativePath string
	Fingerprint        string
	KeyType            string
	Bits               int
	Encrypted          bool
	TransactionID      string
}

// Generate creates a software key pair inside this process and commits both
// files in one journalled transaction. The passphrase never reaches argv, the
// environment or another process, and it is overwritten before Generate returns.
func (service *Service) Generate(request GenerateRequest) (GenerateResult, error) {
	defer Wipe(request.Passphrase)

	if err := ValidateFileName(request.FileName); err != nil {
		return GenerateResult{}, err
	}
	if err := ValidateComment(request.Comment); err != nil {
		return GenerateResult{}, err
	}
	if len(request.Passphrase) == 0 && !request.Unencrypted {
		return GenerateResult{}, ErrPassphraseRequired
	}
	if len(request.Passphrase) > 0 && request.Unencrypted {
		return GenerateResult{}, ErrConflictingPassphraseChoice
	}

	privateKey, err := GeneratePrivateKey(request.Algorithm, request.Bits, service.random)
	if err != nil {
		return GenerateResult{}, err
	}
	privateContents, err := EncodePrivateKey(privateKey, request.Comment, request.Passphrase)
	if err != nil {
		return GenerateResult{}, err
	}
	defer Wipe(privateContents)
	publicContents, err := EncodePublicKey(privateKey, request.Comment)
	if err != nil {
		return GenerateResult{}, err
	}
	info, err := InspectPublicKey(publicContents)
	if err != nil {
		return GenerateResult{}, err
	}

	if err := service.workspace.EnsureDirectory(service.workspace.Root()); err != nil {
		return GenerateResult{}, err
	}
	publicName := request.FileName + ".pub"
	result, err := service.transactions.Commit(storage.Request{
		Operation: "key.generate",
		Changes: []storage.Change{
			{Path: service.absolutePath(request.FileName), Contents: privateContents},
			{Path: service.absolutePath(publicName), Contents: publicContents},
		},
	})
	if err != nil {
		return GenerateResult{}, err
	}
	return GenerateResult{
		ID:                 ItemID(request.FileName),
		RelativePath:       request.FileName,
		PublicRelativePath: publicName,
		Fingerprint:        info.Fingerprint,
		KeyType:            info.KeyType,
		Bits:               info.Bits,
		Encrypted:          len(request.Passphrase) > 0,
		TransactionID:      result.ID,
	}, nil
}

// PassphraseChange re-encrypts one private key.
type PassphraseChange struct {
	KeyID       string
	Current     []byte
	New         []byte
	Unencrypted bool
}

type PassphraseResult struct {
	ID            string
	RelativePath  string
	Encrypted     bool
	Notes         []string
	TransactionID string
}

// ChangePassphrase decrypts a key with the current passphrase and writes it
// back encrypted with the new one, in one journalled transaction guarded by the
// digest of the file it read.
//
// The transaction opts out of the generational backup, because the contents it
// replaces are the user's private key and the design refuses to leave a second
// copy of key material in ~/.ssh/ssh-ui/backups/. The rename that installs the
// new key is atomic, so an interruption leaves either the old key or the new
// one; an interrupted change can be completed but not rolled back.
//
// x/crypto's parser does not expose the comment stored inside an OpenSSH
// private key, so the comment is taken from a public key file whose fingerprint
// matches. When no such file exists the new key carries no comment and the
// result says so through NoteCommentNotPreserved; the engine never invents one.
func (service *Service) ChangePassphrase(change PassphraseChange) (PassphraseResult, error) {
	defer Wipe(change.Current)
	defer Wipe(change.New)

	if len(change.New) == 0 && !change.Unencrypted {
		return PassphraseResult{}, ErrPassphraseRequired
	}
	if len(change.New) > 0 && change.Unencrypted {
		return PassphraseResult{}, ErrConflictingPassphraseChoice
	}

	inventory, err := service.Inventory()
	if err != nil {
		return PassphraseResult{}, err
	}
	item, ok := inventory.Find(change.KeyID)
	if !ok || item.Kind != KindPrivateKey {
		return PassphraseResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	contents, err := service.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		return PassphraseResult{}, err
	}
	defer Wipe(contents)
	precondition := storage.Precondition{Exists: true, Digest: storage.Digest(contents)}

	privateKey, err := DecodePrivateKey(contents, change.Current)
	if err != nil {
		return PassphraseResult{}, err
	}
	comment, notes := commentForKey(inventory, item)
	encoded, err := EncodePrivateKey(privateKey, comment, change.New)
	if err != nil {
		return PassphraseResult{}, err
	}
	defer Wipe(encoded)

	result, err := service.transactions.Commit(storage.Request{
		Operation: "key.passphrase",
		Changes: []storage.Change{{
			Path:         absolute,
			Contents:     encoded,
			Precondition: precondition,
			SkipBackup:   true,
		}},
	})
	if err != nil {
		return PassphraseResult{}, err
	}
	return PassphraseResult{
		ID:            item.ID,
		RelativePath:  item.RelativePath,
		Encrypted:     len(change.New) > 0,
		Notes:         notes,
		TransactionID: result.ID,
	}, nil
}

// RevealResult is the answer to a confirmed private-key reveal.
type RevealResult struct {
	ID            string
	RelativePath  string
	Contents      []byte
	Encrypted     bool
	Fingerprint   string
	TransactionID string
}

// Reveal returns the bytes of one private key.
//
// The audit record is written before the bytes are returned, so a reveal that
// could not be recorded does not happen. The record names the file and the time
// and never contains key material. Reveal deliberately has no other caller: the
// ordinary detail API never returns private key bytes.
func (service *Service) Reveal(keyID string) (RevealResult, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return RevealResult{}, err
	}
	item, ok := inventory.Find(keyID)
	if !ok || item.Kind != KindPrivateKey {
		return RevealResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	contents, err := service.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		return RevealResult{}, err
	}
	result, err := service.transactions.Note("key.reveal", []string{absolute})
	if err != nil {
		Wipe(contents)
		return RevealResult{}, err
	}
	return RevealResult{
		ID:            item.ID,
		RelativePath:  item.RelativePath,
		Contents:      contents,
		Encrypted:     item.Encrypted,
		Fingerprint:   item.Fingerprint,
		TransactionID: result.ID,
	}, nil
}

// ConfirmationSubject names the kind of operation a one-time confirmation
// covers. It is this package's own vocabulary; the HTTP layer maps the session
// package's action kinds onto it, so the use-case layer needs no dependency on
// how a session is authenticated.
type ConfirmationSubject string

const (
	ConfirmRevealKey  ConfirmationSubject = "reveal_key"
	ConfirmPurgeEntry ConfirmationSubject = "purge_entry"
)

// ErrUnknownConfirmation reports a confirmation subject this application does
// not issue tokens for.
var ErrUnknownConfirmation = errors.New("unknown confirmation subject")

// ConfirmationEvidence digests exactly what a confirmation dialog would show
// for one operation, so a token can be bound to it.
//
// The digest is recomputed when the token is spent. If the key or the trash
// entry changed in between, the digests differ and the confirmation is refused,
// because the user agreed to the thing they were shown and not to whatever
// replaced it. Only a digest is produced: no key material, and no path, ever
// leaves this function.
func (service *Service) ConfirmationEvidence(subject ConfirmationSubject, target string) (string, error) {
	switch subject {
	case ConfirmRevealKey:
		return service.revealEvidence(target)
	case ConfirmPurgeEntry:
		return service.purgeEvidence(target)
	default:
		return "", ErrUnknownConfirmation
	}
}

func (service *Service) revealEvidence(keyID string) (string, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return "", err
	}
	item, ok := inventory.Find(keyID)
	if !ok || item.Kind != KindPrivateKey {
		return "", ErrUnknownKey
	}
	contents, err := service.workspace.FileSystem().ReadFile(service.absolutePath(item.RelativePath))
	if err != nil {
		return "", err
	}
	// The file's digest is taken and the buffer is erased immediately; the
	// evidence never holds the bytes themselves.
	contentsDigest := storage.Digest(contents)
	Wipe(contents)

	return digestFields(string(ConfirmRevealKey), item.RelativePath, item.Fingerprint, item.Permission, contentsDigest), nil
}

func (service *Service) purgeEvidence(entryID string) (string, error) {
	manifest, err := service.readManifest(entryID)
	if err != nil {
		return "", err
	}
	fields := []string{string(ConfirmPurgeEntry), manifest.EntryID, manifest.DeletedAt}
	for _, file := range manifest.Files {
		fields = append(fields, file.OriginalPath, file.TrashPath, file.Kind, file.Fingerprint, file.Permission)
		// A file that has since disappeared changes what the dialog lists, so
		// its presence is part of what the user is confirming.
		if _, statErr := service.workspace.FileSystem().Lstat(filepath.Join(service.workspace.Root(), file.TrashPath)); statErr == nil {
			fields = append(fields, "present")
			continue
		}
		fields = append(fields, "missing")
	}
	return digestFields(fields...), nil
}

// digestFields hashes a field list with an unambiguous separator, so two
// different field lists can never produce the same digest by concatenation.
func digestFields(fields ...string) string {
	hash := sha256.New()
	for _, field := range fields {
		hash.Write([]byte(field))
		hash.Write([]byte("\x00"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// RegisterRequest asks the user's ssh-agent to load one key.
type RegisterRequest struct {
	KeyID           string
	Passphrase      []byte
	LifetimeSeconds int
	StoreInKeychain bool
}

type RegisterResult struct {
	ID               string
	RelativePath     string
	Fingerprint      string
	LifetimeSeconds  int
	StoredInKeychain bool
	Identities       []platform.AgentIdentity
}

// Register loads a private key into the user's ssh-agent, optionally storing
// its passphrase in the login Keychain.
//
// Only a key the inventory currently contains can be registered, so a trashed
// key and anything under ~/.ssh/ssh-ui are unreachable by construction. The
// passphrase is overwritten before Register returns, and the registration is
// recorded in history without it. The audit note is written only after the
// agent accepted the key, so a refused registration leaves no record claiming
// it happened.
func (service *Service) Register(ctx context.Context, request RegisterRequest) (RegisterResult, error) {
	defer Wipe(request.Passphrase)

	if service.agent == nil {
		return RegisterResult{}, platform.ErrAgentUnavailable
	}
	inventory, err := service.Inventory()
	if err != nil {
		return RegisterResult{}, err
	}
	item, ok := inventory.Find(request.KeyID)
	if !ok || item.Kind != KindPrivateKey {
		return RegisterResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	if err := service.agent.Add(ctx, platform.AgentAddRequest{
		PrivateKeyPath:  absolute,
		Passphrase:      request.Passphrase,
		LifetimeSeconds: request.LifetimeSeconds,
		StoreInKeychain: request.StoreInKeychain,
	}); err != nil {
		return RegisterResult{}, err
	}
	if _, err := service.transactions.Note("key.agent_add", []string{absolute}); err != nil {
		return RegisterResult{}, err
	}

	identities, listErr := service.agent.List(ctx)
	if listErr != nil {
		identities = nil
	}
	return RegisterResult{
		ID:               item.ID,
		RelativePath:     item.RelativePath,
		Fingerprint:      item.Fingerprint,
		LifetimeSeconds:  request.LifetimeSeconds,
		StoredInKeychain: request.StoreInKeychain,
		Identities:       identities,
	}, nil
}

// AgentIdentities reports what the agent currently holds. The second return
// value is false when no agent is reachable, so the UI can say so instead of
// showing an empty list that looks like a working agent.
func (service *Service) AgentIdentities(ctx context.Context) ([]platform.AgentIdentity, bool) {
	if service.agent == nil || !service.agent.Available(ctx) {
		return nil, false
	}
	identities, err := service.agent.List(ctx)
	if err != nil {
		return nil, false
	}
	return identities, true
}

// commentForKey recovers a private key's comment from a public key file with
// the same fingerprint.
func commentForKey(inventory *Inventory, item *Item) (string, []string) {
	if item.Fingerprint != "" {
		for _, candidate := range inventory.Items {
			if candidate.Kind == KindPublicKey && candidate.Fingerprint == item.Fingerprint && candidate.Comment != "" {
				return candidate.Comment, nil
			}
		}
	}
	return "", []string{NoteCommentNotPreserved}
}
