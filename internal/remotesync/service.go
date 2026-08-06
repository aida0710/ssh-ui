package remotesync

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"ssh-ui/internal/envelope"
	"ssh-ui/internal/objectstore"
	"ssh-ui/internal/storage"
)

// StatePath is where this machine records what it last synced, relative to the
// workspace root. It is written through the transaction manager like every
// other file, so the record of what was synced cannot be left half-written.
const StatePath = "ssh-ui/sync-state.json"

// ObjectKey is the single object this application reads and writes.
const ObjectKey = "ssh-ui/workspace.snapshot"

var (
	// ErrNotConfigured reports that no bucket has been set up.
	ErrNotConfigured = errors.New("remote sync is not configured")
	// ErrRemoteMoved reports that the snapshot changed since this machine last
	// saw it. It is the compare-and-swap failing, which is the property that
	// makes automatic pushing safe: nothing is overwritten.
	ErrRemoteMoved = errors.New("another machine has pushed since this one last synced")
	// ErrNoSnapshot reports an empty bucket.
	ErrNoSnapshot = errors.New("the bucket holds no snapshot yet")
	// ErrConflicts reports that a pull cannot be applied without a decision.
	ErrConflicts = errors.New("this pull needs a decision on at least one file")
	// ErrPushRefused reports a push on a machine set to receive only.
	ErrPushRefused = errors.New("this machine is set to receive only")
	// ErrApplyRefused reports an apply on a machine set to send only.
	ErrApplyRefused = errors.New("this machine is set to send only")
)

// Direction is which way this machine may move data.
//
// It governs the two writes and nothing else. A preview reads the bucket and
// writes nothing, so it stays available in both one-way settings: a laptop that
// may not apply a snapshot can still be told how far behind it is, which is the
// difference between a safety setting and a blindfold.
type Direction string

const (
	// DirectionBoth is the default: this machine may push and may apply.
	DirectionBoth Direction = "both"
	// DirectionPush is for a machine that is the source — a workstation whose
	// configuration is the one worth keeping. It never applies a snapshot, so
	// nothing another machine pushed can overwrite what is on this disk.
	DirectionPush Direction = "push"
	// DirectionPull is for a machine that is a copy — a shared or temporary
	// one. It never writes to the bucket, so nothing done here can reach the
	// other machines.
	DirectionPull Direction = "pull"
)

// ParseDirection accepts the three names and treats the empty string as both,
// so a caller that has never heard of directions behaves as it always did.
func ParseDirection(name string) (Direction, bool) {
	switch Direction(name) {
	case "", DirectionBoth:
		return DirectionBoth, true
	case DirectionPush:
		return DirectionPush, true
	case DirectionPull:
		return DirectionPull, true
	default:
		return DirectionBoth, false
	}
}

// Config is what the user supplies once.
type Config struct {
	Endpoint  string
	Bucket    string
	Region    string
	Direction Direction
}

// state is this machine's record of the last successful sync.
type state struct {
	// ETag identifies the snapshot this machine last pushed or pulled. It is
	// the generation the next conditional write is compared against.
	ETag string `json:"etag"`
	// Base is the manifest of that snapshot, which is what tells a later pull
	// the difference between "deleted on the other machine" and "created here
	// since the last sync".
	Base *Manifest `json:"base,omitempty"`
	// Origin is this installation's opaque id. It is generated once and never
	// derived from anything about the machine.
	Origin string `json:"origin"`
}

// FileSource lists the workspace-relative paths that belong in a snapshot.
//
// It is injected because "which files are part of the configuration" is a
// question the Include graph answers, and this package cannot see it. Passing
// the answer in keeps the dependency pointing the right way: nothing here
// imports the configuration service.
type FileSource func() ([]string, error)

// Service performs one push or one pull at a time.
type Service struct {
	workspace    *storage.Workspace
	transactions *storage.Manager
	files        FileSource
	now          func() string
	newOrigin    func() (string, error)

	mu     sync.Mutex
	config Config
	creds  objectstore.Credentials
	client *objectstore.Client
}

// NewService returns an unconfigured service.
func NewService(workspace *storage.Workspace, transactions *storage.Manager, files FileSource,
	now func() string, newOrigin func() (string, error)) *Service {
	return &Service{
		workspace: workspace, transactions: transactions, files: files,
		now: now, newOrigin: newOrigin,
	}
}

// Configure sets the bucket and the credentials for this run.
//
// The credentials are held in memory and never written to the workspace: a
// snapshot that carried the key to its own bucket would be a bootstrapping
// convenience and a much larger blast radius.
func (s *Service) Configure(config Config, credentials objectstore.Credentials, client *objectstore.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A trailing slash never reached a request — the client replaces the whole
	// path — but it reached every screen that showed where the snapshot goes,
	// as "https://host//bucket". Trimming here rather than only where settings
	// are stored also cleans the ones stored before this existed.
	config.Endpoint = strings.TrimRight(config.Endpoint, "/")
	s.config = config
	s.creds = credentials
	s.client = client
}

// Configured reports whether a bucket and credentials are set.
func (s *Service) Configured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client != nil && s.config.Bucket != "" && s.creds.AccessKeyID != ""
}

// Direction reports which way this machine may move data.
func (s *Service) Direction() Direction {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.Direction == "" {
		return DirectionBoth
	}
	return s.config.Direction
}

func (s *Service) store() (*objectstore.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil || s.config.Bucket == "" || s.creds.AccessKeyID == "" {
		return nil, ErrNotConfigured
	}
	return s.client, nil
}

// Collect reads every file that belongs in a snapshot.
//
// That is: whatever the FileSource names — the entry file and everything the
// Include graph reaches inside the workspace — plus metadata.json, the
// password vault, and every key. A file the source names that is not there is
// skipped rather than failing: an Include can point at a file that does not
// exist yet, and that is a diagnostic, not a reason to refuse to sync.
func (s *Service) Collect() (Manifest, map[string][]byte, error) {
	relatives, err := s.files()
	if err != nil {
		return Manifest{}, nil, err
	}
	keys, err := s.walkKeys()
	if err != nil {
		return Manifest{}, nil, err
	}
	relatives = append(relatives, keys...)
	relatives = append(relatives, "ssh-ui/metadata.json", "ssh-ui/secrets")

	seen := map[string]bool{}
	contents := map[string][]byte{}
	var entries []Entry
	for _, relative := range relatives {
		relative = filepath.ToSlash(relative)
		if seen[relative] || checkPath(relative) != nil {
			continue
		}
		seen[relative] = true

		absolute := filepath.Join(s.workspace.Root(), filepath.FromSlash(relative))
		body, err := s.workspace.FileSystem().ReadFile(absolute)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return Manifest{}, nil, err
		}
		mode := "0600"
		if info, err := os.Stat(absolute); err == nil && info.Mode().Perm() == 0o700 {
			mode = "0700"
		}
		contents[relative] = body
		entries = append(entries, Entry{
			Path:   relative,
			SHA256: Digest(body),
			Mode:   mode,
			// A private key is anything under keys/ without a .pub suffix. The
			// mark is what makes a pull apply it with SkipBackup set.
			Secret: strings.HasPrefix(relative, "keys/") && !strings.HasSuffix(relative, ".pub"),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	current, err := s.readState()
	if err != nil {
		return Manifest{}, nil, err
	}
	return Manifest{
		SchemaVersion: SchemaVersion,
		CreatedAt:     s.now(),
		Origin:        current.Origin,
		Files:         entries,
	}, contents, nil
}

func (s *Service) walkKeys() ([]string, error) {
	root := filepath.Join(s.workspace.Root(), "keys")
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(s.workspace.Root(), path)
		if err != nil {
			return err
		}
		found = append(found, filepath.ToSlash(relative))
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return found, nil
}

// Check asks the bucket one question, to find out whether these settings work.
//
// It is what stands between a typo and a configuration that looks right and
// fails on the first push, hours later, with nobody near the screen where the
// typo was. A bucket holding no snapshot yet answers "not found", and that is a
// working bucket: the question is whether this endpoint, this bucket name and
// these credentials reach a store that will answer, not whether anything has
// been pushed to it.
func (s *Service) Check(ctx context.Context) error {
	client, err := s.store()
	if err != nil {
		return err
	}
	return Check(ctx, client)
}

// Check is the same question asked of a client this service does not hold, so
// settings can be tried before they are stored. Registering settings that were
// never tried is how a typo becomes a configuration that looks right.
func Check(ctx context.Context, client *objectstore.Client) error {
	if _, err := client.Head(ctx, ObjectKey); err != nil && !errors.Is(err, objectstore.ErrNotFound) {
		return err
	}
	return nil
}

// Push seals this workspace and writes it, refusing if the remote moved.
//
// The condition is the whole point. If-None-Match: * for the first write and
// If-Match: <the ETag we last saw> for every write after it, so no push can
// silently clobber another machine's work — which is what makes the word
// "automatic" safe to use about this.
func (s *Service) Push(ctx context.Context, passphrase string) error {
	if s.Direction() == DirectionPull {
		return ErrPushRefused
	}
	client, err := s.store()
	if err != nil {
		return err
	}
	current, err := s.readState()
	if err != nil {
		return err
	}
	if current.Origin == "" {
		if current.Origin, err = s.newOrigin(); err != nil {
			return err
		}
	}

	manifest, contents, err := s.Collect()
	if err != nil {
		return err
	}
	manifest.Origin = current.Origin
	archive, err := Build(manifest, contents)
	if err != nil {
		return err
	}
	key, err := envelope.Derive(passphrase)
	if err != nil {
		return err
	}
	sealed, err := key.Seal(archive)
	if err != nil {
		return err
	}

	ifMatch, ifNoneMatch := current.ETag, ""
	if ifMatch == "" {
		ifNoneMatch = "*"
	}
	etag, err := client.Put(ctx, ObjectKey, sealed, ifMatch, ifNoneMatch)
	if err != nil {
		if errors.Is(err, objectstore.ErrPreconditionFailed) {
			return ErrRemoteMoved
		}
		return err
	}
	return s.writeState(state{ETag: etag, Base: &manifest, Origin: current.Origin})
}

// PullResult is what a pull would do, before it is applied.
type PullResult struct {
	Request   storage.Request
	Conflicts []Conflict
	Manifest  Manifest
	ETag      string
	Origin    string
}

// Pull fetches the snapshot and works out what applying it would change.
//
// It writes nothing. Apply is a separate call so the user sees the preview the
// rest of this application always shows before a write.
func (s *Service) Pull(ctx context.Context, passphrase string) (PullResult, error) {
	client, err := s.store()
	if err != nil {
		return PullResult{}, err
	}
	object, err := client.Get(ctx, ObjectKey)
	if err != nil {
		if errors.Is(err, objectstore.ErrNotFound) {
			return PullResult{}, ErrNoSnapshot
		}
		return PullResult{}, err
	}
	archive, _, err := envelope.Open(object.Body, passphrase)
	if err != nil {
		return PullResult{}, err
	}
	manifest, contents, err := Read(archive)
	if err != nil {
		return PullResult{}, err
	}

	current, err := s.readState()
	if err != nil {
		return PullResult{}, err
	}
	local, err := s.localDigests(manifest, current.Base)
	if err != nil {
		return PullResult{}, err
	}

	request, conflicts, err := Plan(s.workspace.Root(), current.Base, local, manifest, contents)
	if err != nil && !errors.Is(err, ErrNothingToApply) {
		return PullResult{}, err
	}
	return PullResult{
		Request: request, Conflicts: conflicts, Manifest: manifest,
		ETag: object.ETag, Origin: manifest.Origin,
	}, err
}

// Apply commits a pull. It refuses while any file is in conflict, because
// applying half of a snapshot produces a workspace that matches neither side.
func (s *Service) Apply(result PullResult) error {
	// The direction is checked here rather than in Pull: a preview writes
	// nothing, so a send-only machine can still be told how far behind it is.
	// This is the call that would put another machine's bytes on this disk.
	if s.Direction() == DirectionPush {
		return ErrApplyRefused
	}
	if len(result.Conflicts) > 0 {
		return ErrConflicts
	}
	if len(result.Request.Changes)+len(result.Request.Removals) > 0 {
		// A snapshot from another machine names directories this one may not
		// have — connections/work/, keys/work/ — and the transaction manager
		// owns files, not directories: ResolveForWrite refuses a write whose
		// parent is missing. Creating them first is what every other writer in
		// this application does, and it inherits the same stated limitation:
		// the mkdir is outside the journal, so a crash between it and the
		// commit leaves an empty directory. An empty directory is inert.
		for _, change := range result.Request.Changes {
			if err := s.workspace.EnsureDirectory(filepath.Dir(change.Path)); err != nil {
				return err
			}
		}
		if _, err := s.transactions.Commit(result.Request); err != nil {
			return err
		}
	}
	current, err := s.readState()
	if err != nil {
		return err
	}
	origin := current.Origin
	if origin == "" {
		if origin, err = s.newOrigin(); err != nil {
			return err
		}
	}
	manifest := result.Manifest
	return s.writeState(state{ETag: result.ETag, Base: &manifest, Origin: origin})
}

// localDigests hashes every path either side knows about, so a file that is on
// this disk and in neither manifest is not consulted and not touched.
func (s *Service) localDigests(remote Manifest, base *Manifest) (map[string]string, error) {
	paths := map[string]bool{}
	for _, item := range remote.Files {
		paths[item.Path] = true
	}
	if base != nil {
		for _, item := range base.Files {
			paths[item.Path] = true
		}
	}

	digests := map[string]string{}
	for path := range paths {
		body, err := s.workspace.FileSystem().ReadFile(filepath.Join(s.workspace.Root(), filepath.FromSlash(path)))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		digests[path] = Digest(body)
	}
	return digests, nil
}

func (s *Service) statePath() string {
	return filepath.Join(s.workspace.Root(), filepath.FromSlash(StatePath))
}

func (s *Service) readState() (state, error) {
	body, err := s.workspace.FileSystem().ReadFile(s.statePath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return state{}, nil
		}
		return state{}, err
	}
	var parsed state
	if err := json.Unmarshal(body, &parsed); err != nil {
		// A damaged state file is recoverable: the next pull treats this
		// machine as one that has never synced, which is conservative — it
		// deletes nothing and conflicts rather than guessing.
		return state{}, nil
	}
	return parsed, nil
}

func (s *Service) writeState(next state) error {
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := s.workspace.EnsureDirectory(s.workspace.StateDir()); err != nil {
		return err
	}
	precondition := storage.Precondition{}
	if current, err := s.workspace.FileSystem().ReadFile(s.statePath()); err == nil {
		precondition = storage.Precondition{Exists: true, Digest: storage.Digest(current)}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, err = s.transactions.Commit(storage.Request{
		Operation: "sync.state",
		Changes: []storage.Change{{
			Path:         s.statePath(),
			Contents:     body,
			Precondition: precondition,
			// The state names no secret, but it is a file of this
			// application's own and a generation of it per sync is noise in
			// the backup directory.
			SkipBackup: true,
		}},
	})
	return err
}

// Target returns the endpoint and bucket this run points at, for display. The
// access key and the secret are never returned by anything.
func (s *Service) Target() (endpoint, bucket string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config.Endpoint, s.config.Bucket
}

// LastSync reports what this machine last synced, from the state file.
func (s *Service) LastSync() (synced bool, at, origin string, files int) {
	current, err := s.readState()
	if err != nil || current.ETag == "" || current.Base == nil {
		return false, "", "", 0
	}
	return true, current.Base.CreatedAt, current.Base.Origin, len(current.Base.Files)
}

// DisplayPath turns an absolute workspace path back into the relative one the
// rest of this application shows.
func (s *Service) DisplayPath(absolute string) string {
	relative, err := filepath.Rel(s.workspace.Root(), absolute)
	if err != nil {
		return filepath.Base(absolute)
	}
	return filepath.ToSlash(relative)
}
