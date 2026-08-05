package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"time"
)

const (
	journalVersion       = 1
	journalDirectoryName = "journal"
	historyDirectoryName = "history"
	backupDirectoryName  = "backups"
	temporaryPrefix      = ".ssh-ui-"

	statusStaging    = "staging"
	statusStaged     = "staged"
	statusCompleted  = "completed"
	statusRolledBack = "rolled_back"
)

const (
	actionWrite     = "write"
	actionMove      = "move"
	actionRemove    = "remove"
	actionMakeDir   = "mkdir"
	actionRemoveDir = "rmdir"
	actionNote      = "note"
)

var (
	ErrNoChanges     = errors.New("transaction has no changes")
	ErrDuplicatePath = errors.New("transaction contains the same path twice")
	// ErrDirectoryNotEmpty refuses to remove a directory that still holds
	// something. A recursive delete has no place in a journal: rolling it back
	// would mean restoring contents this transaction never read.
	ErrDirectoryNotEmpty   = errors.New("directory is not empty")
	ErrIrreversibleChange  = errors.New("a committed change that kept no backup cannot be rolled back")
	ErrMoveTargetExists    = errors.New("move target already exists")
	ErrMissingSource       = errors.New("file to move or remove does not exist")
	ErrIrreversibleRemoval = errors.New("a committed removal that kept no backup cannot be rolled back")
)

// Precondition records the state the caller based its new contents on.
type Precondition struct {
	Exists bool
	Digest string
}

// Change is one file the transaction replaces or creates.
//
// SkipBackup suppresses the generational backup of the contents this change
// replaces. It exists for one reason: the previous contents may be a private
// key, and the design refuses to leave a second copy of key material in
// ~/.ssh/ssh-ui/backups/. A change that opts out is still journalled and can
// still be completed after an interruption, but it can no longer be rolled
// back, and Rollback says so instead of pretending otherwise. The zero value
// keeps the ordinary behaviour, so an existing caller is unaffected.
type Change struct {
	Path         string
	Contents     []byte
	Precondition Precondition
	SkipBackup   bool
}

// Move relocates one file with rename(2) inside the workspace.
//
// A move copies no bytes, so a private key is never duplicated into the
// generational backup directory, and rename preserves the file's existing
// permission bits exactly.
type Move struct {
	From         string
	To           string
	Precondition Precondition
}

// Removal deletes one file.
//
// By default it writes no backup, because its first caller is a permanent
// delete the user has confirmed twice and copying key material into the backup
// directory would defeat that decision. Such a removal can be completed after
// an interruption but not rolled back, and Rollback says so instead of
// pretending otherwise.
//
// Backup opts in to the generational copy, for callers deleting something that
// is not key material — a configuration file the user removed from the
// explorer. That removal then behaves like every other change this application
// makes: it is in History and it can be undone.
type Removal struct {
	Path         string
	Precondition Precondition
	Backup       bool
}

// DirectoryCreate creates one directory and any missing parent below the root.
//
// It exists so that arranging files and creating the places they go can be one
// transaction. Before it, a caller had to EnsureDirectory outside the journal
// and accept that a crash between the mkdir and the commit left an empty
// directory behind.
type DirectoryCreate struct {
	Path string
}

// DirectoryRemoval removes one empty directory.
//
// Only an empty one: a recursive delete cannot be rolled back without
// restoring contents the transaction never read, so a caller that wants a tree
// gone lists its files as Removals and its directories here, deepest first.
type DirectoryRemoval struct {
	Path string
}

// Request is one logical edit spanning any number of files.
//
// The order is the only one that can work: directories are created first
// because a change needs somewhere to go, then changes, moves and removals,
// and directories are removed last because what emptied them was in this same
// request.
type Request struct {
	Operation   string
	Directories []DirectoryCreate
	Changes     []Change
	Moves       []Move
	Removals    []Removal
	// RemoveDirectories are applied after everything else, deepest first, and
	// each must be empty by then.
	RemoveDirectories []DirectoryRemoval
}

// Result describes a completed transaction.
type Result struct {
	ID        string
	BackupDir string
	Written   []string
}

// ConflictError reports that the file on disk is not the file the caller
// edited. Current carries the on-disk contents so the caller can build a
// three-way diff; Error never includes file contents.
type ConflictError struct {
	Path     string
	Expected string
	Actual   string
	Current  []byte
}

func (e *ConflictError) Error() string {
	return "external change detected for " + e.Path
}

// Digest is the content hash used for preconditions and journal entries.
func Digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

type journalEntry struct {
	Action         string `json:"action,omitempty"`
	Path           string `json:"path"`
	Target         string `json:"target,omitempty"`
	Temp           string `json:"temp,omitempty"`
	Backup         string `json:"backup,omitempty"`
	NoBackup       bool   `json:"noBackup,omitempty"`
	HadPrevious    bool   `json:"hadPrevious"`
	Mode           uint32 `json:"mode"`
	Digest         string `json:"digest"`
	PreviousDigest string `json:"previousDigest,omitempty"`
}

// action defaults to write so a journal written before moves and removals
// existed still replays correctly.
func (e journalEntry) action() string {
	if e.Action == "" {
		return actionWrite
	}
	return e.Action
}

// zeroBytes overwrites a buffer that may hold key material. Like keys.Wipe it
// is best effort: the Go runtime may already have copied the bytes elsewhere.
func zeroBytes(contents []byte) {
	for index := range contents {
		contents[index] = 0
	}
}

type journalRecord struct {
	ID         string         `json:"id"`
	Version    int            `json:"version"`
	Operation  string         `json:"operation"`
	Status     string         `json:"status"`
	StartedAt  time.Time      `json:"startedAt"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
	Committed  int            `json:"committed"`
	Entries    []journalEntry `json:"entries"`
}

// Manager performs journalled, atomic multi-file writes inside a workspace.
//
// Validate is an optional check run after preconditions and before anything is
// journalled or written. The storage layer deliberately knows nothing about
// configuration syntax; the application layer injects a validator that parses
// the new contents and re-checks the Include graph, so a syntactically broken
// file never reaches disk. A nil Validate accepts every request.
type Manager struct {
	workspace *Workspace
	now       func() time.Time
	random    io.Reader
	Validate  func(Request) error
}

func NewManager(workspace *Workspace, now func() time.Time, random io.Reader) *Manager {
	return &Manager{workspace: workspace, now: now, random: random}
}

// Commit validates every change, journals the intent, stages all new contents
// durably, then applies the entries one at a time.
//
// Commit does not roll back automatically. A failure leaves a pending journal
// so the user can choose between completing and restoring, which is the only
// honest option when several files are involved.
func (m *Manager) Commit(request Request) (Result, error) {
	if len(request.Changes)+len(request.Moves)+len(request.Removals)+
		len(request.Directories)+len(request.RemoveDirectories) == 0 {
		return Result{}, ErrNoChanges
	}
	fileSystem := m.workspace.FileSystem()

	capacity := len(request.Changes) + len(request.Moves) + len(request.Removals) +
		len(request.Directories) + len(request.RemoveDirectories)
	entries := make([]journalEntry, 0, capacity)
	stagedContents := make([][]byte, 0, capacity)
	previousContents := make([][]byte, 0, capacity)
	written := make([]string, 0, capacity)
	claimed := make(map[string]bool, capacity)

	claim := func(path string) error {
		if claimed[path] {
			return ErrDuplicatePath
		}
		claimed[path] = true
		return nil
	}

	// planned is every directory this request creates, and each of its
	// ancestors below the root, so a change written into one of them resolves
	// even though nothing is on disk yet.
	planned := map[string]bool{}
	for _, create := range request.Directories {
		cleaned, err := m.workspace.ResolveDirectory(create.Path)
		if err != nil {
			return Result{}, err
		}
		for current := cleaned; m.workspace.Contains(current) && current != m.workspace.Root(); current = filepath.Dir(current) {
			planned[current] = true
		}
	}

	// Directories first: a change needs somewhere to go, and a move needs a
	// destination that exists.
	for _, create := range request.Directories {
		target, err := m.workspace.ResolveDirectory(create.Path)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		// Whether it is already there decides what a rollback does. Removing a
		// directory this transaction did not create would delete something
		// nobody asked it to touch.
		existed := false
		if _, statErr := fileSystem.Lstat(target); statErr == nil {
			existed = true
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return Result{}, statErr
		}
		entries = append(entries, journalEntry{
			Action:      actionMakeDir,
			Path:        target,
			HadPrevious: existed,
			Mode:        uint32(DirectoryPermission),
		})
		stagedContents = append(stagedContents, nil)
		previousContents = append(previousContents, nil)
	}

	for _, change := range request.Changes {
		target, err := m.workspace.ResolveForWriteUnder(change.Path, planned)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}

		previous, mode, exists, err := m.currentState(target)
		if err != nil {
			return Result{}, err
		}
		actual := ""
		expected := ""
		if exists {
			actual = Digest(previous)
		}
		if change.Precondition.Exists {
			expected = change.Precondition.Digest
		}
		if actual != expected {
			return Result{}, &ConflictError{Path: target, Expected: expected, Actual: actual, Current: previous}
		}

		entry := journalEntry{
			Action:      actionWrite,
			Path:        target,
			NoBackup:    change.SkipBackup,
			HadPrevious: exists,
			Mode:        uint32(mode),
			Digest:      Digest(change.Contents),
		}
		if exists {
			entry.PreviousDigest = actual
		}
		entries = append(entries, entry)
		stagedContents = append(stagedContents, change.Contents)
		previousContents = append(previousContents, previous)
		written = append(written, target)
	}

	for _, move := range request.Moves {
		source, err := m.workspace.ResolveForWrite(move.From)
		if err != nil {
			return Result{}, err
		}
		target, err := m.workspace.ResolveForWriteUnder(move.To, planned)
		if err != nil {
			return Result{}, err
		}
		if err := claim(source); err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		if _, statErr := fileSystem.Lstat(target); statErr == nil {
			return Result{}, ErrMoveTargetExists
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return Result{}, statErr
		}

		digest, mode, err := m.sourceState(source, move.Precondition)
		if err != nil {
			return Result{}, err
		}
		entries = append(entries, journalEntry{
			Action:         actionMove,
			Path:           source,
			Target:         target,
			HadPrevious:    true,
			Mode:           uint32(mode),
			Digest:         digest,
			PreviousDigest: digest,
		})
		stagedContents = append(stagedContents, nil)
		previousContents = append(previousContents, nil)
		written = append(written, target)
	}

	for _, removal := range request.Removals {
		target, err := m.workspace.ResolveForWrite(removal.Path)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		digest, mode, err := m.sourceState(target, removal.Precondition)
		if err != nil {
			return Result{}, err
		}
		var previous []byte
		if removal.Backup {
			if previous, err = m.workspace.FileSystem().ReadFile(target); err != nil {
				return Result{}, err
			}
		}
		entries = append(entries, journalEntry{
			Action:         actionRemove,
			Path:           target,
			NoBackup:       !removal.Backup,
			HadPrevious:    true,
			Mode:           uint32(mode),
			Digest:         digest,
			PreviousDigest: digest,
		})
		stagedContents = append(stagedContents, nil)
		previousContents = append(previousContents, previous)
		written = append(written, target)
	}

	// Directory removals last, and each must be empty by the time it runs. The
	// check here is against the disk as it stands, which is deliberately
	// conservative: a directory emptied by this very request is still full
	// now, so a caller removing a tree lists its files as Removals in one
	// transaction and its directories in the next.
	for _, removal := range request.RemoveDirectories {
		target, err := m.workspace.ResolveDirectory(removal.Path)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		info, statErr := fileSystem.Lstat(target)
		if errors.Is(statErr, fs.ErrNotExist) {
			// Nothing to do, and not an error: removing a directory that is
			// already gone is the state the caller asked for.
			continue
		}
		if statErr != nil {
			return Result{}, statErr
		}
		if !info.IsDir() {
			return Result{}, ErrNotDirectory
		}
		contents, err := fileSystem.ReadDir(target)
		if err != nil {
			return Result{}, err
		}
		if len(contents) > 0 {
			return Result{}, ErrDirectoryNotEmpty
		}
		entries = append(entries, journalEntry{
			Action:      actionRemoveDir,
			Path:        target,
			HadPrevious: true,
			Mode:        uint32(info.Mode().Perm()),
		})
		stagedContents = append(stagedContents, nil)
		previousContents = append(previousContents, nil)
	}

	if m.Validate != nil {
		if err := m.Validate(request); err != nil {
			return Result{}, err
		}
	}

	identifier, err := m.newIdentifier()
	if err != nil {
		return Result{}, err
	}
	journalDirectory := filepath.Join(m.workspace.StateDir(), journalDirectoryName)
	historyDirectory := filepath.Join(m.workspace.StateDir(), historyDirectoryName)
	backupDirectory := filepath.Join(m.workspace.StateDir(), backupDirectoryName, identifier)
	for _, directory := range []string{journalDirectory, historyDirectory, backupDirectory} {
		if err := m.workspace.EnsureDirectory(directory); err != nil {
			return Result{}, err
		}
	}

	record := journalRecord{
		ID:        identifier,
		Version:   journalVersion,
		Operation: request.Operation,
		Status:    statusStaging,
		StartedAt: m.now().UTC(),
		Entries:   entries,
	}
	journalPath := filepath.Join(journalDirectory, identifier+".json")
	if err := m.writeRecord(journalPath, record); err != nil {
		return Result{}, err
	}

	// The directories are made here: after the validator has accepted the
	// request, so a refused one creates nothing, and before any temporary file
	// is staged, because a staged file needs its parent to exist. They are
	// journal entries, so an interrupted commit can be rolled back — which is
	// the whole reason this is not an EnsureDirectory outside the transaction.
	for index := range record.Entries {
		entry := record.Entries[index]
		if entry.action() != actionMakeDir {
			continue
		}
		if err := m.workspace.EnsureDirectory(entry.Path); err != nil {
			return Result{}, err
		}
	}

	// Copy the previous contents before anything is replaced or unlinked. A
	// move needs no copy, because it keeps the single copy of the file; a
	// replacement always needs one, and a removal needs one exactly when its
	// caller asked for it. Entries and the staged and previous slices stay
	// index-aligned throughout Commit.
	for index := range record.Entries {
		entry := &record.Entries[index]
		if entry.action() != actionWrite && entry.action() != actionRemove {
			continue
		}
		if !entry.HadPrevious || entry.NoBackup {
			continue
		}
		relative, err := filepath.Rel(m.workspace.Root(), entry.Path)
		if err != nil {
			return Result{}, err
		}
		backupPath := filepath.Join(backupDirectory, relative)
		if err := m.workspace.EnsureDirectory(filepath.Dir(backupPath)); err != nil {
			return Result{}, err
		}
		if err := m.writeFile(backupPath, previousContents[index], fs.FileMode(entry.Mode)); err != nil {
			return Result{}, err
		}
		entry.Backup = backupPath
	}

	// Stage every new file next to its target so a later rename is atomic.
	for index := range record.Entries {
		entry := &record.Entries[index]
		if entry.action() != actionWrite {
			continue
		}
		temporaryPath, err := fileSystem.WriteTemp(
			filepath.Dir(entry.Path),
			temporaryPrefix+identifier+"-",
			fs.FileMode(entry.Mode),
			stagedContents[index],
		)
		if err != nil {
			return Result{}, err
		}
		entry.Temp = temporaryPath
	}
	record.Status = statusStaged
	if err := m.writeRecord(journalPath, record); err != nil {
		return Result{}, err
	}

	if err := m.commitStaged(&record, journalPath); err != nil {
		return Result{}, err
	}
	if err := m.finish(&record, journalPath, statusCompleted); err != nil {
		return Result{}, err
	}
	return Result{ID: identifier, BackupDir: backupDirectory, Written: written}, nil
}

func (m *Manager) commitStaged(record *journalRecord, journalPath string) error {
	fileSystem := m.workspace.FileSystem()
	for index := record.Committed; index < len(record.Entries); index++ {
		entry := record.Entries[index]
		switch entry.action() {
		case actionMove:
			if err := fileSystem.Rename(entry.Path, entry.Target); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Target)); err != nil {
				return err
			}
		case actionRemove:
			if err := fileSystem.Remove(entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
		case actionMakeDir:
			if err := m.workspace.EnsureDirectory(entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
		case actionRemoveDir:
			if err := fileSystem.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
		default:
			if err := fileSystem.Rename(entry.Temp, entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
		}
		record.Committed = index + 1
		record.Entries[index].Temp = ""
		if err := m.writeRecord(journalPath, *record); err != nil {
			return err
		}
	}
	return nil
}

// sourceState hashes a file that is about to be moved or removed and checks the
// caller's precondition.
//
// The bytes are zeroed as soon as the digest exists, because neither a move nor
// a removal ever needs them again and the file may be a private key. The
// returned ConflictError deliberately carries no Current contents for the same
// reason; a three-way diff of key material would be useless and unsafe.
func (m *Manager) sourceState(path string, precondition Precondition) (string, fs.FileMode, error) {
	contents, mode, exists, err := m.currentState(path)
	if err != nil {
		return "", 0, err
	}
	if !exists {
		return "", 0, ErrMissingSource
	}
	digest := Digest(contents)
	zeroBytes(contents)

	expected := ""
	if precondition.Exists {
		expected = precondition.Digest
	}
	if digest != expected {
		return "", 0, &ConflictError{Path: path, Expected: expected, Actual: digest}
	}
	return digest, mode, nil
}

// Note records a completed action that changed no file, such as revealing a
// private key.
//
// A note has no staged content, no backup and no journal file, because there is
// nothing to recover. It exists so history is a complete account of what the
// application did. By construction it can hold no file contents: it stores only
// the operation name, the time and the paths involved.
func (m *Manager) Note(operation string, paths []string) (Result, error) {
	if len(paths) == 0 {
		return Result{}, ErrNoChanges
	}
	entries := make([]journalEntry, 0, len(paths))
	for _, path := range paths {
		resolved, err := m.workspace.ResolveForWrite(path)
		if err != nil {
			return Result{}, err
		}
		entries = append(entries, journalEntry{Action: actionNote, Path: resolved})
	}

	identifier, err := m.newIdentifier()
	if err != nil {
		return Result{}, err
	}
	historyDirectory := filepath.Join(m.workspace.StateDir(), historyDirectoryName)
	if err := m.workspace.EnsureDirectory(historyDirectory); err != nil {
		return Result{}, err
	}
	recorded := m.now().UTC()
	record := journalRecord{
		ID:         identifier,
		Version:    journalVersion,
		Operation:  operation,
		Status:     statusCompleted,
		StartedAt:  recorded,
		FinishedAt: &recorded,
		Committed:  len(entries),
		Entries:    entries,
	}
	if err := m.writeRecord(filepath.Join(historyDirectory, identifier+".json"), record); err != nil {
		return Result{}, err
	}
	return Result{ID: identifier}, nil
}

func (m *Manager) finish(record *journalRecord, journalPath, status string) error {
	fileSystem := m.workspace.FileSystem()
	finished := m.now().UTC()
	record.FinishedAt = &finished
	record.Status = status
	historyPath := filepath.Join(m.workspace.StateDir(), historyDirectoryName, record.ID+".json")
	if err := m.writeRecord(historyPath, *record); err != nil {
		return err
	}
	if err := fileSystem.Remove(journalPath); err != nil {
		return err
	}
	return fileSystem.SyncDir(filepath.Dir(journalPath))
}

// currentState reads the file being replaced. The returned mode keeps a
// stricter existing permission and tightens a looser one to FilePermission.
func (m *Manager) currentState(path string) (contents []byte, mode fs.FileMode, exists bool, err error) {
	info, err := m.workspace.FileSystem().Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, FilePermission, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	contents, err = m.workspace.FileSystem().ReadFile(path)
	if err != nil {
		return nil, 0, false, err
	}
	return contents, info.Mode().Perm() & FilePermission, true, nil
}

func (m *Manager) writeFile(path string, contents []byte, permission fs.FileMode) error {
	fileSystem := m.workspace.FileSystem()
	temporaryPath, err := fileSystem.WriteTemp(filepath.Dir(path), temporaryPrefix, permission, contents)
	if err != nil {
		return err
	}
	if err := fileSystem.Rename(temporaryPath, path); err != nil {
		_ = fileSystem.Remove(temporaryPath)
		return err
	}
	return fileSystem.SyncDir(filepath.Dir(path))
}

func (m *Manager) writeRecord(path string, record journalRecord) error {
	contents, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return m.writeFile(path, append(contents, '\n'), FilePermission)
}

func (m *Manager) newIdentifier() (string, error) {
	suffix := make([]byte, 4)
	if _, err := io.ReadFull(m.random, suffix); err != nil {
		return "", err
	}
	return m.now().UTC().Format("20060102T150405.000") + "-" + hex.EncodeToString(suffix), nil
}
