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

var (
	ErrNoChanges          = errors.New("transaction has no changes")
	ErrDuplicatePath      = errors.New("transaction contains the same path twice")
	ErrIrreversibleChange = errors.New("a committed change that kept no backup cannot be rolled back")
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

// Request is one logical edit spanning any number of files.
type Request struct {
	Operation string
	Changes   []Change
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
	Path           string `json:"path"`
	Temp           string `json:"temp,omitempty"`
	Backup         string `json:"backup,omitempty"`
	NoBackup       bool   `json:"noBackup,omitempty"`
	HadPrevious    bool   `json:"hadPrevious"`
	Mode           uint32 `json:"mode"`
	Digest         string `json:"digest"`
	PreviousDigest string `json:"previousDigest,omitempty"`
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
// durably, then renames them into place one at a time.
//
// Commit does not roll back automatically. A failure leaves a pending journal
// so the user can choose between completing and restoring, which is the only
// honest option when several files are involved.
func (m *Manager) Commit(request Request) (Result, error) {
	if len(request.Changes) == 0 {
		return Result{}, ErrNoChanges
	}
	fileSystem := m.workspace.FileSystem()

	entries := make([]journalEntry, 0, len(request.Changes))
	previousContents := make([][]byte, 0, len(request.Changes))
	written := make([]string, 0, len(request.Changes))
	seen := make(map[string]bool, len(request.Changes))

	for _, change := range request.Changes {
		target, err := m.workspace.ResolveForWrite(change.Path)
		if err != nil {
			return Result{}, err
		}
		if seen[target] {
			return Result{}, ErrDuplicatePath
		}
		seen[target] = true

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
		previousContents = append(previousContents, previous)
		written = append(written, target)
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

	// Copy the previous contents before anything is replaced. Entries and
	// request.Changes stay index-aligned throughout Commit.
	for index := range record.Entries {
		entry := &record.Entries[index]
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
		temporaryPath, err := fileSystem.WriteTemp(
			filepath.Dir(entry.Path),
			temporaryPrefix+identifier+"-",
			fs.FileMode(entry.Mode),
			request.Changes[index].Contents,
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
		if err := fileSystem.Rename(entry.Temp, entry.Path); err != nil {
			return err
		}
		if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
			return err
		}
		record.Committed = index + 1
		record.Entries[index].Temp = ""
		if err := m.writeRecord(journalPath, *record); err != nil {
			return err
		}
	}
	return nil
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
