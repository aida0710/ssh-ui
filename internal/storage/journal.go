package storage

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	ErrUnknownTransaction = errors.New("no pending transaction with that identifier")
	ErrCannotComplete     = errors.New("staged contents are missing or altered")
)

// PendingEntry is one file inside an interrupted transaction.
type PendingEntry struct {
	Path      string
	Committed bool
	HasBackup bool
	HasStaged bool
}

// Pending is an interrupted transaction found at startup. A partial state is
// reported as it is; it is never presented as a healthy result.
type Pending struct {
	ID          string
	Operation   string
	Status      string
	StartedAt   time.Time
	Committed   int
	Entries     []PendingEntry
	CanComplete bool
}

func (m *Manager) journalDirectory() string {
	return filepath.Join(m.workspace.StateDir(), journalDirectoryName)
}

func (m *Manager) historyDirectory() string {
	return filepath.Join(m.workspace.StateDir(), historyDirectoryName)
}

// Pending lists interrupted transactions, oldest first.
func (m *Manager) Pending() ([]Pending, error) {
	records, err := m.readRecords(m.journalDirectory())
	if err != nil {
		return nil, err
	}
	pending := make([]Pending, 0, len(records))
	for _, record := range records {
		item := Pending{
			ID:          record.ID,
			Operation:   record.Operation,
			Status:      record.Status,
			StartedAt:   record.StartedAt,
			Committed:   record.Committed,
			CanComplete: true,
		}
		for index, entry := range record.Entries {
			pendingEntry := PendingEntry{
				Path:      entry.Path,
				Committed: index < record.Committed,
				HasBackup: entry.Backup != "",
			}
			if !pendingEntry.Committed {
				pendingEntry.HasStaged = m.stagedMatches(entry)
				if !pendingEntry.HasStaged {
					item.CanComplete = false
				}
			}
			item.Entries = append(item.Entries, pendingEntry)
		}
		pending = append(pending, item)
	}
	return pending, nil
}

// Complete finishes an interrupted transaction using the staged contents.
func (m *Manager) Complete(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	for index := record.Committed; index < len(record.Entries); index++ {
		if !m.stagedMatches(record.Entries[index]) {
			return ErrCannotComplete
		}
	}
	if err := m.commitStaged(record, journalPath); err != nil {
		return err
	}
	return m.finish(record, journalPath, statusCompleted)
}

// Rollback restores every file the interrupted transaction had already
// replaced and discards the staged contents.
func (m *Manager) Rollback(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	// A change that deliberately kept no backup cannot be undone. Refusing is
	// the only honest answer; restoring nothing and reporting success would be
	// a lie about the state of the user's key.
	for index := 0; index < record.Committed; index++ {
		if record.Entries[index].HadPrevious && record.Entries[index].NoBackup {
			return ErrIrreversibleChange
		}
	}

	fileSystem := m.workspace.FileSystem()
	for index := record.Committed - 1; index >= 0; index-- {
		entry := record.Entries[index]
		if entry.HadPrevious {
			contents, readErr := fileSystem.ReadFile(entry.Backup)
			if readErr != nil {
				return readErr
			}
			if err := m.writeFile(entry.Path, contents, fs.FileMode(entry.Mode)); err != nil {
				return err
			}
			continue
		}
		if err := fileSystem.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
			return err
		}
	}
	for _, entry := range record.Entries {
		if entry.Temp == "" {
			continue
		}
		if err := fileSystem.Remove(entry.Temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	record.Committed = 0
	return m.finish(record, journalPath, statusRolledBack)
}

func (m *Manager) stagedMatches(entry journalEntry) bool {
	if entry.Temp == "" {
		return false
	}
	contents, err := m.workspace.FileSystem().ReadFile(entry.Temp)
	if err != nil {
		return false
	}
	return Digest(contents) == entry.Digest
}

func (m *Manager) loadPending(identifier string) (*journalRecord, string, error) {
	if identifier == "" || identifier != filepath.Base(identifier) || strings.Contains(identifier, "..") {
		return nil, "", ErrUnknownTransaction
	}
	journalPath := filepath.Join(m.journalDirectory(), identifier+".json")
	contents, err := m.workspace.FileSystem().ReadFile(journalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", ErrUnknownTransaction
	}
	if err != nil {
		return nil, "", err
	}
	var record journalRecord
	if err := json.Unmarshal(contents, &record); err != nil {
		return nil, "", err
	}
	return &record, journalPath, nil
}

// readRecords loads every journal document in a directory, oldest first.
// Identifiers start with a UTC timestamp, so lexical order is chronological.
func (m *Manager) readRecords(directory string) ([]journalRecord, error) {
	entries, err := m.workspace.FileSystem().ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	records := make([]journalRecord, 0, len(names))
	for _, name := range names {
		contents, readErr := m.workspace.FileSystem().ReadFile(filepath.Join(directory, name))
		if readErr != nil {
			return nil, readErr
		}
		var record journalRecord
		if unmarshalErr := json.Unmarshal(contents, &record); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		records = append(records, record)
	}
	return records, nil
}
