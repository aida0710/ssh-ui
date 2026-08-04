package storage

import (
	"path/filepath"
	"time"
)

// HistoryRecord is a finished transaction. It holds paths and hashes only; it
// never stores file contents, and the engine never deletes a backup on its own.
type HistoryRecord struct {
	ID         string
	Operation  string
	Status     string
	StartedAt  time.Time
	FinishedAt time.Time
	Paths      []string
	BackupDir  string
}

// History returns finished transactions, newest first.
func (m *Manager) History() ([]HistoryRecord, error) {
	records, err := m.readRecords(m.historyDirectory())
	if err != nil {
		return nil, err
	}
	history := make([]HistoryRecord, 0, len(records))
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		item := HistoryRecord{
			ID:        record.ID,
			Operation: record.Operation,
			Status:    record.Status,
			StartedAt: record.StartedAt,
			BackupDir: filepath.Join(m.workspace.StateDir(), backupDirectoryName, record.ID),
		}
		if record.FinishedAt != nil {
			item.FinishedAt = *record.FinishedAt
		}
		for _, entry := range record.Entries {
			item.Paths = append(item.Paths, entry.Path)
		}
		history = append(history, item)
	}
	return history, nil
}
