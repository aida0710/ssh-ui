package storage

import (
	"path/filepath"
	"time"
)

// HistoryRecord は完了したトランザクション。パスとハッシュだけを保持し、ファイルの
// 内容を保存することはない。エンジンが自らバックアップを削除することもない。
type HistoryRecord struct {
	ID         string
	Operation  string
	Status     string
	StartedAt  time.Time
	FinishedAt time.Time
	Paths      []string
	BackupDir  string
}

// History は完了したトランザクションを、新しいものから順に返す。
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
