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

// PendingEntry は、中断されたトランザクションに含まれるファイルひとつ。
type PendingEntry struct {
	Path      string
	Target    string
	Action    string
	Committed bool
	HasBackup bool
	HasStaged bool
}

// Pending は、起動時に見つかった中断済みトランザクション。部分的な状態はそのまま
// 報告される。健全な結果として提示されることは決してない。
type Pending struct {
	ID          string
	Operation   string
	Status      string
	StartedAt   time.Time
	Committed   int
	Entries     []PendingEntry
	CanComplete bool
	CanRollback bool
}

func (m *Manager) journalDirectory() string {
	return filepath.Join(m.workspace.StateDir(), journalDirectoryName)
}

func (m *Manager) historyDirectory() string {
	return filepath.Join(m.workspace.StateDir(), historyDirectoryName)
}

// Pending は、中断されたトランザクションを古いものから順に列挙する。
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
			CanRollback: true,
		}
		for index, entry := range record.Entries {
			pendingEntry := PendingEntry{
				Path:      entry.Path,
				Target:    entry.Target,
				Action:    entry.action(),
				Committed: index < record.Committed,
				HasBackup: entry.Backup != "",
			}
			switch {
			case pendingEntry.Committed && pendingEntry.Action == actionRemove && entry.NoBackup:
				item.CanRollback = false
			case pendingEntry.Committed && pendingEntry.Action == actionWrite && entry.HadPrevious && entry.NoBackup:
				item.CanRollback = false
			case !pendingEntry.Committed && pendingEntry.Action == actionWrite:
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

// Complete は、中断されたトランザクションを完了させる。検証すべきステージ済みの
// 内容を持つのは置き換えだけである。移動と削除は、その意図の全体をジャーナルの
// エントリに持っている。
func (m *Manager) Complete(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	for index := record.Committed; index < len(record.Entries); index++ {
		if record.Entries[index].action() != actionWrite {
			continue
		}
		if !m.stagedMatches(record.Entries[index]) {
			return ErrCannotComplete
		}
	}
	if err := m.commitStaged(record, journalPath); err != nil {
		return err
	}
	return m.finish(record, journalPath, statusCompleted)
}

// Rollback は、中断されたトランザクションがすでに変更したすべてのファイルを復元
// し、ステージ済みの内容を捨てる。すでにファイルを削除した、あるいは意図して
// バックアップを残さずに置き換えたトランザクションは、巻き戻せない。Rollback は、
// 実際には行っていない復旧を報告するのではなく、
// 拒否する。
func (m *Manager) Rollback(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	for index := 0; index < record.Committed; index++ {
		entry := record.Entries[index]
		// バックアップを残した削除は、置き換えと同じくらい可逆である。バイト列は
		// 世代ディレクトリにあり、モードはエントリにある。巻き戻せないのは、意図して
		// 何も残さなかったものだけである。
		if entry.action() == actionRemove && entry.NoBackup {
			return ErrIrreversibleRemoval
		}
		if entry.action() == actionWrite && entry.HadPrevious && entry.NoBackup {
			return ErrIrreversibleChange
		}
	}

	fileSystem := m.workspace.FileSystem()
	for index := record.Committed - 1; index >= 0; index-- {
		entry := record.Entries[index]
		if entry.action() == actionMove {
			if err := fileSystem.Rename(entry.Target, entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Target)); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
			continue
		}
		if entry.action() == actionMakeDir {
			// もとからあったディレクトリは、このトランザクションが取り除いてよいもの
			// ではない。取り消すのはこれが作ったものだけであり、しかもまだ空である
			// 場合に限る — その後に何かが書き込まれているかもしれず、それを巻き戻しと
			// 一緒に持っていけば、誰も触れてくれと頼んでいないものを削除することに
			// なる。
			if entry.HadPrevious {
				continue
			}
			contents, readErr := fileSystem.ReadDir(entry.Path)
			if errors.Is(readErr, fs.ErrNotExist) {
				continue
			}
			if readErr != nil {
				return readErr
			}
			if len(contents) > 0 {
				continue
			}
			if err := fileSystem.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
			continue
		}
		if entry.action() == actionRemoveDir {
			// 取り除かれた時点で空だったので、空のまま作り直せば失われたものが
			// そのまま復元される。
			if err := m.workspace.EnsureDirectory(entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
			continue
		}
		if entry.HadPrevious {
			contents, readErr := m.ReadBackup(entry.Backup)
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

// readRecords は、ディレクトリ内のすべてのジャーナル文書を古い順に読み込む。
// 識別子は UTC のタイムスタンプで始まるので、辞書順は時系列順である。
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
