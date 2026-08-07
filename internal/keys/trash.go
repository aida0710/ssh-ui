package keys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"sshc/internal/storage"
)

const (
	// TrashRetentionDays は、UI がごみ箱の鍵を「古い」と印付ける年齢。自動的に削除
	// されるものは何もない。この数字は表示のためだけのものである。
	TrashRetentionDays = 30

	trashDirectoryName = "trash"
	manifestFileName   = "manifest.json"
	manifestVersion    = 1
)

var (
	ErrUnknownTrashEntry = errors.New("no trash entry with that identifier")
	ErrRestoreBlocked    = errors.New("restore would overwrite or duplicate an existing key")
	ErrTrashNameConflict = errors.New("two files in one delete share a base name")
)

// Blocker のコードは安定した識別子で、そのあとに ':' と関係するパスが続く。
const (
	BlockerPathOccupied       = "restore_path_occupied"
	BlockerFingerprintPresent = "restore_fingerprint_present"
	BlockerEntryIncomplete    = "restore_entry_incomplete"
)

// trashEntryPattern は、ごみ箱の識別子が取りうる唯一の形。トランザクション識別子の
// 形式を映したものであり、これによって '..' やその他のトラバーサルの試みは、パスが
// 組み立てられる前に不可能になる。
var trashEntryPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{3}-[0-9a-f]{8}$`)

type manifestFile struct {
	OriginalPath string `json:"originalPath"`
	TrashPath    string `json:"trashPath"`
	Kind         string `json:"kind"`
	Fingerprint  string `json:"fingerprint"`
	Permission   string `json:"permission"`
}

// trashManifest は、ひとつのソフト削除が何を移動したかを記録する。パスはワーク
// スペース相対なので、ホームディレクトリが変わってもエントリは生き残る。どの
// フィールドもファイルの内容を保持しない。
type trashManifest struct {
	SchemaVersion int            `json:"schemaVersion"`
	EntryID       string         `json:"entryId"`
	DeletedAt     string         `json:"deletedAt"`
	Files         []manifestFile `json:"files"`
}

// TrashFile は、ごみ箱エントリ内のファイルひとつ。
type TrashFile struct {
	OriginalRelativePath string
	TrashRelativePath    string
	Kind                 Kind
	Fingerprint          string
	Permission           string
}

// TrashEntry は、ソフト削除されたファイルのグループひとつ。
type TrashEntry struct {
	ID         string
	DeletedAt  time.Time
	AgeDays    int
	Stale      bool
	Files      []TrashFile
	Restorable bool
	Blockers   []string
}

type TrashResult struct {
	EntryID       string
	Files         []TrashFile
	Skipped       []string
	TransactionID string
}

type RestoreResult struct {
	EntryID       string
	Restored      []string
	Blockers      []string
	TransactionID string
}

type PurgeResult struct {
	EntryID       string
	Removed       []string
	TransactionID string
}

func (service *Service) trashRoot() string {
	return filepath.Join(service.workspace.StateDir(), trashDirectoryName)
}

func (service *Service) newEntryID() (string, error) {
	suffix := make([]byte, 4)
	if _, err := io.ReadFull(service.random, suffix); err != nil {
		return "", err
	}
	return service.now().UTC().Format("20060102T150405.000") + "-" + hex.EncodeToString(suffix), nil
}

// Trash は、鍵と、同じ鍵ペアに属するファイルを ~/.ssh/sshc/trash/<entry>/ へ、
// ひとつのジャーナル付きトランザクションで移動させることでソフト削除する。
//
// 移動は同じファイルシステム内の rename なので、バイト列がコピーされることはなく、
// ファイルはすでに持っていた権限ビットを保つ。ごみ箱のエントリが鍵の復旧地点で
// ある。世代バックアップのディレクトリは意図的に使わない。それでは鍵の二つ目の
// コピーが残ってしまうからだ。
func (service *Service) Trash(keyID string) (TrashResult, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return TrashResult{}, err
	}
	item, ok := inventory.Find(keyID)
	if !ok {
		return TrashResult{}, ErrUnknownKey
	}
	group := inventory.Group(item)

	entryID, err := service.newEntryID()
	if err != nil {
		return TrashResult{}, err
	}
	entryRelative := filepath.Join(StateDirectoryName, trashDirectoryName, entryID)
	entryDirectory := filepath.Join(service.workspace.Root(), entryRelative)
	if err := service.workspace.EnsureDirectory(entryDirectory); err != nil {
		return TrashResult{}, err
	}

	manifest := trashManifest{
		SchemaVersion: manifestVersion,
		EntryID:       entryID,
		DeletedAt:     service.now().UTC().Format(time.RFC3339),
	}
	request := storage.Request{Operation: "key.trash"}
	files := make([]TrashFile, 0, len(group))
	usedNames := make(map[string]bool, len(group))

	for _, member := range group {
		baseName := filepath.Base(member.RelativePath)
		if usedNames[baseName] {
			return TrashResult{}, ErrTrashNameConflict
		}
		usedNames[baseName] = true

		absolute := service.absolutePath(member.RelativePath)
		contents, readErr := service.workspace.FileSystem().ReadFile(absolute)
		if readErr != nil {
			return TrashResult{}, readErr
		}
		digest := storage.Digest(contents)
		Wipe(contents)

		trashRelative := filepath.Join(entryRelative, baseName)
		request.Moves = append(request.Moves, storage.Move{
			From:         absolute,
			To:           filepath.Join(service.workspace.Root(), trashRelative),
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		files = append(files, TrashFile{
			OriginalRelativePath: member.RelativePath,
			TrashRelativePath:    trashRelative,
			Kind:                 member.Kind,
			Fingerprint:          member.Fingerprint,
			Permission:           member.Permission,
		})
		manifest.Files = append(manifest.Files, manifestFile{
			OriginalPath: member.RelativePath,
			TrashPath:    trashRelative,
			Kind:         string(member.Kind),
			Fingerprint:  member.Fingerprint,
			Permission:   member.Permission,
		})
	}

	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return TrashResult{}, err
	}
	request.Changes = append(request.Changes, storage.Change{
		Path:     filepath.Join(entryDirectory, manifestFileName),
		Contents: append(document, '\n'),
	})

	result, err := service.transactions.Commit(request)
	if err != nil {
		return TrashResult{}, err
	}
	return TrashResult{
		EntryID:       entryID,
		Files:         files,
		Skipped:       skippedSiblings(inventory, item, group),
		TransactionID: result.ID,
	}, nil
}

// skippedSiblings は、名前の上では関連して見えるが、フィンガープリントを比較できな
// かったためその場に残されたファイルを列挙する。暗号化された旧来の PEM 鍵でそれが
// 起きる。名前を根拠に何かが移動されることは決してない。この一覧は、何が残ったかを
// ユーザーに伝えるためだけに存在する。
func skippedSiblings(inventory *Inventory, item *Item, group []Item) []string {
	if item.Kind != KindPrivateKey || item.Fingerprint != "" {
		return nil
	}
	moved := make(map[string]bool, len(group))
	for _, member := range group {
		moved[member.RelativePath] = true
	}
	skipped := make([]string, 0)
	for _, candidate := range inventory.Items {
		if moved[candidate.RelativePath] {
			continue
		}
		if candidate.Kind != KindPublicKey && candidate.Kind != KindCertificate {
			continue
		}
		if strings.HasPrefix(candidate.RelativePath, item.RelativePath) {
			skipped = append(skipped, candidate.RelativePath)
		}
	}
	if len(skipped) == 0 {
		return nil
	}
	return skipped
}

// ListTrash は、すべてのごみ箱エントリを新しいものから順に返す。書き込みは行わず、
// エントリがどれだけ古くても何も削除しない。
func (service *Service) ListTrash() ([]TrashEntry, error) {
	directories, err := service.workspace.FileSystem().ReadDir(service.trashRoot())
	if errors.Is(err, fs.ErrNotExist) {
		return []TrashEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	inventory, err := service.Inventory()
	if err != nil {
		return nil, err
	}

	entries := make([]TrashEntry, 0, len(directories))
	for _, directory := range directories {
		if !directory.IsDir() || !trashEntryPattern.MatchString(directory.Name()) {
			continue
		}
		manifest, manifestErr := service.readManifest(directory.Name())
		if manifestErr != nil {
			// 読める manifest を持たないディレクトリは、エンジンが残した残骸である。
			// たとえば、何かを書く前に失敗した削除がこれにあたる。復旧可能な鍵として
			// 提示されることはない。
			continue
		}
		entries = append(entries, service.describeEntry(inventory, manifest))
	}
	sort.Slice(entries, func(first, second int) bool { return entries[first].ID > entries[second].ID })
	return entries, nil
}

func (service *Service) readManifest(entryID string) (trashManifest, error) {
	if !trashEntryPattern.MatchString(entryID) {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	path := filepath.Join(service.trashRoot(), entryID, manifestFileName)
	contents, err := service.workspace.FileSystem().ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	if err != nil {
		return trashManifest{}, err
	}
	var manifest trashManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	if manifest.SchemaVersion != manifestVersion || manifest.EntryID != entryID {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	return manifest, nil
}

func (service *Service) describeEntry(inventory *Inventory, manifest trashManifest) TrashEntry {
	entry := TrashEntry{ID: manifest.EntryID}
	if deletedAt, err := time.Parse(time.RFC3339, manifest.DeletedAt); err == nil {
		entry.DeletedAt = deletedAt
		entry.AgeDays = int(service.now().UTC().Sub(deletedAt).Hours() / 24)
		entry.Stale = entry.AgeDays >= TrashRetentionDays
	}
	for _, file := range manifest.Files {
		entry.Files = append(entry.Files, TrashFile{
			OriginalRelativePath: file.OriginalPath,
			TrashRelativePath:    file.TrashPath,
			Kind:                 Kind(file.Kind),
			Fingerprint:          file.Fingerprint,
			Permission:           file.Permission,
		})
	}
	entry.Blockers = service.restoreBlockers(inventory, manifest)
	entry.Restorable = len(entry.Blockers) == 0
	return entry
}

// restoreBlockers は、復元が推測を強いられる理由をすべて報告する。
//
// エンジンは復元したファイルの名前を変えず、既存のファイルを上書きせず、同一の
// 二つの鍵のうちどちらを Host が意図したかを決めることもしない。blocker があれば
// 拒否し、その理由を示す。
func (service *Service) restoreBlockers(inventory *Inventory, manifest trashManifest) []string {
	fileSystem := service.workspace.FileSystem()
	blockers := make([]string, 0)
	for _, file := range manifest.Files {
		if _, err := fileSystem.Lstat(filepath.Join(service.workspace.Root(), file.TrashPath)); err != nil {
			blockers = append(blockers, BlockerEntryIncomplete+":"+file.OriginalPath)
			continue
		}
		if _, err := fileSystem.Lstat(filepath.Join(service.workspace.Root(), file.OriginalPath)); err == nil {
			blockers = append(blockers, BlockerPathOccupied+":"+file.OriginalPath)
			continue
		}
		if file.Fingerprint == "" || Kind(file.Kind) != KindPrivateKey {
			continue
		}
		for _, candidate := range inventory.Items {
			if candidate.Kind == KindPrivateKey && candidate.Fingerprint == file.Fingerprint {
				blockers = append(blockers, BlockerFingerprintPresent+":"+candidate.RelativePath)
				break
			}
		}
	}
	if len(blockers) == 0 {
		return nil
	}
	return blockers
}

// Restore は、ごみ箱エントリのすべてのファイルを元のパスへ戻し、そのエントリの
// manifest を取り除く。すべてひとつのジャーナル付きトランザクションで行う。空に
// なったエントリのディレクトリは残る。マネージャが所有するのはファイルであって
// ディレクトリではないからだ。ListTrash は manifest のないディレクトリを無視する。
func (service *Service) Restore(entryID string) (RestoreResult, error) {
	manifest, err := service.readManifest(entryID)
	if err != nil {
		return RestoreResult{}, err
	}
	inventory, err := service.Inventory()
	if err != nil {
		return RestoreResult{}, err
	}
	if blockers := service.restoreBlockers(inventory, manifest); len(blockers) > 0 {
		return RestoreResult{EntryID: entryID, Blockers: blockers}, ErrRestoreBlocked
	}

	fileSystem := service.workspace.FileSystem()
	request := storage.Request{Operation: "key.restore"}
	restored := make([]string, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		trashAbsolute := filepath.Join(service.workspace.Root(), file.TrashPath)
		originalAbsolute := filepath.Join(service.workspace.Root(), file.OriginalPath)
		if err := service.workspace.EnsureDirectory(filepath.Dir(originalAbsolute)); err != nil {
			return RestoreResult{}, err
		}
		contents, readErr := fileSystem.ReadFile(trashAbsolute)
		if readErr != nil {
			return RestoreResult{}, readErr
		}
		digest := storage.Digest(contents)
		Wipe(contents)
		request.Moves = append(request.Moves, storage.Move{
			From:         trashAbsolute,
			To:           originalAbsolute,
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		restored = append(restored, file.OriginalPath)
	}

	manifestPath := filepath.Join(service.trashRoot(), entryID, manifestFileName)
	manifestContents, err := fileSystem.ReadFile(manifestPath)
	if err != nil {
		return RestoreResult{}, err
	}
	request.Removals = append(request.Removals, storage.Removal{
		Path:         manifestPath,
		Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(manifestContents)},
	})

	result, err := service.transactions.Commit(request)
	if err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{EntryID: entryID, Restored: restored, TransactionID: result.ID}, nil
}

// Purge は、ごみ箱エントリを恒久的に削除する。何もバックアップされないので、結果は
// 取り消せない。HTTP 層は、これを呼ぶ前に二度目の確認と自前のアクショントークンを
// 要求する。
func (service *Service) Purge(entryID string) (PurgeResult, error) {
	manifest, err := service.readManifest(entryID)
	if err != nil {
		return PurgeResult{}, err
	}
	fileSystem := service.workspace.FileSystem()
	request := storage.Request{Operation: "key.purge"}
	removed := make([]string, 0, len(manifest.Files))

	for _, file := range manifest.Files {
		absolute := filepath.Join(service.workspace.Root(), file.TrashPath)
		contents, readErr := fileSystem.ReadFile(absolute)
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return PurgeResult{}, readErr
		}
		digest := storage.Digest(contents)
		Wipe(contents)
		request.Removals = append(request.Removals, storage.Removal{
			Path:         absolute,
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		removed = append(removed, file.OriginalPath)
	}

	manifestPath := filepath.Join(service.trashRoot(), entryID, manifestFileName)
	manifestContents, err := fileSystem.ReadFile(manifestPath)
	if err != nil {
		return PurgeResult{}, err
	}
	request.Removals = append(request.Removals, storage.Removal{
		Path:         manifestPath,
		Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(manifestContents)},
	})

	result, err := service.transactions.Commit(request)
	if err != nil {
		return PurgeResult{}, err
	}
	return PurgeResult{EntryID: entryID, Removed: removed, TransactionID: result.ID}, nil
}
