package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	journalVersion       = 1
	journalDirectoryName = "journal"
	historyDirectoryName = "history"
	backupDirectoryName  = "backups"
	// BackupDirectoryName は同じ名前を公開する。このパッケージの外で、ディレクトリを
	// 自分で読まなければならない唯一の呼び出し側のためである。マスターパスワードが
	// 変わったときにすべてのバックアップを封じ直す処理は ReadBackup を通せない。
	// ReadBackup は、封をしたときの鍵ではなく、サービスがいま持っている鍵で開く
	// からだ。
	BackupDirectoryName = backupDirectoryName
	temporaryPrefix     = ".sshc-"

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
	// ErrDirectoryNotEmpty は、まだ何かを保持しているディレクトリの削除を拒否する。
	// 再帰的な削除にジャーナルの居場所はない。それを巻き戻すには、このトランザクション
	// が一度も読んでいない内容を復元しなければならなくなる。
	ErrDirectoryNotEmpty   = errors.New("directory is not empty")
	ErrIrreversibleChange  = errors.New("a committed change that kept no backup cannot be rolled back")
	ErrMoveTargetExists    = errors.New("move target already exists")
	ErrMissingSource       = errors.New("file to move or remove does not exist")
	ErrIrreversibleRemoval = errors.New("a committed removal that kept no backup cannot be rolled back")
)

// Precondition は、呼び出し側が新しい内容の前提とした状態を記録する。
type Precondition struct {
	Exists bool
	Digest string
}

// Change は、トランザクションが置き換えるか新規作成するファイルひとつ。
//
// SkipBackup は、この変更が置き換える内容の世代バックアップを抑止する。理由は
// ひとつだけだ。以前の内容が秘密鍵かもしれず、この設計は鍵素材の二つ目のコピーを
// ~/.ssh/sshc/backups/ に残すことを拒む。これを選んだ変更も、ジャーナルには残り、
// 中断後に完了させることもできるが、もはや巻き戻すことはできない。そして Rollback
// は、できるふりをせずにその旨を述べる。ゼロ値は従来どおりの挙動を保つので、既存の
// 呼び出し側には影響が
// ない。
type Change struct {
	Path         string
	Contents     []byte
	Precondition Precondition
	SkipBackup   bool
}

// Move は、ワークスペース内でファイルひとつを rename(2) により移す。
//
// 移動はバイトをコピーしないので、秘密鍵が世代バックアップのディレクトリへ複製
// されることはない。また rename は、ファイルの既存の権限ビットをそのまま正確に
// 保つ。
type Move struct {
	From         string
	To           string
	Precondition Precondition
}

// Removal はファイルをひとつ削除する。
//
// 既定ではバックアップを書かない。最初の呼び出し側が、ユーザーが二度確認した恒久
// 削除であり、鍵素材をバックアップディレクトリへコピーすればその判断を台無しに
// してしまうからだ。そうした削除は中断後に完了させられるが、巻き戻すことはでき
// ない。そして Rollback は、できるふりをせずにその旨を
// 述べる。
//
// Backup は世代コピーを明示的に選ぶ。鍵素材ではないもの — ユーザーがエクスプ
// ローラから取り除いた設定ファイルなど — を削除する呼び出し側のためである。その
// 削除は、このアプリケーションが行う他のすべての変更と同じ振る舞いになる。History
// に載り、取り消せる。
type Removal struct {
	Path         string
	Precondition Precondition
	Backup       bool
}

// DirectoryCreate は、ディレクトリひとつと、ルートより下で欠けている親を作る。
//
// これがあるおかげで、ファイルの配置と、その置き場所を作ることをひとつの
// トランザクションにできる。これがなかった頃は、呼び出し側はジャーナルの外で
// EnsureDirectory を呼び、mkdir とコミットのあいだでクラッシュすれば空の
// ディレクトリが残ることを受け入れるしかなかった。
type DirectoryCreate struct {
	Path string
}

// DirectoryRemoval は、空のディレクトリをひとつ取り除く。
//
// 空のものだけである。再帰的な削除は、トランザクションが一度も読んでいない内容を
// 復元しない限り巻き戻せない。したがって木をまるごと消したい呼び出し側は、
// ファイルを Removal として、ディレクトリをここに、深いものから順に列挙する。
type DirectoryRemoval struct {
	Path string
}

// Request は、任意の数のファイルにまたがる論理的な編集ひとつ。
//
// この順序だけが成立しうる。変更には置き場所が要るのでディレクトリを最初に作り、
// 次に変更・移動・削除を行う。ディレクトリの削除を最後にするのは、それらを空に
// したのがほかならぬこの同じリクエストだから
// である。
type Request struct {
	Operation   string
	Directories []DirectoryCreate
	Changes     []Change
	Moves       []Move
	Removals    []Removal
	// RemoveDirectories は他のすべてのあとで、深いものから順に適用され、その時点で
	// それぞれ空でなければならない。
	RemoveDirectories []DirectoryRemoval
}

// Result は、完了したトランザクションを記述する。
type Result struct {
	ID        string
	BackupDir string
	Written   []string
}

// ConflictError は、ディスク上のファイルが呼び出し側の編集したファイルではないと
// 報告する。Current はディスク上の内容を運ぶので、呼び出し側は三方向の差分を作れる。
// Error がファイルの内容を含むことは決してない。
type ConflictError struct {
	Path     string
	Expected string
	Actual   string
	Current  []byte
}

func (e *ConflictError) Error() string {
	return "external change detected for " + e.Path
}

// ReadBackup は世代バックアップをひとつ読み、それを開く。
//
// 読み手はすべてここを通る — 下の巻き戻しと、ファイルひとつの復元を提案する履歴
// 画面である。したがって「バックアップは暗号文である」ことを知る場所はひとつだけ
// になり、それを忘れて封じられたままのバイト列を誰かの設定の上に書いてしまう
// 呼び出し側は存在しない。
func (m *Manager) ReadBackup(path string) ([]byte, error) {
	contents, err := m.workspace.FileSystem().ReadFile(path)
	if err != nil {
		return nil, err
	}
	if m.Unseal == nil {
		return contents, nil
	}
	return m.Unseal(contents)
}

// Digest は、事前条件とジャーナルエントリに使う内容ハッシュ。
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

// action は既定で write にする。移動と削除が存在するより前に書かれたジャーナル
// でも、正しく再生できるようにするためである。
func (e journalEntry) action() string {
	if e.Action == "" {
		return actionWrite
	}
	return e.Action
}

// zeroBytes は、鍵素材を保持しているかもしれないバッファを上書きする。keys.Wipe と
// 同じくベストエフォート。Go ランタイムがすでに別の場所へコピーしている場合がある。
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

// Manager は、ワークスペース内でジャーナル付きの原子的な複数ファイル書き込みを行う。
//
// Validate は、事前条件のあと、ジャーナルへの記録や書き込みの前に走る省略可能な
// 検査である。ストレージ層は意図的に設定の構文を何も知らない。アプリケーション層が
// バリデータを注入し、それが新しい内容を解析して Include グラフを再検査するので、
// 構文的に壊れたファイルがディスクへ届くことはない。Validate が nil なら、すべての
// リクエストを受け入れる。
type Manager struct {
	workspace *Workspace
	now       func() time.Time
	random    io.Reader
	Validate  func(Request) error
	// Seal と Unseal は、世代バックアップを暗号文にし、また戻す。
	//
	// これらを注入するのは、秘密がどこにあるかは secret パッケージの領分であり、
	// このパッケージはそれを尋ねるために import してはならないからだ — 鍵 vault が
	// パスフレーズを探すために import しないのと同じ理屈である。Seal を持たない
	// マネージャは平文でバックアップを書く。マスターパスワードで封じられるように
	// なる前は、これがそうしていたことだ。マスターパスワードを持つ配線は、いずれも
	// 両方を設定する。
	Seal   func(plaintext []byte) ([]byte, error)
	Unseal func(sealed []byte) ([]byte, error)
}

func NewManager(workspace *Workspace, now func() time.Time, random io.Reader) *Manager {
	return &Manager{workspace: workspace, now: now, random: random}
}

// Commit はすべての変更を検証し、意図をジャーナルへ記録し、新しい内容をすべて
// 永続的にステージし、そのうえでエントリをひとつずつ適用する。
//
// Commit は自動では巻き戻さない。失敗すると保留中のジャーナルが残るので、ユーザー
// は「完了させる」か「復元する」かを選べる。複数のファイルが関わるとき、それが
// 唯一の誠実な選択肢である。
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

	// planned は、このリクエストが作るすべてのディレクトリと、ルートより下にある
	// そのそれぞれの祖先である。これにより、そのいずれかに書き込まれる変更は、まだ
	// ディスク上に何もなくても解決できる。
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

	// ディレクトリが先。変更には置き場所が要り、移動には存在する
	// 行き先が要る。
	for _, create := range request.Directories {
		target, err := m.workspace.ResolveDirectory(create.Path)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		// すでにそこにあるかどうかが、巻き戻しの内容を決める。このトランザクションが
		// 作っていないディレクトリを取り除けば、誰も触れてくれと頼んでいないものを
		// 削除することになる。
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

	// ディレクトリの削除は最後で、実行される時点でそれぞれ空でなければならない。
	// 検査は、このリクエストが残すことになるディスクの状態に対して行う。この同じ
	// リクエストが移動させ、削除し、あるいはディレクトリとして取り除くエントリは、
	// その親を生かし続けない。以前は現状のディスクに対して検査していたため、呼び出し
	// 側は一方のトランザクションで木を空にし、次のトランザクションで取り除かねばなら
	// なかった — つまり操作が自分で始めたことを終えられず、二つのあいだでクラッシュ
	// すれば空の抜け殻が残った。
	//
	// 深いものから順が唯一成立する順序であり、ここで整列しておくことが、呼び出し側に
	// それを知らせずに済ませている。
	ordered := append([]DirectoryRemoval(nil), request.RemoveDirectories...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return strings.Count(ordered[i].Path, string(filepath.Separator)) >
			strings.Count(ordered[j].Path, string(filepath.Separator))
	})
	for _, removal := range ordered {
		target, err := m.workspace.ResolveDirectory(removal.Path)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		info, statErr := fileSystem.Lstat(target)
		if errors.Is(statErr, fs.ErrNotExist) {
			// 何もすることがない。エラーでもない。すでに消えているディレクトリを
			// 取り除くことは、呼び出し側が求めた状態である。
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
		for _, entry := range contents {
			// claimed は、このリクエストがすでに責任を引き受けたすべてのパスを
			// 保持する。移動の元、削除、そしてこれより深いところに列挙された
			// ディレクトリの削除である。
			if !claimed[filepath.Join(target, entry.Name())] {
				return Result{}, ErrDirectoryNotEmpty
			}
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

	// ディレクトリはここで作る。バリデータがリクエストを受理したあとなので、拒否
	// されたリクエストは何も作らない。そして一時ファイルがステージされる前なので、
	// ステージされるファイルには親が存在する。これらはジャーナルのエントリなので、
	// 中断されたコミットは巻き戻せる — これがトランザクションの外の EnsureDirectory で
	// ない理由のすべてである。
	for index := range record.Entries {
		entry := record.Entries[index]
		if entry.action() != actionMakeDir {
			continue
		}
		if err := m.workspace.EnsureDirectory(entry.Path); err != nil {
			return Result{}, err
		}
	}

	// 何かが置き換えられたり unlink されたりする前に、以前の内容をコピーする。移動に
	// コピーは不要だ。ファイルの唯一のコピーをそのまま保つからである。置き換えには
	// 常に必要で、削除には呼び出し側が求めたときにちょうど必要になる。entries と、
	// staged および previous のスライスは、Commit の全体を通じて添字が対応したまま
	// である。
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
		contents := previousContents[index]
		if m.Seal != nil {
			sealed, err := m.Seal(contents)
			if err != nil {
				return Result{}, err
			}
			contents = sealed
		}
		if err := m.writeFile(backupPath, contents, fs.FileMode(entry.Mode)); err != nil {
			return Result{}, err
		}
		entry.Backup = backupPath
	}

	// 新しいファイルはすべて対象の隣にステージし、あとの rename が原子的になるようにする。
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

// sourceState は、これから移動または削除されるファイルをハッシュし、呼び出し側の
// 事前条件を検査する。
//
// ダイジェストができた時点でバイト列をゼロで埋める。移動も削除も二度とそれを必要と
// せず、そのファイルは秘密鍵かもしれないからだ。返される ConflictError が意図的に
// Current の内容を運ばないのも同じ理由である。鍵素材の三方向差分は無用でもあり
// 危険でもある。
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

// Note は、ファイルを変えなかった完了済みの操作を記録する。秘密鍵の表示などが
// これにあたる。
//
// note にはステージされた内容もバックアップもジャーナルファイルもない。復旧すべき
// ものが何もないからだ。これがあるのは、履歴をアプリケーションが行ったことの完全な
// 記録にするためである。構造上、ファイルの内容を持ちようがない。保存するのは操作名、
// 時刻、関係したパスだけである。
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

// currentState は、置き換えられるファイルを読む。返されるモードは、既存のより
// 厳しい権限を保ち、より緩いものは FilePermission まで締める。
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
