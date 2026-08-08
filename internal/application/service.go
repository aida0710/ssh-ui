package application

import (
	"bytes"
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"sshc/internal/config"
	"sshc/internal/platform"
	"sshc/internal/storage"
)

const (
	// entryFileName は、このアプリケーションが Include graph の root として
	// 扱う、OpenSSH のユーザー設定ファイルである。
	entryFileName = "config"
	// maxEffectivePreviews は、グループ preview が説明する alias の数の上限
	// であり、大規模な設定が 1 回の preview を無制限の walk に変えてしまわないようにする。
	maxEffectivePreviews = 50
)

var (
	ErrUnknownEditKind       = errors.New("unknown edit kind")
	ErrUnknownRecoveryAction = errors.New("unknown recovery action")
	ErrNotEditable           = errors.New("file is not editable through this application")
	// ErrGroupNotDeclared は、どの Include 行も宣言していないグループを
	// 名指す操作を拒否する。存在するディレクトリがグループであるとは限らない。
	ErrGroupNotDeclared = errors.New("no generated Include line declares that group")
	// ErrAmbiguousDestination は、グループと path の両方を名指す move を拒否する。
	// その 2 つは食い違うことがあり、このアプリケーションはどちらかを選ぶことをしない。
	ErrAmbiguousDestination = errors.New("a move names either a destination group or a destination path")
)

// EditKind は、UI が要求できる操作を名指す。
type EditKind string

const (
	EditHostFields EditKind = "host_fields"
	EditBlockRaw   EditKind = "block_raw"
	EditFileRaw    EditKind = "file_raw"
	EditRename     EditKind = "rename"
	EditGroups     EditKind = "groups"
	EditMetadata   EditKind = "metadata"
	EditMove       EditKind = "move"
	// EditComment は、Host ブロックの上のコメント行を設定する。コメントは
	// metadata ではなく設定の中に存在するので、このアプリケーション無し
	// でそのファイルを読む誰にとっても残り続ける。
	EditComment EditKind = "comment"
	// EditFileRename は 1 個の設定ファイルを移動し、それを名指していた
	// Include 行を書き換える。EditFileDelete は 1 個を削除し、それらの行を
	// 取り除く。どちらもブロック操作ではなくファイル操作なので、
	// file_raw の一形態としてではなく独自の種類として存在する。file_raw
	// はファイルを空にはできるが、その存在を止めることはできず、もはや
	// include されていないファイルは空のファイルとは別のものだからである。
	EditFileRename EditKind = "file_rename"
	EditFileDelete EditKind = "file_delete"
	// EditDirectoryCreate と EditDirectoryDelete は、explorer の
	// ディレクトリ操作である。rename はここには無い。それは中のすべての
	// ファイルを名指す Include 行を運ばなければならず、これは file_rename
	// が 1 個のファイルに対して行うのと同じ作業であり、それらの書き換えが積み重なる必要がある。
	EditDirectoryCreate EditKind = "directory_create"
	EditDirectoryDelete EditKind = "directory_delete"
)

// EditRequest は、要求された 1 個の変更である。
//
// Base は、クライアントが Path のために読み込んだ厳密なバイト列を
// 運ぶ。ファイルを対象とするすべての編集はそのバイト列に対して適用され、
// その digest を事前条件として commit されるので、ユーザーは常に自分が
// 見たものを編集することになり、外部の変更は黙った上書きではなく本物の三者 diff を生む。
//
// Fields 内のすべての行番号は 1-based であり、この service が FormField、
// Source、DiffLine で報告する行番号と一致する。internal/config の
// 0-based の index が、この境界をどちらの方向にも越えることは決してない。
type EditRequest struct {
	Kind     EditKind    `json:"kind"`
	Path     string      `json:"path,omitempty"`
	Base     string      `json:"base,omitempty"`
	Alias    string      `json:"alias,omitempty"`
	NewAlias string      `json:"newAlias,omitempty"`
	Fields   []FieldEdit `json:"fields,omitempty"`
	Raw      string      `json:"raw,omitempty"`
	Comment  string      `json:"comment,omitempty"`
	Metadata *Metadata   `json:"metadata,omitempty"`
	// DestinationGroup は、ファイルではなくグループを名指すことでホストを
	// グループへ移動する。destination path はそこから導出されるので、
	// 呼び出し側は食い違うグループと path を名指すことができない。両方を送ることは拒否される。
	DestinationGroup string `json:"destinationGroup,omitempty"`
	// DestinationPath と DestinationBase は、move の 2 番目のファイルを記述する。
	// DestinationBase は、クライアントがそれのために読み込んだ厳密な
	// バイト列を運ぶので、destination は source と同じ事前条件の保証を持つ。
	DestinationPath string `json:"destinationPath,omitempty"`
	DestinationBase string `json:"destinationBase,omitempty"`
}

// SavePreview は、save が書き込むであろうものそのものである。
type SavePreview struct {
	Operation string          `json:"operation"`
	Diffs     []FileDiff      `json:"diffs"`
	Effective []EffectiveDiff `json:"effective,omitempty"`
	Notices   []Notice        `json:"notices,omitempty"`
}

// SaveResult は、commit された transaction を報告する。
type SaveResult struct {
	TransactionID string      `json:"transactionId"`
	Written       []string    `json:"written"`
	Preview       SavePreview `json:"preview"`
	// KeyRelocations は HTTP 応答には出さず、同じプロセス内で鍵パスに
	// 結び付いた資格情報を追従させるためだけに運ぶ。
	KeyRelocations []RelocatedKeyFile `json:"-"`
}

// IncludeReference は、1 個の Include 引数と、それが解決した先である。
type IncludeReference struct {
	Line      int       `json:"line"`
	Pattern   string    `json:"pattern"`
	Condition string    `json:"condition,omitempty"`
	Matches   []FileRef `json:"matches,omitempty"`
}

// FileNode は、Include graph の 1 個のファイルである。
type FileNode struct {
	File     FileRef            `json:"file"`
	Missing  bool               `json:"missing,omitempty"`
	Editable bool               `json:"editable"`
	Loads    int                `json:"loads"`
	Includes []IncludeReference `json:"includes,omitempty"`
}

// FileContents は、raw editor のための設定ファイル全体である。
type FileContents struct {
	File     FileRef `json:"file"`
	Contents string  `json:"contents"`
	Digest   string  `json:"digest"`
	Editable bool    `json:"editable"`
	Exists   bool    `json:"exists"`
}

// PendingView は、ユーザーが判断しなければならない中断された transaction である。
type PendingView struct {
	ID          string   `json:"id"`
	Operation   string   `json:"operation"`
	Status      string   `json:"status"`
	StartedAt   string   `json:"startedAt"`
	Committed   int      `json:"committed"`
	Paths       []string `json:"paths"`
	CanComplete bool     `json:"canComplete"`
}

// HistoryEntry は、1 個の完了した transaction である。
type HistoryEntry struct {
	ID         string   `json:"id"`
	Operation  string   `json:"operation"`
	Status     string   `json:"status"`
	StartedAt  string   `json:"startedAt"`
	FinishedAt string   `json:"finishedAt,omitempty"`
	Paths      []string `json:"paths"`
	Restorable []string `json:"restorable,omitempty"`
}

// Overview は、Connections tree と Config Explorer が必要とするすべてである。
type Overview struct {
	Entry       FileRef          `json:"entry"`
	Files       []FileNode       `json:"files"`
	Hosts       []HostEntry      `json:"hosts"`
	Groups      []GroupView      `json:"groups"`
	Metadata    Metadata         `json:"metadata"`
	Diagnostics []DiagnosticView `json:"diagnostics"`
	Notices     []Notice         `json:"notices"`
	Pending     []PendingView    `json:"pending,omitempty"`
}

// HostDetail は、ホスト editor が必要とするすべてであり、クライアント
// が edit base として送り返せるようファイル全体を含む。
type HostDetail struct {
	Form      HostForm     `json:"form"`
	Metadata  HostMetadata `json:"metadata"`
	Effective Effective    `json:"effective"`
	File      FileContents `json:"file"`
}

// Service はワークスペースと transaction manager を所有する。これはプロセス内で唯一の書き
// 手である。すべての mutation は saveMutex によって直列化され、manager の Validate
// hook はここで設置されるので、どの code path もそれ無しで commit することはできない。
type Service struct {
	workspace *storage.Workspace
	manager   *storage.Manager
	resolver  config.Resolver
	metadata  *MetadataStore
	entryPath string

	saveMutex       sync.Mutex
	pendingBase     map[string][]byte
	pendingBaseline map[string]bool
}

func NewService(workspace *storage.Workspace, manager *storage.Manager) *Service {
	service := &Service{
		workspace: workspace,
		manager:   manager,
		resolver:  storage.NewResolver(workspace),
		metadata:  NewMetadataStore(workspace),
		entryPath: filepath.Join(workspace.Root(), entryFileName),
	}
	manager.Validate = service.validate
	return service
}

// PreferredTerminal は画面と端末ランチャーが共有する現在の選択を返す。
// metadata が壊れて読めない場合は、起動そのものを失わせず安全な既定へ戻る。
func (s *Service) PreferredTerminal() platform.TerminalID {
	metadata, _, err := s.metadata.Load()
	if err != nil || !platform.ValidTerminalID(metadata.Terminal) {
		return platform.TerminalApple
	}
	return metadata.Terminal
}

// displayPath は、UI とエラー payload のために path を表す。ファイルが
// その内側にあるときは~/.ssh からの相対 path、Include が外側を
// 指しているときのみ絶対 path となる。log 行はどちらの形式も受け取ることがない。
func (s *Service) displayPath(absolute string) string {
	reference := NewFileRef(s.workspace.Root(), absolute)
	if reference.External {
		return reference.Absolute
	}
	return reference.Path
}

func (s *Service) readFile(absolute string) (contents []byte, exists bool, err error) {
	contents, err = s.workspace.FileSystem().ReadFile(absolute)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return contents, true, nil
}

func (s *Service) resolve() (*config.Graph, error) {
	return s.resolver.Resolve(s.entryPath)
}

func (s *Service) resolveWith(pending map[string][]byte) (*config.Graph, error) {
	resolver := s.resolver
	resolver.Loader = overlayLoader{base: s.resolver.Loader, pending: pending}
	return resolver.Resolve(s.entryPath)
}

// Overview は、Connections tree、Include graph、metadata を構築する。
func (s *Service) Overview() (Overview, error) {
	graph, err := s.resolve()
	if err != nil {
		return Overview{}, err
	}
	root := s.workspace.Root()
	hosts, notices := ProjectHosts(graph, root)

	stored, _, err := s.metadata.Load()
	if err != nil {
		return Overview{}, err
	}
	identities := make([]HostIdentity, 0, len(hosts))
	for _, host := range hosts {
		if !host.Identity.IsZero() {
			identities = append(identities, host.Identity)
		}
	}
	reconciled, orphanNotices := ReconcileMetadata(stored, identities)
	notices = append(notices, orphanNotices...)
	notices = append(notices, s.unreachedConnectionFiles(graph)...)

	// 宣言とディスクが互いについて何を語っているか。connections/配下に
	// あってどの Include も名指していないディレクトリこそが、黙って
	// 何もしないものである。その中のファイルは誰も読まない設定である。
	// エントリファイルが無いワークスペースはグループを何も宣言せず、nil のファイル
	// に何を宣言しているか尋ねることが、これが最初に production へ届いた経緯である。
	entryNode := graph.Nodes[s.entryPath]
	var groups []GroupView
	if entryNode != nil && entryNode.File != nil {
		// 1 個のマーカーしか持たない生成領域は、このアプリケーションから見れば
		// 何も宣言していないことになり、すべてのグループが未宣言に見えて
		// しまう。実際に起きたのはそういうことではないし、それを 4 回繰り返して言うことは、
		// Include 行がまさにそこにある 4 個のディレクトリをユーザーに見に行かせることになる。
		if _, _, _, regionErr := FindRegion(entryNode.File); errors.Is(regionErr, ErrRegionDamaged) {
			notices = append(notices, Notice{
				Code: NoticeRegionDamaged, Path: s.displayPath(s.entryPath),
			})
		} else {
			present, presentErr := s.presentGroupDirectories()
			if presentErr != nil {
				return Overview{}, presentErr
			}
			var groupNotices []Notice
			groups, groupNotices = BuildGroupsView(entryNode.File, hosts, reconciled, present)
			notices = append(notices, groupNotices...)
		}
	}

	overview := Overview{
		Entry:    NewFileRef(root, s.entryPath),
		Hosts:    hosts,
		Groups:   groups,
		Metadata: reconciled,
		Notices:  notices,
	}
	for _, nodePath := range graph.Order {
		node := graph.Nodes[nodePath]
		reference := NewFileRef(root, nodePath)
		file := FileNode{
			File:     reference,
			Missing:  node.Missing,
			Editable: node.Editable && !reference.External,
			Loads:    node.Loads,
		}
		for _, edge := range node.Includes {
			include := IncludeReference{Line: edge.Line, Pattern: edge.Pattern, Condition: edge.Condition}
			for _, match := range edge.Matches {
				include.Matches = append(include.Matches, NewFileRef(root, match))
			}
			file.Includes = append(file.Includes, include)
		}
		overview.Files = append(overview.Files, file)
	}
	for _, diagnostic := range graph.Diagnostics {
		overview.Diagnostics = append(overview.Diagnostics, NewDiagnosticView(root, diagnostic))
	}
	pending, err := s.Pending()
	if err != nil {
		return Overview{}, err
	}
	overview.Pending = pending

	// contract で必須の配列は、通信上で決して null にならない。frontend は
	// 実行時に形を validate し、配列が無いことは contract 違反であって
	// 空のリストではない。
	if overview.Files == nil {
		overview.Files = []FileNode{}
	}
	if overview.Hosts == nil {
		overview.Hosts = []HostEntry{}
	}
	if overview.Diagnostics == nil {
		overview.Diagnostics = []DiagnosticView{}
	}
	if overview.Notices == nil {
		overview.Notices = []Notice{}
	}
	return overview, nil
}

// HostDetail は、説明された値と共に 1 個のホストブロックを射影する。
func (s *Service) HostDetail(relative, alias string) (HostDetail, error) {
	graph, err := s.resolve()
	if err != nil {
		return HostDetail{}, err
	}
	identity := HostIdentity{Path: relative, Alias: alias}
	form, err := ProjectHostForm(graph, s.workspace.Root(), identity)
	if err != nil {
		return HostDetail{}, err
	}
	contents, err := s.FileContents(relative)
	if err != nil {
		return HostDetail{}, err
	}
	stored, _, err := s.metadata.Load()
	if err != nil {
		return HostDetail{}, err
	}
	detail := HostDetail{
		Form:      form,
		Effective: ComputeEffective(graph, s.workspace.Root(), alias),
		File:      contents,
		Metadata:  HostMetadata{Identity: identity},
	}
	for _, host := range stored.Hosts {
		if host.Identity == identity {
			detail.Metadata = host
		}
	}
	return detail, nil
}

// FileContents は、ワークスペース内の編集可能な 1 個のファイルを読む。
func (s *Service) FileContents(relative string) (FileContents, error) {
	absolute, err := AbsolutePath(s.workspace.Root(), relative)
	if err != nil {
		return FileContents{}, err
	}
	contents, exists, err := s.readFile(absolute)
	if err != nil {
		return FileContents{}, err
	}
	editable := true
	if _, resolveErr := s.workspace.ResolveForWrite(absolute); resolveErr != nil {
		editable = false
	}
	return FileContents{
		File:     NewFileRef(s.workspace.Root(), absolute),
		Contents: string(contents),
		Digest:   storage.Digest(contents),
		Editable: editable,
		Exists:   exists,
	}, nil
}

// planned は、1 個の準備された transaction である。厳密な変更、
// validator が比較対象とする base の内容、そして呼び出し側が見る preview である。
// directoryCreates と directoryRemovals は、計画されたディレクトリを
// journal が取る形に変換する。作成は既に絶対 path で表され、削除は
// ワークスペース相対の言葉で計画される。それは通知とグループ名が
// 使う語彙である。
// requestFor は、計画された transaction が storage request になる唯一の場所である。
//
// 以前はこれが 2 個あり、グループ側の path は、save 側の path が持っていて
// 自分には無いもの——removals と、rename が始めたことを終えるために必要なディレクトリの
// removals——を静かに落としていた。1 個の関数は自分自身からずれることはできない。
func (s *Service) requestFor(prepared planned) storage.Request {
	return storage.Request{
		Operation:         prepared.operation,
		Directories:       directoryCreates(prepared.directories),
		Changes:           prepared.changes,
		Moves:             prepared.moves,
		Removals:          prepared.removals,
		RemoveDirectories: directoryRemovals(s.workspace.Root(), prepared.removeDirectories),
	}
}

// どちらも重複を除去する。planner は、destination ディレクトリに
// 着地するファイルごとに 1 回それを追加していく。これはディレクトリが journal の外側で
// 作成されていたときは無害だったが、journal の内側では重複した path になる。
func directoryCreates(absolute []string) []storage.DirectoryCreate {
	creates := make([]storage.DirectoryCreate, 0, len(absolute))
	seen := map[string]bool{}
	for _, path := range absolute {
		cleaned := filepath.Clean(path)
		if seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		creates = append(creates, storage.DirectoryCreate{Path: cleaned})
	}
	return creates
}

func directoryRemovals(root string, relative []string) []storage.DirectoryRemoval {
	removals := make([]storage.DirectoryRemoval, 0, len(relative))
	seen := map[string]bool{}
	for _, path := range relative {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if seen[absolute] {
			continue
		}
		seen[absolute] = true
		removals = append(removals, storage.DirectoryRemoval{Path: absolute})
	}
	return removals
}

type planned struct {
	operation string
	changes   []storage.Change
	// move と removal は、変更と同じ transaction で運ばれるので、ファイルの
	// 再配置とそれを名指す設定は一緒に着地するか、まったく着地しないか
	// のどちらかになる。ディレクトリは、Commit がその書き込み path を解決する前に作成される。
	moves    []storage.Move
	removals []storage.Removal
	// ディレクトリは、何かが書き込まれる前に作成され、他のすべての後に
	// 削除される。どちらも transaction の内側で行われる。journal の外側
	// での mkdir や rmdir は、復旧記録の無い filesystem 上の効果になってしまう。
	directories       []string
	removeDirectories []string
	base              map[string][]byte
	baseline          map[string]bool
	preview           SavePreview
	keyRelocations    []RelocatedKeyFile
}

// Preview は transaction を準備し、書き込まずにその diff を返す。
func (s *Service) Preview(request EditRequest) (SavePreview, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	prepared, err := s.plan(request)
	if err != nil {
		return SavePreview{}, err
	}
	return prepared.preview, nil
}

// Save は同じ transaction を準備し、それを commit する。
func (s *Service) Save(request EditRequest) (SaveResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	prepared, err := s.plan(request)
	if err != nil {
		return SaveResult{}, err
	}
	// Commit は実際のディレクトリに対して書き込み path を解決するので、
	// この transaction が必要とするものは先に作成される。ここに到達するのは
	// 計画済みの transaction だけである。拒否は上流で返され、ディスクは手つかずのままになる。
	metadataPath := filepath.Clean(s.metadata.Path())
	for _, change := range prepared.changes {
		if filepath.Clean(change.Path) != metadataPath {
			continue
		}
		if err := s.metadata.EnsureDirectory(); err != nil {
			return SaveResult{}, err
		}
	}
	s.pendingBase = prepared.base
	s.pendingBaseline = prepared.baseline
	defer func() { s.pendingBase, s.pendingBaseline = nil, nil }()

	result, err := s.manager.Commit(s.requestFor(prepared))
	var conflict *storage.ConflictError
	if errors.As(err, &conflict) {
		cleaned := filepath.Clean(conflict.Path)
		var edited []byte
		for _, change := range prepared.changes {
			if filepath.Clean(change.Path) == cleaned {
				edited = change.Contents
			}
		}
		return SaveResult{}, &ConflictError{Report: BuildConflictReport(
			s.displayPath(cleaned), prepared.base[cleaned], conflict.Current, edited,
		)}
	}
	if err != nil {
		return SaveResult{}, err
	}
	written := make([]string, 0, len(result.Written))
	for _, path := range result.Written {
		written = append(written, s.displayPath(path))
	}
	return SaveResult{TransactionID: result.ID, Written: written, Preview: prepared.preview}, nil
}

func (s *Service) plan(request EditRequest) (planned, error) {
	graph, err := s.resolve()
	if err != nil {
		return planned{}, err
	}
	switch request.Kind {
	case EditHostFields, EditBlockRaw, EditRename, EditFileRaw, EditComment:
		return s.planFileEdit(graph, request)
	case EditGroups, EditMetadata:
		return s.planMetadataEdit(graph, request)
	case EditMove:
		return s.planMoveHost(graph, request)
	case EditFileRename:
		return s.planFileRename(graph, request)
	case EditDirectoryCreate:
		return s.planDirectoryCreate(graph, request)
	case EditDirectoryDelete:
		return s.planDirectoryDelete(graph, request)
	case EditFileDelete:
		return s.planFileDelete(graph, request)
	default:
		return planned{}, ErrUnknownEditKind
	}
}

func (s *Service) planFileEdit(graph *config.Graph, request EditRequest) (planned, error) {
	absolute, err := AbsolutePath(s.workspace.Root(), request.Path)
	if err != nil {
		return planned{}, err
	}
	if _, err := s.workspace.ResolveForWrite(absolute); err != nil {
		return planned{}, err
	}
	base := []byte(request.Base)
	file := config.Parse(base)

	var renameFrom, renameTo HostIdentity
	switch request.Kind {
	case EditFileRaw:
		file = config.Parse([]byte(request.Raw))
	case EditHostFields, EditBlockRaw, EditRename, EditComment:
		block, ok := FindHostBlock(file, request.Alias)
		if !ok {
			return planned{}, ErrHostNotFound
		}
		switch request.Kind {
		case EditHostFields:
			if err := ApplyFieldEdits(file, block, request.Fields); err != nil {
				return planned{}, err
			}
		case EditBlockRaw:
			if err := ReplaceBlock(file, block, request.Raw); err != nil {
				return planned{}, err
			}
		case EditComment:
			if err := SetHostComment(file, block, request.Comment); err != nil {
				return planned{}, err
			}
		case EditRename:
			if err := refuseTakenAlias(graph, request.Alias, request.NewAlias); err != nil {
				return planned{}, err
			}
			if err := RenameHostAlias(file, block, request.Alias, request.NewAlias); err != nil {
				return planned{}, err
			}
			renameFrom = HostIdentity{Path: request.Path, Alias: request.Alias}
			renameTo = HostIdentity{Path: request.Path, Alias: request.NewAlias}
		}
	}
	updated := file.Render()

	disk, exists, err := s.readFile(absolute)
	if err != nil {
		return planned{}, err
	}
	if !bytes.Equal(base, disk) {
		return planned{}, &ConflictError{Report: BuildConflictReport(request.Path, base, disk, updated)}
	}

	precondition := storage.Precondition{}
	if exists {
		precondition = storage.Precondition{Exists: true, Digest: storage.Digest(base)}
	}
	prepared := planned{
		operation: "config." + string(request.Kind),
		changes:   []storage.Change{{Path: absolute, Contents: updated, Precondition: precondition}},
		base:      map[string][]byte{filepath.Clean(absolute): base},
		baseline:  diagnosticBaseline(graph),
		preview: SavePreview{
			Operation: "config." + string(request.Kind),
			Diffs:     []FileDiff{BuildFileDiff(request.Path, diskOrNil(disk, exists), updated)},
		},
	}

	if !renameFrom.IsZero() {
		stored, precondition, err := s.metadata.Load()
		if err != nil {
			return planned{}, err
		}
		renamed := RenameHostIdentity(stored, renameFrom, renameTo)
		change, err := s.metadata.Change(renamed, precondition)
		if err != nil {
			return planned{}, err
		}
		previous, _, err := s.readFile(change.Path)
		if err != nil {
			return planned{}, err
		}
		prepared.changes = append(prepared.changes, change)
		prepared.base[filepath.Clean(change.Path)] = previous
		prepared.preview.Diffs = append(prepared.preview.Diffs,
			BuildFileDiff(s.displayPath(change.Path), previous, change.Contents))
	}

	// コメントは同じホストの note を退役させる。両者は 2 箇所に書かれた
	// 同じものであり、このアプリケーション無しでも生き残るのは設定の
	// 方なので、note はコメントと食い違ったまま残されるのではなく、
	// コメントを書くのと同じ transaction に入る。
	if request.Kind == EditComment {
		stored, precondition, err := s.metadata.Load()
		if err != nil {
			return planned{}, err
		}
		cleared := ClearHostNote(stored, HostIdentity{Path: request.Path, Alias: request.Alias})
		change, err := s.metadata.Change(cleared, precondition)
		if err != nil {
			return planned{}, err
		}
		previous, _, err := s.readFile(change.Path)
		if err != nil {
			return planned{}, err
		}
		if !bytes.Equal(previous, change.Contents) {
			prepared.changes = append(prepared.changes, change)
			prepared.base[filepath.Clean(change.Path)] = previous
			prepared.preview.Diffs = append(prepared.preview.Diffs,
				BuildFileDiff(s.displayPath(change.Path), previous, change.Contents))
		}
	}

	if request.Alias != "" {
		pending := map[string][]byte{filepath.Clean(absolute): updated}
		after, err := s.resolveWith(pending)
		if err != nil {
			return planned{}, err
		}
		alias := request.Alias
		if request.Kind == EditRename {
			alias = request.NewAlias
		}
		prepared.preview.Effective = []EffectiveDiff{DiffEffective(
			ComputeEffective(graph, s.workspace.Root(), request.Alias),
			ComputeEffective(after, s.workspace.Root(), alias),
		)}
	}
	return prepared, nil
}

// resolveDestination は、destination グループを destination path へ変える。
//
// ファイルは自分自身の名前を保ったままディレクトリを変えるので、
// グループ間の move は shell で見えるとおりのものそのものである。同じ
// ファイルが、どこか別の場所にある。名前はまず GroupFileName を通る。
// グループは 1 個の Include pattern によって読まれるので、その pattern に match
// しない名前は、OpenSSH が決して見に行かない場所にブロックを着地させてしまうからである。
//
// グループは既に宣言されていなければならない——グループを作ることは
// それ自身の preview を持つそれ自身の操作であり、move からグループを推測することは、
// 無関係な要求の副作用としてエントリファイルに Include を置いてしまうことになる。
func (s *Service) resolveDestination(graph *config.Graph, request EditRequest) (EditRequest, error) {
	if request.DestinationGroup == "" {
		return request, nil
	}
	if request.DestinationPath != "" {
		return EditRequest{}, ErrAmbiguousDestination
	}
	if err := ValidateGroupName(request.DestinationGroup); err != nil {
		return EditRequest{}, err
	}
	declared := false
	for _, name := range s.declaredGroups(graph) {
		if name == request.DestinationGroup {
			declared = true
			break
		}
	}
	if !declared {
		return EditRequest{}, ErrGroupNotDeclared
	}
	name := GroupFileName(path.Base(filepath.ToSlash(request.Path)))
	request.DestinationPath = GroupDirectory(request.DestinationGroup) + "/" + name
	return request, nil
}

// destinationWillBeRead は、move が destination を書き込んだ後に
// OpenSSH がそれを読むかどうかを報告する。
//
// 既に Include graph の中にあるファイルは読まれる。まだそこに無いファイルは、
// 宣言済みグループの Include pattern がそれに match するときに読まれる。graph の glob
// は、そのときのディスクの状態に対して解決されたものであり、この move こそがファイルをそこ
// に置くものである。それについて警告すると、グループへの最初の move すべてに通知
// が付いてしまい、ユーザーがそれをクリックして通り過ぎることを学ぶ、まさにその原因になる。
func (s *Service) destinationWillBeRead(graph *config.Graph, absolute, relative string) bool {
	if _, included := graph.Nodes[absolute]; included {
		return true
	}
	destination := filepath.ToSlash(relative)
	for _, name := range s.declaredGroups(graph) {
		if matched, err := path.Match(GroupIncludePattern(name), destination); err == nil && matched {
			return true
		}
	}
	return false
}

// unreachedConnectionFiles は、解決済み graph 内のどの Include も
// 届かない、connections/配下のすべての.conf ファイルを報告する。
//
// そこにあるファイルは誰にも読まれないが、その間ずっと完全に正しく見える。
// ブロックは parse でき、ホストの綴りも合っていて、`ssh` は単にそれについて一度も
// 聞いたことがないだけである。グループ delete は、destination を与えられなかったとき、
// 意図的にファイルをまさにこの位置に置く。だから、それが報告されるという約束はどこかで
// 守られなければならず、これは既にすべての画面が読んでいる唯一の view である。
//
// 宣言されたグループではないディレクトリも walk される。未宣言で
// あることこそが、その中のファイルを到達不能にしているものだからである。
// presentGroupDirectories は、connections/配下のディレクトリを
// ワークスペース相対でスラッシュ区切りで列挙する。それはグループ名が使う語彙である。
//
// そこに存在することがグループを作るのではない——Include 行が
// そうするのである——そして、まさにそれゆえにこのリストが必要になる。
// その 2 つの違いこそが diagnostics が報告するものである。
func (s *Service) presentGroupDirectories() ([]string, error) {
	root := s.workspace.Root()
	base := filepath.Join(root, ConnectionsDirectory)
	var present []string
	var walk func(directory, prefix string, depth int) error
	walk = func(directory, prefix string, depth int) error {
		if depth > MaxGroupSegments {
			return nil
		}
		entries, err := s.workspace.FileSystem().ReadDir(directory)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if prefix != "" {
				name = prefix + "/" + name
			}
			present = append(present, name)
			if err := walk(filepath.Join(directory, entry.Name()), name, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(base, "", 1); err != nil {
		return nil, err
	}
	sort.Strings(present)
	return present, nil
}

func (s *Service) unreachedConnectionFiles(graph *config.Graph) []Notice {
	root := s.workspace.Root()
	base := filepath.Join(root, ConnectionsDirectory)
	var notices []Notice

	var walk func(directory string, depth int)
	walk = func(directory string, depth int) {
		if depth > MaxGroupSegments {
			return
		}
		entries, err := s.workspace.FileSystem().ReadDir(directory)
		if err != nil {
			return
		}
		for _, entry := range entries {
			path := filepath.Join(directory, entry.Name())
			if entry.IsDir() {
				walk(path, depth+1)
				continue
			}
			if !strings.HasSuffix(entry.Name(), groupFileSuffix) {
				continue
			}
			if _, reached := graph.Nodes[path]; reached {
				continue
			}
			notices = appendNotice(notices, Notice{
				Code: NoticeGroupFileUnreached,
				Path: NewFileRef(root, path).Path,
			})
		}
	}
	walk(base, 0)
	return notices
}

// refuseTakenAlias は、Include graph が届くどこであれ、別の Host
// ブロックが既に宣言している名前への rename を拒否する。
//
// graph は編集の前に解決されたものなので、rename されているブロック
// はまだ古い名前を持っていて、新しい名前と match することはない。
// 既に持っている名前への rename は no-op であり、自分自身と衝突すると
// して拒否されるのではなく通される。
//
// その alias を直接に名指すブロックだけが数えられる。catch-all はすべての alias に
// match しどれも宣言しないので、それを理由に拒否してしまうと、`Host *` で終わるあらゆる設定
// ——それはほとんどの設定である——ですべての rename を拒否することになってしまう。
func refuseTakenAlias(graph *config.Graph, from, to string) error {
	if from == to {
		return nil
	}
	var taken error
	WalkDirectives(graph, func(visit Visit) bool {
		if visit.Block.Kind != config.BlockHost || visit.Block.Header != visit.Index {
			return true
		}
		if declaresExactly(visit.Block.Patterns, to) {
			taken = ErrAliasAlreadyDeclared
			return false
		}
		return true
	})
	return taken
}

// declaredGroups は、解決済みのエントリファイルからグループ宣言を読み出す。
func (s *Service) declaredGroups(graph *config.Graph) []string {
	node := graph.Nodes[s.entryPath]
	if node == nil || node.File == nil {
		return nil
	}
	return DeclaredGroups(node.File)
}

// planMoveHost は、1 個のホストブロックを別のファイルへ移動する。
// 両方の設定ファイルと metadata 文書は 1 個の storage.Request なので、
// move は単一の journal 化された transaction である。何かが stage される前に
// すべての事前条件がチェックされ、どちらかのファイルが一致しなければ何も書き込まれない。
func (s *Service) planMoveHost(graph *config.Graph, request EditRequest) (planned, error) {
	root := s.workspace.Root()
	request, err := s.resolveDestination(graph, request)
	if err != nil {
		return planned{}, err
	}
	sourceAbsolute, err := AbsolutePath(root, request.Path)
	if err != nil {
		return planned{}, err
	}
	destinationAbsolute, err := AbsolutePath(root, request.DestinationPath)
	if err != nil {
		return planned{}, err
	}
	if sourceAbsolute == destinationAbsolute {
		return planned{}, ErrSameFileMove
	}
	if _, err := s.workspace.ResolveForWrite(sourceAbsolute); err != nil {
		return planned{}, err
	}
	if _, err := s.workspace.ResolveForWrite(destinationAbsolute); err != nil {
		return planned{}, err
	}

	destinationDisk, destinationExists, err := s.readFile(destinationAbsolute)
	if err != nil {
		return planned{}, err
	}

	sourceBase := []byte(request.Base)
	destinationBase := []byte(request.DestinationBase)
	// グループを名指した move は destination ファイルを名指していなかった
	// ので、クライアントはそれを読んだことがなく、そのバイト列を渡す
	// こともできなかった。ディスク上のファイルをその空の base と比較する
	// と、既に connection を保持しているグループファイルはすべて、アプリケーション外部で
	// 変更されたものとして報告されてしまう——そのため、グループへの最初の connection は
	// 成功し、それ以降のものはすべて、起きてもいない外部編集についてのメッセージで失敗した。
	//
	// 保証は変わっていない。下にある事前条件は依然としてたった今
	// 読んだものの digest を運び、storage は commit 中にそれを再チェック
	// するので、この読み取りと書き込みの間に変化したファイルは、
	// 依然として transaction 全体を止める。
	if request.DestinationGroup != "" && request.DestinationBase == "" {
		destinationBase = destinationDisk
	}

	sourceFile := config.Parse(sourceBase)
	destinationFile := config.Parse(destinationBase)
	moved, err := MoveHostBlock(sourceFile, destinationFile, request.Alias)
	if err != nil {
		return planned{}, err
	}
	sourceUpdated := sourceFile.Render()
	destinationUpdated := destinationFile.Render()

	sourceDisk, sourceExists, err := s.readFile(sourceAbsolute)
	if err != nil {
		return planned{}, err
	}
	if !bytes.Equal(sourceBase, sourceDisk) {
		return planned{}, &ConflictError{Report: BuildConflictReport(request.Path, sourceBase, sourceDisk, sourceUpdated)}
	}
	if !bytes.Equal(destinationBase, destinationDisk) {
		return planned{}, &ConflictError{
			Report: BuildConflictReport(request.DestinationPath, destinationBase, destinationDisk, destinationUpdated),
		}
	}

	sourcePrecondition := storage.Precondition{}
	if sourceExists {
		sourcePrecondition = storage.Precondition{Exists: true, Digest: storage.Digest(sourceBase)}
	}
	destinationPrecondition := storage.Precondition{}
	if destinationExists {
		destinationPrecondition = storage.Precondition{Exists: true, Digest: storage.Digest(destinationBase)}
	}

	stored, metadataPrecondition, err := s.metadata.Load()
	if err != nil {
		return planned{}, err
	}
	relocated := RenameHostIdentity(stored,
		HostIdentity{Path: request.Path, Alias: request.Alias},
		HostIdentity{Path: request.DestinationPath, Alias: request.Alias},
	)
	metadataChange, err := s.metadata.Change(relocated, metadataPrecondition)
	if err != nil {
		return planned{}, err
	}
	previousMetadata, _, err := s.readFile(metadataChange.Path)
	if err != nil {
		return planned{}, err
	}

	prepared := planned{
		operation: "config.move",
		changes: []storage.Change{
			{Path: sourceAbsolute, Contents: sourceUpdated, Precondition: sourcePrecondition},
			{Path: destinationAbsolute, Contents: destinationUpdated, Precondition: destinationPrecondition},
			metadataChange,
		},
		base: map[string][]byte{
			filepath.Clean(sourceAbsolute):      sourceBase,
			filepath.Clean(destinationAbsolute): destinationBase,
			filepath.Clean(metadataChange.Path): previousMetadata,
		},
		baseline: diagnosticBaseline(graph),
		preview: SavePreview{
			Operation: "config.move",
			Diffs: []FileDiff{
				BuildFileDiff(request.Path, diskOrNil(sourceDisk, sourceExists), sourceUpdated),
				BuildFileDiff(request.DestinationPath, diskOrNil(destinationDisk, destinationExists), destinationUpdated),
				BuildFileDiff(s.displayPath(metadataChange.Path), previousMetadata, metadataChange.Contents),
			},
		},
	}

	if !s.destinationWillBeRead(graph, destinationAbsolute, request.DestinationPath) {
		prepared.preview.Notices = appendNotice(prepared.preview.Notices, Notice{
			Code:   NoticeDestinationNotIncluded,
			Path:   request.DestinationPath,
			Detail: request.Alias,
		})
	}
	if request.DestinationGroup != "" {
		// ディレクトリは、Commit が書き込み path を解決する前に作成される。
		// ここまでたどり着いた plan のためにのみ作成されるので、拒否は
		// 空のディレクトリを後に残さない。
		directory, dirErr := AbsolutePath(root, GroupDirectory(request.DestinationGroup))
		if dirErr != nil {
			return planned{}, dirErr
		}
		prepared.directories = append(prepared.directories, directory)
		prepared.preview.Notices = appendNotice(prepared.preview.Notices, Notice{
			Code:   NoticeGroupDirectoryCreated,
			Path:   GroupDirectory(request.DestinationGroup),
			Detail: request.DestinationGroup,
		})
	}

	// ブロックを移動すると、OpenSSH がそれを読む場所が変わり、OpenSSH は
	// 見つけた最初の値を保持する。何も変わらなかったと仮定するのでは
	// なく、そのブロックが宣言するすべての具体的な alias について、前後の説明を示す。
	pending := map[string][]byte{
		filepath.Clean(sourceAbsolute):      sourceUpdated,
		filepath.Clean(destinationAbsolute): destinationUpdated,
	}
	after, err := s.resolveWith(pending)
	if err != nil {
		return planned{}, err
	}
	for _, alias := range movedAliases(moved) {
		if len(prepared.preview.Effective) >= maxEffectivePreviews {
			break
		}
		prepared.preview.Effective = append(prepared.preview.Effective, DiffEffective(
			ComputeEffective(graph, root, alias),
			ComputeEffective(after, root, alias),
		))
	}
	return prepared, nil
}

func (s *Service) planMetadataEdit(graph *config.Graph, request EditRequest) (planned, error) {
	if request.Metadata == nil {
		return planned{}, ErrUnknownEditKind
	}
	root := s.workspace.Root()
	hosts, _ := ProjectHosts(graph, root)
	identities := make([]HostIdentity, 0, len(hosts))
	for _, host := range hosts {
		if !host.Identity.IsZero() {
			identities = append(identities, host.Identity)
		}
	}
	reconciled, notices := ReconcileMetadata(*request.Metadata, identities)

	_, metadataPrecondition, err := s.metadata.Load()
	if err != nil {
		return planned{}, err
	}
	metadataChange, err := s.metadata.Change(reconciled, metadataPrecondition)
	if err != nil {
		return planned{}, err
	}
	previousMetadata, _, err := s.readFile(metadataChange.Path)
	if err != nil {
		return planned{}, err
	}

	prepared := planned{
		operation: "config." + string(request.Kind),
		changes:   []storage.Change{metadataChange},
		base:      map[string][]byte{filepath.Clean(metadataChange.Path): previousMetadata},
		baseline:  diagnosticBaseline(graph),
		preview: SavePreview{
			Operation: "config." + string(request.Kind),
			Diffs: []FileDiff{BuildFileDiff(
				s.displayPath(metadataChange.Path), previousMetadata, metadataChange.Contents)},
			Notices: notices,
		},
	}
	if request.Kind == EditMetadata {
		return prepared, nil
	}

	// グループの compilation は、生成された設定ファイルと、まだ
	// include されていない場合はエントリファイル内の 1 本の Include 行も書き込む。
	groupsRelative := reconciled.GroupsPath()
	groupsAbsolute, err := AbsolutePath(root, groupsRelative)
	if err != nil {
		return planned{}, err
	}
	if _, err := s.workspace.ResolveForWrite(groupsAbsolute); err != nil {
		return planned{}, err
	}
	previousGroups, groupsExist, err := s.readFile(groupsAbsolute)
	if err != nil {
		return planned{}, err
	}
	entryContents, entryExists, err := s.readFile(s.entryPath)
	if err != nil {
		return planned{}, err
	}
	entryFile := config.Parse(entryContents)

	// 宣言済み集合は、生成領域が既に名指しているものすべてに、metadata
	// が presentation を運んでいるすべてのグループを加えたものである。
	// グループを宣言することが、そもそもそのディレクトリをグループにしているものなので、
	// これで全部である。誰も宣言しなかったディレクトリは、他人のディレクトリのままである。
	declared := declaredGroupSet(entryFile, reconciled)
	regionPlan, err := PlanRegion(entryFile, declared, groupsRelative)
	if err != nil {
		return planned{}, err
	}
	if err := ApplyRegion(entryFile, regionPlan); err != nil {
		return planned{}, err
	}
	entryUpdated := entryFile.Render()

	pending := map[string][]byte{}
	if !bytes.Equal(entryUpdated, entryContents) {
		entryPrecondition := storage.Precondition{}
		if entryExists {
			entryPrecondition = storage.Precondition{Exists: true, Digest: storage.Digest(entryContents)}
		}
		prepared.changes = append(prepared.changes, storage.Change{
			Path: s.entryPath, Contents: entryUpdated, Precondition: entryPrecondition,
		})
		prepared.base[filepath.Clean(s.entryPath)] = entryContents
		prepared.preview.Diffs = append(prepared.preview.Diffs,
			BuildFileDiff(entryFileName, diskOrNil(entryContents, entryExists), entryUpdated))
		pending[filepath.Clean(s.entryPath)] = entryUpdated
	}

	// membership は、入ってきた設定からではなく、生成領域が生み出す設定から読まなければ
	// ならない。生成領域がグループのディレクトリを名指すまでは何もそれを読まないので、
	// この save が宣言しようとしているグループ内のすべてのホストは、
	// そうしなければ見えないままになり、その settings ブロックは空のまま出てきてしまう。
	reachable, err := s.resolveWith(pending)
	if err != nil {
		return planned{}, err
	}
	members, _ := ProjectHosts(reachable, root)
	groupContents, groupNotices := CompileGroups(declared, reconciled, members, dominantEnding(entryFile))
	prepared.preview.Notices = append(prepared.preview.Notices, groupNotices...)

	groupsPrecondition := storage.Precondition{}
	if groupsExist {
		groupsPrecondition = storage.Precondition{Exists: true, Digest: storage.Digest(previousGroups)}
	}
	prepared.changes = append(prepared.changes, storage.Change{
		Path: groupsAbsolute, Contents: groupContents, Precondition: groupsPrecondition,
	})
	prepared.base[filepath.Clean(groupsAbsolute)] = previousGroups
	prepared.preview.Diffs = append(prepared.preview.Diffs,
		BuildFileDiff(groupsRelative, diskOrNil(previousGroups, groupsExist), groupContents))
	pending[filepath.Clean(groupsAbsolute)] = groupContents
	// ディレクトリがまだ存在しない宣言済みグループは、
	// include_no_match 警告を生むだけで他には何も生まないので、ディレクトリは
	// 最初に到着するホストに任せるのではなく、ここで作成される。
	for _, name := range declared {
		absolute, dirErr := AbsolutePath(root, GroupDirectory(name))
		if dirErr != nil {
			return planned{}, dirErr
		}
		prepared.directories = append(prepared.directories, absolute)
	}

	after, err := s.resolveWith(pending)
	if err != nil {
		return planned{}, err
	}
	// 説明すべきホストは、今の設定が持っているものではなく、保存後の
	// 設定が持つことになるものである。グループのファイルは生成領域がそれらを名指すまで読めな
	// いので、そうしなければ、グループと共に到着するホストはここで見えないままになってしまう。
	afterHosts, _ := ProjectHosts(after, root)
	for _, host := range afterHosts {
		if host.Group == "" || host.Identity.IsZero() || len(prepared.preview.Effective) >= maxEffectivePreviews {
			continue
		}
		diff := DiffEffective(
			ComputeEffective(graph, root, host.Identity.Alias),
			ComputeEffective(after, root, host.Identity.Alias),
		)
		if len(diff.Changes) == 0 {
			continue
		}
		prepared.preview.Effective = append(prepared.preview.Effective, diff)
	}
	return prepared, nil
}

func diskOrNil(contents []byte, exists bool) []byte {
	if !exists {
		return nil
	}
	if contents == nil {
		return []byte{}
	}
	return contents
}

// Pending は中断された transaction を列挙し、部分的な書き込みが
// 健全な状態として示されることが決してないようにする。
func (s *Service) Pending() ([]PendingView, error) {
	pending, err := s.manager.Pending()
	if err != nil {
		return nil, err
	}
	views := make([]PendingView, 0, len(pending))
	for _, item := range pending {
		view := PendingView{
			ID:          item.ID,
			Operation:   item.Operation,
			Status:      item.Status,
			StartedAt:   item.StartedAt.UTC().Format(time.RFC3339),
			Committed:   item.Committed,
			CanComplete: item.CanComplete,
		}
		for _, entry := range item.Entries {
			view.Paths = append(view.Paths, s.displayPath(entry.Path))
		}
		views = append(views, view)
	}
	return views, nil
}

// Recover は、中断された transaction を完了させるか元に戻す。どちらの
// 経路も、stage される前に既に validate されていた内容を持つ journal
// を再生するので、意図的に validator を再度実行しない。
func (s *Service) Recover(identifier, action string) error {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	switch action {
	case "complete":
		return s.manager.Complete(identifier)
	case "rollback":
		return s.manager.Rollback(identifier)
	default:
		return ErrUnknownRecoveryAction
	}
}

// History は、完了した transaction と、それらのファイルのうち
// generational backup から復元できるものを列挙する。
func (s *Service) History() ([]HistoryEntry, error) {
	records, err := s.manager.History()
	if err != nil {
		return nil, err
	}
	entries := make([]HistoryEntry, 0, len(records))
	for _, record := range records {
		entry := HistoryEntry{
			ID:        record.ID,
			Operation: record.Operation,
			Status:    record.Status,
			StartedAt: record.StartedAt.UTC().Format(time.RFC3339),
		}
		if !record.FinishedAt.IsZero() {
			entry.FinishedAt = record.FinishedAt.UTC().Format(time.RFC3339)
		}
		for _, path := range record.Paths {
			display := s.displayPath(path)
			entry.Paths = append(entry.Paths, display)
			relative, relativeErr := RelativePath(s.workspace.Root(), path)
			if relativeErr != nil || record.BackupDir == "" {
				continue
			}
			backup := filepath.Join(record.BackupDir, filepath.FromSlash(relative))
			if _, statErr := s.workspace.FileSystem().Lstat(backup); statErr == nil {
				entry.Restorable = append(entry.Restorable, display)
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Restore は、新しい transaction を通じて generational backup を書き
// 戻すので、restore それ自体も journal 化され、validate され、取り消し可能である。
func (s *Service) Restore(identifier, relative string) (SaveResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()

	records, err := s.manager.History()
	if err != nil {
		return SaveResult{}, err
	}
	var record storage.HistoryRecord
	found := false
	for _, candidate := range records {
		if candidate.ID == identifier {
			record, found = candidate, true
		}
	}
	if !found {
		return SaveResult{}, storage.ErrUnknownTransaction
	}
	absolute, err := AbsolutePath(s.workspace.Root(), relative)
	if err != nil {
		return SaveResult{}, err
	}
	// manager を通す。バックアップは ciphertext だからである。ファイルを
	// 直接読むと、封印されたバイト列がユーザーの設定の上に書き込まれてしまう。
	contents, err := s.manager.ReadBackup(filepath.Join(record.BackupDir, filepath.FromSlash(relative)))
	if err != nil {
		return SaveResult{}, err
	}
	current, exists, err := s.readFile(absolute)
	if err != nil {
		return SaveResult{}, err
	}
	precondition := storage.Precondition{}
	if exists {
		precondition = storage.Precondition{Exists: true, Digest: storage.Digest(current)}
	}
	graph, err := s.resolve()
	if err != nil {
		return SaveResult{}, err
	}

	if err := s.metadata.EnsureDirectory(); err != nil {
		return SaveResult{}, err
	}
	s.pendingBase = map[string][]byte{filepath.Clean(absolute): current}
	s.pendingBaseline = diagnosticBaseline(graph)
	defer func() { s.pendingBase, s.pendingBaseline = nil, nil }()

	result, err := s.manager.Commit(storage.Request{
		Operation: "config.restore",
		Changes:   []storage.Change{{Path: absolute, Contents: contents, Precondition: precondition}},
	})
	if err != nil {
		return SaveResult{}, err
	}
	return SaveResult{
		TransactionID: result.ID,
		Written:       []string{relative},
		Preview: SavePreview{
			Operation: "config.restore",
			Diffs:     []FileDiff{BuildFileDiff(relative, diskOrNil(current, exists), contents)},
		},
	}, nil
}

// WorkspaceFiles は、ワークスペース内のすべての設定ファイルを、
// ワークスペース相対の path で列挙する。
//
// これは remote snapshot のために存在する。それは、Include graph を見ることが
// できないまま、何が設定であるかを知らなければならない。ワークスペース
// の外側にあるファイル——Include で到達する /etc/ssh/ssh_config など——
// は除外される。このアプリケーションは ~/.ssh の外側に書き込むことは決してなく、
// 書き込むことを拒否するはずのファイルを運ぶことも決してあってはならない。
func (s *Service) WorkspaceFiles() ([]string, error) {
	graph, err := s.resolver.Resolve(s.entryPath)
	if err != nil {
		return nil, err
	}
	root := s.workspace.Root()
	seen := map[string]bool{}
	var relatives []string
	for _, path := range graph.Order {
		if !s.workspace.Contains(path) {
			continue
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		relative = filepath.ToSlash(relative)
		if seen[relative] {
			continue
		}
		seen[relative] = true
		relatives = append(relatives, relative)
	}
	sort.Strings(relatives)
	return relatives, nil
}
