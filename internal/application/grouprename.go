package application

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"sshc/internal/config"
	"sshc/internal/keys"
	"sshc/internal/storage"
)

var (
	// ErrGroupExists は、既に存在するグループへの名前変更を拒否する。
	// 2 組の設定をマージすることは、このアプリケーションが下さない決定だからだ。
	ErrGroupExists = errors.New("a group of that name already exists")
	// ErrGroupSelfNesting は、グループを自分自身の中へ移動することを拒否する。
	ErrGroupSelfNesting = errors.New("a group cannot be nested inside itself")
)

// NoticeGroupDirectoryLeftover は、名前変更が削除できなかったディレクトリを名指しする。
//
// storage.Move はファイルを移動する。ディレクトリ自体の名前変更には、ダイジェストを持た
// ないものに対する事前条件と、それに見合う巻き戻しの仕組みを持つジャーナルアクションが
// 必要になる。これはグループの機能ではなく、ストレージ層の設計上の決定である。だから
// 名前変更は N 回のファイル移動であり、空になった元のディレクトリはそのまま残る。
// ちょうど、ごみ箱からの復元が既にそのエントリディレクトリを残しているのと同じだ。
const NoticeGroupDirectoryLeftover = "group_directory_leftover"

// RenameGroup は、グループとそれを名指しするすべてのものを 1 つのジャーナル済み
// トランザクションで名前変更する: connections/<old> 配下のすべての connection ファイル、
// keys/<old> 配下のすべての鍵、その鍵ディレクトリを指していたすべての IdentityFile、
// 生成された Include region、コンパイル済み settings ファイル、metadata.json である。
//
// ネストしたグループはその親と共に移動する。グループ名は
// ディレクトリパスであり、親ディレクトリの名前変更は子の名前も変えるからだ。
func (s *Service) RenameGroup(inventory *keys.Inventory, from, to string) (SaveResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	return s.commitGroupPlan(func(graph *config.Graph) (planned, error) {
		return s.planGroupRename(graph, inventory, from, to)
	})
}

// DeleteGroup は、グループの宣言を削除し、その connections を
// 別のグループへ、destination が空ならワークスペースのルートへ再配置する。
//
// 設定ファイルが削除されることは決してない。ごみ箱は鍵のため
// にあり、設定用のごみ箱は存在しない。グループを削除する
// 副作用としてそれを新設するのは、導入するにはこれ以上ないほど悪い場所だろう。
func (s *Service) DeleteGroup(inventory *keys.Inventory, name, destination string) (SaveResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	return s.commitGroupPlan(func(graph *config.Graph) (planned, error) {
		return s.planGroupDelete(graph, inventory, name, destination)
	})
}

// commitGroupPlan は、1 つのグループプランを保存と同じコミット経路に通す。
func (s *Service) commitGroupPlan(plan func(*config.Graph) (planned, error)) (SaveResult, error) {
	graph, err := s.resolve()
	if err != nil {
		return SaveResult{}, err
	}
	prepared, err := plan(graph)
	if err != nil {
		return SaveResult{}, err
	}
	if err := s.metadata.EnsureDirectory(); err != nil {
		return SaveResult{}, err
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

// groupRelocation は、グループ操作が移動する 1 つのファイルである。
type groupRelocation struct {
	from string
	to   string
}

func (s *Service) planGroupRename(graph *config.Graph, inventory *keys.Inventory, from, to string) (planned, error) {
	if err := ValidateGroupName(from); err != nil {
		return planned{}, err
	}
	if err := ValidateGroupName(to); err != nil {
		return planned{}, err
	}
	if from == to {
		return planned{}, ErrKeyRelocateUnchanged
	}
	if strings.HasPrefix(to+"/", from+"/") {
		return planned{}, ErrGroupSelfNesting
	}

	declared := s.declaredGroups(graph)
	renamed := make(map[string]string)
	for _, name := range declared {
		switch {
		case name == from:
			renamed[name] = to
		case strings.HasPrefix(name, from+"/"):
			// ネストしたグループの名前は親の名前を含むので、親の名前
			// 変更はそれも変える。置き去りにすればそのファイルが取り残されてしまう。
			renamed[name] = to + strings.TrimPrefix(name, from)
		case name == to || strings.HasPrefix(name, to+"/"):
			// 2 組の設定をマージすることには明らかに正しい答えがない
			// 決定なので、推測するのではなく拒否する。
			return planned{}, ErrGroupExists
		}
	}
	if len(renamed) == 0 {
		return planned{}, ErrGroupNotDeclared
	}

	next := make([]string, 0, len(declared))
	for _, name := range declared {
		if replacement, ok := renamed[name]; ok {
			next = append(next, replacement)
			continue
		}
		next = append(next, name)
	}
	return s.planGroupLayout(graph, inventory, "config.group_rename", renamed, next, false)
}

func (s *Service) planGroupDelete(graph *config.Graph, inventory *keys.Inventory, name, destination string) (planned, error) {
	if err := ValidateGroupName(name); err != nil {
		return planned{}, err
	}
	if destination != "" {
		if err := ValidateGroupName(destination); err != nil {
			return planned{}, err
		}
		if strings.HasPrefix(destination+"/", name+"/") {
			return planned{}, ErrGroupSelfNesting
		}
	}

	declared := s.declaredGroups(graph)
	removed := make(map[string]bool)
	next := make([]string, 0, len(declared))
	for _, candidate := range declared {
		if candidate == name || strings.HasPrefix(candidate, name+"/") {
			removed[candidate] = true
			continue
		}
		next = append(next, candidate)
	}
	if len(removed) == 0 {
		return planned{}, ErrGroupNotDeclared
	}
	if destination != "" {
		found := false
		for _, candidate := range next {
			if candidate == destination {
				found = true
			}
		}
		if !found {
			return planned{}, ErrGroupNotDeclared
		}
	}

	// グループとその子孫のすべてのファイルは 1 つの destination へ
	// 移動する: 平坦化することが「このグループは無くなる」という
	// ことの意味であり、驚きではなくプレビューで明言される。
	moved := make(map[string]string, len(removed))
	for candidate := range removed {
		moved[candidate] = destination
	}
	return s.planGroupLayout(graph, inventory, "config.group_delete", moved, next, true)
}

// planGroupLayout は、グループの名前変更や削除に必要な 1 つのトランザクションを構築する。
//
// renamed は、影響を受ける各グループ名を、そのファイルの
// 移動先グループへ対応付ける。空の destination はワークスペースの
// ルートを意味する。next は、region がその後に宣言すべきグループ集合である。
func (s *Service) planGroupLayout(
	graph *config.Graph,
	inventory *keys.Inventory,
	operation string,
	renamed map[string]string,
	next []string,
	discardPresentation bool,
) (planned, error) {
	root := s.workspace.Root()
	prepared := planned{
		operation: operation,
		base:      map[string][]byte{},
		baseline:  diagnosticBaseline(graph),
		preview:   SavePreview{Operation: operation},
	}

	connectionMoves, err := s.groupFileMoves(renamed, ConnectionsDirectory, GroupDirectory)
	if err != nil {
		return planned{}, err
	}
	keyMoves, err := s.groupFileMoves(renamed, KeysDirectory, GroupKeyDirectory)
	if err != nil {
		return planned{}, err
	}

	stored, metadataPrecondition, err := s.metadata.Load()
	if err != nil {
		return planned{}, err
	}
	updated := stored
	for _, relocation := range append(append([]groupRelocation{}, connectionMoves...), keyMoves...) {
		absoluteFrom := filepath.Join(root, filepath.FromSlash(relocation.from))
		absoluteTo := filepath.Join(root, filepath.FromSlash(relocation.to))
		if _, statErr := s.workspace.FileSystem().Lstat(absoluteTo); statErr == nil {
			return planned{}, ErrGroupExists
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return planned{}, statErr
		}
		contents, readErr := s.workspace.FileSystem().ReadFile(absoluteFrom)
		if readErr != nil {
			return planned{}, readErr
		}
		digest := storage.Digest(contents)
		keys.Wipe(contents)
		prepared.moves = append(prepared.moves, storage.Move{
			From:         absoluteFrom,
			To:           absoluteTo,
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		directory, dirErr := AbsolutePath(root, path.Dir(relocation.to))
		if dirErr != nil {
			return planned{}, dirErr
		}
		prepared.directories = append(prepared.directories, directory)
	}
	for _, relocation := range connectionMoves {
		// ファイルで宣言されたすべての alias はパスが変わるので、
		// その metadata エントリも identity が変わる。これを同じトランザクションで
		// 行うことが、エントリがユーザーの手作業での再関連付けを要する孤児になるのを防ぐ。
		updated = RelocateHostIdentities(updated, relocation.from, relocation.to)
	}
	updated.Groups = renameGroupMetadata(updated.Groups, renamed, discardPresentation)

	// 移動する鍵は、IdentityFile 行が追従しなければならない鍵で
	// あり、それは鍵の relocation が行うのと同じ書き換えである。
	keyRelocations := make([]keyRelocation, 0, len(keyMoves))
	members := make([]keys.Item, 0, len(keyMoves))
	for _, relocation := range keyMoves {
		item, found := inventory.Find(keys.ItemID(relocation.from))
		if !found {
			continue
		}
		members = append(members, *item)
		keyRelocations = append(keyRelocations, keyRelocation{from: relocation.from, to: relocation.to})
	}
	if blockers := s.keyRelocationBlockers(graph, inventory, members, keyRelocations, "", false); len(blockers) > 0 {
		// 半端にしか適用できない名前変更は丸ごと拒否される: 鍵の
		// relocation が適用するのと同じ規則である。同じ書き換えだからだ。
		return planned{}, &GroupBlockedError{Blockers: blockers}
	}
	changes, _, err := s.rewriteKeyReferences(members, keyRelocations)
	if err != nil {
		return planned{}, err
	}
	for _, change := range changes {
		previous, _, readErr := s.readFile(change.Path)
		if readErr != nil {
			return planned{}, readErr
		}
		prepared.changes = append(prepared.changes, change)
		prepared.base[filepath.Clean(change.Path)] = previous
		prepared.preview.Diffs = append(prepared.preview.Diffs,
			BuildFileDiff(s.displayPath(change.Path), previous, change.Contents))
	}

	entryContents, entryExists, err := s.readFile(s.entryPath)
	if err != nil {
		return planned{}, err
	}
	entryFile := config.Parse(entryContents)
	regionPlan, err := PlanRegion(entryFile, GroupNameOrder(next, groupOrder(updated)), updated.GroupsPath())
	if err != nil {
		return planned{}, err
	}
	if err := ApplyRegion(entryFile, regionPlan); err != nil {
		return planned{}, err
	}
	entryUpdated := entryFile.Render()
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

	// settings ファイルはコメントでグループを名指しし、メンバーを
	// 列挙するので、このトランザクションが生む layout から再生成される。
	pending := map[string][]byte{filepath.Clean(s.entryPath): entryUpdated}
	gone := map[string]bool{}
	for _, move := range prepared.moves {
		pending[filepath.Clean(move.To)] = nil
		gone[filepath.Clean(move.From)] = true
	}
	for _, move := range prepared.moves {
		contents, readErr := s.workspace.FileSystem().ReadFile(move.From)
		if readErr != nil {
			return planned{}, readErr
		}
		pending[filepath.Clean(move.To)] = contents
	}
	after, err := s.resolveOverlay(pending, gone)
	if err != nil {
		return planned{}, err
	}
	hosts, _ := ProjectHosts(after, root)
	groupsRelative := updated.GroupsPath()
	groupsAbsolute, err := AbsolutePath(root, groupsRelative)
	if err != nil {
		return planned{}, err
	}
	previousGroups, groupsExist, err := s.readFile(groupsAbsolute)
	if err != nil {
		return planned{}, err
	}
	groupContents, groupNotices := CompileGroups(next, updated, hosts, dominantEnding(entryFile))
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

	metadataChange, err := s.metadata.Change(updated, metadataPrecondition)
	if err != nil {
		return planned{}, err
	}
	previousMetadata, _, err := s.readFile(metadataChange.Path)
	if err != nil {
		return planned{}, err
	}
	prepared.changes = append(prepared.changes, metadataChange)
	prepared.base[filepath.Clean(metadataChange.Path)] = previousMetadata
	prepared.preview.Diffs = append(prepared.preview.Diffs,
		BuildFileDiff(s.displayPath(metadataChange.Path), previousMetadata, metadataChange.Contents))

	// この操作が空にするディレクトリは、深い方から順に同じトランザクションで一緒に削除される。
	// 何かを保持したままのディレクトリはそのまま残され、明言される:
	// グループのファイルはグループと共に移動するが、何にも宣言されていない
	// ディレクトリは移動しない。どこへ行くべきか誰も知らないからだ。
	sources := make([]string, 0, len(renamed)*2)
	for name := range renamed {
		sources = append(sources, GroupDirectory(name), GroupKeyDirectory(name))
	}
	moving := map[string]bool{}
	for _, relocation := range append(append([]groupRelocation{}, connectionMoves...), keyMoves...) {
		moving[relocation.from] = true
	}
	emptied, left, err := s.emptiedDirectories(sources, moving)
	if err != nil {
		return planned{}, err
	}
	prepared.removeDirectories = append(prepared.removeDirectories, emptied...)
	for _, directory := range left {
		name := strings.TrimPrefix(strings.TrimPrefix(directory, ConnectionsDirectory+"/"), KeysDirectory+"/")
		prepared.preview.Notices = appendNotice(prepared.preview.Notices, Notice{
			Code: NoticeGroupDirectoryLeftover, Detail: name, Path: directory,
		})
	}
	// destination のない削除は、その connections をどの Include も
	// 名指ししない connections/ の直下に置く。それは設計どおりに
	// 動作しているということであり、同時に connection が設定から
	// 外れるということでもある。だからそれは保存の前、ここで
	// 述べられる。何かが解決しなくなってからユーザーが気づくのに任せるのではなく。
	for _, relocation := range connectionMoves {
		if _, inGroup := GroupOfPath(relocation.to); inGroup {
			continue
		}
		prepared.preview.Notices = appendNotice(prepared.preview.Notices, Notice{
			Code: NoticeGroupFileUnreached, Path: relocation.to, Detail: relocation.from,
		})
	}
	return prepared, nil
}

// GroupBlockedError は、グループ操作が拒否した理由を報告する。
// 鍵の relocation が生むのと同じ blocker コードを運ぶ。
// 起こるはずだった書き換えが同じものだからだ。
type GroupBlockedError struct {
	Blockers []string
}

func (e *GroupBlockedError) Error() string { return "group operation blocked" }

// groupFileMoves は、影響を受けるグループディレクトリの
// いずれかの下にあるすべてのファイルと、その移動先を列挙する。
func (s *Service) groupFileMoves(renamed map[string]string, root string, directoryOf func(string) string) ([]groupRelocation, error) {
	names := make([]string, 0, len(renamed))
	for name := range renamed {
		names = append(names, name)
	}
	sort.Strings(names)

	moves := make([]groupRelocation, 0)
	for _, name := range names {
		source := directoryOf(name)
		absolute := filepath.Join(s.workspace.Root(), filepath.FromSlash(source))
		entries, err := s.workspace.FileSystem().ReadDir(absolute)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		destination := renamed[name]
		for _, entry := range entries {
			if entry.IsDir() {
				// ネストしたグループは renamed の中で独自の destination を
				// 持つ別のエントリなので、ここからそのファイルが二重に移動されることはない。
				continue
			}
			// destination がない場合、ファイルはグループの中ではなく
			// 自身のツリーの直下 — connections/ または keys/ — に置かれる。
			// connection にとってそれは何にも読まれないことを意味し、プレビューは今やそれを
			// はっきり述べる。鍵にとってはディレクトリ以外は何も変わらないことを意味する。
			//
			// 両方のルートは意図的に同じに扱う。以前はこれが行っていた
			// ように鍵をワークスペースのルートへ向けると、ディレクトリが
			// "." になり、AbsolutePath はそれをルートだからという理由で
			// 拒否していた。削除全体は "path is outside the ssh directory" で
			// 失敗し、鍵を保持するグループは、置き先を別に名指ししない限り
			// 一切削除できなかった。
			target := root + "/" + entry.Name()
			if destination != "" {
				target = directoryOf(destination) + "/" + entry.Name()
			}
			moves = append(moves, groupRelocation{from: source + "/" + entry.Name(), to: target})
		}
	}
	return moves, nil
}

// renameGroupMetadata は、グループ操作が影響するプレゼンテーション
// エントリを書き換える。
//
// 名前変更は色、note、settings を新しい名前へ運ぶ。別名の下の
// 同じグループだからだ。削除はそれらを破棄する: destination は
// 独自のプレゼンテーションを持つ別のグループであり、削除された
// グループの色で黙って塗り直すのは、誰も求めていない変更になってしまう。
func renameGroupMetadata(groups []GroupMetadata, renamed map[string]string, discard bool) []GroupMetadata {
	updated := make([]GroupMetadata, 0, len(groups))
	for _, group := range groups {
		destination, affected := renamed[group.Name]
		if !affected {
			updated = append(updated, group)
			continue
		}
		if discard || destination == "" {
			continue
		}
		group.Name = destination
		updated = append(updated, group)
	}
	return updated
}

func groupOrder(metadata Metadata) map[string]int {
	order := make(map[string]int, len(metadata.Groups))
	for _, group := range metadata.Groups {
		order[group.Name] = group.Order
	}
	return order
}

// resolveOverlay は、このトランザクションを既に適用したファイル
// システムに対してグラフを解決する。
func (s *Service) resolveOverlay(pending map[string][]byte, gone map[string]bool) (*config.Graph, error) {
	resolver := s.resolver
	resolver.Loader = overlayLoader{base: s.resolver.Loader, pending: pending, gone: gone}
	return resolver.Resolve(s.entryPath)
}

// emptiedDirectories は、このトランザクションがこれらの
// ディレクトリのうちどれを空にし、どれがまだ何かを保持しているかを割り出す。
//
// 削除可能なものは深い順に返る。それはジャーナルが適用する
// 順序であり、機能しうる唯一の順序である: 親は子がすべて
// 無くなって初めて空になる。そもそも存在しないディレクトリはどちらでもない。
func (s *Service) emptiedDirectories(sources []string, moving map[string]bool) (removable, left []string, err error) {
	root := s.workspace.Root()
	// 候補となるのは、この操作が明け渡そうとしているディレクトリ
	// だけである。誰も宣言していないサブディレクトリは、たとえ
	// たまたま空であっても候補ではない。それはこの操作が削除する
	// ものではなく、その上のグループディレクトリを生かし続ける。
	ours := map[string]bool{}
	for _, source := range sources {
		ours[source] = true
	}
	seen := map[string]bool{}
	var visit func(relative string) (bool, error)
	visit = func(relative string) (bool, error) {
		absolute := filepath.Join(root, filepath.FromSlash(relative))
		entries, readErr := s.workspace.FileSystem().ReadDir(absolute)
		if errors.Is(readErr, fs.ErrNotExist) {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
		empties := true
		for _, entry := range entries {
			child := relative + "/" + entry.Name()
			if !entry.IsDir() {
				// このトランザクションが移動させないファイルは、ディレクトリを存続させる。
				if !moving[child] {
					empties = false
				}
				continue
			}
			if !ours[child] {
				empties = false
				continue
			}
			childEmpties, childErr := visit(child)
			if childErr != nil {
				return false, childErr
			}
			if !childEmpties {
				empties = false
			}
		}
		if !empties {
			return false, nil
		}
		if !seen[relative] {
			seen[relative] = true
			// 深い順から: これは子が追加され終えた後に実行される。
			removable = append(removable, relative)
		}
		return true, nil
	}

	sort.Strings(sources)
	for _, source := range sources {
		empties, visitErr := visit(source)
		if visitErr != nil {
			return nil, nil, visitErr
		}
		if !empties {
			absolute := filepath.Join(root, filepath.FromSlash(source))
			if _, statErr := s.workspace.FileSystem().Lstat(absolute); statErr == nil {
				left = append(left, source)
			}
		}
	}
	sort.Strings(left)
	return removable, left, nil
}
