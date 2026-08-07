package application

import (
	"bytes"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"sshc/internal/config"
	"sshc/internal/storage"
)

var (
	// ErrCannotTouchEntryFile は、ssh が最初に読むファイルの
	// 名前変更や削除を拒否する。ワークスペースの他のすべてはそれを経由して
	// 到達するので、それをどければ設定を移動させたことにはならず、終わらせることになる。
	ErrCannotTouchEntryFile = errors.New("the entry configuration file cannot be renamed or deleted here")
	// ErrDestinationExists は既に存在するファイルへの名前変更を拒否する。
	// 2 つの設定をマージすることは、このアプリケーションが下さない決定である。
	ErrDestinationExists = errors.New("a file already exists at that path")
	// ErrSamePath は、どこへも行かない名前変更を拒否する。
	ErrSamePath = errors.New("the destination is the file itself")
	// ErrFileNotFound は、指定されたファイルが操作対象として存在しないことを報告する。
	ErrFileNotFound = errors.New("no such file in the workspace")
	// ErrNotADirectory は、ファイルに向けたディレクトリ操作を拒否する。
	ErrNotADirectory = errors.New("that path is not a directory")
)

// GroupDeclaredError は、宣言済みグループへのディレクトリ操作を
// 拒否し、それがどのグループかを伝える。インターフェースがその
// 操作の本来の場所へユーザーを送れるようにするためである。
type GroupDeclaredError struct{ Group string }

func (e *GroupDeclaredError) Error() string { return "that directory is a declared group" }

const (
	// NoticeIncludeNoLongerMatches は、これまでこのファイルに
	// 届いていたパターンが、新しい名前ではもう届かなくなることを
	// 警告する。ファイルはディスク上に残るが、ssh は単に読むのを
	// やめてしまう。これはこのアプリケーションが防ぐために存在する種類の沈黙である。
	NoticeIncludeNoLongerMatches = "include_no_longer_matches"
	// NoticeIncludeNotRewritten は、このアプリケーションが書き換え
	// ない形式でこのファイルを名指しする Include に印を付ける —
	// 絶対パス、あるいはチルダで始まるものである。書き換えるとしたら
	// 作者の意図を推測することになるので、報告した上でそのまま残す。
	NoticeIncludeNotRewritten = "include_not_rewritten"
	// NoticeIncludeNowUnreached は、名前変更によってファイルが
	// どの Include も届かない場所に置かれたことを警告する。
	NoticeIncludeNowUnreached = "include_now_unreached"
	// NoticeDirectoryCreated と NoticeDirectoryRemoved は、
	// ディレクトリ操作が何を行ったかを報告する。ディレクトリには
	// diff すべき中身がないので、プレビューに表示するものが必要だからだ。
	NoticeDirectoryCreated = "directory_created"
	NoticeDirectoryRemoved = "directory_removed"
)

// hasGlobMetacharacter は、パターンが名前ではなく形で選択して
// いるかどうかを報告する。1 つのファイルを名指しするパターンは
// そのファイルが移動すると書き換えられる。集合を表すパターンは
// そのまま残される。もともとこの特定のファイルについてのものではなかったからだ。
func hasGlobMetacharacter(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

// includeEdges はグラフ中のすべての Include エッジをファイル順で
// 返す。これにより後段の書き換えが、名指しする各ファイルを一度だけ、決定的に訪れる。
func includeEdges(graph *config.Graph) []config.Edge {
	var edges []config.Edge
	for _, path := range graph.Order {
		node, ok := graph.Nodes[path]
		if !ok {
			continue
		}
		edges = append(edges, node.Includes...)
	}
	return edges
}

// RenameFile は 1 つの設定ファイルを移動し、それを名指ししていた
// Include 行を 1 つのジャーナル済みトランザクションで書き換える。
//
// ファイルが読み込まれるのは、何かがそれを include しているから
// である。それを名指しする行なしにファイルを移動すれば、構文的には
// 通るのに黙って適用されなくなる設定が残る。これはこの
// アプリケーション全体が、うっかり起こせないよう作られている種類の失敗である。
func (s *Service) planFileRename(graph *config.Graph, request EditRequest) (planned, error) {
	source, err := AbsolutePath(s.workspace.Root(), request.Path)
	if err != nil {
		return planned{}, err
	}
	destination, err := AbsolutePath(s.workspace.Root(), request.DestinationPath)
	if err != nil {
		return planned{}, err
	}
	if filepath.Clean(source) == filepath.Clean(destination) {
		return planned{}, ErrSamePath
	}
	if filepath.Clean(source) == filepath.Clean(graph.Root) {
		return planned{}, ErrCannotTouchEntryFile
	}
	if _, err := s.workspace.ResolveForWrite(source); err != nil {
		return planned{}, err
	}
	if _, exists, err := s.readFile(destination); err != nil {
		return planned{}, err
	} else if exists {
		return planned{}, ErrDestinationExists
	}

	current, exists, err := s.readFile(source)
	if err != nil {
		return planned{}, err
	}
	if !exists {
		return planned{}, ErrFileNotFound
	}
	if !bytes.Equal(current, []byte(request.Base)) {
		return planned{}, &ConflictError{
			Report: BuildConflictReport(request.Path, []byte(request.Base), current, current),
		}
	}

	prepared := planned{
		operation: "config." + string(EditFileRename),
		moves: []storage.Move{{
			From:         source,
			To:           destination,
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(current)},
		}},
		directories: []string{filepath.Dir(destination)},
		base:        map[string][]byte{},
		baseline:    diagnosticBaseline(graph),
		preview: SavePreview{
			Operation: "config." + string(EditFileRename),
			Diffs: []FileDiff{
				BuildFileDiff(request.Path, current, nil),
				BuildFileDiff(request.DestinationPath, nil, current),
			},
		},
	}

	rewritten, notices, err := s.rewriteIncludes(graph, source, request.Path, request.DestinationPath)
	if err != nil {
		return planned{}, err
	}
	prepared.preview.Notices = notices
	if err := s.appendRewrites(&prepared, rewritten); err != nil {
		return planned{}, err
	}
	if len(rewritten) == 0 && !anyPatternStillMatches(graph, s.workspace.Root(), source, request.DestinationPath) {
		prepared.preview.Notices = append(prepared.preview.Notices,
			Notice{Code: NoticeIncludeNowUnreached, Path: request.DestinationPath})
	}
	return prepared, nil
}

// planFileDelete は 1 つの設定ファイルと、それを名指ししていた
// Include 行を削除する。
//
// この削除は世代バックアップを保つので、他のすべての変更と
// 同じく History で復元可能として現れる。それが設定ファイルの
// 削除と鍵の purge との違いである。鍵の削除は 2 回確認され、
// 意図的に何も残さない。
func (s *Service) planFileDelete(graph *config.Graph, request EditRequest) (planned, error) {
	target, err := AbsolutePath(s.workspace.Root(), request.Path)
	if err != nil {
		return planned{}, err
	}
	if filepath.Clean(target) == filepath.Clean(graph.Root) {
		return planned{}, ErrCannotTouchEntryFile
	}
	if _, err := s.workspace.ResolveForWrite(target); err != nil {
		return planned{}, err
	}
	current, exists, err := s.readFile(target)
	if err != nil {
		return planned{}, err
	}
	if !exists {
		return planned{}, ErrFileNotFound
	}
	if !bytes.Equal(current, []byte(request.Base)) {
		return planned{}, &ConflictError{
			Report: BuildConflictReport(request.Path, []byte(request.Base), current, current),
		}
	}

	prepared := planned{
		operation: "config." + string(EditFileDelete),
		removals: []storage.Removal{{
			Path:         target,
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(current)},
			Backup:       true,
		}},
		base:     map[string][]byte{},
		baseline: diagnosticBaseline(graph),
		preview: SavePreview{
			Operation: "config." + string(EditFileDelete),
			Diffs:     []FileDiff{BuildFileDiff(request.Path, current, nil)},
		},
	}

	rewritten, notices, err := s.rewriteIncludes(graph, target, request.Path, "")
	if err != nil {
		return planned{}, err
	}
	prepared.preview.Notices = notices
	if err := s.appendRewrites(&prepared, rewritten); err != nil {
		return planned{}, err
	}
	return prepared, nil
}

// rewrite は Include 行が変わった 1 つのファイルである。
type rewrite struct {
	absolute string
	display  string
	previous []byte
	updated  []byte
}

// rewriteIncludes は、すべてのリテラルな Include をファイルの
// 新しいパスへ向け直す。新しいパスがない場合は行を削除する。
//
// 移動対象のワークスペース相対パスにちょうど解決するパターンだけが
// 変更される。絶対パス、チルダ、glob は報告した上でそのまま
// 残される。それらを書き換えるとしたら作者の意図を決めつけることに
// なり、このアプリケーションは説明のつかないバイトは編集しない。
func (s *Service) rewriteIncludes(
	graph *config.Graph, absolute, from, to string,
) ([]rewrite, []Notice, error) {
	var notices []Notice
	edited := map[string][]int{}
	for _, edge := range includeEdges(graph) {
		if !matchesTarget(edge, absolute) {
			continue
		}
		if hasGlobMetacharacter(edge.Pattern) {
			if to != "" && patternWouldMatch(edge, s.workspace.Root(), to) {
				continue
			}
			if to != "" {
				notices = append(notices, Notice{
					Code: NoticeIncludeNoLongerMatches,
					Path: s.displayPath(edge.FromPath), Line: edge.Line, Detail: edge.Pattern,
				})
			}
			continue
		}
		if filepath.ToSlash(edge.Pattern) != from {
			notices = append(notices, Notice{
				Code: NoticeIncludeNotRewritten,
				Path: s.displayPath(edge.FromPath), Line: edge.Line, Detail: edge.Pattern,
			})
			continue
		}
		edited[edge.FromPath] = append(edited[edge.FromPath], edge.Line)
	}

	var rewrites []rewrite
	for _, path := range graph.Order {
		lines, ok := edited[path]
		if !ok {
			continue
		}
		previous, exists, err := s.readFile(path)
		if err != nil {
			return nil, nil, err
		}
		if !exists {
			continue
		}
		file := config.Parse(previous)
		updated, err := applyIncludeEdits(file, lines, to)
		if err != nil {
			return nil, nil, err
		}
		rewrites = append(rewrites, rewrite{
			absolute: path, display: s.displayPath(path), previous: previous, updated: updated,
		})
	}
	return rewrites, notices, nil
}

// applyIncludeEdits は指定された 1 始まりの行を書き換えるか削除する。
// 削除は後ろから前へ進むので、前の方のインデックスが有効なまま保たれる。
func applyIncludeEdits(file *config.File, lines []int, to string) ([]byte, error) {
	sorted := append([]int(nil), lines...)
	for index := 0; index < len(sorted); index++ {
		for other := index + 1; other < len(sorted); other++ {
			if sorted[other] > sorted[index] {
				sorted[index], sorted[other] = sorted[other], sorted[index]
			}
		}
	}
	for _, line := range sorted {
		position := line - 1
		if position < 0 || position >= len(file.Lines) {
			continue
		}
		if to == "" {
			file.Lines = append(file.Lines[:position], file.Lines[position+1:]...)
			continue
		}
		replacement, err := buildLine(
			file.Lines[position].Indent, file.Lines[position].Keyword,
			[]string{to}, file.Lines[position].Ending,
		)
		if err != nil {
			return nil, err
		}
		file.Lines[position] = replacement
	}
	return file.Render(), nil
}

// appendRewrites は、書き換えた各ファイルを固有の事前条件と
// ともにトランザクションへ入れる。グラフを読んだ後にこのアプリケーションの
// 外で Include が編集されていた場合、全体が止まるのであって、半端に終わることはない。
func (s *Service) appendRewrites(prepared *planned, rewrites []rewrite) error {
	for _, item := range rewrites {
		prepared.changes = append(prepared.changes, storage.Change{
			Path:         item.absolute,
			Contents:     item.updated,
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(item.previous)},
		})
		prepared.base[filepath.Clean(item.absolute)] = item.previous
		prepared.preview.Diffs = append(prepared.preview.Diffs,
			BuildFileDiff(item.display, item.previous, item.updated))
	}
	return nil
}

func matchesTarget(edge config.Edge, absolute string) bool {
	for _, match := range edge.Matches {
		if filepath.Clean(match) == filepath.Clean(absolute) {
			return true
		}
	}
	return false
}

// patternWouldMatch は、旧パスに届いていた glob が新しいパスにも
// 届くかどうかを報告する。同じディレクトリ内での名前変更が、
// 依然として完全に正しいパターンについて警告を出さないようにするためである。
func patternWouldMatch(edge config.Edge, root, to string) bool {
	expanded := edge.Expanded
	if expanded == "" {
		expanded = edge.Pattern
	}
	candidate := filepath.Join(root, filepath.FromSlash(to))
	matched, err := filepath.Match(filepath.Clean(expanded), filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return matched
}

// anyPatternStillMatches は、いずれかの Include が新しいパスの
// ファイルに既に届いているかどうかを報告する。glob が
// カバーするディレクトリへの名前変更が、到達不能として報告されないようにするためである。
func anyPatternStillMatches(graph *config.Graph, root, absolute, to string) bool {
	for _, edge := range includeEdges(graph) {
		if !matchesTarget(edge, absolute) {
			continue
		}
		if patternWouldMatch(edge, root, to) {
			return true
		}
	}
	return false
}

// planDirectoryCreate は、他のすべてと同様にジャーナル記録しつつ 1 つのディレクトリを作る。
//
// グループを宣言することはしない。どの Include も名指ししない
// connections/ 配下のディレクトリは何にも読まれず、overview は
// それを group_not_declared として正直に伝える。宣言すると
// エントリファイルの生成領域が変わり、それは Groups 画面の領分だからである。
func (s *Service) planDirectoryCreate(graph *config.Graph, request EditRequest) (planned, error) {
	target, err := AbsolutePath(s.workspace.Root(), request.Path)
	if err != nil {
		return planned{}, err
	}
	if _, statErr := s.workspace.FileSystem().Lstat(target); statErr == nil {
		return planned{}, ErrDestinationExists
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return planned{}, statErr
	}
	return planned{
		operation:   "config." + string(EditDirectoryCreate),
		directories: []string{target},
		base:        map[string][]byte{},
		baseline:    diagnosticBaseline(graph),
		preview: SavePreview{
			Operation: "config." + string(EditDirectoryCreate),
			Notices:   []Notice{{Code: NoticeDirectoryCreated, Path: request.Path}},
		},
	}, nil
}

// planDirectoryDelete は空のディレクトリを 1 つ削除する。
//
// 空のときだけ。ツリーごと削除するとしたら、このトランザクションが
// 見ていない Include 行を持つ設定ファイルまで削除することになる。
// そうしたファイルには、それを見る専用の削除がある。生成された
// Include 行がグループとして宣言しているディレクトリは端から
// 拒否される。その削除は connections を移動させ、region、
// グループ設定、metadata を書き換える操作であり、それは Groups
// 画面の領分である。2 つの画面がそれを呼ぶとしたら、食い違う場所が 2 つできることになる。
func (s *Service) planDirectoryDelete(graph *config.Graph, request EditRequest) (planned, error) {
	target, err := AbsolutePath(s.workspace.Root(), request.Path)
	if err != nil {
		return planned{}, err
	}
	info, statErr := s.workspace.FileSystem().Lstat(target)
	if errors.Is(statErr, fs.ErrNotExist) {
		return planned{}, ErrFileNotFound
	}
	if statErr != nil {
		return planned{}, statErr
	}
	if !info.IsDir() {
		return planned{}, ErrNotADirectory
	}
	if name, declared := s.declaredGroupAt(graph, request.Path); declared {
		return planned{}, &GroupDeclaredError{Group: name}
	}
	return planned{
		operation:         "config." + string(EditDirectoryDelete),
		removeDirectories: []string{filepath.ToSlash(request.Path)},
		base:              map[string][]byte{},
		baseline:          diagnosticBaseline(graph),
		preview: SavePreview{
			Operation: "config." + string(EditDirectoryDelete),
			Notices:   []Notice{{Code: NoticeDirectoryRemoved, Path: request.Path}},
		},
	}, nil
}

// declaredGroupAt は、このパスがエントリファイルの宣言するグループかどうかを報告する。
func (s *Service) declaredGroupAt(graph *config.Graph, relative string) (string, bool) {
	node := graph.Nodes[s.entryPath]
	if node == nil || node.File == nil {
		return "", false
	}
	cleaned := filepath.ToSlash(filepath.Clean(relative))
	for _, name := range DeclaredGroups(node.File) {
		if GroupDirectory(name) == cleaned || GroupKeyDirectory(name) == cleaned {
			return name, true
		}
	}
	return "", false
}
