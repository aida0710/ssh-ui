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
	// ErrCannotTouchEntryFile refuses to rename or delete the file ssh reads
	// first. Everything else in the workspace is reached through it, so moving
	// it out of the way would not relocate a configuration, it would end one.
	ErrCannotTouchEntryFile = errors.New("the entry configuration file cannot be renamed or deleted here")
	// ErrDestinationExists refuses a rename onto a file that is already there.
	// Merging two configurations is a decision this application will not make.
	ErrDestinationExists = errors.New("a file already exists at that path")
	// ErrSamePath refuses a rename that goes nowhere.
	ErrSamePath = errors.New("the destination is the file itself")
	// ErrFileNotFound reports that the file named is not there to operate on.
	ErrFileNotFound = errors.New("no such file in the workspace")
	// ErrNotADirectory refuses a directory operation aimed at a file.
	ErrNotADirectory = errors.New("that path is not a directory")
)

// GroupDeclaredError refuses a directory operation on a declared group and says
// which group it is, so the interface can send the user where that operation
// actually lives.
type GroupDeclaredError struct{ Group string }

func (e *GroupDeclaredError) Error() string { return "that directory is a declared group" }

const (
	// NoticeIncludeNoLongerMatches warns that a pattern which used to reach
	// this file will not reach it under its new name. The file is still on
	// disk and ssh will simply stop reading it, which is the kind of silence
	// this application exists to prevent.
	NoticeIncludeNoLongerMatches = "include_no_longer_matches"
	// NoticeIncludeNotRewritten marks an Include that names this file in a
	// form this application will not rewrite — an absolute path, or one that
	// starts with a tilde. Rewriting it would mean guessing what the author
	// meant by it, so it is reported and left exactly as it was.
	NoticeIncludeNotRewritten = "include_not_rewritten"
	// NoticeIncludeNowUnreached warns that a rename has put the file
	// somewhere no Include reaches.
	NoticeIncludeNowUnreached = "include_now_unreached"
	// NoticeDirectoryCreated and NoticeDirectoryRemoved report what a directory
	// operation did, so the preview has something to show: a directory has no
	// contents to diff.
	NoticeDirectoryCreated = "directory_created"
	NoticeDirectoryRemoved = "directory_removed"
)

// hasGlobMetacharacter reports whether a pattern selects by shape rather than
// by name. A pattern that names one file is rewritten when that file moves; a
// pattern that describes a set is left alone, because it was never about this
// file in particular.
func hasGlobMetacharacter(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

// includeEdges returns every Include edge in the graph, in file order, so the
// rewriting below visits each naming file once and deterministically.
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

// RenameFile moves one configuration file and rewrites the Include lines that
// named it, in one journalled transaction.
//
// A file is loaded because something includes it. Moving the file without the
// line that names it would leave a configuration that still parses and quietly
// stops applying, which is the failure this whole application is built to make
// impossible to reach by accident.
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

// planFileDelete removes one configuration file and the Include lines that
// named it.
//
// The removal keeps a generational backup, so it appears in History as
// restorable like every other change. That is the difference between deleting
// a configuration file and purging a key: the key delete is confirmed twice
// and deliberately keeps nothing.
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

// rewrite is one file whose Include lines changed.
type rewrite struct {
	absolute string
	display  string
	previous []byte
	updated  []byte
}

// rewriteIncludes points every literal Include at the file's new path, or
// removes the line when there is no new path.
//
// Only a pattern that resolves to exactly the workspace-relative path being
// moved is touched. An absolute path, a tilde, or a glob is reported and left
// alone: rewriting those would mean deciding what their author meant, and this
// application does not edit bytes it cannot account for.
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

// applyIncludeEdits rewrites or removes the named 1-based lines. Removal walks
// backwards so the earlier indices stay valid.
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

// appendRewrites puts each rewritten file into the transaction with its own
// precondition, so an Include edited outside this application since the graph
// was read stops the whole thing rather than half of it.
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

// patternWouldMatch reports whether a glob that reached the old path also
// reaches the new one, so a rename inside the same directory does not raise a
// warning about a pattern that is still perfectly correct.
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

// anyPatternStillMatches reports whether some Include already reaches the file
// at its new path, so a rename into a directory a glob covers is not reported
// as unreachable.
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

// planDirectoryCreate makes one directory, journalled like everything else.
//
// It does not declare a group. A directory under connections/ that no Include
// names is read by nothing, and the overview says so as group_not_declared —
// which is the honest answer, because declaring one changes the entry file's
// generated region and that belongs to the Groups screen.
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

// planDirectoryDelete removes one empty directory.
//
// Empty only: removing a tree would mean deleting configuration files whose
// Include lines this transaction never looked at, and the files have a delete
// of their own that does look. A directory a generated Include line declares as
// a group is refused outright — that removal moves connections, rewrites the
// region, the group settings and the metadata, and the Groups screen is where
// that operation lives. Two screens calling it would be two places for it to
// drift apart.
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

// declaredGroupAt reports whether this path is a group the entry file declares.
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
