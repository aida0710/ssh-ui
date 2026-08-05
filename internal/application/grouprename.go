package application

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"ssh-ui/internal/config"
	"ssh-ui/internal/keys"
	"ssh-ui/internal/storage"
)

var (
	// ErrGroupExists refuses a rename onto a group that already exists, because
	// merging two sets of settings is a decision this application will not make.
	ErrGroupExists = errors.New("a group of that name already exists")
	// ErrGroupSelfNesting refuses moving a group inside itself.
	ErrGroupSelfNesting = errors.New("a group cannot be nested inside itself")
)

// NoticeGroupDirectoryLeftover names a directory a rename emptied.
//
// storage.Move moves files. Renaming the directory itself would need a journal
// action with a precondition for a thing that has no digest and a rollback
// story to match, which is a storage-layer design decision and not a group
// feature. So a rename is N file moves and the empty source directory stays,
// exactly as a restore from the trash already leaves its entry directory.
const NoticeGroupDirectoryLeftover = "group_directory_leftover"

// RenameGroup renames a group and everything that names it, in one journalled
// transaction: every connection file under connections/<old>, every key under
// keys/<old>, every IdentityFile that pointed into that key directory, the
// generated Include region, the compiled settings file and metadata.json.
//
// Nested groups travel with their parent, because a group name is a directory
// path and renaming the parent directory renames the child's too.
func (s *Service) RenameGroup(inventory *keys.Inventory, from, to string) (SaveResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	return s.commitGroupPlan(func(graph *config.Graph) (planned, error) {
		return s.planGroupRename(graph, inventory, from, to)
	})
}

// DeleteGroup removes a group's declaration and relocates its connections into
// another group, or to the workspace root when destination is empty.
//
// No configuration file is ever deleted. The trash is for keys; there is no
// configuration trash, and inventing one as a side effect of removing a group
// would be the worst possible place to introduce it.
func (s *Service) DeleteGroup(inventory *keys.Inventory, name, destination string) (SaveResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	return s.commitGroupPlan(func(graph *config.Graph) (planned, error) {
		return s.planGroupDelete(graph, inventory, name, destination)
	})
}

// commitGroupPlan runs one group plan through the same commit path a save uses.
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
	for _, directory := range prepared.directories {
		if err := s.workspace.EnsureDirectory(directory); err != nil {
			return SaveResult{}, err
		}
	}

	s.pendingBase = prepared.base
	s.pendingBaseline = prepared.baseline
	defer func() { s.pendingBase, s.pendingBaseline = nil, nil }()

	result, err := s.manager.Commit(storage.Request{
		Operation: prepared.operation,
		Changes:   prepared.changes,
		Moves:     prepared.moves,
	})
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

// groupRelocation is one file a group operation moves.
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
			// A nested group's name contains its parent's, so renaming the
			// parent renames it too. Leaving it behind would strand its files.
			renamed[name] = to + strings.TrimPrefix(name, from)
		case name == to || strings.HasPrefix(name, to+"/"):
			// Merging two sets of settings is a decision with no obviously
			// right answer, so it is refused rather than guessed.
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

	// Every file in the group and its descendants moves to one destination:
	// flattening is what "this group is gone" means, and it is stated in the
	// preview rather than being a surprise.
	moved := make(map[string]string, len(removed))
	for candidate := range removed {
		moved[candidate] = destination
	}
	return s.planGroupLayout(graph, inventory, "config.group_delete", moved, next, true)
}

// planGroupLayout builds the one transaction a group rename or delete needs.
//
// renamed maps each affected group name to the group its files move into; an
// empty destination means the workspace root. next is the group set the region
// must declare afterwards.
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
		// Every alias declared in the file changes path, so its metadata entry
		// changes identity. Doing it in this transaction is what stops the
		// entry becoming an orphan the user has to re-associate by hand.
		updated = RelocateHostIdentities(updated, relocation.from, relocation.to)
	}
	updated.Groups = renameGroupMetadata(updated.Groups, renamed, discardPresentation)

	// A key that moves is a key whose IdentityFile lines have to follow, and
	// that is the same rewrite a key relocation performs.
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
		// A rename that would half-apply is refused entirely: the same rule a
		// key relocation applies, because it is the same rewrite.
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

	// The settings file names the group in a comment and lists its members, so
	// it is regenerated from the layout this transaction produces.
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

	for name := range renamed {
		prepared.preview.Notices = appendNotice(prepared.preview.Notices, Notice{
			Code: NoticeGroupDirectoryLeftover, Detail: name, Path: GroupDirectory(name),
		})
	}
	// A delete with no destination lands its connections directly under
	// connections/, which no Include names. That is the operation working as
	// designed, and it is also a connection leaving the configuration, so it is
	// said here — before the save — rather than being left for the user to
	// notice when something stops resolving.
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

// GroupBlockedError reports the reasons a group operation refused. It carries
// the same blocker codes a key relocation produces, because it is the same
// rewrite that would have had to happen.
type GroupBlockedError struct {
	Blockers []string
}

func (e *GroupBlockedError) Error() string { return "group operation blocked" }

// groupFileMoves lists every file below one of the affected group directories
// and where it goes.
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
				// A nested group is a separate entry in renamed with its own
				// destination, so its files are not moved twice from here.
				continue
			}
			// With no destination the file lands directly under its own tree —
			// connections/ or keys/ — rather than in a group. For a connection
			// that means nothing reads it, which the preview now says outright.
			// For a key it means nothing has changed except its directory.
			//
			// Both roots are treated the same on purpose. Aiming a key at the
			// workspace root instead, as this did, gave it the directory ".",
			// which AbsolutePath refuses because it is the root; the whole
			// delete then failed with "path is outside the ssh directory", and
			// a group holding a key could not be deleted at all without naming
			// somewhere else to put it.
			target := root + "/" + entry.Name()
			if destination != "" {
				target = directoryOf(destination) + "/" + entry.Name()
			}
			moves = append(moves, groupRelocation{from: source + "/" + entry.Name(), to: target})
		}
	}
	return moves, nil
}

// renameGroupMetadata rewrites the presentation entries a group operation
// affects.
//
// A rename carries the colour, note and settings to the new name, because it is
// the same group under another name. A delete discards them: the destination is
// a different group with presentation of its own, and silently repainting it in
// the deleted group's colour would be a change nobody asked for.
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

// resolveOverlay resolves the graph against a filesystem that has already had
// this transaction applied.
func (s *Service) resolveOverlay(pending map[string][]byte, gone map[string]bool) (*config.Graph, error) {
	resolver := s.resolver
	resolver.Loader = overlayLoader{base: s.resolver.Loader, pending: pending, gone: gone}
	return resolver.Resolve(s.entryPath)
}
