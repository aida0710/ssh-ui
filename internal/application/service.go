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

	"ssh-ui/internal/config"
	"ssh-ui/internal/storage"
)

const (
	// entryFileName is the OpenSSH user configuration file this application
	// treats as the root of the Include graph.
	entryFileName = "config"
	// maxEffectivePreviews bounds how many aliases a group preview explains, so
	// a large configuration cannot turn one preview into an unbounded walk.
	maxEffectivePreviews = 50
)

var (
	ErrUnknownEditKind       = errors.New("unknown edit kind")
	ErrUnknownRecoveryAction = errors.New("unknown recovery action")
	ErrNotEditable           = errors.New("file is not editable through this application")
	// ErrGroupNotDeclared refuses an operation naming a group that no Include
	// line declares. A directory that exists is not a group.
	ErrGroupNotDeclared = errors.New("no generated Include line declares that group")
	// ErrAmbiguousDestination refuses a move that names both a group and a
	// path, because the two can disagree and this application will not pick.
	ErrAmbiguousDestination = errors.New("a move names either a destination group or a destination path")
)

// EditKind names the operations the UI can request.
type EditKind string

const (
	EditHostFields EditKind = "host_fields"
	EditBlockRaw   EditKind = "block_raw"
	EditFileRaw    EditKind = "file_raw"
	EditRename     EditKind = "rename"
	EditGroups     EditKind = "groups"
	EditMetadata   EditKind = "metadata"
	EditMove       EditKind = "move"
	// EditComment sets the comment lines above a Host block. The comment lives
	// in the configuration rather than in metadata, so it survives for anyone
	// reading the file without this application.
	EditComment EditKind = "comment"
	// EditFileRename moves one configuration file and rewrites the Include
	// lines that named it. EditFileDelete removes one and removes those lines.
	// Both are file operations rather than block operations, which is why they
	// are their own kinds rather than a shape of file_raw: file_raw can empty a
	// file but cannot make it stop existing, and a file that is no longer
	// included is a different thing from a file that is empty.
	EditFileRename EditKind = "file_rename"
	EditFileDelete EditKind = "file_delete"
)

// EditRequest is one requested change.
//
// Base carries the exact bytes the client loaded for Path. Every file-targeted
// edit is applied to those bytes and committed with their digest as the
// precondition, so the user always edits what they saw and an external change
// produces a real three-way diff instead of a silent overwrite.
//
// Every line number in Fields is 1-based, matching the line numbers this
// service reports in FormField, Source and DiffLine. The 0-based indices of
// internal/config never cross this boundary in either direction.
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
	// DestinationGroup moves a host into a group by naming the group rather
	// than the file. The destination path is derived from it, so the caller
	// cannot name a group and a path that disagree; sending both is refused.
	DestinationGroup string `json:"destinationGroup,omitempty"`
	// DestinationPath and DestinationBase describe the second file of a move.
	// DestinationBase carries the exact bytes the client loaded for it, so the
	// destination has the same precondition guarantee as the source.
	DestinationPath string `json:"destinationPath,omitempty"`
	DestinationBase string `json:"destinationBase,omitempty"`
}

// SavePreview is exactly what a save would write.
type SavePreview struct {
	Operation string          `json:"operation"`
	Diffs     []FileDiff      `json:"diffs"`
	Effective []EffectiveDiff `json:"effective,omitempty"`
	Notices   []Notice        `json:"notices,omitempty"`
}

// SaveResult reports a committed transaction.
type SaveResult struct {
	TransactionID string      `json:"transactionId"`
	Written       []string    `json:"written"`
	Preview       SavePreview `json:"preview"`
}

// IncludeReference is one Include argument and what it resolved to.
type IncludeReference struct {
	Line      int       `json:"line"`
	Pattern   string    `json:"pattern"`
	Condition string    `json:"condition,omitempty"`
	Matches   []FileRef `json:"matches,omitempty"`
}

// FileNode is one file of the Include graph.
type FileNode struct {
	File     FileRef            `json:"file"`
	Missing  bool               `json:"missing,omitempty"`
	Editable bool               `json:"editable"`
	Loads    int                `json:"loads"`
	Includes []IncludeReference `json:"includes,omitempty"`
}

// FileContents is a whole configuration file for the raw editor.
type FileContents struct {
	File     FileRef `json:"file"`
	Contents string  `json:"contents"`
	Digest   string  `json:"digest"`
	Editable bool    `json:"editable"`
	Exists   bool    `json:"exists"`
}

// PendingView is an interrupted transaction the user must decide about.
type PendingView struct {
	ID          string   `json:"id"`
	Operation   string   `json:"operation"`
	Status      string   `json:"status"`
	StartedAt   string   `json:"startedAt"`
	Committed   int      `json:"committed"`
	Paths       []string `json:"paths"`
	CanComplete bool     `json:"canComplete"`
}

// HistoryEntry is one completed transaction.
type HistoryEntry struct {
	ID         string   `json:"id"`
	Operation  string   `json:"operation"`
	Status     string   `json:"status"`
	StartedAt  string   `json:"startedAt"`
	FinishedAt string   `json:"finishedAt,omitempty"`
	Paths      []string `json:"paths"`
	Restorable []string `json:"restorable,omitempty"`
}

// Overview is everything the Connections tree and Config Explorer need.
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

// HostDetail is everything the host editor needs, including the whole file so
// the client can send it back as the edit base.
type HostDetail struct {
	Form      HostForm     `json:"form"`
	Metadata  HostMetadata `json:"metadata"`
	Effective Effective    `json:"effective"`
	File      FileContents `json:"file"`
}

// Service owns the workspace and the transaction manager. It is the only writer
// in the process: every mutation is serialised by saveMutex, and the manager's
// Validate hook is installed here so no code path can commit without it.
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

// displayPath renders a path for the UI and for error payloads: relative to
// ~/.ssh when the file is inside it, absolute only when an Include points
// outside. Log lines never receive either form.
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

// Overview builds the Connections tree, the Include graph and the metadata.
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

	// What the declaration and the disk say about each other. A directory
	// under connections/ that no Include names is the one that silently does
	// nothing: the files in it are configuration nobody reads.
	// A workspace whose entry file is missing declares no groups, and asking a
	// nil file what it declares is how this first reached production.
	entryNode := graph.Nodes[s.entryPath]
	var groups []GroupView
	if entryNode != nil && entryNode.File != nil {
		present, presentErr := s.presentGroupDirectories()
		if presentErr != nil {
			return Overview{}, presentErr
		}
		var groupNotices []Notice
		groups, groupNotices = BuildGroupsView(entryNode.File, hosts, reconciled, present)
		notices = append(notices, groupNotices...)
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

	// Required contract arrays are never null on the wire: the frontend
	// validates shapes at runtime and an absent array is a contract violation,
	// not an empty list.
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

// HostDetail projects one host block together with its explained values.
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

// FileContents reads one editable file inside the workspace.
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

// planned is one prepared transaction: the exact changes, the base contents the
// validator compares against, and the preview the caller sees.
// directoryCreates and directoryRemovals put the planned directories into the
// shapes the journal takes. Creation is by absolute path already; removal is
// planned in workspace-relative terms, which is the vocabulary the notices and
// the group names use.
// requestFor is the one place a planned transaction becomes a storage request.
//
// There were two, and the group path quietly dropped whatever the save path
// had that it did not: the removals, and then the directory removals a rename
// needs to finish what it started. One function cannot drift from itself.
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

// Both deduplicate. The planners append a destination directory once per file
// that lands in it, which was harmless while directories were created outside
// the journal and is a duplicate path inside it.
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
	// moves and removals travel in the same transaction as the changes, so a
	// file relocation and the configuration that names it land together or not
	// at all. directories are created before Commit resolves its write paths.
	moves    []storage.Move
	removals []storage.Removal
	// directories are created before anything is written and removed after
	// everything else, both inside the transaction: a mkdir or an rmdir outside
	// the journal is a filesystem effect with no recovery record.
	directories       []string
	removeDirectories []string
	base              map[string][]byte
	baseline          map[string]bool
	preview           SavePreview
}

// Preview prepares a transaction and returns its diffs without writing.
func (s *Service) Preview(request EditRequest) (SavePreview, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	prepared, err := s.plan(request)
	if err != nil {
		return SavePreview{}, err
	}
	return prepared.preview, nil
}

// Save prepares the same transaction and commits it.
func (s *Service) Save(request EditRequest) (SaveResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	prepared, err := s.plan(request)
	if err != nil {
		return SaveResult{}, err
	}
	// Commit resolves a write path against real directories, so the ones this
	// transaction needs are created first. Only a planned transaction gets
	// here: a refusal returns above, leaving the disk untouched.
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

	// A comment retires the note for the same host. Both are the same thing
	// written in two places, and the configuration is the one that survives
	// without this application, so the note goes in the same transaction that
	// writes the comment rather than being left to disagree with it.
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

// resolveDestination turns a destination group into the destination path.
//
// The file keeps its own name and changes directory, so a move between groups
// is exactly what it looks like in a shell: the same file, somewhere else. The
// name passes through GroupFileName first, because a group is read by one
// Include pattern and a name that pattern does not match would land the block
// somewhere OpenSSH never looks.
//
// The group must already be declared — creating one is its own operation with
// its own preview, and inferring a group from a move would put an Include in
// the entry file as a side effect of an unrelated request.
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

// destinationWillBeRead reports whether OpenSSH reads the destination once the
// move has written it.
//
// A file already in the Include graph is read. A file that is not there yet is
// read when a declared group's Include pattern matches it: the graph's globs
// were resolved against the disk as it was, and this move is what puts the file
// on it. Warning about those would attach the notice to every first move into a
// group, which is exactly how a user learns to click past it.
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

// unreachedConnectionFiles reports every .conf file under connections/ that no
// Include in the resolved graph reaches.
//
// A file there is read by nobody, and looks entirely correct while it is: the
// blocks parse, the host is spelled right, and `ssh` has simply never heard of
// it. The group delete puts a file in exactly this position on purpose when it
// is given no destination, so the promise that it would be reported has to be
// kept somewhere, and this is the only view every screen already reads.
//
// A directory that is not a declared group is walked too, because being
// undeclared is precisely what makes the files inside it unreachable.
// presentGroupDirectories lists the directories under connections/, workspace
// relative and slash separated, which is the vocabulary a group name uses.
//
// Being there is not what makes one a group — an Include line is — and that is
// exactly why this list is needed: the difference between the two is what the
// diagnostics report.
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

// refuseTakenAlias refuses a rename onto a name another Host block already
// declares, anywhere the Include graph reaches.
//
// The graph is the one resolved before the edit, so the block being renamed
// still carries its old name and cannot match the new one. A rename to the name
// it already has is a no-op and is let through rather than refused for
// colliding with itself.
//
// Only a block that names the alias outright counts. A catch-all matches every
// alias and declares none, so refusing on it would refuse every rename in any
// configuration that ends with `Host *` — which is most of them.
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

// declaredGroups reads the group declaration out of the resolved entry file.
func (s *Service) declaredGroups(graph *config.Graph) []string {
	node := graph.Nodes[s.entryPath]
	if node == nil || node.File == nil {
		return nil
	}
	return DeclaredGroups(node.File)
}

// planMoveHost moves one host block into another file. Both configuration
// files and the metadata document are one storage.Request, so the move is a
// single journalled transaction: every precondition is checked before anything
// is staged, and a mismatch on either file writes nothing.
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
	// A move that named a group did not name a destination file, so the client
	// never read one and could not have supplied its bytes. Comparing the file
	// on disk against that empty base reported every group file that already
	// held a connection as changed outside the application — so the first
	// connection into a group worked and every one after it failed, with a
	// message about an external edit that had not happened.
	//
	// The guarantee is unchanged. The precondition below still carries the
	// digest of what was just read, and storage re-checks it while committing,
	// so a file that changes between this read and the write still stops the
	// whole transaction.
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
		// The directory is created before Commit resolves the write path. It is
		// created only for a plan that got this far, so a refusal leaves no
		// empty directory behind.
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

	// Moving a block changes where OpenSSH reads it, and OpenSSH keeps the
	// first value it finds. Show the before and after explanation for every
	// concrete alias the block declares instead of assuming nothing changed.
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

	// Group compilation also writes the generated configuration file and, when
	// it is not included yet, one Include line in the entry file.
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

	// The declared set is whatever the region already names plus every group the
	// metadata carries presentation for. Declaring a group is what makes its
	// directory a group at all, so this is the whole of it: a directory nobody
	// declared stays a stranger's directory.
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

	// Membership has to be read from the configuration the region produces, not
	// from the one that came in: until the region names a group's directory
	// nothing reads it, so every host in a group this save is declaring would
	// otherwise be invisible and its settings block would come out empty.
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
	// A declared group whose directory does not exist yet produces an
	// include_no_match warning and nothing else, so the directories are created
	// here rather than left for the first host to arrive.
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
	// The hosts to explain are the ones the saved configuration will have, not
	// the ones it has: a group's files are unreadable until the region names
	// them, so a host arriving with its group would otherwise be invisible here.
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

// Pending lists interrupted transactions so a partial write is never presented
// as a healthy state.
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

// Recover finishes or reverts an interrupted transaction. Both paths replay a
// journal whose contents were already validated before they were staged, so
// they deliberately do not run the validator again.
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

// History lists completed transactions and which of their files can be restored
// from the generation backup.
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

// Restore writes a generation backup back through a new transaction, so the
// restore itself is journalled, validated and reversible.
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
	// Through the manager, because a backup is ciphertext: reading the file
	// directly would write the sealed bytes over the user's configuration.
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

// WorkspaceFiles lists every configuration file inside the workspace, by
// workspace-relative path.
//
// It exists for the remote snapshot, which has to know what a configuration is
// without being able to see the Include graph. Files outside the workspace —
// /etc/ssh/ssh_config reached by an Include — are excluded: this application
// never writes outside ~/.ssh, and it must never carry a file it would refuse
// to write.
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
