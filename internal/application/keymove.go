package application

import (
	"errors"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"sshc/internal/config"
	"sshc/internal/keys"
	"sshc/internal/storage"
)

var (
	// ErrKeyRelocateNotSupported refuses an entry that is not a key, and half
	// of a key pair.
	ErrKeyRelocateNotSupported = errors.New("only a private key, or a public key with no private key beside it, can be relocated")
	// ErrKeyRelocateUnchanged refuses a request that would move nothing.
	ErrKeyRelocateUnchanged = errors.New("the key already has that name in that group")
	// ErrKeyRelocateBlocked refuses a relocation that would leave a reference
	// this application cannot rewrite.
	ErrKeyRelocateBlocked = errors.New("relocating this key would leave a reference behind")
	// ErrKeyReferenceMoved reports a configuration file that changed while the
	// relocation was being prepared.
	ErrKeyReferenceMoved = errors.New("a configuration file changed while the relocation was being prepared")
)

// Blocker codes are a stable identifier, ':' and the detail it names.
const (
	BlockerKeyTargetOccupied    = "key_destination_occupied"
	BlockerKeyUnresolved        = "key_reference_unresolved"
	BlockerKeyReferenceExternal = "key_reference_outside_workspace"
	BlockerKeyGroupNotDeclared  = "key_group_not_declared"
	BlockerKeyDestinationRead   = "key_destination_is_config"
	BlockerKeyStateDirectory    = "key_in_state_directory"
)

// NoteKeychainEntryStale reports that a Keychain entry, if the user made one,
// still names the key under the path it had before.
const NoteKeychainEntryStale = "keychain_entry_stale"

// KeyRelocateRequest changes a key's name, its group, or both.
//
// A nil field means "leave this as it is", which is what lets one operation
// serve a rename, a move between groups, and both at once. Group is a pointer
// rather than a string because "" is a real destination: the root of ~/.ssh,
// where an ungrouped key lives.
type KeyRelocateRequest struct {
	KeyID   string
	NewName *string
	Group   *string
}

// RelocatedKeyFile is one file the relocation moved, by workspace-relative path.
type RelocatedKeyFile struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// RewrittenKeyReference is one configuration directive the relocation updated.
type RewrittenKeyReference struct {
	Directive  string `json:"directive"`
	ConfigPath string `json:"configPath"`
	Line       int    `json:"line"`
	From       string `json:"from"`
	To         string `json:"to"`
}

// KeyRelocateResult is what the relocation did, or what stopped it.
type KeyRelocateResult struct {
	ID            string                  `json:"id"`
	RelativePath  string                  `json:"relativePath"`
	Group         string                  `json:"group"`
	Files         []RelocatedKeyFile      `json:"files"`
	References    []RewrittenKeyReference `json:"references"`
	Skipped       []string                `json:"skipped"`
	Notes         []string                `json:"notes"`
	Blockers      []string                `json:"blockers"`
	TransactionID string                  `json:"transactionId"`
	Preview       SavePreview             `json:"preview"`
}

// ValidateDeclaredGroup reports whether a group both parses as a name and is
// declared by the entry file's generated region.
//
// It exists so another package can ask what a group is without importing this
// one's whole use-case layer, and without deciding for itself: the key vault
// generates into a group directory only when a line in ~/.ssh/config says that
// directory is a group.
func (s *Service) ValidateDeclaredGroup(name string) error {
	if err := ValidateGroupName(name); err != nil {
		return err
	}
	graph, err := s.resolve()
	if err != nil {
		return err
	}
	for _, declared := range s.declaredGroups(graph) {
		if declared == name {
			return nil
		}
	}
	return ErrGroupNotDeclared
}

// keyRelocation is one planned move of one file.
type keyRelocation struct {
	from string
	to   string
}

// RelocateKey moves a key and rewrites every configuration directive that names
// it, in one journalled transaction committed through the configuration
// manager.
//
// The manager matters. The key vault has its own, deliberately without the
// configuration validator, because it writes private keys and a JSON manifest
// that would be refused as syntax errors. A relocation is the inverse case: its
// dangerous half is a configuration rewrite, and it must be re-parsed and
// re-resolved before a byte lands. The key files travel as storage.Move, which
// the validator never parses, so both halves get the treatment they need.
//
// It refuses rather than guesses. A directive whose path cannot be resolved
// might be this key; a configuration file outside ~/.ssh cannot be rewritten at
// all; a destination an Include glob would read would turn a private key into
// configuration. Each of those blocks the whole transaction and is reported.
func (s *Service) RelocateKey(inventory *keys.Inventory, request KeyRelocateRequest) (KeyRelocateResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()

	prepared, result, err := s.planKeyRelocation(inventory, request)
	if err != nil {
		return result, err
	}
	for _, directory := range prepared.directories {
		if err := s.workspace.EnsureDirectory(directory); err != nil {
			return KeyRelocateResult{}, err
		}
	}

	s.pendingBase = prepared.base
	s.pendingBaseline = prepared.baseline
	defer func() { s.pendingBase, s.pendingBaseline = nil, nil }()

	committed, err := s.manager.Commit(storage.Request{
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
		return KeyRelocateResult{}, &ConflictError{Report: BuildConflictReport(
			s.displayPath(cleaned), prepared.base[cleaned], conflict.Current, edited,
		)}
	}
	if err != nil {
		return KeyRelocateResult{}, err
	}
	result.TransactionID = committed.ID
	return result, nil
}

// PreviewKeyRelocation prepares the same transaction and returns what it would
// do without writing anything.
func (s *Service) PreviewKeyRelocation(inventory *keys.Inventory, request KeyRelocateRequest) (KeyRelocateResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	_, result, err := s.planKeyRelocation(inventory, request)
	return result, err
}

func (s *Service) planKeyRelocation(inventory *keys.Inventory, request KeyRelocateRequest) (planned, KeyRelocateResult, error) {
	graph, err := s.resolve()
	if err != nil {
		return planned{}, KeyRelocateResult{}, err
	}
	item, ok := inventory.Find(request.KeyID)
	if !ok {
		return planned{}, KeyRelocateResult{}, keys.ErrUnknownKey
	}
	members, skipped, err := keyRelocationMembers(inventory, item)
	if err != nil {
		return planned{}, KeyRelocateResult{}, err
	}

	stem := keyStem(item)
	newStem := stem
	if request.NewName != nil {
		newStem = *request.NewName
		if err := keys.ValidateFileName(newStem); err != nil {
			return planned{}, KeyRelocateResult{}, err
		}
	}
	group, _ := GroupOfKeyPath(item.RelativePath)
	newGroup := group
	if request.Group != nil {
		newGroup = *request.Group
		if newGroup != "" {
			if err := ValidateGroupName(newGroup); err != nil {
				return planned{}, KeyRelocateResult{}, err
			}
		}
	}
	if newStem == stem && newGroup == group {
		return planned{}, KeyRelocateResult{}, ErrKeyRelocateUnchanged
	}

	directory := path.Dir(filepath.ToSlash(item.RelativePath))
	if request.Group != nil {
		directory = "."
		if newGroup != "" {
			directory = GroupKeyDirectory(newGroup)
		}
	}
	relocations := make([]keyRelocation, 0, len(members))
	for _, member := range members {
		suffix := strings.TrimPrefix(path.Base(filepath.ToSlash(member.RelativePath)), stem)
		relocations = append(relocations, keyRelocation{
			from: member.RelativePath,
			to:   path.Join(directory, newStem+suffix),
		})
	}

	result := KeyRelocateResult{
		ID:           keys.ItemID(relocations[0].to),
		RelativePath: relocations[0].to,
		Group:        newGroup,
		Files:        make([]RelocatedKeyFile, 0, len(relocations)),
		References:   []RewrittenKeyReference{},
		Skipped:      skipped,
		Notes:        []string{},
		Blockers:     []string{},
	}
	if item.Kind == keys.KindPrivateKey {
		// A passphrase stored in the login Keychain is filed under the key's
		// absolute path. macOS owns that entry, so nothing here can move it,
		// and this application does not read the Keychain and cannot even tell
		// whether one exists.
		result.Notes = append(result.Notes, NoteKeychainEntryStale)
	}

	blockers := s.keyRelocationBlockers(graph, inventory, members, relocations, newGroup, request.Group != nil)
	if len(blockers) > 0 {
		result.Blockers = blockers
		return planned{}, result, ErrKeyRelocateBlocked
	}

	prepared := planned{
		operation: "key.relocate",
		base:      map[string][]byte{},
		baseline:  diagnosticBaseline(graph),
		preview:   SavePreview{Operation: "key.relocate"},
	}
	root := s.workspace.Root()
	for _, relocation := range relocations {
		absoluteFrom := filepath.Join(root, filepath.FromSlash(relocation.from))
		contents, readErr := s.workspace.FileSystem().ReadFile(absoluteFrom)
		if readErr != nil {
			return planned{}, KeyRelocateResult{}, readErr
		}
		digest := storage.Digest(contents)
		keys.Wipe(contents)
		prepared.moves = append(prepared.moves, storage.Move{
			From:         absoluteFrom,
			To:           filepath.Join(root, filepath.FromSlash(relocation.to)),
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		result.Files = append(result.Files, RelocatedKeyFile{From: relocation.from, To: relocation.to})
	}
	if directory != "." {
		absolute, dirErr := AbsolutePath(root, directory)
		if dirErr != nil {
			return planned{}, KeyRelocateResult{}, dirErr
		}
		prepared.directories = append(prepared.directories, absolute)
	}

	changes, rewritten, err := s.rewriteKeyReferences(members, relocations)
	if err != nil {
		return planned{}, KeyRelocateResult{}, err
	}
	prepared.changes = changes
	result.References = rewritten
	for _, change := range changes {
		previous, _, readErr := s.readFile(change.Path)
		if readErr != nil {
			return planned{}, KeyRelocateResult{}, readErr
		}
		prepared.base[filepath.Clean(change.Path)] = previous
		prepared.preview.Diffs = append(prepared.preview.Diffs,
			BuildFileDiff(s.displayPath(change.Path), previous, change.Contents))
	}
	result.Preview = prepared.preview
	return prepared, result, nil
}

// keyRelocationMembers returns the files one relocation moves, the item first.
//
// A private key takes with it the public key and certificate files that carry
// its fingerprint and sit beside it under its own name. Anything else that
// shares the fingerprint is left alone and named, because a file the user gave
// an unrelated name is a file the user named on purpose.
//
// A public key or certificate can be relocated only on its own, and only when
// no private key in the inventory belongs to it: OpenSSH still pairs those two
// files by name, so moving one without the other breaks the pair silently.
func keyRelocationMembers(inventory *keys.Inventory, item *keys.Item) (members []keys.Item, skipped []string, err error) {
	switch item.Kind {
	case keys.KindPrivateKey:
		stem := path.Base(filepath.ToSlash(item.RelativePath))
		directory := path.Dir(filepath.ToSlash(item.RelativePath))
		members = append(members, *item)
		for _, candidate := range inventory.Group(item) {
			if candidate.ID == item.ID {
				continue
			}
			base := path.Base(filepath.ToSlash(candidate.RelativePath))
			if path.Dir(filepath.ToSlash(candidate.RelativePath)) != directory || !strings.HasPrefix(base, stem) {
				skipped = append(skipped, candidate.RelativePath)
				continue
			}
			members = append(members, candidate)
		}
		sort.Strings(skipped)
		return members, skipped, nil
	case keys.KindPublicKey, keys.KindCertificate:
		if privateKeyFor(inventory, item) {
			return nil, nil, ErrKeyRelocateNotSupported
		}
		return []keys.Item{*item}, nil, nil
	default:
		return nil, nil, ErrKeyRelocateNotSupported
	}
}

// privateKeyFor reports whether a private key in the inventory owns this
// public key or certificate.
func privateKeyFor(inventory *keys.Inventory, item *keys.Item) bool {
	fingerprint := item.Fingerprint
	if item.Kind == keys.KindCertificate && item.Certificate != nil {
		fingerprint = item.Certificate.SignedKeyFingerprint
	}
	if fingerprint == "" {
		return false
	}
	for index := range inventory.Items {
		candidate := &inventory.Items[index]
		if candidate.Kind == keys.KindPrivateKey && candidate.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// keyStem is the part of the base name every moved file shares.
//
// For a private key it is the whole name: OpenSSH derives the public key's name
// by appending '.pub', and ValidateFileName refuses to create a private key
// already spelled that way. For a public key or certificate relocated on its
// own the suffix says what the file is, so it is kept and only the stem
// changes: renaming 'old.pub' to 'new' produces 'new.pub'.
func keyStem(item *keys.Item) string {
	base := path.Base(filepath.ToSlash(item.RelativePath))
	if item.Kind == keys.KindPrivateKey {
		return base
	}
	for _, suffix := range []string{"-cert.pub", ".pub"} {
		if trimmed := strings.TrimSuffix(base, suffix); trimmed != base && trimmed != "" {
			return trimmed
		}
	}
	return base
}

// keyRelocationBlockers reports every reason this relocation would have to
// guess. Each blocker refuses the whole transaction; nothing is written.
func (s *Service) keyRelocationBlockers(
	graph *config.Graph,
	inventory *keys.Inventory,
	members []keys.Item,
	relocations []keyRelocation,
	group string,
	groupRequested bool,
) []string {
	blockers := make([]string, 0)
	root := s.workspace.Root()

	if groupRequested && group != "" {
		declared := false
		for _, name := range s.declaredGroups(graph) {
			if name == group {
				declared = true
				break
			}
		}
		if !declared {
			// A key group mirrors a connection group. Creating keys/marketing
			// for a group nobody declared is the inference this design avoids.
			blockers = append(blockers, BlockerKeyGroupNotDeclared+":"+group)
		}
	}

	for _, relocation := range relocations {
		absolute := filepath.Join(root, filepath.FromSlash(relocation.to))
		if _, err := s.workspace.FileSystem().Lstat(absolute); err == nil {
			blockers = append(blockers, BlockerKeyTargetOccupied+":"+relocation.to)
		}
		if strings.HasPrefix(relocation.to+"/", keys.StateDirectoryName+"/") ||
			strings.HasPrefix(relocation.from+"/", keys.StateDirectoryName+"/") {
			// Trash, backups and journal are engine state. The inventory
			// already excludes them; this is the second lock on the same door.
			blockers = append(blockers, BlockerKeyStateDirectory+":"+relocation.to)
		}
		if reachedByInclude(graph, absolute) {
			// A private key read as ssh_config is the worst outcome available,
			// so a destination an Include glob would reach is refused outright.
			blockers = append(blockers, BlockerKeyDestinationRead+":"+relocation.to)
		}
	}

	for _, member := range members {
		for _, reference := range member.References {
			if !s.workspace.Contains(reference.ConfigPath) {
				// Design §5.3 forbids writing outside ~/.ssh. Moving the key
				// anyway would leave that file naming a path that is gone.
				blockers = append(blockers, BlockerKeyReferenceExternal+":"+s.displayPath(reference.ConfigPath))
			}
		}
	}
	for _, unresolved := range inventory.UnresolvedReferences {
		if risk := unresolvedKeyRisk(unresolved, members); risk != "" {
			blockers = append(blockers, BlockerKeyUnresolved+":"+risk)
		}
	}
	if len(blockers) == 0 {
		return nil
	}
	sort.Strings(blockers)
	return blockers
}

// reachedByInclude reports whether an Include glob in the graph would read this
// path. A destination the graph already reaches is a destination where a key
// file would be parsed as configuration.
func reachedByInclude(graph *config.Graph, absolute string) bool {
	cleaned := filepath.Clean(absolute)
	for _, node := range graph.Nodes {
		for _, edge := range node.Includes {
			if edge.Expanded == "" {
				continue
			}
			matched, err := filepath.Match(edge.Expanded, cleaned)
			if err == nil && matched {
				return true
			}
		}
	}
	return false
}

// unresolvedKeyRisk reports whether a directive the engine could not resolve
// might name one of the files this relocation moves.
//
// A path outside the workspace resolved to a definite location that is not one
// of these files, so it cannot be affected. A relative path has an unknown
// directory but a known base name, so it matters only when that base name is
// one being moved. A path carrying an expansion this engine does not implement
// could become anything at all, so it always matters.
func unresolvedKeyRisk(unresolved keys.UnresolvedReference, members []keys.Item) string {
	if unresolved.Directive == "IdentityAgent" {
		return ""
	}
	switch unresolved.Reason {
	case keys.ReasonOutsideWorkspace:
		return ""
	case keys.ReasonRelativePath:
		base := path.Base(filepath.ToSlash(unresolved.Value))
		for _, member := range members {
			if path.Base(filepath.ToSlash(member.RelativePath)) == base {
				return unresolved.Value
			}
		}
		return ""
	default:
		return unresolved.Value
	}
}

// rewriteKeyReferences rewrites every directive that names a moved file,
// producing one change per configuration file.
//
// The form the user wrote — '~/.ssh/…', '%d/…' or an absolute path — is what
// OpenSSH resolves and what the user recognises, so the prefix survives and
// only the part below the workspace root is replaced. A value spelled in a form
// this function cannot decompose is rewritten as an absolute path instead,
// which always resolves.
func (s *Service) rewriteKeyReferences(members []keys.Item, relocations []keyRelocation) ([]storage.Change, []RewrittenKeyReference, error) {
	root := s.workspace.Root()
	destinations := make(map[string]string, len(relocations))
	for _, relocation := range relocations {
		destinations[relocation.from] = relocation.to
	}
	byConfigPath := make(map[string][]keys.Reference)
	order := make([]string, 0)
	for _, member := range members {
		for _, reference := range member.References {
			if _, seen := byConfigPath[reference.ConfigPath]; !seen {
				order = append(order, reference.ConfigPath)
			}
			byConfigPath[reference.ConfigPath] = append(byConfigPath[reference.ConfigPath], reference)
		}
	}
	sort.Strings(order)

	changes := make([]storage.Change, 0, len(order))
	rewritten := make([]RewrittenKeyReference, 0)
	for _, configPath := range order {
		contents, err := s.workspace.FileSystem().ReadFile(configPath)
		if err != nil {
			return nil, nil, err
		}
		parsed := config.Parse(contents)
		touched := false

		for _, reference := range byConfigPath[configPath] {
			index := reference.Line - 1
			if index < 0 || index >= len(parsed.Lines) || parsed.Lines[index].Kind != config.LineDirective {
				return nil, nil, ErrKeyReferenceMoved
			}
			line := &parsed.Lines[index]
			for argumentIndex := range line.Arguments {
				argument := &line.Arguments[argumentIndex]
				// OpenSSH's argument list ends at an unquoted '#', so what
				// follows one is a comment and is left exactly as written.
				if strings.HasPrefix(argument.Raw, "#") {
					break
				}
				from, moved := relocationFor(destinations, root, s.workspace, argument.Value)
				if !moved {
					continue
				}
				replacement := rewriteKeyValue(argument.Value, from, destinations[from], root)
				rendered, renderErr := config.RenderArgument(argument.Lead, replacement)
				if renderErr != nil {
					return nil, nil, renderErr
				}
				rewritten = append(rewritten, RewrittenKeyReference{
					Directive:  line.Keyword,
					ConfigPath: s.displayPath(configPath),
					Line:       reference.Line,
					From:       argument.Value,
					To:         replacement,
				})
				*argument = rendered
				touched = true
			}
		}
		if !touched {
			continue
		}
		changes = append(changes, storage.Change{
			Path:         configPath,
			Contents:     parsed.Render(),
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(contents)},
		})
	}
	return changes, rewritten, nil
}

// relocationFor reports which moved file a directive argument names.
func relocationFor(destinations map[string]string, root string, workspace *storage.Workspace, value string) (string, bool) {
	for from := range destinations {
		if keys.ExpandsTo(workspace, value, filepath.Join(root, filepath.FromSlash(from))) {
			return from, true
		}
	}
	return "", false
}

// rewriteKeyValue re-expresses a directive argument for the file's new path,
// keeping whatever prefix the user used to name the workspace.
func rewriteKeyValue(value, from, to, root string) string {
	if prefix, ok := strings.CutSuffix(filepath.ToSlash(value), from); ok {
		return prefix + to
	}
	return filepath.ToSlash(filepath.Join(root, filepath.FromSlash(to)))
}
