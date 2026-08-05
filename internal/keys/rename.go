package keys

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"ssh-ui/internal/config"
	"ssh-ui/internal/storage"
)

var (
	ErrRenameNotSupported   = errors.New("only a private key, or a public key with no private key beside it, can be renamed")
	ErrRenameUnchanged      = errors.New("the new name is the name the key already has")
	ErrRenameBlocked        = errors.New("rename would leave a reference this application cannot rewrite")
	ErrConfigurationChanged = errors.New("a configuration file changed while the rename was being prepared")
)

// Rename blocker codes are stable identifiers followed by ':' and the detail.
const (
	BlockerRenameTargetOccupied  = "rename_target_occupied"
	BlockerRenameUnresolved      = "rename_reference_unresolved"
	BlockerRenameFileNotEditable = "rename_reference_not_editable"
)

// NoteKeychainEntryStale reports that a Keychain entry, if the user made one,
// still names the key under the path it had before the rename.
const NoteKeychainEntryStale = "keychain_entry_stale"

// RenameRequest changes the name of one key, and of the files that belong to it.
type RenameRequest struct {
	KeyID   string
	NewName string
}

// RenamedFile is one file the rename moved, by workspace-relative path.
type RenamedFile struct {
	From string
	To   string
}

// RewrittenReference is one configuration directive the rename updated.
type RewrittenReference struct {
	Directive  string
	ConfigPath string
	Line       int
	From       string
	To         string
}

type RenameResult struct {
	ID            string
	RelativePath  string
	Files         []RenamedFile
	References    []RewrittenReference
	Skipped       []string
	Notes         []string
	Blockers      []string
	TransactionID string
}

// renameTarget is one file the rename moves.
type renameTarget struct {
	from string
	to   string
}

// Rename changes a key's file name and rewrites every configuration directive
// that names it, in one journalled transaction.
//
// The rename is a move, so no bytes are copied and the permission bits survive
// exactly; the files and the directives that point at them change together or
// not at all. A key is only ever renamed inside the directory it already
// occupies: moving it elsewhere is a different operation with different
// consequences, and ValidateFileName accepts one path segment precisely so that
// this operation cannot become that one by accident.
//
// Rename refuses rather than guesses. If a directive that names a key file
// cannot be resolved to a path, or lives in a file this application may not
// write, the rename is blocked and the reason is reported: a rename that
// silently left a dangling IdentityFile behind would break authentication later,
// at a moment the user has no reason to connect with this change.
func (service *Service) Rename(request RenameRequest) (RenameResult, error) {
	if err := ValidateFileName(request.NewName); err != nil {
		return RenameResult{}, err
	}
	inventory, err := service.Inventory()
	if err != nil {
		return RenameResult{}, err
	}
	item, ok := inventory.Find(request.KeyID)
	if !ok {
		return RenameResult{}, ErrUnknownKey
	}

	members, skipped, err := renameMembers(inventory, item)
	if err != nil {
		return RenameResult{}, err
	}
	stem := renameStem(item)
	if stem == request.NewName {
		return RenameResult{}, ErrRenameUnchanged
	}

	directory := filepath.Dir(item.RelativePath)
	targets := make([]renameTarget, 0, len(members))
	for _, member := range members {
		suffix := strings.TrimPrefix(filepath.Base(member.RelativePath), stem)
		targets = append(targets, renameTarget{
			from: member.RelativePath,
			to:   filepath.Join(directory, request.NewName+suffix),
		})
	}

	if blockers := service.renameBlockers(inventory, members, targets); len(blockers) > 0 {
		return RenameResult{Blockers: blockers}, ErrRenameBlocked
	}

	transaction := storage.Request{Operation: "key.rename"}
	files := make([]RenamedFile, 0, len(targets))
	for _, target := range targets {
		absolute := service.absolutePath(target.from)
		contents, readErr := service.workspace.FileSystem().ReadFile(absolute)
		if readErr != nil {
			return RenameResult{}, readErr
		}
		digest := storage.Digest(contents)
		Wipe(contents)
		transaction.Moves = append(transaction.Moves, storage.Move{
			From:         absolute,
			To:           service.absolutePath(target.to),
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		files = append(files, RenamedFile{From: target.from, To: target.to})
	}

	changes, rewritten, err := service.rewriteReferences(members, targets)
	if err != nil {
		return RenameResult{}, err
	}
	transaction.Changes = changes

	result, err := service.transactions.Commit(transaction)
	if err != nil {
		return RenameResult{}, err
	}
	return RenameResult{
		ID:            ItemID(targets[0].to),
		RelativePath:  targets[0].to,
		Files:         files,
		References:    rewritten,
		Skipped:       skipped,
		Notes:         renameNotes(item),
		TransactionID: result.ID,
	}, nil
}

// renameNotes reports what a rename cannot carry with it.
//
// A passphrase stored in the login Keychain is filed under the key's absolute
// path, and nothing this application does can move it: the entry belongs to the
// user's Keychain, not to ~/.ssh. The note is unconditional for a private key
// because whether such an entry exists is not something this application can
// find out without asking for the user's Keychain, which it does not do.
func renameNotes(item *Item) []string {
	if item.Kind != KindPrivateKey {
		return nil
	}
	return []string{NoteKeychainEntryStale}
}

// renameMembers returns the files one rename moves, with the item itself first.
//
// A private key takes with it the public key and certificate files that carry
// its fingerprint and sit beside it under its own name. Anything else that
// shares the fingerprint is left alone and named in the skipped list, because a
// file the user gave an unrelated name is a file the user named on purpose.
//
// A public key or certificate can be renamed only on its own, and only when no
// private key in the inventory belongs to it. Renaming half of a pair would
// leave two files that OpenSSH still pairs by name and a reader no longer can.
func renameMembers(inventory *Inventory, item *Item) (members []Item, skipped []string, err error) {
	switch item.Kind {
	case KindPrivateKey:
		stem := filepath.Base(item.RelativePath)
		directory := filepath.Dir(item.RelativePath)
		members = append(members, *item)
		for _, candidate := range inventory.Group(item) {
			if candidate.ID == item.ID {
				continue
			}
			base := filepath.Base(candidate.RelativePath)
			if filepath.Dir(candidate.RelativePath) != directory || !strings.HasPrefix(base, stem) {
				skipped = append(skipped, candidate.RelativePath)
				continue
			}
			members = append(members, candidate)
		}
		sort.Strings(skipped)
		return members, skipped, nil
	case KindPublicKey, KindCertificate:
		if _, paired := privateKeyFor(inventory, item); paired {
			return nil, nil, ErrRenameNotSupported
		}
		return []Item{*item}, nil, nil
	default:
		return nil, nil, ErrRenameNotSupported
	}
}

// privateKeyFor reports the private key a public key or certificate belongs to.
func privateKeyFor(inventory *Inventory, item *Item) (*Item, bool) {
	fingerprint := item.Fingerprint
	if item.Kind == KindCertificate && item.Certificate != nil {
		fingerprint = item.Certificate.SignedKeyFingerprint
	}
	if fingerprint == "" {
		return nil, false
	}
	for index := range inventory.Items {
		candidate := &inventory.Items[index]
		if candidate.Kind == KindPrivateKey && candidate.Fingerprint == fingerprint {
			return candidate, true
		}
	}
	return nil, false
}

// renameStem is the part of the base name every moved file shares.
//
// For a private key it is the whole name: OpenSSH derives the public key's name
// by appending '.pub', and ValidateFileName refuses to create a private key
// whose name already ends that way. For a public key or certificate renamed on
// its own the suffix says what the file is, so it is kept and only the stem
// changes; renaming 'old.pub' to 'new' produces 'new.pub' rather than a public
// key with no visible kind.
func renameStem(item *Item) string {
	base := filepath.Base(item.RelativePath)
	if item.Kind == KindPrivateKey {
		return base
	}
	for _, suffix := range []string{"-cert.pub", ".pub"} {
		if trimmed := strings.TrimSuffix(base, suffix); trimmed != base && trimmed != "" {
			return trimmed
		}
	}
	return base
}

// renameBlockers reports every reason this rename would have to guess.
func (service *Service) renameBlockers(inventory *Inventory, members []Item, targets []renameTarget) []string {
	blockers := make([]string, 0)
	for _, target := range targets {
		if _, err := service.workspace.FileSystem().Lstat(service.absolutePath(target.to)); err == nil {
			blockers = append(blockers, BlockerRenameTargetOccupied+":"+target.to)
		}
	}
	for _, member := range members {
		for _, reference := range member.References {
			if !service.workspace.Contains(reference.ConfigPath) {
				blockers = append(blockers, BlockerRenameFileNotEditable+":"+reference.ConfigPath)
			}
		}
	}
	for _, unresolved := range inventory.UnresolvedReferences {
		if risk := renameUnresolvedRisk(unresolved, members); risk != "" {
			blockers = append(blockers, BlockerRenameUnresolved+":"+risk)
		}
	}
	if len(blockers) == 0 {
		return nil
	}
	return blockers
}

// renameUnresolvedRisk reports whether a directive the engine could not resolve
// might name one of the files this rename moves.
//
// A path outside the workspace resolved to a definite location that is not one
// of these files, so it cannot be affected. A relative path has an unknown
// directory but a known base name, so it matters only when that base name is
// one being renamed. A path carrying an expansion this engine does not
// implement could become anything at all, so it always matters.
func renameUnresolvedRisk(unresolved UnresolvedReference, members []Item) string {
	if unresolved.Directive == "IdentityAgent" {
		return ""
	}
	switch unresolved.Reason {
	case ReasonOutsideWorkspace:
		return ""
	case ReasonRelativePath:
		base := filepath.Base(unresolved.Value)
		for _, member := range members {
			if filepath.Base(member.RelativePath) == base {
				return unresolved.Value
			}
		}
		return ""
	default:
		return unresolved.Value
	}
}

// rewriteReferences rewrites every directive that names a moved file, producing
// one change per configuration file.
//
// Only the last path segment of an argument is replaced. The form the user
// wrote — '~/.ssh/…', '%d/…' or an absolute path — is what OpenSSH resolves and
// what the user recognises, so it survives; rewriting all three into one
// spelling would be a change nobody asked for in a file the user reads.
func (service *Service) rewriteReferences(members []Item, targets []renameTarget) ([]storage.Change, []RewrittenReference, error) {
	newBaseByOldPath := make(map[string]string, len(targets))
	for _, target := range targets {
		newBaseByOldPath[target.from] = filepath.Base(target.to)
	}
	oldAbsolute := make(map[string]string, len(members))
	byConfigPath := make(map[string][]Reference)
	order := make([]string, 0)
	for _, member := range members {
		oldAbsolute[member.RelativePath] = service.absolutePath(member.RelativePath)
		for _, reference := range member.References {
			if _, seen := byConfigPath[reference.ConfigPath]; !seen {
				order = append(order, reference.ConfigPath)
			}
			byConfigPath[reference.ConfigPath] = append(byConfigPath[reference.ConfigPath], reference)
		}
	}
	sort.Strings(order)

	changes := make([]storage.Change, 0, len(order))
	rewritten := make([]RewrittenReference, 0)
	for _, configPath := range order {
		contents, err := service.workspace.FileSystem().ReadFile(configPath)
		if err != nil {
			return nil, nil, err
		}
		parsed := config.Parse(contents)
		touched := false

		for _, reference := range byConfigPath[configPath] {
			index := reference.Line - 1
			if index < 0 || index >= len(parsed.Lines) || parsed.Lines[index].Kind != config.LineDirective {
				return nil, nil, ErrConfigurationChanged
			}
			line := &parsed.Lines[index]
			for argumentIndex := range line.Arguments {
				argument := &line.Arguments[argumentIndex]
				// OpenSSH's argument list ends at an unquoted '#', so what
				// follows one is a comment and is left exactly as written.
				if strings.HasPrefix(argument.Raw, "#") {
					break
				}
				expanded, reason := expandKeyPath(argument.Value, service.workspace.Home())
				if reason != "" {
					continue
				}
				relative, moved := movedPath(oldAbsolute, expanded)
				if !moved {
					continue
				}
				replacement := replaceBaseName(argument.Value, newBaseByOldPath[relative])
				rendered, renderErr := config.RenderArgument(argument.Lead, replacement)
				if renderErr != nil {
					return nil, nil, renderErr
				}
				rewritten = append(rewritten, RewrittenReference{
					Directive:  line.Keyword,
					ConfigPath: configPath,
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

func movedPath(oldAbsolute map[string]string, expanded string) (relative string, moved bool) {
	for candidate, absolute := range oldAbsolute {
		if absolute == expanded {
			return candidate, true
		}
	}
	return "", false
}

// replaceBaseName swaps the last path segment of a directive argument, keeping
// every byte that precedes it.
func replaceBaseName(value, newBase string) string {
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		return value[:index+1] + newBase
	}
	return newBase
}
