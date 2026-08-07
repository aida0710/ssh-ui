package application

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"sshc/internal/config"
	"sshc/internal/storage"
)

// SyntaxError refuses a save whose new contents cannot be represented. It
// carries a location, never the file contents.
type SyntaxError struct {
	Path   string
	Line   int
	Column int
	Detail string
}

func (e *SyntaxError) Error() string {
	return "configuration syntax error at line " + strconv.Itoa(e.Line)
}

// GraphError refuses a save that would introduce a new Include graph error.
type GraphError struct {
	Diagnostics []DiagnosticView
}

func (e *GraphError) Error() string { return "include graph error" }

// ConflictError reports that the file on disk is not the file the user edited.
type ConflictError struct {
	Report ConflictReport
}

func (e *ConflictError) Error() string { return "external change detected" }

// overlayLoader lets the resolver see the contents a transaction is about to
// write, including files the transaction creates, and lets it stop seeing the
// files the transaction is about to take away.
//
// gone is not an optimisation. A transaction that moves a file writes it at the
// destination and removes it from the source, so an overlay carrying only
// pending would resolve the graph against a world where the file exists in both
// places at once: an Include glob would match twice, a duplicate alias would be
// reported that will not exist, and a diagnostic the move actually fixes would
// still look present. The same is true of a removal.
type overlayLoader struct {
	base    config.Loader
	pending map[string][]byte
	gone    map[string]bool
}

func (loader overlayLoader) ReadFile(name string) ([]byte, error) {
	cleaned := filepath.Clean(name)
	if contents, ok := loader.pending[cleaned]; ok {
		return contents, nil
	}
	// pending wins over gone, so a transaction that moves a file onto a path it
	// also removes still reads the new contents rather than reporting nothing.
	if loader.gone[cleaned] {
		return nil, fs.ErrNotExist
	}
	return loader.base.ReadFile(name)
}

func (loader overlayLoader) Glob(pattern string) ([]string, error) {
	found, err := loader.base.Glob(pattern)
	if err != nil {
		return nil, err
	}
	matches := make([]string, 0, len(found))
	seen := make(map[string]bool, len(found))
	for _, match := range found {
		cleaned := filepath.Clean(match)
		if loader.gone[cleaned] && loader.pending[cleaned] == nil {
			continue
		}
		matches = append(matches, match)
		seen[cleaned] = true
	}
	for name := range loader.pending {
		if seen[name] {
			continue
		}
		matched, matchErr := filepath.Match(pattern, name)
		if matchErr != nil {
			return nil, matchErr
		}
		if matched {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

// overlayFor describes the filesystem a request is about to produce: the
// contents it writes, and the paths that will no longer be there. A move
// contributes to both, because its destination arrives and its source leaves.
func overlayFor(request storage.Request) (map[string][]byte, map[string]bool) {
	pending := make(map[string][]byte, len(request.Changes)+len(request.Moves))
	gone := make(map[string]bool, len(request.Moves)+len(request.Removals))
	for _, change := range request.Changes {
		pending[filepath.Clean(change.Path)] = change.Contents
	}
	for _, move := range request.Moves {
		gone[filepath.Clean(move.From)] = true
	}
	for _, removal := range request.Removals {
		gone[filepath.Clean(removal.Path)] = true
	}
	return pending, gone
}

// diagnosticKey identifies a diagnostic so a save is blocked only by problems
// it introduces, not by problems the configuration already had.
func diagnosticKey(diagnostic config.Diagnostic) string {
	return diagnostic.Code + "\x00" + diagnostic.Path + "\x00" + strconv.Itoa(diagnostic.Line)
}

func diagnosticBaseline(graph *config.Graph) map[string]bool {
	baseline := make(map[string]bool, len(graph.Diagnostics))
	for _, diagnostic := range graph.Diagnostics {
		baseline[diagnosticKey(diagnostic)] = true
	}
	return baseline
}

// newUnstructuredLine finds a line the edit made unparsable. Lines that were
// already unparsable stay allowed, because the engine preserves them verbatim
// and the user may only be able to fix them gradually.
func newUnstructuredLine(before, after *config.File) (line, column int, found bool) {
	known := map[string]int{}
	if before != nil {
		for _, existing := range before.Lines {
			if existing.Kind == config.LineUnstructured {
				known[existing.Text]++
			}
		}
	}
	for index, candidate := range after.Lines {
		if candidate.Kind != config.LineUnstructured {
			continue
		}
		if known[candidate.Text] > 0 {
			known[candidate.Text]--
			continue
		}
		return index + 1, unstructuredColumn(candidate.Text), true
	}
	return 0, 0, false
}

func unstructuredColumn(text string) int {
	if index := strings.IndexByte(text, '"'); index >= 0 {
		return index + 1
	}
	return 1
}

// validate is installed as storage.Manager.Validate, so it runs after the
// preconditions are checked and before anything is journalled, staged or
// renamed. It parses every new configuration file, proves the parse renders
// back to the same bytes, refuses newly unparsable lines, and re-resolves the
// whole Include graph with the pending contents overlaid.
//
// It validates configuration and nothing else. Files inside the workspace
// state directory are this application's own — metadata.json, journals,
// backups, the password vault — and are not ssh_config. Parsing them as though
// they were is not merely pointless: the password vault is ciphertext, and a
// blob whose random bytes happen to contain an odd number of quotation marks
// was rejected as "unbalanced quoting". That is a coin flip on every save, and
// it is how this was found — an end-to-end test that stored a password passed
// locally and failed in CI.
func (s *Service) validate(request storage.Request) error {
	pending, gone := overlayFor(request)

	metadataPath := filepath.Clean(s.metadata.Path())
	stateDir := filepath.Clean(s.workspace.StateDir())
	for _, change := range request.Changes {
		cleaned := filepath.Clean(change.Path)
		if cleaned == metadataPath {
			if _, err := DecodeMetadata(change.Contents); err != nil {
				return err
			}
			continue
		}
		// Anything else under sshc/ is application state, never read by
		// OpenSSH and never part of the Include graph.
		if isInside(stateDir, cleaned) {
			continue
		}
		parsed := config.Parse(change.Contents)
		if !bytes.Equal(parsed.Render(), change.Contents) {
			return &SyntaxError{Path: s.displayPath(cleaned), Line: 1, Column: 1, Detail: "parsed file does not render back to the same bytes"}
		}
		var base *config.File
		if contents, ok := s.pendingBase[cleaned]; ok {
			base = config.Parse(contents)
		}
		if line, column, found := newUnstructuredLine(base, parsed); found {
			return &SyntaxError{Path: s.displayPath(cleaned), Line: line, Column: column, Detail: "unbalanced quoting"}
		}
	}

	// A request that touches nothing OpenSSH reads cannot have changed the
	// Include graph, so it is not asked to produce a resolvable one. The vault
	// lives under sshc/ and the whole application is behind it: without this,
	// a workspace whose config file is missing or broken is a workspace where
	// the master password cannot be set, and the tool for fixing a broken
	// configuration would refuse to start because the configuration is broken.
	if !s.touchesConfiguration(request) {
		return nil
	}

	resolver := s.resolver
	resolver.Loader = overlayLoader{base: s.resolver.Loader, pending: pending, gone: gone}
	graph, err := resolver.Resolve(s.entryPath)
	if err != nil {
		return err
	}
	var introduced []DiagnosticView
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Severity != config.SeverityError || s.pendingBaseline[diagnosticKey(diagnostic)] {
			continue
		}
		introduced = append(introduced, NewDiagnosticView(s.workspace.Root(), diagnostic))
	}
	if len(introduced) > 0 {
		return &GraphError{Diagnostics: introduced}
	}
	return nil
}

// touchesConfiguration reports whether any path in the request is somewhere
// OpenSSH could read. The metadata document is this application's own, but it
// sits beside the state directory rather than inside it, so it is named here
// too — changing it cannot change the graph either.
func (s *Service) touchesConfiguration(request storage.Request) bool {
	stateDir := filepath.Clean(s.workspace.StateDir())
	metadataPath := filepath.Clean(s.metadata.Path())
	outside := func(path string) bool {
		cleaned := filepath.Clean(path)
		return cleaned != metadataPath && !isInside(stateDir, cleaned)
	}
	for _, change := range request.Changes {
		if outside(change.Path) {
			return true
		}
	}
	for _, move := range request.Moves {
		if outside(move.From) || outside(move.To) {
			return true
		}
	}
	for _, removal := range request.Removals {
		if outside(removal.Path) {
			return true
		}
	}
	// A directory this application creates or removes is only ever a group
	// directory or one of its own, and a group directory changes what an
	// Include reaches.
	return len(request.Directories) > 0 || len(request.RemoveDirectories) > 0
}

// isInside reports whether path is directory itself or below it. It compares
// cleaned paths component-wise rather than by string prefix, so a sibling
// named sshc-backup is not mistaken for a child of sshc.
func isInside(directory, path string) bool {
	if path == directory {
		return true
	}
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
