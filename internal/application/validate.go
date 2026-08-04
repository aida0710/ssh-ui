package application

import (
	"bytes"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ssh-ui/internal/config"
	"ssh-ui/internal/storage"
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
// write, including files the transaction creates.
type overlayLoader struct {
	base    config.Loader
	pending map[string][]byte
}

func (loader overlayLoader) ReadFile(name string) ([]byte, error) {
	if contents, ok := loader.pending[filepath.Clean(name)]; ok {
		return contents, nil
	}
	return loader.base.ReadFile(name)
}

func (loader overlayLoader) Glob(pattern string) ([]string, error) {
	matches, err := loader.base.Glob(pattern)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(matches))
	for _, match := range matches {
		seen[filepath.Clean(match)] = true
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
// renamed. It parses every new file, proves the parse renders back to the same
// bytes, refuses newly unparsable lines, and re-resolves the whole Include
// graph with the pending contents overlaid.
func (s *Service) validate(request storage.Request) error {
	pending := make(map[string][]byte, len(request.Changes))
	for _, change := range request.Changes {
		pending[filepath.Clean(change.Path)] = change.Contents
	}

	metadataPath := filepath.Clean(s.metadata.Path())
	for _, change := range request.Changes {
		cleaned := filepath.Clean(change.Path)
		if cleaned == metadataPath {
			if _, err := DecodeMetadata(change.Contents); err != nil {
				return err
			}
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

	resolver := s.resolver
	resolver.Loader = overlayLoader{base: s.resolver.Loader, pending: pending}
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
