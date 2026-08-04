package config

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Severity ranks a diagnostic for display. The engine never converts a
// diagnostic into a silent repair.
type Severity uint8

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
)

// Diagnostic codes are stable identifiers the UI maps to its own copy.
const (
	DiagnosticIncludeNoMatch       = "include_no_match"
	DiagnosticIncludeUnreadable    = "include_unreadable"
	DiagnosticIncludeCycle         = "include_cycle"
	DiagnosticIncludeDuplicate     = "include_duplicate"
	DiagnosticIncludeConditional   = "include_conditional"
	DiagnosticIncludeOutsideRoot   = "include_outside_root"
	DiagnosticIncludeDepthExceeded = "include_depth_exceeded"
	DiagnosticIncludeUnsupported   = "include_unsupported_expansion"
	DiagnosticIncludeEmpty         = "include_without_argument"
	DiagnosticUnstructuredLine     = "unstructured_line"
)

// ErrPathNotAbsolute is returned when a graph walk is asked to start from a
// path that is not absolute.
var ErrPathNotAbsolute = errors.New("configuration path must be absolute")

// Diagnostic describes something the user should decide about. Line is
// 1-based, or 0 when the diagnostic is about a whole file.
type Diagnostic struct {
	Severity Severity
	Code     string
	Path     string
	Line     int
	Detail   string
}

// Edge is one Include argument and the files it resolved to.
type Edge struct {
	FromPath  string
	Line      int
	Pattern   string
	Expanded  string
	Matches   []string
	Condition string
}

// Node is one configuration file in the graph.
type Node struct {
	Path     string
	Editable bool
	Missing  bool
	File     *File
	Includes []Edge
	Loads    int
}

// Graph is the Include structure reachable from a single entry file.
type Graph struct {
	Root        string
	Order       []string
	Nodes       map[string]*Node
	Diagnostics []Diagnostic
}

// Resolve reads the entry file and every file it includes. Resolve returns an
// error only when the request itself is invalid; unreadable files, cycles and
// unsupported patterns are reported as diagnostics so the UI can show the real
// structure instead of failing.
func (r Resolver) Resolve(rootPath string) (*Graph, error) {
	if !path.IsAbs(rootPath) {
		return nil, ErrPathNotAbsolute
	}
	graph := &Graph{Root: path.Clean(rootPath), Nodes: make(map[string]*Node)}
	r.walk(graph, graph.Root, nil, 0)
	return graph, nil
}

func (g *Graph) diagnose(severity Severity, code, filePath string, line int, detail string) {
	g.Diagnostics = append(g.Diagnostics, Diagnostic{
		Severity: severity,
		Code:     code,
		Path:     filePath,
		Line:     line,
		Detail:   detail,
	})
}

func (r Resolver) insideRoot(candidate string) bool {
	cleaned := path.Clean(candidate)
	return cleaned == r.Root || strings.HasPrefix(cleaned, r.Root+"/")
}

func (r Resolver) walk(graph *Graph, filePath string, chain []string, depth int) {
	node := &Node{Path: filePath, Editable: r.insideRoot(filePath), Loads: 1}
	graph.Nodes[filePath] = node
	graph.Order = append(graph.Order, filePath)

	contents, err := r.Loader.ReadFile(filePath)
	if err != nil {
		node.Missing = errors.Is(err, fs.ErrNotExist)
		graph.diagnose(SeverityError, DiagnosticIncludeUnreadable, filePath, 0, err.Error())
		return
	}
	node.File = Parse(contents)

	currentChain := make([]string, 0, len(chain)+1)
	currentChain = append(currentChain, chain...)
	currentChain = append(currentChain, filePath)

	for index, line := range node.File.Lines {
		lineNumber := index + 1
		if line.Kind == LineUnstructured {
			graph.diagnose(SeverityInfo, DiagnosticUnstructuredLine, filePath, lineNumber, "line is preserved verbatim and can only be edited as raw text")
			continue
		}
		if line.Kind != LineDirective || !EqualKeyword(line.Keyword, "Include") {
			continue
		}

		condition := node.File.Condition(node.File.BlockAt(index))
		if condition != "" {
			graph.diagnose(SeverityWarning, DiagnosticIncludeConditional, filePath, lineNumber, condition)
		}
		values := line.Values()
		if len(values) == 0 {
			graph.diagnose(SeverityWarning, DiagnosticIncludeEmpty, filePath, lineNumber, "")
			continue
		}

		for _, value := range values {
			edge := Edge{FromPath: filePath, Line: lineNumber, Pattern: value, Condition: condition}
			expanded, expandErr := r.expandPattern(value)
			if expandErr != nil {
				graph.diagnose(SeverityWarning, DiagnosticIncludeUnsupported, filePath, lineNumber, value)
				node.Includes = append(node.Includes, edge)
				continue
			}
			edge.Expanded = expanded

			matches, globErr := r.Loader.Glob(expanded)
			if globErr != nil {
				graph.diagnose(SeverityWarning, DiagnosticIncludeUnreadable, filePath, lineNumber, globErr.Error())
				node.Includes = append(node.Includes, edge)
				continue
			}
			sort.Strings(matches)
			if len(matches) == 0 {
				graph.diagnose(SeverityWarning, DiagnosticIncludeNoMatch, filePath, lineNumber, expanded)
			}
			edge.Matches = matches
			node.Includes = append(node.Includes, edge)

			for _, match := range matches {
				if !r.insideRoot(match) {
					graph.diagnose(SeverityInfo, DiagnosticIncludeOutsideRoot, filePath, lineNumber, match)
				}
				if slicesContains(currentChain, match) {
					graph.diagnose(SeverityError, DiagnosticIncludeCycle, filePath, lineNumber, match)
					continue
				}
				if existing, seen := graph.Nodes[match]; seen {
					existing.Loads++
					graph.diagnose(SeverityWarning, DiagnosticIncludeDuplicate, filePath, lineNumber, match)
					continue
				}
				if depth+1 > r.maxDepth() {
					graph.diagnose(SeverityError, DiagnosticIncludeDepthExceeded, filePath, lineNumber, match)
					continue
				}
				r.walk(graph, match, currentChain, depth+1)
			}
		}
	}
}

func slicesContains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
