package keys

import (
	"path/filepath"
	"strings"

	"ssh-ui/internal/config"
	"ssh-ui/internal/storage"
)

// Reference is one configuration directive that names a key file.
type Reference struct {
	Directive    string
	ConfigPath   string
	Line         int
	Condition    string
	HostPatterns []string
	Value        string
}

// UnresolvedReference is a directive whose argument the engine refuses to
// guess at, so the UI can show the real reason instead of an invented answer.
type UnresolvedReference struct {
	Directive  string
	Value      string
	ConfigPath string
	Line       int
	Reason     string
}

// Unresolved reason codes.
const (
	ReasonUnsupportedToken = "unsupported_token"
	ReasonRelativePath     = "relative_path"
	ReasonOutsideWorkspace = "outside_workspace"
)

// referencedDirectives are the client directives that name a key file or an
// agent. Every other directive is ignored by this index.
var referencedDirectives = []string{"IdentityFile", "CertificateFile", "IdentityAgent"}

// ReferenceIndex maps workspace-relative paths to the directives naming them.
type ReferenceIndex struct {
	byRelativePath map[string][]Reference
	agent          []Reference
	unresolved     []UnresolvedReference
}

func (index *ReferenceIndex) For(relativePath string) []Reference {
	return index.byRelativePath[relativePath]
}

func (index *ReferenceIndex) AgentDelegations() []Reference { return index.agent }

func (index *ReferenceIndex) Unresolved() []UnresolvedReference { return index.unresolved }

// BuildReferenceIndex walks every file the Include graph reached and records
// which Hosts name which key file.
func BuildReferenceIndex(graph *config.Graph, workspace *storage.Workspace) *ReferenceIndex {
	index := &ReferenceIndex{byRelativePath: make(map[string][]Reference)}
	for _, path := range graph.Order {
		node := graph.Nodes[path]
		if node == nil || node.File == nil {
			continue
		}
		for lineIndex, line := range node.File.Lines {
			if line.Kind != config.LineDirective {
				continue
			}
			directive, matched := matchDirective(line.Keyword)
			if !matched {
				continue
			}
			block := node.File.BlockAt(lineIndex)
			condition := node.File.Condition(block)
			patterns := make([]string, 0, len(block.Patterns))
			for _, pattern := range block.Patterns {
				patterns = append(patterns, pattern.Raw)
			}
			for _, value := range line.Values() {
				index.record(workspace, directive, value, path, lineIndex+1, condition, patterns)
			}
		}
	}
	return index
}

func matchDirective(keyword string) (string, bool) {
	for _, directive := range referencedDirectives {
		if config.EqualKeyword(keyword, directive) {
			return directive, true
		}
	}
	return "", false
}

func (index *ReferenceIndex) record(
	workspace *storage.Workspace,
	directive, value, configPath string,
	line int,
	condition string,
	patterns []string,
) {
	reference := Reference{
		Directive:    directive,
		ConfigPath:   configPath,
		Line:         line,
		Condition:    condition,
		HostPatterns: patterns,
		Value:        value,
	}
	if directive == "IdentityAgent" {
		index.agent = append(index.agent, reference)
		if value == "none" || value == "SSH_AUTH_SOCK" {
			return
		}
	}

	// Expanded against Home, compared against Root: Normalise is what makes
	// those the same space when ~/.ssh is reached through a link.
	expanded, reason := expandKeyPath(value, workspace.Home())
	absolute := workspace.Normalise(expanded)
	if reason != "" {
		index.unresolved = append(index.unresolved, UnresolvedReference{
			Directive: directive, Value: value, ConfigPath: configPath, Line: line, Reason: reason,
		})
		return
	}
	if !workspace.Contains(absolute) {
		index.unresolved = append(index.unresolved, UnresolvedReference{
			Directive: directive, Value: value, ConfigPath: configPath, Line: line, Reason: ReasonOutsideWorkspace,
		})
		return
	}
	relative, err := filepath.Rel(workspace.Root(), absolute)
	if err != nil {
		index.unresolved = append(index.unresolved, UnresolvedReference{
			Directive: directive, Value: value, ConfigPath: configPath, Line: line, Reason: ReasonOutsideWorkspace,
		})
		return
	}
	index.byRelativePath[relative] = append(index.byRelativePath[relative], reference)
}

// expandKeyPath resolves an IdentityFile style argument to an absolute path.
//
// Only '%d' and a leading '~/' are expanded, because they are the only forms
// whose meaning is fixed before a destination host is chosen. A relative path
// is reported rather than guessed at, because OpenSSH resolves it against the
// working directory of the ssh process, which this application cannot know.
func expandKeyPath(value, home string) (absolute string, reason string) {
	if value == "" {
		return "", ReasonUnsupportedToken
	}
	expanded := value
	if strings.ContainsRune(expanded, '%') {
		var builder strings.Builder
		for index := 0; index < len(expanded); index++ {
			if expanded[index] != '%' {
				builder.WriteByte(expanded[index])
				continue
			}
			index++
			if index >= len(expanded) {
				return "", ReasonUnsupportedToken
			}
			switch expanded[index] {
			case '%':
				builder.WriteByte('%')
			case 'd':
				builder.WriteString(home)
			default:
				return "", ReasonUnsupportedToken
			}
		}
		expanded = builder.String()
	}
	switch {
	case expanded == "~":
		expanded = home
	case strings.HasPrefix(expanded, "~/"):
		expanded = filepath.Join(home, expanded[2:])
	case strings.HasPrefix(expanded, "~"):
		return "", ReasonUnsupportedToken
	case !filepath.IsAbs(expanded):
		return "", ReasonRelativePath
	}
	return filepath.Clean(expanded), ""
}

// AttachReferences copies the Hosts that name each file onto its inventory
// item and records the directives the engine could not resolve.
func (inventory *Inventory) AttachReferences(index *ReferenceIndex) {
	for itemIndex := range inventory.Items {
		item := &inventory.Items[itemIndex]
		item.References = index.For(item.RelativePath)
	}
	inventory.AgentDelegations = index.AgentDelegations()
	inventory.UnresolvedReferences = index.Unresolved()
}

// ExpandsTo reports whether an IdentityFile-style argument names this exact
// file. It is the one way another package may ask that question: expandKeyPath
// stays unexported so the rule about what this engine refuses to guess — a
// relative path, an unknown token — is decided in one place.
// The workspace rather than a bare home, because the answer is a comparison
// against a path under the root and the two spellings have to be reconciled
// before it is made. Passing the home alone let a caller compare an expanded
// "~/.ssh/…" with a path built from the resolved root and be told they were
// different files.
func ExpandsTo(workspace *storage.Workspace, value, absolute string) bool {
	expanded, reason := expandKeyPath(value, workspace.Home())
	return reason == "" && workspace.Normalise(expanded) == workspace.Normalise(absolute)
}
