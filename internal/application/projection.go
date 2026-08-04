package application

import (
	"errors"
	"strings"

	"ssh-ui/internal/config"
)

// ErrHostNotFound reports that no Host block in the graph declares the
// requested identity.
var ErrHostNotFound = errors.New("host block not found")

// FieldCategory decides which tab of the host editor shows a directive.
type FieldCategory string

const (
	CategoryBasic    FieldCategory = "basic"
	CategoryJump     FieldCategory = "jump"
	CategoryAdvanced FieldCategory = "advanced"
)

// basicKeywords and jumpKeywords hold the directives with a dedicated form.
// Everything else is edited as an arbitrary key-value pair, so a directive
// OpenSSH adds later is still fully editable without a code change.
var basicKeywords = map[string]bool{
	"hostname": true, "user": true, "port": true, "identityfile": true,
	"identitiesonly": true, "addkeystoagent": true, "tag": true,
}

var jumpKeywords = map[string]bool{
	"proxyjump": true, "proxycommand": true, "forwardagent": true, "requesttty": true,
}

// dangerousKeywords are the executable directives of design §8.3. They may be
// edited and saved, but never evaluated or executed by this application.
var dangerousKeywords = map[string]bool{
	"proxycommand": true, "knownhostscommand": true, "localcommand": true,
	"remotecommand": true, "permitlocalcommand": true,
}

// CategoryFor decides where a directive belongs.
func CategoryFor(keyword string) FieldCategory {
	lowered := strings.ToLower(keyword)
	switch {
	case basicKeywords[lowered]:
		return CategoryBasic
	case jumpKeywords[lowered]:
		return CategoryJump
	default:
		return CategoryAdvanced
	}
}

// IsDangerousKeyword reports a directive whose value OpenSSH can execute.
func IsDangerousKeyword(keyword string) bool {
	return dangerousKeywords[strings.ToLower(keyword)]
}

// FormField is one directive occurrence inside a host block. Line is 1-based so
// it matches the diagnostics and the editor gutter.
type FormField struct {
	Line      int           `json:"line"`
	Keyword   string        `json:"keyword"`
	Values    []string      `json:"values"`
	Category  FieldCategory `json:"category"`
	Dangerous bool          `json:"dangerous,omitempty"`
	Duplicate bool          `json:"duplicate,omitempty"`
	Editable  bool          `json:"editable"`
}

// FileRef identifies a configuration file for the UI. Files outside the root
// are displayed but carry no relative identifier, so no edit can address them.
type FileRef struct {
	Path     string `json:"path,omitempty"`
	Absolute string `json:"absolute"`
	External bool   `json:"external,omitempty"`
}

func NewFileRef(root, absolute string) FileRef {
	relative, err := RelativePath(root, absolute)
	if err != nil {
		return FileRef{Absolute: absolute, External: true}
	}
	return FileRef{Path: relative, Absolute: absolute}
}

// HostEntry is one Host block as the tree shows it.
type HostEntry struct {
	Identity  HostIdentity `json:"identity"`
	File      FileRef      `json:"file"`
	Line      int          `json:"line"`
	Patterns  []string     `json:"patterns"`
	Wildcard  bool         `json:"wildcard,omitempty"`
	Negated   bool         `json:"negated,omitempty"`
	Duplicate bool         `json:"duplicate,omitempty"`
	Editable  bool         `json:"editable"`
}

// HostForm is one Host block projected for the detail editor. Raw is the exact
// text of the block, so saving it back unchanged reproduces the file byte for
// byte.
type HostForm struct {
	Entry   HostEntry   `json:"entry"`
	Fields  []FormField `json:"fields"`
	Raw     string      `json:"raw"`
	Notices []Notice    `json:"notices,omitempty"`
}

// PrimaryAlias returns the first concrete alias of a Host line, which is the
// alias the UI uses as an identity. A line made only of wildcards or negations
// has no primary alias.
func PrimaryAlias(patterns []config.Pattern) string {
	for _, pattern := range patterns {
		if pattern.Negated || pattern.Wildcard {
			continue
		}
		return pattern.Value
	}
	return ""
}

// MatchesPattern implements OpenSSH's match_pattern: '*' matches any run of
// characters and '?' matches exactly one. Matching is case sensitive and there
// are no character classes.
func MatchesPattern(pattern, candidate string) bool {
	patternIndex, candidateIndex := 0, 0
	starIndex, resumeIndex := -1, 0
	for candidateIndex < len(candidate) {
		switch {
		case patternIndex < len(pattern) && (pattern[patternIndex] == '?' || pattern[patternIndex] == candidate[candidateIndex]):
			patternIndex++
			candidateIndex++
		case patternIndex < len(pattern) && pattern[patternIndex] == '*':
			starIndex = patternIndex
			resumeIndex = candidateIndex
			patternIndex++
		case starIndex >= 0:
			patternIndex = starIndex + 1
			resumeIndex++
			candidateIndex = resumeIndex
		default:
			return false
		}
	}
	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
}

// MatchHostLine applies OpenSSH's rule that any matching negated pattern
// rejects the whole line, and at least one positive pattern must match.
func MatchHostLine(patterns []config.Pattern, candidate string) bool {
	matched := false
	for _, pattern := range patterns {
		if !MatchesPattern(pattern.Value, candidate) {
			continue
		}
		if pattern.Negated {
			return false
		}
		matched = true
	}
	return matched
}

// ProjectHosts lists every Host block in reading order together with the
// notices explaining why some of them cannot be edited as simple hosts.
func ProjectHosts(graph *config.Graph, root string) ([]HostEntry, []Notice) {
	var hosts []HostEntry
	var notices []Notice
	seen := map[string]bool{}

	WalkDirectives(graph, func(visit Visit) bool {
		if visit.Block.Kind != config.BlockHost || visit.Block.Header != visit.Index {
			return true
		}
		entry := HostEntry{
			File:     NewFileRef(root, visit.Path),
			Line:     visit.Index + 1,
			Patterns: make([]string, 0, len(visit.Block.Patterns)),
		}
		node, ok := graph.Nodes[visit.Path]
		entry.Editable = ok && node.Editable && !entry.File.External
		for _, pattern := range visit.Block.Patterns {
			entry.Patterns = append(entry.Patterns, pattern.Raw)
			entry.Wildcard = entry.Wildcard || pattern.Wildcard
			entry.Negated = entry.Negated || pattern.Negated
		}
		if entry.File.External {
			notices = appendNotice(notices, Notice{
				Code: NoticeExternalFile, Line: entry.Line, Detail: visit.Path,
			})
		}

		if entry.Negated {
			notices = appendNotice(notices, Notice{
				Code: NoticeNegatedPattern, Path: entry.File.Path, Line: entry.Line,
				Detail: visit.Condition,
			})
			notices = appendNotice(notices, Notice{
				Code: NoticeComplexExternalRule, Path: entry.File.Path, Line: entry.Line,
				Detail: visit.Condition,
			})
		}

		alias := PrimaryAlias(visit.Block.Patterns)
		if alias == "" {
			notices = appendNotice(notices, Notice{
				Code: NoticeUnnamedHostBlock, Path: entry.File.Path, Line: entry.Line,
				Detail: visit.Condition,
			})
			notices = appendNotice(notices, Notice{
				Code: NoticeWildcardShadow, Path: entry.File.Path, Line: entry.Line,
				Detail: visit.Condition,
			})
			hosts = append(hosts, entry)
			return true
		}
		if !entry.File.External {
			entry.Identity = HostIdentity{Path: entry.File.Path, Alias: alias}
		}
		key := entry.File.Absolute + "\x00" + alias
		if seen[key] {
			entry.Duplicate = true
			notices = appendNotice(notices, Notice{
				Code: NoticeDuplicateAlias, Path: entry.File.Path, Line: entry.Line, Detail: alias,
			})
			notices = appendNotice(notices, Notice{
				Code: NoticeComplexExternalRule, Path: entry.File.Path, Line: entry.Line, Detail: alias,
			})
		}
		seen[key] = true
		hosts = append(hosts, entry)
		return true
	})
	return hosts, notices
}

// ProjectHostForm builds the detail view of one host block. The first block
// declaring the identity wins, which is also the block OpenSSH reads first.
func ProjectHostForm(graph *config.Graph, root string, identity HostIdentity) (HostForm, error) {
	absolute, err := AbsolutePath(root, identity.Path)
	if err != nil {
		return HostForm{}, err
	}
	node, ok := graph.Nodes[absolute]
	if !ok || node.File == nil {
		return HostForm{}, ErrHostNotFound
	}
	block, ok := FindHostBlock(node.File, identity.Alias)
	if !ok {
		return HostForm{}, ErrHostNotFound
	}

	form := HostForm{
		Entry: HostEntry{
			Identity: identity,
			File:     NewFileRef(root, absolute),
			Line:     block.Header + 1,
			Patterns: make([]string, 0, len(block.Patterns)),
			Editable: node.Editable,
		},
		// Fields is required by the contract, so it is an empty array rather
		// than null for a block that declares no directive.
		Fields: []FormField{},
	}
	for _, pattern := range block.Patterns {
		form.Entry.Patterns = append(form.Entry.Patterns, pattern.Raw)
		form.Entry.Wildcard = form.Entry.Wildcard || pattern.Wildcard
		form.Entry.Negated = form.Entry.Negated || pattern.Negated
	}

	keywordSeen := map[string]bool{}
	var raw strings.Builder
	raw.WriteString(node.File.Lines[block.Header].Render())
	for index := block.Start; index < block.End; index++ {
		line := node.File.Lines[index]
		raw.WriteString(line.Render())
		switch line.Kind {
		case config.LineUnstructured:
			form.Notices = appendNotice(form.Notices, Notice{
				Code: NoticeUnstructuredLine, Path: identity.Path, Line: index + 1,
			})
		case config.LineDirective:
			lowered := strings.ToLower(line.Keyword)
			field := FormField{
				Line:      index + 1,
				Keyword:   line.Keyword,
				Values:    line.Values(),
				Category:  CategoryFor(line.Keyword),
				Dangerous: IsDangerousKeyword(line.Keyword),
				Duplicate: keywordSeen[lowered],
				Editable:  node.Editable,
			}
			keywordSeen[lowered] = true
			if field.Dangerous {
				form.Notices = appendNotice(form.Notices, Notice{
					Code: NoticeDangerousDirective, Path: identity.Path, Line: field.Line, Detail: line.Keyword,
				})
			}
			form.Fields = append(form.Fields, field)
		}
	}
	form.Raw = raw.String()
	return form, nil
}

// FindHostBlock returns the first Host block whose primary alias matches.
func FindHostBlock(file *config.File, alias string) (config.Block, bool) {
	for _, block := range file.Blocks() {
		if block.Kind != config.BlockHost {
			continue
		}
		if PrimaryAlias(block.Patterns) == alias {
			return block, true
		}
	}
	return config.Block{}, false
}

// DiagnosticView is a config.Diagnostic prepared for the HTTP contract.
type DiagnosticView struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
	Absolute string `json:"absolute,omitempty"`
	External bool   `json:"external,omitempty"`
	Line     int    `json:"line,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// SeverityName renders a severity as the stable string the contract uses.
func SeverityName(severity config.Severity) string {
	switch severity {
	case config.SeverityError:
		return "error"
	case config.SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

func NewDiagnosticView(root string, diagnostic config.Diagnostic) DiagnosticView {
	reference := NewFileRef(root, diagnostic.Path)
	return DiagnosticView{
		Severity: SeverityName(diagnostic.Severity),
		Code:     diagnostic.Code,
		Path:     reference.Path,
		Absolute: reference.Absolute,
		External: reference.External,
		Line:     diagnostic.Line,
		Detail:   diagnostic.Detail,
	}
}
