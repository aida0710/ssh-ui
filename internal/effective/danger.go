// Package effective explains and evaluates the configuration OpenSSH will
// actually use for one Host alias.
//
// Nothing in this package starts a program unless the caller passed an
// explicit confirmation obtained from the user, because evaluating an OpenSSH
// configuration can execute a command all by itself.
package effective

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"ssh-ui/internal/config"
)

// TokenEscapeWarning is displayed next to every executable directive.
//
// OpenSSH expands %h, %p, %r and friends into the command it runs without
// quoting them for a shell, so a hostname or user value taken from the
// configuration can reach that shell unchanged.
const TokenEscapeWarning = "OpenSSH does not shell-escape the tokens it expands. A hostname, port or user value can reach the shell of this command unchanged."

// Executable is one directive that can make OpenSSH run a program.
type Executable struct {
	// Keyword is the canonical spelling, or "Match exec" for a Match criterion.
	Keyword string
	// Command is the argument text exactly as it appears in the file.
	Command string
	Path    string
	// Line is 1-based.
	Line int
	// Condition is the enclosing Host or Match header, empty in the global block.
	Condition string
	// OnEvaluate is true when merely evaluating the configuration runs it.
	OnEvaluate bool
	// OnConnect is true when establishing a connection runs it.
	OnConnect bool
	// Overridable is true when a command-line option can disable it for one run.
	Overridable bool
}

// Report lists every executable directive reachable from the configuration.
//
// The scan is not narrowed to one alias on purpose. OpenSSH evaluates Match
// lines while it reads the file, so a Match exec anywhere in the graph can run
// while any alias is evaluated, and a reader deserves to see every command the
// file can start rather than a filtered subset.
type Report struct {
	Directives []Executable
}

var executableDirectives = map[string]Executable{
	"proxycommand":      {Keyword: "ProxyCommand", OnConnect: true},
	"knownhostscommand": {Keyword: "KnownHostsCommand", OnConnect: true},
	"localcommand":      {Keyword: "LocalCommand", OnConnect: true, Overridable: true},
	"remotecommand":     {Keyword: "RemoteCommand", OnConnect: true, Overridable: true},
}

// Scan collects the executable directives of every file in the graph.
func Scan(graph *config.Graph) Report {
	report := Report{}
	if graph == nil {
		return report
	}
	for _, filePath := range graph.Order {
		node := graph.Nodes[filePath]
		if node == nil || node.File == nil {
			continue
		}
		for _, block := range node.File.Blocks() {
			condition := node.File.Condition(block)
			if block.Kind == config.BlockMatch {
				for _, criterion := range block.Criteria {
					// config lowercases Match criterion keywords.
					if criterion.Keyword != "exec" {
						continue
					}
					report.Directives = append(report.Directives, Executable{
						Keyword:    "Match exec",
						Command:    criterion.Argument,
						Path:       filePath,
						Line:       block.Header + 1,
						Condition:  condition,
						OnEvaluate: true,
						OnConnect:  true,
					})
				}
			}
			for index := block.Start; index < block.End; index++ {
				line := node.File.Lines[index]
				if line.Kind != config.LineDirective {
					continue
				}
				template, ok := executableDirectives[strings.ToLower(line.Keyword)]
				if !ok {
					continue
				}
				directive := template
				directive.Command = argumentText(line)
				directive.Path = filePath
				directive.Line = index + 1
				directive.Condition = condition
				report.Directives = append(report.Directives, directive)
			}
		}
	}
	return report
}

// EvaluationNeedsConfirmation reports whether `ssh -G` may run a command.
func (r Report) EvaluationNeedsConfirmation() bool {
	for _, directive := range r.Directives {
		if directive.OnEvaluate {
			return true
		}
	}
	return false
}

// ConnectionNeedsConfirmation reports whether connecting may run a command.
func (r Report) ConnectionNeedsConfirmation() bool {
	return len(r.Directives) > 0
}

// Unavoidable returns the directives no command-line option can disable. A
// connection that would run one of them starts only after the user confirmed
// the exact command text.
func (r Report) Unavoidable() []Executable {
	var remaining []Executable
	for _, directive := range r.Directives {
		if directive.OnConnect && !directive.Overridable {
			remaining = append(remaining, directive)
		}
	}
	return remaining
}

// Evidence is a stable digest of what a confirmation dialog must display.
//
// An action token is bound to this value, so a configuration edited between
// the confirmation and the execution invalidates the confirmation instead of
// silently running a different command.
func (r Report) Evidence() string {
	entries := make([]string, 0, len(r.Directives))
	for _, directive := range r.Directives {
		entries = append(entries, fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s",
			directive.Keyword, directive.Command, directive.Path, directive.Line, directive.Condition))
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:])
}

// argumentText returns a directive's argument portion exactly as written,
// without the indent, keyword, separator or line ending.
func argumentText(line config.Line) string {
	var builder strings.Builder
	for _, argument := range line.Arguments {
		builder.WriteString(argument.Lead)
		builder.WriteString(argument.Raw)
	}
	return strings.TrimSpace(builder.String())
}
