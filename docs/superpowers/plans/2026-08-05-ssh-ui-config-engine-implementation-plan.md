# SSH UI Lossless Config Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the byte-preserving SSH configuration engine and the safe filesystem layer beneath it: a lossless parser and renderer, a block view, an `Include` graph with diagnostics, a workspace path guard, an atomic multi-file transaction manager, and a journal that survives a crash.

**Architecture:** `internal/config` is a pure, stdlib-only syntax package. It parses a configuration file into lines that render back byte-for-byte, exposes `Host`/`Match` blocks over those lines, and resolves the `Include` graph through a small read-only `Loader` interface it defines itself. `internal/storage` owns every filesystem effect: a `FileSystem` seam for fault injection, a `Workspace` that pins all writes inside the resolved `~/.ssh` root without following symbolic links, and a `Manager` that stages all new contents durably, journals its intent, renames atomically, and can roll back or complete an interrupted commit at startup. `storage` depends on `config` only in the adapter and integration test; `config` never imports `storage`.

**Tech Stack:** Go 1.26.5, standard library only for this plan (no new modules), `testing.F` fuzzing, `t.TempDir()` filesystem tests.

## Global Constraints

- This plan adds no HTTP routes, no OpenAPI changes, and no frontend code. Roadmap subsystem 3 owns the Connections UI, Include explorer and Raw editor; this plan delivers only the Go engine those features consume.
- Add no third-party Go dependency. `go.mod` direct requirements must be unchanged when this plan completes.
- Parsing then rendering an unmodified file must produce the original bytes exactly, for every input, including invalid UTF-8, CRLF, missing final newline and unknown directives.
- Never delete, reformat or normalise a directive the engine does not understand. Unparsable lines are preserved verbatim.
- Automated tests must not read or modify the real `~/.ssh`, Keychain, ssh-agent, Terminal, or any remote host. Filesystem tests use `t.TempDir()` and fakes only.
- Every write path stays inside the resolved workspace root. External paths, `..` segments and symbolic links must not widen the writable set.
- Reads use `O_NOFOLLOW`; a symbolic link is displayed but never followed for editing.
- Configuration files are written `0600`; managed directories are `0700`. A stricter existing permission is preserved; a looser one is tightened.
- Do not log file contents, request bodies, secrets, or full paths. Errors returned to callers may name a path; log lines must not.
- Keep macOS-specific syscalls inside `internal/storage`'s OS `FileSystem` implementation.
- `ssh -G` differential testing (design §10.2) is explicitly deferred to roadmap subsystem 5, which owns effective-configuration evaluation; do not execute `ssh` from this plan's code or tests.

---

## File Structure

```text
internal/
├── config/                          # pure syntax engine, no filesystem effects
│   ├── token.go                     # argument tokenizer and quoting rules
│   ├── line.go                      # Line/Argument model and line rendering
│   ├── parse.go                     # Parse and File rendering
│   ├── block.go                     # Host/Match block view, patterns, criteria
│   ├── include.go                   # Loader interface, Resolver, path expansion
│   ├── graph.go                     # Include graph walk and diagnostics
│   ├── token_test.go
│   ├── parse_test.go
│   ├── fuzz_test.go
│   ├── block_test.go
│   ├── include_test.go
│   ├── graph_test.go
│   └── testdata/golden/realistic.conf
└── storage/                         # every filesystem effect lives here
    ├── filesystem.go                # FileSystem seam and OS implementation
    ├── workspace.go                 # root resolution and write-path guard
    ├── transaction.go               # staged, journalled, atomic multi-file commit
    ├── journal.go                   # pending detection, rollback, completion
    ├── history.go                   # completed transaction records
    ├── loader.go                    # config.Loader adapter over the workspace
    ├── filesystem_test.go
    ├── workspace_test.go
    ├── transaction_test.go
    ├── journal_test.go
    ├── history_test.go
    └── integration_test.go          # package storage_test, config + storage
```

## Task 1: Lossless line model, tokenizer, parser and renderer

**Files:**
- Create: `internal/config/token.go`
- Create: `internal/config/line.go`
- Create: `internal/config/parse.go`
- Create: `internal/config/token_test.go`
- Create: `internal/config/parse_test.go`
- Create: `internal/config/fuzz_test.go`
- Create: `internal/config/testdata/golden/realistic.conf`

**Interfaces:**
- Produces: `config.Argument{Lead, Raw, Value string}`.
- Produces: `config.LineKind` constants `LineBlank`, `LineComment`, `LineDirective`, `LineUnstructured`.
- Produces: `config.Line{Kind, Text, Indent, Keyword, Separator, Arguments, Trailing, Ending}` and `(Line).Render() string`, `(Line).Values() []string`.
- Produces: `config.File{Lines []Line}`, `config.Parse(source []byte) *File`, `(*File).Render() []byte`.
- Produces: `config.EqualKeyword(a, b string) bool`.
- Consumes: nothing.

- [ ] **Step 1: Write the failing tokenizer test**

```go
// internal/config/token_test.go
package config

import "testing"

func TestSplitArgumentsPreservesEveryByte(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		values   []string
		trailing string
	}{
		{"single", " example", []string{"example"}, ""},
		{"multiple with tabs", "\tone\ttwo  three", []string{"one", "two", "three"}, ""},
		{"quoted with spaces", ` "jump host" plain`, []string{"jump host", "plain"}, ""},
		{"empty quotes", ` ""`, []string{""}, ""},
		{"trailing whitespace", " value  \t", []string{"value"}, "  \t"},
		{"only whitespace", "   ", nil, "   "},
		{"empty", "", nil, ""},
		{"hash token is preserved", " 22 #trailing", []string{"22", "#trailing"}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments, trailing, ok := splitArguments(test.input)
			if !ok {
				t.Fatalf("splitArguments(%q) reported unstructured input", test.input)
			}
			if trailing != test.trailing {
				t.Errorf("trailing = %q, want %q", trailing, test.trailing)
			}
			if len(arguments) != len(test.values) {
				t.Fatalf("arguments = %#v, want %d values", arguments, len(test.values))
			}
			rendered := ""
			for index, argument := range arguments {
				if argument.Value != test.values[index] {
					t.Errorf("value[%d] = %q, want %q", index, argument.Value, test.values[index])
				}
				rendered += argument.Lead + argument.Raw
			}
			if rendered+trailing != test.input {
				t.Fatalf("re-rendered %q, want %q", rendered+trailing, test.input)
			}
		})
	}
}

func TestSplitArgumentsRejectsQuotingItCannotReproduce(t *testing.T) {
	for _, input := range []string{` "unterminated`, ` "closed"tail`, ` bare"quote`} {
		if _, _, ok := splitArguments(input); ok {
			t.Errorf("splitArguments(%q) accepted ambiguous quoting", input)
		}
	}
}
```

- [ ] **Step 2: Run the test and verify the package is absent**

Run: `go test ./internal/config`

Expected: FAIL — the package does not exist yet, so the build reports `no Go files` or `undefined: splitArguments`.

- [ ] **Step 3: Implement the tokenizer**

```go
// internal/config/token.go
package config

import "strings"

// Argument is one directive argument together with the exact bytes that
// produced it. Lead holds the whitespace that precedes the argument so a
// parsed line can be rendered back byte-for-byte.
type Argument struct {
	Lead  string
	Raw   string
	Value string
}

// splitArguments splits the argument portion of a directive line.
//
// OpenSSH's argv_split treats a double quote that starts a token as the start
// of a quoted string that runs to the next double quote, and supports no
// backslash escapes. Input whose quoting cannot be reproduced under that rule
// is reported as unstructured (ok == false) so the caller keeps the line
// verbatim instead of guessing at its meaning.
func splitArguments(input string) (arguments []Argument, trailing string, ok bool) {
	index := 0
	for {
		leadStart := index
		for index < len(input) && isSpace(input[index]) {
			index++
		}
		lead := input[leadStart:index]
		if index == len(input) {
			return arguments, lead, true
		}

		rawStart := index
		var value string
		if input[index] == '"' {
			index++
			closing := strings.IndexByte(input[index:], '"')
			if closing < 0 {
				return nil, "", false
			}
			value = input[index : index+closing]
			index += closing + 1
			if index < len(input) && !isSpace(input[index]) {
				return nil, "", false
			}
		} else {
			for index < len(input) && !isSpace(input[index]) {
				if input[index] == '"' {
					return nil, "", false
				}
				index++
			}
			value = input[rawStart:index]
		}

		arguments = append(arguments, Argument{
			Lead:  lead,
			Raw:   input[rawStart:index],
			Value: value,
		})
	}
}

func isSpace(character byte) bool {
	return character == ' ' || character == '\t'
}
```

- [ ] **Step 4: Run the tokenizer tests**

Run: `go test ./internal/config -run TestSplitArguments -v`

Expected: PASS.

- [ ] **Step 5: Write the failing parser and round-trip tests**

```go
// internal/config/parse_test.go
package config

import (
	"bytes"
	"os"
	"testing"
)

func TestParseClassifiesLines(t *testing.T) {
	source := []byte("# comment\n\n  Host  example  \nHostName=10.0.0.1\n\tUnknownDirective \"a b\"\n\"quoted keyword\" x\n")
	file := Parse(source)
	if len(file.Lines) != 6 {
		t.Fatalf("lines = %d", len(file.Lines))
	}
	wantKinds := []LineKind{LineComment, LineBlank, LineDirective, LineDirective, LineDirective, LineUnstructured}
	for index, want := range wantKinds {
		if file.Lines[index].Kind != want {
			t.Errorf("line %d kind = %v, want %v", index, file.Lines[index].Kind, want)
		}
	}

	host := file.Lines[2]
	if host.Indent != "  " || host.Keyword != "Host" || host.Separator != "  " || host.Trailing != "  " {
		t.Errorf("host line = %#v", host)
	}
	if values := host.Values(); len(values) != 1 || values[0] != "example" {
		t.Errorf("host values = %#v", values)
	}

	hostName := file.Lines[3]
	if hostName.Keyword != "HostName" || hostName.Separator != "=" {
		t.Errorf("hostname line = %#v", hostName)
	}
	if values := file.Lines[4].Values(); len(values) != 1 || values[0] != "a b" {
		t.Errorf("unknown directive values = %#v", file.Lines[4].Values())
	}
}

func TestParseAndRenderRoundTripsExactBytes(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{"empty", ""},
		{"no trailing newline", "Host example"},
		{"crlf", "Host example\r\nHostName 10.0.0.1\r\n"},
		{"mixed endings", "Host a\nHost b\r\n\nHost c"},
		{"blank whitespace line", "Host a\n \t\nPort 22\n"},
		{"equals with spaces", "Host   =  example\n"},
		{"unterminated quote", "ProxyCommand \"broken\n"},
		{"invalid utf8", "Host \xff\xfe\n"},
		{"nul byte", "Host a\x00b\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rendered := Parse([]byte(test.source)).Render()
			if !bytes.Equal(rendered, []byte(test.source)) {
				t.Fatalf("render = %q, want %q", rendered, test.source)
			}
		})
	}
}

func TestGoldenFixtureRoundTripsExactBytes(t *testing.T) {
	source, err := os.ReadFile("testdata/golden/realistic.conf")
	if err != nil {
		t.Fatal(err)
	}
	if rendered := Parse(source).Render(); !bytes.Equal(rendered, source) {
		t.Fatalf("golden fixture did not round-trip")
	}
}

func TestEqualKeywordIgnoresCase(t *testing.T) {
	if !EqualKeyword("hostname", "HostName") || EqualKeyword("host", "hostname") {
		t.Fatal("EqualKeyword does not match OpenSSH case-insensitive keywords")
	}
}

func TestValuesStopAtCommentButRenderKeepsIt(t *testing.T) {
	source := []byte("Port 22 # inline note\n")
	file := Parse(source)
	if values := file.Lines[0].Values(); len(values) != 1 || values[0] != "22" {
		t.Fatalf("values = %#v, want [22]", file.Lines[0].Values())
	}
	if rendered := file.Render(); !bytes.Equal(rendered, source) {
		t.Fatalf("render = %q, want %q", rendered, source)
	}
}
```

- [ ] **Step 6: Create the golden fixture**

```text
# internal/config/testdata/golden/realistic.conf
# Managed by hand since 2019. Do not reformat.

Include conf.d/*.conf
Include	"~/.ssh/extra hosts.conf"

Host bastion jump.example.com
	HostName=203.0.113.10
	User    ops
	Port 2222
	IdentityFile ~/.ssh/id_ed25519_bastion

Host internal-* !internal-legacy
  ProxyJump bastion
  ForwardAgent yes
  UnknownFutureDirective some "quoted value" 3

Match host db.internal user ops
	IdentityAgent "/tmp/agent sock"

Host *
	ServerAliveInterval 30
	# trailing comment inside a block
```

Keep the file's final byte a newline and keep the mixture of tab and space indentation exactly as written; the fixture exists to prove the parser preserves it.

- [ ] **Step 7: Implement the line model**

```go
// internal/config/line.go
package config

import "strings"

// LineKind classifies a physical line of an OpenSSH client configuration file.
type LineKind uint8

const (
	// LineBlank is an empty line or a line containing only whitespace.
	LineBlank LineKind = iota
	// LineComment is a line whose first non-whitespace character is '#'.
	LineComment
	// LineDirective is a keyword with zero or more arguments.
	LineDirective
	// LineUnstructured is a line the engine preserves verbatim because its
	// structure cannot be reproduced exactly. It is never rewritten.
	LineUnstructured
)

// Line is one physical line. For every kind except LineDirective the complete
// line text is kept in Text. For LineDirective the components satisfy
// Indent+Keyword+Separator+arguments+Trailing == the original line text.
type Line struct {
	Kind      LineKind
	Text      string
	Indent    string
	Keyword   string
	Separator string
	Arguments []Argument
	Trailing  string
	Ending    string
}

// Render returns the line exactly as it appeared in the source file.
func (l Line) Render() string {
	if l.Kind != LineDirective {
		return l.Text + l.Ending
	}
	var builder strings.Builder
	builder.WriteString(l.Indent)
	builder.WriteString(l.Keyword)
	builder.WriteString(l.Separator)
	for _, argument := range l.Arguments {
		builder.WriteString(argument.Lead)
		builder.WriteString(argument.Raw)
	}
	builder.WriteString(l.Trailing)
	builder.WriteString(l.Ending)
	return builder.String()
}

// Values returns the unquoted argument values of a directive line, stopping at
// the first unquoted '#' token because OpenSSH's argv_split terminates a
// configuration line's argument list at a comment. Arguments keeps the full
// tokenization so the line still renders byte-for-byte.
func (l Line) Values() []string {
	if l.Kind != LineDirective || len(l.Arguments) == 0 {
		return nil
	}
	values := make([]string, 0, len(l.Arguments))
	for _, argument := range l.Arguments {
		if strings.HasPrefix(argument.Raw, "#") {
			break
		}
		values = append(values, argument.Value)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

// EqualKeyword compares two directive keywords the way OpenSSH does, which is
// case-insensitively for ASCII keywords.
func EqualKeyword(first, second string) bool {
	return strings.EqualFold(first, second)
}
```

- [ ] **Step 8: Implement the parser and file renderer**

```go
// internal/config/parse.go
package config

import "strings"

// File is a parsed configuration file. Rendering an unmodified File returns
// the original bytes exactly.
type File struct {
	Lines []Line
}

// Parse splits source into lines and classifies each one. Parse never fails:
// input it cannot decompose is preserved as LineUnstructured.
func Parse(source []byte) *File {
	file := &File{}
	remaining := string(source)
	for len(remaining) > 0 {
		content, ending, rest := splitLine(remaining)
		file.Lines = append(file.Lines, parseLine(content, ending))
		remaining = rest
	}
	return file
}

// Render returns the file contents.
func (f *File) Render() []byte {
	var builder strings.Builder
	for _, line := range f.Lines {
		builder.WriteString(line.Render())
	}
	return []byte(builder.String())
}

func splitLine(text string) (content, ending, rest string) {
	index := strings.IndexByte(text, '\n')
	if index < 0 {
		return text, "", ""
	}
	content, ending, rest = text[:index], "\n", text[index+1:]
	if strings.HasSuffix(content, "\r") {
		content, ending = content[:len(content)-1], "\r\n"
	}
	return content, ending, rest
}

func parseLine(content, ending string) Line {
	index := 0
	for index < len(content) && isSpace(content[index]) {
		index++
	}
	if index == len(content) {
		return Line{Kind: LineBlank, Text: content, Ending: ending}
	}
	if content[index] == '#' {
		return Line{Kind: LineComment, Text: content, Ending: ending}
	}

	indent := content[:index]
	keywordStart := index
	for index < len(content) && !isSpace(content[index]) && content[index] != '=' && content[index] != '"' {
		index++
	}
	keyword := content[keywordStart:index]
	if keyword == "" {
		return Line{Kind: LineUnstructured, Text: content, Ending: ending}
	}

	separatorStart := index
	for index < len(content) && isSpace(content[index]) {
		index++
	}
	if index < len(content) && content[index] == '=' {
		index++
		for index < len(content) && isSpace(content[index]) {
			index++
		}
	}
	separator := content[separatorStart:index]

	arguments, trailing, ok := splitArguments(content[index:])
	if !ok {
		return Line{Kind: LineUnstructured, Text: content, Ending: ending}
	}
	return Line{
		Kind:      LineDirective,
		Indent:    indent,
		Keyword:   keyword,
		Separator: separator,
		Arguments: arguments,
		Trailing:  trailing,
		Ending:    ending,
	}
}
```

- [ ] **Step 9: Add the round-trip fuzz target**

```go
// internal/config/fuzz_test.go
package config

import (
	"bytes"
	"testing"
)

func FuzzParseRendersOriginalBytes(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("Host example\n  HostName 10.0.0.1\n"))
	f.Add([]byte("Host=a\r\n\t# comment\nInclude \"conf.d/*.conf\"\n"))
	f.Add([]byte("ProxyCommand \"unterminated\nPort 22"))
	f.Add([]byte(" \t\n\x00\xff=\"\"\n"))
	f.Fuzz(func(t *testing.T, source []byte) {
		file := Parse(source)
		rendered := file.Render()
		if !bytes.Equal(rendered, source) {
			t.Fatalf("round trip changed bytes: got %q, want %q", rendered, source)
		}
		for index, line := range file.Lines {
			if line.Kind == LineDirective && line.Keyword == "" {
				t.Fatalf("line %d is a directive without a keyword", index)
			}
		}
	})
}
```

- [ ] **Step 10: Run the parser tests, the seed corpus and the race detector**

Run:

```bash
go test ./internal/config -v
go test -race ./internal/config
go test ./internal/config -run '^$' -fuzz FuzzParseRendersOriginalBytes -fuzztime 60s
```

Expected: all PASS; the fuzz run reports no failing input and writes nothing to `testdata/fuzz` (delete any crasher only after fixing the parser, never by weakening the assertion).

- [ ] **Step 11: Commit the lossless parser**

```bash
git add internal/config
git commit -m "feat: parse ssh config without losing bytes"
```

## Task 2: Expose the Host and Match block view

**Files:**
- Create: `internal/config/block.go`
- Create: `internal/config/block_test.go`

**Interfaces:**
- Consumes: Task 1 `config.File`, `config.Line`, `config.EqualKeyword`.
- Produces: `config.BlockKind` constants `BlockGlobal`, `BlockHost`, `BlockMatch`.
- Produces: `config.Pattern{Raw, Value string, Negated, Wildcard bool}`.
- Produces: `config.Criterion{Keyword, Argument string, Negated bool}`.
- Produces: `config.Block{Kind BlockKind, Header, Start, End int, Patterns []Pattern, Criteria []Criterion}`.
- Produces: `(*File).Blocks() []Block` and `(*File).BlockAt(line int) Block`.
- Produces: `(*File).Condition(block Block) string` returning the trimmed header text for display, empty for the global block.

- [ ] **Step 1: Write the failing block tests**

```go
// internal/config/block_test.go
package config

import "testing"

func TestBlocksSplitGlobalHostAndMatchRanges(t *testing.T) {
	source := []byte("Port 22\n\nHost alpha bravo\n\tUser ops\n\nHost !legacy *.internal\n\tPort 2222\n\nMatch host db user ops\n\tIdentityAgent none\n")
	file := Parse(source)
	blocks := file.Blocks()
	if len(blocks) != 4 {
		t.Fatalf("blocks = %d, want 4", len(blocks))
	}

	global := blocks[0]
	if global.Kind != BlockGlobal || global.Header != -1 || global.Start != 0 || global.End != 2 {
		t.Errorf("global = %#v", global)
	}

	alpha := blocks[1]
	if alpha.Kind != BlockHost || alpha.Header != 2 || alpha.Start != 3 || alpha.End != 5 {
		t.Errorf("alpha = %#v", alpha)
	}
	if len(alpha.Patterns) != 2 || alpha.Patterns[0].Value != "alpha" || alpha.Patterns[1].Value != "bravo" {
		t.Errorf("alpha patterns = %#v", alpha.Patterns)
	}

	negated := blocks[2].Patterns
	if len(negated) != 2 {
		t.Fatalf("negated patterns = %#v", negated)
	}
	if !negated[0].Negated || negated[0].Value != "legacy" || negated[0].Raw != "!legacy" {
		t.Errorf("negated[0] = %#v", negated[0])
	}
	if negated[1].Negated || !negated[1].Wildcard || negated[1].Value != "*.internal" {
		t.Errorf("negated[1] = %#v", negated[1])
	}

	match := blocks[3]
	if match.Kind != BlockMatch || len(match.Criteria) != 2 {
		t.Fatalf("match = %#v", match)
	}
	if match.Criteria[0].Keyword != "host" || match.Criteria[0].Argument != "db" {
		t.Errorf("criterion 0 = %#v", match.Criteria[0])
	}
	if match.Criteria[1].Keyword != "user" || match.Criteria[1].Argument != "ops" {
		t.Errorf("criterion 1 = %#v", match.Criteria[1])
	}
	if got := file.Condition(match); got != "Match host db user ops" {
		t.Errorf("condition = %q", got)
	}
	if got := file.Condition(global); got != "" {
		t.Errorf("global condition = %q", got)
	}
}

func TestMatchCriteriaCoverEqualsFormAndArgumentlessKeywords(t *testing.T) {
	file := Parse([]byte("Match final !host=db canonical\n"))
	criteria := file.Blocks()[1].Criteria
	if len(criteria) != 3 {
		t.Fatalf("criteria = %#v", criteria)
	}
	if criteria[0].Keyword != "final" || criteria[0].Argument != "" {
		t.Errorf("criterion 0 = %#v", criteria[0])
	}
	if criteria[1].Keyword != "host" || criteria[1].Argument != "db" || !criteria[1].Negated {
		t.Errorf("criterion 1 = %#v", criteria[1])
	}
	if criteria[2].Keyword != "canonical" {
		t.Errorf("criterion 2 = %#v", criteria[2])
	}
}

func TestBlockAtReturnsEnclosingBlockForEveryLine(t *testing.T) {
	file := Parse([]byte("Port 22\nHost alpha\n\tUser ops\n"))
	if file.BlockAt(0).Kind != BlockGlobal {
		t.Error("line 0 is not global")
	}
	if file.BlockAt(1).Kind != BlockHost || file.BlockAt(2).Kind != BlockHost {
		t.Error("host header and body are not in the host block")
	}
}

func TestEmptyFileStillHasGlobalBlock(t *testing.T) {
	blocks := Parse(nil).Blocks()
	if len(blocks) != 1 || blocks[0].Kind != BlockGlobal || blocks[0].End != 0 {
		t.Fatalf("blocks = %#v", blocks)
	}
}
```

- [ ] **Step 2: Run the tests and verify the block view is absent**

Run: `go test ./internal/config -run 'TestBlock|TestMatch|TestEmptyFile' -v`

Expected: FAIL with `undefined: BlockGlobal` and `file.Blocks undefined`.

- [ ] **Step 3: Implement the block view**

```go
// internal/config/block.go
package config

import "strings"

// BlockKind identifies which conditional construct owns a range of lines.
type BlockKind uint8

const (
	// BlockGlobal holds the lines before the first Host or Match line. It
	// always exists, even when it is empty.
	BlockGlobal BlockKind = iota
	BlockHost
	BlockMatch
)

// Pattern is one argument of a Host line.
type Pattern struct {
	Raw      string
	Value    string
	Negated  bool
	Wildcard bool
}

// Criterion is one attribute of a Match line.
type Criterion struct {
	Keyword  string
	Argument string
	Negated  bool
}

// Block is a half-open line range [Start, End) governed by one header line.
type Block struct {
	Kind     BlockKind
	Header   int
	Start    int
	End      int
	Patterns []Pattern
	Criteria []Criterion
}

// matchCriteriaWithArgument lists the Match attributes that consume the next
// token as their argument. all, canonical and final take no argument.
var matchCriteriaWithArgument = map[string]bool{
	"exec":         true,
	"host":         true,
	"localnetwork": true,
	"localuser":    true,
	"originalhost": true,
	"tagged":       true,
	"user":         true,
}

// Blocks returns every block in file order. The first entry is always the
// global block.
func (f *File) Blocks() []Block {
	blocks := []Block{{Kind: BlockGlobal, Header: -1, Start: 0}}
	for index, line := range f.Lines {
		if line.Kind != LineDirective {
			continue
		}
		switch {
		case EqualKeyword(line.Keyword, "Host"):
			blocks[len(blocks)-1].End = index
			blocks = append(blocks, Block{
				Kind:     BlockHost,
				Header:   index,
				Start:    index + 1,
				Patterns: parsePatterns(line.Values()),
			})
		case EqualKeyword(line.Keyword, "Match"):
			blocks[len(blocks)-1].End = index
			blocks = append(blocks, Block{
				Kind:     BlockMatch,
				Header:   index,
				Start:    index + 1,
				Criteria: parseCriteria(line.Values()),
			})
		}
	}
	blocks[len(blocks)-1].End = len(f.Lines)
	return blocks
}

// BlockAt returns the block that governs the given line index. A Host or Match
// header line belongs to the block it opens.
func (f *File) BlockAt(line int) Block {
	blocks := f.Blocks()
	found := blocks[0]
	for _, block := range blocks {
		if block.Header == line || (line >= block.Start && line < block.End) {
			found = block
		}
	}
	return found
}

// Condition returns the header text of a block for display, without indent or
// line ending. The global block has no condition.
func (f *File) Condition(block Block) string {
	if block.Header < 0 || block.Header >= len(f.Lines) {
		return ""
	}
	return strings.TrimSpace(f.Lines[block.Header].Render())
}

func parsePatterns(values []string) []Pattern {
	patterns := make([]Pattern, 0, len(values))
	for _, value := range values {
		pattern := Pattern{Raw: value, Value: value}
		if strings.HasPrefix(pattern.Value, "!") {
			pattern.Negated = true
			pattern.Value = pattern.Value[1:]
		}
		pattern.Wildcard = strings.ContainsAny(pattern.Value, "*?")
		patterns = append(patterns, pattern)
	}
	return patterns
}

func parseCriteria(values []string) []Criterion {
	criteria := make([]Criterion, 0, len(values))
	for index := 0; index < len(values); index++ {
		keyword := values[index]
		criterion := Criterion{}
		if strings.HasPrefix(keyword, "!") {
			criterion.Negated = true
			keyword = keyword[1:]
		}
		// OpenSSH's strdelim splits a Match attribute from its argument on
		// whitespace or a single '=', so both spellings must be accepted.
		name, argument, hasEquals := strings.Cut(keyword, "=")
		criterion.Keyword = strings.ToLower(name)
		if hasEquals {
			criterion.Argument = argument
			criteria = append(criteria, criterion)
			continue
		}
		if matchCriteriaWithArgument[criterion.Keyword] && index+1 < len(values) {
			index++
			criterion.Argument = values[index]
		}
		criteria = append(criteria, criterion)
	}
	return criteria
}
```

- [ ] **Step 4: Run the block tests**

Run:

```bash
go test ./internal/config
go test -race ./internal/config
```

Expected: PASS.

- [ ] **Step 5: Commit the block view**

```bash
git add internal/config/block.go internal/config/block_test.go
git commit -m "feat: expose ssh config host and match blocks"
```

## Task 3: Expand Include patterns the way OpenSSH does

**Files:**
- Create: `internal/config/include.go`
- Create: `internal/config/include_test.go`

**Interfaces:**
- Consumes: Task 1 and Task 2 types.
- Produces: `config.Loader` interface with `ReadFile(path string) ([]byte, error)` and `Glob(pattern string) ([]string, error)`.
- Produces: `config.Resolver{Loader Loader, Home string, Root string, Tokens map[byte]string, MaxDepth int}`.
- Produces: `config.ErrUnsupportedExpansion`.
- Produces: `(Resolver).expandPattern(argument string) (string, error)` used by Task 4's graph walk.
- Produces: `config.DefaultMaxDepth = 16` matching OpenSSH's `MAX_READCONF_DEPTH`.

- [ ] **Step 1: Write the failing expansion tests**

```go
// internal/config/include_test.go
package config

import (
	"errors"
	"testing"
)

func newTestResolver() Resolver {
	return Resolver{
		Home:   "/Users/tester",
		Root:   "/Users/tester/.ssh",
		Tokens: map[byte]string{'d': "/Users/tester", 'u': "tester", 'i': "501"},
	}
}

func TestExpandPatternFollowsOpenSSHRules(t *testing.T) {
	resolver := newTestResolver()
	tests := []struct {
		name     string
		argument string
		want     string
	}{
		{"relative resolves under the ssh directory", "conf.d/*.conf", "/Users/tester/.ssh/conf.d/*.conf"},
		{"absolute stays absolute", "/etc/ssh/ssh_config", "/etc/ssh/ssh_config"},
		{"tilde uses the home directory", "~/work/config", "/Users/tester/work/config"},
		{"bare tilde is the home directory", "~", "/Users/tester"},
		{"percent d is the home directory", "%d/.ssh/extra", "/Users/tester/.ssh/extra"},
		{"double percent is a literal percent", "weird%%name", "/Users/tester/.ssh/weird%name"},
		{"parent segments are cleaned", "conf.d/../other.conf", "/Users/tester/.ssh/other.conf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolver.expandPattern(test.argument)
			if err != nil {
				t.Fatalf("expandPattern(%q) error = %v", test.argument, err)
			}
			if got != test.want {
				t.Fatalf("expandPattern(%q) = %q, want %q", test.argument, got, test.want)
			}
		})
	}
}

func TestExpandPatternRefusesToGuess(t *testing.T) {
	resolver := newTestResolver()
	for _, argument := range []string{"~other/config", "%h/config", "%C.conf", ""} {
		if got, err := resolver.expandPattern(argument); !errors.Is(err, ErrUnsupportedExpansion) {
			t.Errorf("expandPattern(%q) = %q, %v; want ErrUnsupportedExpansion", argument, got, err)
		}
	}
}

func TestIncludeArgumentsIgnoreOtherDirectives(t *testing.T) {
	file := Parse([]byte("Include a.conf b.conf # note\ninclude\t\"c d.conf\"\nHostName example\n"))
	var collected []string
	for _, line := range file.Lines {
		if line.Kind == LineDirective && EqualKeyword(line.Keyword, "Include") {
			collected = append(collected, line.Values()...)
		}
	}
	want := []string{"a.conf", "b.conf", "c d.conf"}
	if len(collected) != len(want) {
		t.Fatalf("collected = %#v, want %#v", collected, want)
	}
	for index := range want {
		if collected[index] != want[index] {
			t.Fatalf("collected[%d] = %q, want %q", index, collected[index], want[index])
		}
	}
}
```

- [ ] **Step 2: Run the tests and verify the resolver is absent**

Run: `go test ./internal/config -run TestExpandPattern -v`

Expected: FAIL with `undefined: Resolver`.

- [ ] **Step 3: Implement pattern expansion**

```go
// internal/config/include.go
package config

import (
	"errors"
	"path"
	"strings"
)

// DefaultMaxDepth mirrors OpenSSH's MAX_READCONF_DEPTH.
const DefaultMaxDepth = 16

// ErrUnsupportedExpansion is returned for an Include argument whose meaning
// depends on information the engine does not have. The graph reports the
// pattern verbatim instead of guessing which files it would match.
var ErrUnsupportedExpansion = errors.New("include pattern uses an unsupported expansion")

// Loader gives the resolver read-only access to configuration files. The
// storage layer supplies the implementation used in production; tests supply a
// map-backed fake. Paths and patterns are absolute and already cleaned.
type Loader interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// Resolver walks an Include graph starting from a user configuration file.
//
// Home is the absolute home directory used for '~' and '%d'. Root is the
// directory that relative Include arguments resolve against, which OpenSSH
// defines as ~/.ssh for user configuration files, and is also the only
// directory this application may write to. Tokens holds the percent tokens
// that are known before a destination host is chosen; any other token is
// reported as an unsupported expansion.
type Resolver struct {
	Loader   Loader
	Home     string
	Root     string
	Tokens   map[byte]string
	MaxDepth int
}

func (r Resolver) maxDepth() int {
	if r.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return r.MaxDepth
}

// expandPattern converts one Include argument into an absolute glob pattern.
func (r Resolver) expandPattern(argument string) (string, error) {
	if argument == "" {
		return "", ErrUnsupportedExpansion
	}
	expanded, err := r.expandTokens(argument)
	if err != nil {
		return "", err
	}
	switch {
	case expanded == "~":
		expanded = r.Home
	case strings.HasPrefix(expanded, "~/"):
		expanded = r.Home + expanded[1:]
	case strings.HasPrefix(expanded, "~"):
		// '~user/...' needs a password database lookup the engine does not do.
		return "", ErrUnsupportedExpansion
	case !strings.HasPrefix(expanded, "/"):
		expanded = r.Root + "/" + expanded
	}
	return path.Clean(expanded), nil
}

func (r Resolver) expandTokens(argument string) (string, error) {
	if !strings.ContainsRune(argument, '%') {
		return argument, nil
	}
	var builder strings.Builder
	for index := 0; index < len(argument); index++ {
		if argument[index] != '%' {
			builder.WriteByte(argument[index])
			continue
		}
		if index+1 >= len(argument) {
			return "", ErrUnsupportedExpansion
		}
		index++
		if argument[index] == '%' {
			builder.WriteByte('%')
			continue
		}
		value, ok := r.Tokens[argument[index]]
		if !ok {
			return "", ErrUnsupportedExpansion
		}
		builder.WriteString(value)
	}
	return builder.String(), nil
}
```

- [ ] **Step 4: Run the expansion tests**

Run: `go test ./internal/config -run 'TestExpandPattern|TestIncludeArguments' -v`

Expected: PASS.

- [ ] **Step 5: Commit Include expansion**

```bash
git add internal/config/include.go internal/config/include_test.go
git commit -m "feat: expand ssh include patterns without guessing"
```

## Task 4: Walk the Include graph and report diagnostics

**Files:**
- Create: `internal/config/graph.go`
- Create: `internal/config/graph_test.go`

**Interfaces:**
- Consumes: Task 3 `Resolver`, `Loader`, `expandPattern`; Task 2 `Blocks`, `Condition`.
- Produces: `config.Severity` constants `SeverityInfo`, `SeverityWarning`, `SeverityError`.
- Produces: diagnostic code constants listed in Step 3.
- Produces: `config.Diagnostic{Severity, Code, Path, Line, Detail}`.
- Produces: `config.Edge{FromPath string, Line int, Pattern, Expanded string, Matches []string, Condition string}`.
- Produces: `config.Node{Path string, Editable, Missing bool, File *File, Includes []Edge, Loads int}`.
- Produces: `config.Graph{Root string, Order []string, Nodes map[string]*Node, Diagnostics []Diagnostic}`.
- Produces: `(Resolver).Resolve(rootPath string) (*Graph, error)` and `config.ErrPathNotAbsolute`.

- [ ] **Step 1: Write the failing graph tests**

```go
// internal/config/graph_test.go
package config

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"testing"
)

type fakeLoader struct {
	files map[string]string
	fail  map[string]error
}

func (l fakeLoader) ReadFile(name string) ([]byte, error) {
	if err, ok := l.fail[name]; ok {
		return nil, err
	}
	contents, ok := l.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(contents), nil
}

func (l fakeLoader) Glob(pattern string) ([]string, error) {
	var matches []string
	for name := range l.files {
		if matched, err := path.Match(pattern, name); err == nil && matched {
			matches = append(matches, name)
		}
	}
	for name := range l.fail {
		if matched, err := path.Match(pattern, name); err == nil && matched {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

func resolverFor(files map[string]string) Resolver {
	resolver := newTestResolver()
	resolver.Loader = fakeLoader{files: files}
	return resolver
}

func diagnosticCodes(graph *Graph) []string {
	codes := make([]string, 0, len(graph.Diagnostics))
	for _, diagnostic := range graph.Diagnostics {
		codes = append(codes, diagnostic.Code)
	}
	return codes
}

func requireDiagnostic(t *testing.T, graph *Graph, code string) Diagnostic {
	t.Helper()
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Code == code {
			return diagnostic
		}
	}
	t.Fatalf("diagnostic %q missing, got %v", code, diagnosticCodes(graph))
	return Diagnostic{}
}

func TestResolveLoadsIncludedFilesInLexicalGlobOrder(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config":            "Include conf.d/*.conf\nHost direct\n",
		"/Users/tester/.ssh/conf.d/20-b.conf":  "Host bravo\n",
		"/Users/tester/.ssh/conf.d/10-a.conf":  "Host alpha\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/Users/tester/.ssh/config",
		"/Users/tester/.ssh/conf.d/10-a.conf",
		"/Users/tester/.ssh/conf.d/20-b.conf",
	}
	if len(graph.Order) != len(want) {
		t.Fatalf("order = %#v", graph.Order)
	}
	for index := range want {
		if graph.Order[index] != want[index] {
			t.Fatalf("order[%d] = %q, want %q", index, graph.Order[index], want[index])
		}
	}
	root := graph.Nodes["/Users/tester/.ssh/config"]
	if !root.Editable || root.Missing || root.File == nil {
		t.Fatalf("root node = %#v", root)
	}
	if len(root.Includes) != 1 || root.Includes[0].Line != 1 || len(root.Includes[0].Matches) != 2 {
		t.Fatalf("root includes = %#v", root.Includes)
	}
	if root.Includes[0].Condition != "" {
		t.Errorf("top-level include has condition %q", root.Includes[0].Condition)
	}
}

func TestResolveStopsAtIncludeCycle(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Include a.conf\n",
		"/Users/tester/.ssh/a.conf": "Include b.conf\n",
		"/Users/tester/.ssh/b.conf": "Include config\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	cycle := requireDiagnostic(t, graph, DiagnosticIncludeCycle)
	if cycle.Path != "/Users/tester/.ssh/b.conf" || cycle.Severity != SeverityError {
		t.Fatalf("cycle diagnostic = %#v", cycle)
	}
	if len(graph.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(graph.Nodes))
	}
}

func TestResolveCountsDuplicateIncludesWithoutWalkingTwice(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Include shared.conf\nInclude shared.conf\n",
		"/Users/tester/.ssh/shared.conf": "Host shared\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeDuplicate)
	if loads := graph.Nodes["/Users/tester/.ssh/shared.conf"].Loads; loads != 2 {
		t.Fatalf("loads = %d, want 2", loads)
	}
	if len(graph.Order) != 2 {
		t.Fatalf("order = %#v", graph.Order)
	}
}

func TestResolveFlagsConditionalIncludes(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Host work\n\tInclude work.conf\n",
		"/Users/tester/.ssh/work.conf": "User ops\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	conditional := requireDiagnostic(t, graph, DiagnosticIncludeConditional)
	if conditional.Line != 2 {
		t.Fatalf("conditional diagnostic = %#v", conditional)
	}
	edge := graph.Nodes["/Users/tester/.ssh/config"].Includes[0]
	if edge.Condition != "Host work" {
		t.Fatalf("edge condition = %q", edge.Condition)
	}
}

func TestResolveMarksFilesOutsideTheRootAsNotEditable(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Include /etc/ssh/shared.conf\n",
		"/etc/ssh/shared.conf":      "Host shared\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeOutsideRoot)
	outside := graph.Nodes["/etc/ssh/shared.conf"]
	if outside == nil || outside.Editable || outside.File == nil {
		t.Fatalf("outside node = %#v", outside)
	}
}

func TestResolveReportsPatternsItRefusesToExpand(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Include %h/config\nInclude missing/*.conf\nInclude\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	unsupported := requireDiagnostic(t, graph, DiagnosticIncludeUnsupported)
	if unsupported.Line != 1 || unsupported.Severity != SeverityWarning {
		t.Fatalf("unsupported diagnostic = %#v", unsupported)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeNoMatch)
	requireDiagnostic(t, graph, DiagnosticIncludeEmpty)
	edges := graph.Nodes["/Users/tester/.ssh/config"].Includes
	if len(edges) != 2 || edges[0].Expanded != "" || len(edges[0].Matches) != 0 {
		t.Fatalf("edges = %#v", edges)
	}
}

func TestResolveReportsUnreadableAndMissingRoot(t *testing.T) {
	resolver := newTestResolver()
	resolver.Loader = fakeLoader{
		files: map[string]string{"/Users/tester/.ssh/config": "Include broken.conf\n"},
		fail:  map[string]error{"/Users/tester/.ssh/broken.conf": fs.ErrPermission},
	}
	graph, err := resolver.Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	unreadable := requireDiagnostic(t, graph, DiagnosticIncludeUnreadable)
	if unreadable.Severity != SeverityError {
		t.Fatalf("unreadable diagnostic = %#v", unreadable)
	}
	if node := graph.Nodes["/Users/tester/.ssh/broken.conf"]; node == nil || node.File != nil {
		t.Fatalf("broken node = %#v", graph.Nodes["/Users/tester/.ssh/broken.conf"])
	}

	empty := resolverFor(map[string]string{})
	missing, err := empty.Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	if !missing.Nodes["/Users/tester/.ssh/config"].Missing {
		t.Fatal("missing root file was not reported as missing")
	}
}

func TestResolveStopsAtMaxDepth(t *testing.T) {
	files := map[string]string{"/Users/tester/.ssh/config": "Include chain-0.conf\n"}
	for index := 0; index < 20; index++ {
		files[fmt.Sprintf("/Users/tester/.ssh/chain-%d.conf", index)] =
			fmt.Sprintf("Include chain-%d.conf\n", index+1)
	}
	graph, err := resolverFor(files).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeDepthExceeded)
	if len(graph.Nodes) != DefaultMaxDepth+1 {
		t.Fatalf("nodes = %d, want %d", len(graph.Nodes), DefaultMaxDepth+1)
	}
}

func TestResolveRejectsRelativeEntryPath(t *testing.T) {
	if _, err := resolverFor(nil).Resolve("config"); err == nil {
		t.Fatal("Resolve accepted a relative entry path")
	}
}
```

- [ ] **Step 2: Run the tests and verify the graph is absent**

Run: `go test ./internal/config -run TestResolve -v`

Expected: FAIL with `undefined: Graph` and `resolver.Resolve undefined`.

- [ ] **Step 3: Implement the graph walk**

```go
// internal/config/graph.go
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
```

Use the local `slicesContains` helper rather than importing `slices` so the file keeps a single small dependency surface; if the repository later adopts `slices` elsewhere, replace it in one place.

- [ ] **Step 4: Run the graph tests with the race detector**

Run:

```bash
go test ./internal/config -run TestResolve -v
go test -race ./internal/config
```

Expected: PASS, and `TestResolveStopsAtIncludeCycle` completes without hanging.

- [ ] **Step 5: Commit the Include graph**

```bash
git add internal/config/graph.go internal/config/graph_test.go
git commit -m "feat: resolve ssh include graph with diagnostics"
```

## Task 5: Guard every filesystem effect behind a workspace

**Files:**
- Create: `internal/storage/filesystem.go`
- Create: `internal/storage/workspace.go`
- Create: `internal/storage/filesystem_test.go`
- Create: `internal/storage/workspace_test.go`

**Interfaces:**
- Produces: `storage.FileSystem` interface with `ReadFile`, `Lstat`, `ReadDir`, `Glob`, `MkdirAll`, `WriteTemp`, `Rename`, `Remove`, `SyncDir`, `EvalSymlinks`.
- Produces: `storage.OSFileSystem` implementing it for macOS.
- Produces: constants `storage.MaxFileSize`, `storage.DirectoryPermission` (`0o700`), `storage.FilePermission` (`0o600`).
- Produces: errors `ErrFileTooLarge`, `ErrNotRegularFile`, `ErrOutsideWorkspace`, `ErrSymlinkPath`, `ErrMissingDirectory`, `ErrNotDirectory`, `ErrInvalidHome`.
- Produces: `storage.NewWorkspace(fileSystem FileSystem, home string) (*Workspace, error)` and methods `FileSystem()`, `Home()`, `Root()`, `StateDir()`, `Contains(string) bool`, `ResolveForWrite(string) (string, error)`, `EnsureDirectory(string) error`.
- Consumes: nothing from `internal/config`.

- [ ] **Step 1: Write the failing filesystem tests**

```go
// internal/storage/filesystem_test.go
package storage

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOSFileSystemReadFileRefusesSymlinksAndOversizedFiles(t *testing.T) {
	directory := t.TempDir()
	fileSystem := OSFileSystem{}

	target := filepath.Join(directory, "config")
	if err := os.WriteFile(target, []byte("Host example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := fileSystem.ReadFile(target)
	if err != nil || !bytes.Equal(contents, []byte("Host example\n")) {
		t.Fatalf("ReadFile = %q, %v", contents, err)
	}

	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSystem.ReadFile(link); !errors.Is(err, ErrSymlinkPath) {
		t.Fatalf("ReadFile(symlink) error = %v, want ErrSymlinkPath", err)
	}

	if _, err := fileSystem.ReadFile(directory); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("ReadFile(directory) error = %v, want ErrNotRegularFile", err)
	}

	oversized := filepath.Join(directory, "big")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSystem.ReadFile(oversized); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("ReadFile(oversized) error = %v, want ErrFileTooLarge", err)
	}
}

func TestOSFileSystemWriteTempCreatesPrivateFileInTargetDirectory(t *testing.T) {
	directory := t.TempDir()
	path, err := OSFileSystem{}.WriteTemp(directory, ".ssh-ui-", FilePermission, []byte("staged"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != directory || !strings.HasPrefix(filepath.Base(path), ".ssh-ui-") {
		t.Fatalf("temp path = %q", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != FilePermission {
		t.Fatalf("permission = %v, want %v", info.Mode().Perm(), FilePermission)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "staged" {
		t.Fatalf("contents = %q, %v", contents, err)
	}
}

func TestOSFileSystemSyncDirAndGlobAreLexical(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"20-b.conf", "10-a.conf"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := OSFileSystem{}.Glob(filepath.Join(directory, "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 || filepath.Base(matches[0]) != "10-a.conf" {
		t.Fatalf("matches = %#v", matches)
	}
	if err := OSFileSystem{}.SyncDir(directory); err != nil {
		t.Fatalf("SyncDir = %v", err)
	}
	if _, err := OSFileSystem{}.Lstat(filepath.Join(directory, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Lstat(missing) error = %v", err)
	}
}
```

- [ ] **Step 2: Write the failing workspace tests**

```go
// internal/storage/workspace_test.go
package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newTestWorkspace builds an isolated home directory. macOS temporary
// directories are themselves reached through a symbolic link, so tests must
// compare against workspace.Root() instead of the literal path they built.
func newTestWorkspace(t *testing.T) *Workspace {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := NewWorkspace(OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestNewWorkspaceResolvesSymlinkedRootAndRejectsRelativeHome(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "real-ssh")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	workspace, err := NewWorkspace(OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Root() != resolved {
		t.Fatalf("root = %q, want %q", workspace.Root(), resolved)
	}
	if _, err := NewWorkspace(OSFileSystem{}, "relative/home"); !errors.Is(err, ErrInvalidHome) {
		t.Fatalf("relative home error = %v", err)
	}
}

func TestResolveForWriteAcceptsOnlyRealFilesInsideTheRoot(t *testing.T) {
	workspace := newTestWorkspace(t)
	root := workspace.Root()
	existing := filepath.Join(root, "config")
	if err := os.WriteFile(existing, []byte("Host example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}

	if got, err := workspace.ResolveForWrite(existing); err != nil || got != existing {
		t.Fatalf("existing file = %q, %v", got, err)
	}
	newFile := filepath.Join(root, "conf.d", "new.conf")
	if got, err := workspace.ResolveForWrite(newFile); err != nil || got != newFile {
		t.Fatalf("new file = %q, %v", got, err)
	}

	outside := filepath.Join(filepath.Dir(root), "outside.conf")
	for name, candidate := range map[string]string{
		"outside the root":  outside,
		"parent traversal":  filepath.Join(root, "..", "outside.conf"),
		"root itself":       root,
		"missing directory": filepath.Join(root, "absent", "new.conf"),
		"relative path":     "config",
	} {
		if _, err := workspace.ResolveForWrite(candidate); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestResolveForWriteRejectsSymlinkedFileAndParent(t *testing.T) {
	workspace := newTestWorkspace(t)
	root := workspace.Root()
	outsideDirectory := t.TempDir()
	outsideFile := filepath.Join(outsideDirectory, "target.conf")
	if err := os.WriteFile(outsideFile, []byte("Host elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "linked.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDirectory, filepath.Join(root, "linked.d")); err != nil {
		t.Fatal(err)
	}

	if _, err := workspace.ResolveForWrite(filepath.Join(root, "linked.conf")); !errors.Is(err, ErrSymlinkPath) {
		t.Errorf("symlinked file error = %v, want ErrSymlinkPath", err)
	}
	if _, err := workspace.ResolveForWrite(filepath.Join(root, "linked.d", "new.conf")); !errors.Is(err, ErrSymlinkPath) {
		t.Errorf("symlinked parent error = %v, want ErrSymlinkPath", err)
	}
}

func TestEnsureDirectoryCreatesPrivateDirectoriesAndRejectsSymlinks(t *testing.T) {
	workspace := newTestWorkspace(t)
	nested := filepath.Join(workspace.StateDir(), "journal")
	if err := workspace.EnsureDirectory(nested); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != DirectoryPermission {
		t.Fatalf("permission = %v, want %v", info.Mode().Perm(), DirectoryPermission)
	}
	if err := workspace.EnsureDirectory(nested); err != nil {
		t.Fatalf("second call = %v", err)
	}

	if err := os.Symlink(t.TempDir(), filepath.Join(workspace.Root(), "linked.d")); err != nil {
		t.Fatal(err)
	}
	if err := workspace.EnsureDirectory(filepath.Join(workspace.Root(), "linked.d", "child")); !errors.Is(err, ErrSymlinkPath) {
		t.Fatalf("symlinked component error = %v, want ErrSymlinkPath", err)
	}
	if err := workspace.EnsureDirectory(filepath.Join(filepath.Dir(workspace.Root()), "outside")); !errors.Is(err, ErrOutsideWorkspace) {
		t.Fatalf("outside error = %v, want ErrOutsideWorkspace", err)
	}
}
```

- [ ] **Step 3: Run the tests and verify the package is absent**

Run: `go test ./internal/storage`

Expected: FAIL — the package does not exist, so the build reports `no Go files` or `undefined: OSFileSystem`.

- [ ] **Step 4: Implement the filesystem seam**

```go
// internal/storage/filesystem.go
package storage

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// MaxFileSize bounds how much of one configuration file is read into
	// memory. Real client configurations are far smaller.
	MaxFileSize = 1 << 20

	// DirectoryPermission is applied to directories this application creates.
	DirectoryPermission fs.FileMode = 0o700
	// FilePermission is the maximum permission a managed file may carry. A
	// stricter existing permission is preserved.
	FilePermission fs.FileMode = 0o600
)

var (
	ErrFileTooLarge   = errors.New("file is larger than the supported maximum")
	ErrNotRegularFile = errors.New("path is not a regular file")
)

// FileSystem is the only path through which this package touches the disk.
// Tests wrap an OSFileSystem to inject a failure at a chosen stage.
type FileSystem interface {
	// ReadFile reads a regular file without following a symbolic link.
	ReadFile(path string) ([]byte, error)
	Lstat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	// Glob returns matches in lexical order.
	Glob(pattern string) ([]string, error)
	MkdirAll(path string, permission fs.FileMode) error
	// WriteTemp creates a new file in directory, writes contents, applies
	// permission, flushes it to disk and returns its path.
	WriteTemp(directory, prefix string, permission fs.FileMode, contents []byte) (string, error)
	Rename(oldPath, newPath string) error
	Remove(path string) error
	SyncDir(path string) error
	EvalSymlinks(path string) (string, error)
}

// OSFileSystem is the macOS implementation of FileSystem.
type OSFileSystem struct{}

func (OSFileSystem) ReadFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrSymlinkPath
		}
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegularFile
	}
	contents, err := io.ReadAll(io.LimitReader(file, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > MaxFileSize {
		return nil, ErrFileTooLarge
	}
	return contents, nil
}

func (OSFileSystem) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }

func (OSFileSystem) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }

func (OSFileSystem) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

func (OSFileSystem) MkdirAll(path string, permission fs.FileMode) error {
	return os.MkdirAll(path, permission)
}

func (OSFileSystem) WriteTemp(directory, prefix string, permission fs.FileMode, contents []byte) (string, error) {
	file, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := writeAndFlush(file, permission, contents); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func writeAndFlush(file *os.File, permission fs.FileMode, contents []byte) error {
	if err := file.Chmod(permission); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	return file.Sync()
}

func (OSFileSystem) Rename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

func (OSFileSystem) Remove(path string) error { return os.Remove(path) }

func (OSFileSystem) SyncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (OSFileSystem) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }
```

- [ ] **Step 5: Implement the workspace guard**

```go
// internal/storage/workspace.go
package storage

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

var (
	ErrOutsideWorkspace = errors.New("path is outside the ssh-ui workspace")
	ErrSymlinkPath      = errors.New("path contains a symbolic link")
	ErrMissingDirectory = errors.New("parent directory does not exist")
	ErrNotDirectory     = errors.New("path component is not a directory")
	ErrInvalidHome      = errors.New("home directory must be an absolute path")
)

// Workspace pins every write to the user's resolved ~/.ssh directory.
//
// The root is resolved once through EvalSymlinks so a user who keeps ~/.ssh on
// another volume still works, while every component below the root must be a
// real directory. Symbolic links below the root are shown by the UI but are
// never written through, so a link cannot widen the writable set.
type Workspace struct {
	fileSystem FileSystem
	home       string
	root       string
}

// NewWorkspace resolves home/.ssh. A missing directory is not an error; it is
// created on first write.
func NewWorkspace(fileSystem FileSystem, home string) (*Workspace, error) {
	if !filepath.IsAbs(home) {
		return nil, ErrInvalidHome
	}
	cleanedHome := filepath.Clean(home)
	root := filepath.Join(cleanedHome, ".ssh")
	resolved, err := fileSystem.EvalSymlinks(root)
	switch {
	case err == nil:
		root = filepath.Clean(resolved)
	case errors.Is(err, fs.ErrNotExist):
		// Keep the literal path; EnsureDirectory creates it later.
	default:
		return nil, err
	}
	return &Workspace{fileSystem: fileSystem, home: cleanedHome, root: root}, nil
}

func (w *Workspace) FileSystem() FileSystem { return w.fileSystem }

func (w *Workspace) Home() string { return w.home }

func (w *Workspace) Root() string { return w.root }

// StateDir is the directory holding journals, history and backups.
func (w *Workspace) StateDir() string { return filepath.Join(w.root, "ssh-ui") }

// Contains reports whether candidate is the root or lives below it.
func (w *Workspace) Contains(candidate string) bool {
	cleaned := filepath.Clean(candidate)
	return cleaned == w.root || strings.HasPrefix(cleaned, w.root+string(filepath.Separator))
}

// ResolveForWrite validates that candidate is an absolute path below the root
// whose parents are real directories and which is either absent or a regular
// file. It returns the cleaned path.
func (w *Workspace) ResolveForWrite(candidate string) (string, error) {
	cleaned := filepath.Clean(candidate)
	if !filepath.IsAbs(cleaned) || !w.Contains(cleaned) || cleaned == w.root {
		return "", ErrOutsideWorkspace
	}
	relative, err := filepath.Rel(w.root, cleaned)
	if err != nil {
		return "", ErrOutsideWorkspace
	}

	segments := strings.Split(relative, string(filepath.Separator))
	current := w.root
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, statErr := w.fileSystem.Lstat(current)
		last := index == len(segments)-1
		switch {
		case errors.Is(statErr, fs.ErrNotExist):
			if last {
				return cleaned, nil
			}
			return "", ErrMissingDirectory
		case statErr != nil:
			return "", statErr
		case info.Mode()&fs.ModeSymlink != 0:
			return "", ErrSymlinkPath
		case last && !info.Mode().IsRegular():
			return "", ErrNotRegularFile
		case !last && !info.IsDir():
			return "", ErrNotDirectory
		}
	}
	return cleaned, nil
}

// EnsureDirectory creates candidate and any missing parent below the root with
// DirectoryPermission, refusing to traverse a symbolic link.
func (w *Workspace) EnsureDirectory(candidate string) error {
	cleaned := filepath.Clean(candidate)
	if !w.Contains(cleaned) {
		return ErrOutsideWorkspace
	}
	if _, err := w.fileSystem.Lstat(w.root); errors.Is(err, fs.ErrNotExist) {
		if err := w.fileSystem.MkdirAll(w.root, DirectoryPermission); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	relative, err := filepath.Rel(w.root, cleaned)
	if err != nil {
		return ErrOutsideWorkspace
	}
	current := w.root
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, statErr := w.fileSystem.Lstat(current)
		switch {
		case errors.Is(statErr, fs.ErrNotExist):
			if err := w.fileSystem.MkdirAll(current, DirectoryPermission); err != nil {
				return err
			}
		case statErr != nil:
			return statErr
		case info.Mode()&fs.ModeSymlink != 0:
			return ErrSymlinkPath
		case !info.IsDir():
			return ErrNotDirectory
		}
	}
	return nil
}
```

- [ ] **Step 6: Run the storage tests**

Run:

```bash
go test ./internal/storage -v
go test -race ./internal/storage
```

Expected: PASS, and no test writes outside its own `t.TempDir()`.

- [ ] **Step 7: Commit the workspace guard**

```bash
git add internal/storage
git commit -m "feat: confine ssh config writes to the workspace root"
```

## Task 6: Commit configuration changes atomically

**Files:**
- Create: `internal/storage/transaction.go`
- Create: `internal/storage/transaction_test.go`

**Interfaces:**
- Consumes: Task 5 `Workspace`, `FileSystem`, permission constants.
- Produces: `storage.Precondition{Exists bool, Digest string}` and `storage.Digest(contents []byte) string`.
- Produces: `storage.Change{Path string, Contents []byte, Precondition Precondition}` and `storage.Request{Operation string, Changes []Change}`.
- Produces: `storage.ConflictError{Path, Expected, Actual string, Current []byte}`.
- Produces: `storage.NewManager(workspace *Workspace, now func() time.Time, random io.Reader) *Manager` with the optional field `Validate func(Request) error`, which the application layer sets in a later subsystem to parse the new contents before anything is written.
- Produces: `(*Manager).Commit(request Request) (Result, error)` with `Result{ID, BackupDir string, Written []string}`.
- Produces: unexported `journalRecord` and `journalEntry` consumed by Task 7.

- [ ] **Step 1: Write the failing commit tests**

```go
// internal/storage/transaction_test.go
package storage

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	moment := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		moment = moment.Add(time.Second)
		return moment
	}
}

func newTestManager(t *testing.T) (*Manager, *Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	return NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096))), workspace
}

func writeWorkspaceFile(t *testing.T, workspace *Workspace, name, contents string, permission fs.FileMode) string {
	t.Helper()
	path := filepath.Join(workspace.Root(), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), permission); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCommitWritesEveryChangeAndRecordsHistory(t *testing.T) {
	manager, workspace := newTestManager(t)
	config := writeWorkspaceFile(t, workspace, "config", "Host old\n", 0o644)
	extra := filepath.Join(workspace.Root(), "conf.d", "new.conf")
	if err := os.MkdirAll(filepath.Dir(extra), 0o700); err != nil {
		t.Fatal(err)
	}

	result, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: config, Contents: []byte("Host new\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host old\n"))}},
			{Path: extra, Contents: []byte("Host extra\n")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Written) != 2 || result.ID == "" {
		t.Fatalf("result = %#v", result)
	}

	for path, want := range map[string]string{config: "Host new\n", extra: "Host extra\n"} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != FilePermission {
			t.Fatalf("%s permission = %v, want %v", path, info.Mode().Perm(), FilePermission)
		}
	}

	backup, err := os.ReadFile(filepath.Join(result.BackupDir, "config"))
	if err != nil || string(backup) != "Host old\n" {
		t.Fatalf("backup = %q, %v", backup, err)
	}
	if _, err := os.Stat(filepath.Join(result.BackupDir, "conf.d", "new.conf")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a file that did not exist was backed up")
	}

	journalEntries, err := os.ReadDir(filepath.Join(workspace.StateDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if len(journalEntries) != 0 {
		t.Fatalf("journal still holds %d entries", len(journalEntries))
	}
	historyEntries, err := os.ReadDir(filepath.Join(workspace.StateDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	if len(historyEntries) != 1 || !strings.HasSuffix(historyEntries[0].Name(), ".json") {
		t.Fatalf("history = %#v", historyEntries)
	}

	staged, err := os.ReadDir(workspace.Root())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range staged {
		if strings.HasPrefix(entry.Name(), ".ssh-ui-") {
			t.Fatalf("temporary file %q was left behind", entry.Name())
		}
	}
}

func TestCommitPreservesStricterPermissions(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "strict.conf", "Host old\n", 0o400)
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path, Contents: []byte("Host new\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host old\n"))}}},
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("permission = %v, want 0400", info.Mode().Perm())
	}
}

func TestCommitRejectsExternalChangesWithThreeWayData(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host disk\n", 0o600)

	_, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path, Contents: []byte("Host ui\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host base\n"))}}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
	if conflict.Path != path || string(conflict.Current) != "Host disk\n" {
		t.Fatalf("conflict = %#v", conflict)
	}
	if conflict.Expected == conflict.Actual {
		t.Fatal("conflict does not distinguish the two versions")
	}
	if strings.Contains(conflict.Error(), "Host disk") {
		t.Fatal("conflict error message leaks file contents")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "Host disk\n" {
		t.Fatalf("file changed during a rejected commit: %q", contents)
	}
}

func TestCommitRejectsCreationWhenTheFileAlreadyExists(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host disk\n", 0o600)
	_, err := manager.Commit(Request{
		Operation: "config.create",
		Changes:   []Change{{Path: path, Contents: []byte("Host ui\n")}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
}

func TestCommitRejectsInvalidRequests(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := filepath.Join(workspace.Root(), "config")

	if _, err := manager.Commit(Request{Operation: "config.save"}); !errors.Is(err, ErrNoChanges) {
		t.Errorf("empty request error = %v", err)
	}
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path}, {Path: path}},
	}); !errors.Is(err, ErrDuplicatePath) {
		t.Errorf("duplicate path error = %v", err)
	}
	outside := filepath.Join(filepath.Dir(workspace.Root()), "outside.conf")
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: outside}},
	}); !errors.Is(err, ErrOutsideWorkspace) {
		t.Errorf("outside path error = %v", err)
	}
}

func TestCommitLeavesRecoverableJournalWhenRenameFails(t *testing.T) {
	workspace := newTestWorkspace(t)
	first := writeWorkspaceFile(t, workspace, "first.conf", "Host first\n", 0o600)
	second := writeWorkspaceFile(t, workspace, "second.conf", "Host second\n", 0o600)
	failure := errors.New("injected rename failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "rename" && path == second {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))

	_, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: first, Contents: []byte("Host first changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host first\n"))}},
			{Path: second, Contents: []byte("Host second changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host second\n"))}},
		},
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want the injected failure", err)
	}

	if contents, readErr := os.ReadFile(first); readErr != nil || string(contents) != "Host first changed\n" {
		t.Fatalf("first file = %q, %v", contents, readErr)
	}
	if contents, readErr := os.ReadFile(second); readErr != nil || string(contents) != "Host second\n" {
		t.Fatalf("second file = %q, %v", contents, readErr)
	}
	journalEntries, readErr := os.ReadDir(filepath.Join(workspace.StateDir(), "journal"))
	if readErr != nil || len(journalEntries) != 1 {
		t.Fatalf("journal = %#v, %v", journalEntries, readErr)
	}
}

func TestCommitRunsTheInjectedValidatorBeforeTouchingDisk(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host old\n", 0o600)
	rejected := errors.New("syntax error at line 1")
	manager.Validate = func(request Request) error {
		if len(request.Changes) != 1 || request.Operation != "config.save" {
			t.Fatalf("validator received %#v", request)
		}
		return rejected
	}

	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes:   []Change{{Path: path, Contents: []byte("Host new\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host old\n"))}}},
	}); !errors.Is(err, rejected) {
		t.Fatalf("error = %v, want the validator's error", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "Host old\n" {
		t.Fatalf("file changed despite validation failure: %q", contents)
	}
	if _, err := os.Stat(workspace.StateDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a rejected request created state directories")
	}
}

func TestCommitFailureWhileStagingLeavesEveryFileUntouched(t *testing.T) {
	workspace := newTestWorkspace(t)
	first := writeWorkspaceFile(t, workspace, "first.conf", "Host first\n", 0o600)
	second := writeWorkspaceFile(t, workspace, "conf.d/second.conf", "Host second\n", 0o600)
	failure := errors.New("injected staging failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "writeTemp" && path == filepath.Dir(second) {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))

	_, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: first, Contents: []byte("Host first changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host first\n"))}},
			{Path: second, Contents: []byte("Host second changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host second\n"))}},
		},
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want the injected failure", err)
	}
	for path, want := range map[string]string{first: "Host first\n", second: "Host second\n"} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, readErr)
		}
	}
	journalEntries, readErr := os.ReadDir(filepath.Join(workspace.StateDir(), "journal"))
	if readErr != nil || len(journalEntries) != 1 {
		t.Fatalf("journal = %#v, %v", journalEntries, readErr)
	}
	// Nothing was renamed, so the recovery test in Task 7 can roll this back
	// without restoring any file.
}

// faultyFileSystem injects one failure into an otherwise real filesystem so a
// test can interrupt a transaction at a chosen stage.
type faultyFileSystem struct {
	FileSystem
	failOn func(operation, path string) error
}

func (f faultyFileSystem) Rename(oldPath, newPath string) error {
	if err := f.failOn("rename", newPath); err != nil {
		return err
	}
	return f.FileSystem.Rename(oldPath, newPath)
}

func (f faultyFileSystem) WriteTemp(directory, prefix string, permission fs.FileMode, contents []byte) (string, error) {
	if err := f.failOn("writeTemp", directory); err != nil {
		return "", err
	}
	return f.FileSystem.WriteTemp(directory, prefix, permission, contents)
}

func (f faultyFileSystem) SyncDir(path string) error {
	if err := f.failOn("syncDir", path); err != nil {
		return err
	}
	return f.FileSystem.SyncDir(path)
}

func (f faultyFileSystem) Remove(path string) error {
	if err := f.failOn("remove", path); err != nil {
		return err
	}
	return f.FileSystem.Remove(path)
}
```

- [ ] **Step 2: Run the tests and verify the manager is absent**

Run: `go test ./internal/storage -run TestCommit -v`

Expected: FAIL with `undefined: NewManager`.

- [ ] **Step 3: Implement the transaction manager**

```go
// internal/storage/transaction.go
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"time"
)

const (
	journalVersion       = 1
	journalDirectoryName = "journal"
	historyDirectoryName = "history"
	backupDirectoryName  = "backups"
	temporaryPrefix      = ".ssh-ui-"

	statusStaging    = "staging"
	statusStaged     = "staged"
	statusCompleted  = "completed"
	statusRolledBack = "rolled_back"
)

var (
	ErrNoChanges     = errors.New("transaction has no changes")
	ErrDuplicatePath = errors.New("transaction contains the same path twice")
)

// Precondition records the state the caller based its new contents on.
type Precondition struct {
	Exists bool
	Digest string
}

// Change is one file the transaction replaces or creates.
type Change struct {
	Path         string
	Contents     []byte
	Precondition Precondition
}

// Request is one logical edit spanning any number of files.
type Request struct {
	Operation string
	Changes   []Change
}

// Result describes a completed transaction.
type Result struct {
	ID        string
	BackupDir string
	Written   []string
}

// ConflictError reports that the file on disk is not the file the caller
// edited. Current carries the on-disk contents so the caller can build a
// three-way diff; Error never includes file contents.
type ConflictError struct {
	Path     string
	Expected string
	Actual   string
	Current  []byte
}

func (e *ConflictError) Error() string {
	return "external change detected for " + e.Path
}

// Digest is the content hash used for preconditions and journal entries.
func Digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

type journalEntry struct {
	Path           string `json:"path"`
	Temp           string `json:"temp,omitempty"`
	Backup         string `json:"backup,omitempty"`
	HadPrevious    bool   `json:"hadPrevious"`
	Mode           uint32 `json:"mode"`
	Digest         string `json:"digest"`
	PreviousDigest string `json:"previousDigest,omitempty"`
}

type journalRecord struct {
	ID         string         `json:"id"`
	Version    int            `json:"version"`
	Operation  string         `json:"operation"`
	Status     string         `json:"status"`
	StartedAt  time.Time      `json:"startedAt"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
	Committed  int            `json:"committed"`
	Entries    []journalEntry `json:"entries"`
}

// Manager performs journalled, atomic multi-file writes inside a workspace.
//
// Validate is an optional check run after preconditions and before anything is
// journalled or written. The storage layer deliberately knows nothing about
// configuration syntax; the application layer injects a validator that parses
// the new contents and re-checks the Include graph, so a syntactically broken
// file never reaches disk. A nil Validate accepts every request.
type Manager struct {
	workspace *Workspace
	now       func() time.Time
	random    io.Reader
	Validate  func(Request) error
}

func NewManager(workspace *Workspace, now func() time.Time, random io.Reader) *Manager {
	return &Manager{workspace: workspace, now: now, random: random}
}

// Commit validates every change, journals the intent, stages all new contents
// durably, then renames them into place one at a time.
//
// Commit does not roll back automatically. A failure leaves a pending journal
// so the user can choose between completing and restoring, which is the only
// honest option when several files are involved.
func (m *Manager) Commit(request Request) (Result, error) {
	if len(request.Changes) == 0 {
		return Result{}, ErrNoChanges
	}
	fileSystem := m.workspace.FileSystem()

	entries := make([]journalEntry, 0, len(request.Changes))
	previousContents := make([][]byte, 0, len(request.Changes))
	written := make([]string, 0, len(request.Changes))
	seen := make(map[string]bool, len(request.Changes))

	for _, change := range request.Changes {
		target, err := m.workspace.ResolveForWrite(change.Path)
		if err != nil {
			return Result{}, err
		}
		if seen[target] {
			return Result{}, ErrDuplicatePath
		}
		seen[target] = true

		previous, mode, exists, err := m.currentState(target)
		if err != nil {
			return Result{}, err
		}
		actual := ""
		expected := ""
		if exists {
			actual = Digest(previous)
		}
		if change.Precondition.Exists {
			expected = change.Precondition.Digest
		}
		if actual != expected {
			return Result{}, &ConflictError{Path: target, Expected: expected, Actual: actual, Current: previous}
		}

		entry := journalEntry{
			Path:        target,
			HadPrevious: exists,
			Mode:        uint32(mode),
			Digest:      Digest(change.Contents),
		}
		if exists {
			entry.PreviousDigest = actual
		}
		entries = append(entries, entry)
		previousContents = append(previousContents, previous)
		written = append(written, target)
	}

	if m.Validate != nil {
		if err := m.Validate(request); err != nil {
			return Result{}, err
		}
	}

	identifier, err := m.newIdentifier()
	if err != nil {
		return Result{}, err
	}
	journalDirectory := filepath.Join(m.workspace.StateDir(), journalDirectoryName)
	historyDirectory := filepath.Join(m.workspace.StateDir(), historyDirectoryName)
	backupDirectory := filepath.Join(m.workspace.StateDir(), backupDirectoryName, identifier)
	for _, directory := range []string{journalDirectory, historyDirectory, backupDirectory} {
		if err := m.workspace.EnsureDirectory(directory); err != nil {
			return Result{}, err
		}
	}

	record := journalRecord{
		ID:        identifier,
		Version:   journalVersion,
		Operation: request.Operation,
		Status:    statusStaging,
		StartedAt: m.now().UTC(),
		Entries:   entries,
	}
	journalPath := filepath.Join(journalDirectory, identifier+".json")
	if err := m.writeRecord(journalPath, record); err != nil {
		return Result{}, err
	}

	// Copy the previous contents before anything is replaced. Entries and
	// request.Changes stay index-aligned throughout Commit.
	for index := range record.Entries {
		entry := &record.Entries[index]
		if !entry.HadPrevious {
			continue
		}
		relative, err := filepath.Rel(m.workspace.Root(), entry.Path)
		if err != nil {
			return Result{}, err
		}
		backupPath := filepath.Join(backupDirectory, relative)
		if err := m.workspace.EnsureDirectory(filepath.Dir(backupPath)); err != nil {
			return Result{}, err
		}
		if err := m.writeFile(backupPath, previousContents[index], fs.FileMode(entry.Mode)); err != nil {
			return Result{}, err
		}
		entry.Backup = backupPath
	}

	// Stage every new file next to its target so a later rename is atomic.
	for index := range record.Entries {
		entry := &record.Entries[index]
		temporaryPath, err := fileSystem.WriteTemp(
			filepath.Dir(entry.Path),
			temporaryPrefix+identifier+"-",
			fs.FileMode(entry.Mode),
			request.Changes[index].Contents,
		)
		if err != nil {
			return Result{}, err
		}
		entry.Temp = temporaryPath
	}
	record.Status = statusStaged
	if err := m.writeRecord(journalPath, record); err != nil {
		return Result{}, err
	}

	if err := m.commitStaged(&record, journalPath); err != nil {
		return Result{}, err
	}
	if err := m.finish(&record, journalPath, statusCompleted); err != nil {
		return Result{}, err
	}
	return Result{ID: identifier, BackupDir: backupDirectory, Written: written}, nil
}

func (m *Manager) commitStaged(record *journalRecord, journalPath string) error {
	fileSystem := m.workspace.FileSystem()
	for index := record.Committed; index < len(record.Entries); index++ {
		entry := record.Entries[index]
		if err := fileSystem.Rename(entry.Temp, entry.Path); err != nil {
			return err
		}
		if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
			return err
		}
		record.Committed = index + 1
		record.Entries[index].Temp = ""
		if err := m.writeRecord(journalPath, *record); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) finish(record *journalRecord, journalPath, status string) error {
	fileSystem := m.workspace.FileSystem()
	finished := m.now().UTC()
	record.FinishedAt = &finished
	record.Status = status
	historyPath := filepath.Join(m.workspace.StateDir(), historyDirectoryName, record.ID+".json")
	if err := m.writeRecord(historyPath, *record); err != nil {
		return err
	}
	if err := fileSystem.Remove(journalPath); err != nil {
		return err
	}
	return fileSystem.SyncDir(filepath.Dir(journalPath))
}

// currentState reads the file being replaced. The returned mode keeps a
// stricter existing permission and tightens a looser one to FilePermission.
func (m *Manager) currentState(path string) (contents []byte, mode fs.FileMode, exists bool, err error) {
	info, err := m.workspace.FileSystem().Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, FilePermission, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	contents, err = m.workspace.FileSystem().ReadFile(path)
	if err != nil {
		return nil, 0, false, err
	}
	return contents, info.Mode().Perm() & FilePermission, true, nil
}

func (m *Manager) writeFile(path string, contents []byte, permission fs.FileMode) error {
	fileSystem := m.workspace.FileSystem()
	temporaryPath, err := fileSystem.WriteTemp(filepath.Dir(path), temporaryPrefix, permission, contents)
	if err != nil {
		return err
	}
	if err := fileSystem.Rename(temporaryPath, path); err != nil {
		_ = fileSystem.Remove(temporaryPath)
		return err
	}
	return fileSystem.SyncDir(filepath.Dir(path))
}

func (m *Manager) writeRecord(path string, record journalRecord) error {
	contents, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return m.writeFile(path, append(contents, '\n'), FilePermission)
}

func (m *Manager) newIdentifier() (string, error) {
	suffix := make([]byte, 4)
	if _, err := io.ReadFull(m.random, suffix); err != nil {
		return "", err
	}
	return m.now().UTC().Format("20060102T150405.000") + "-" + hex.EncodeToString(suffix), nil
}
```

- [ ] **Step 4: Run the commit tests and the race detector**

Run:

```bash
go test ./internal/storage -run TestCommit -v
go test -race ./internal/storage
```

Expected: PASS.

- [ ] **Step 5: Commit the transaction manager**

```bash
git add internal/storage/transaction.go internal/storage/transaction_test.go
git commit -m "feat: commit ssh config changes atomically"
```

## Task 7: Recover interrupted transactions and list history

**Files:**
- Create: `internal/storage/journal.go`
- Create: `internal/storage/history.go`
- Create: `internal/storage/journal_test.go`
- Create: `internal/storage/history_test.go`

**Interfaces:**
- Consumes: Task 6 `journalRecord`, `journalEntry`, `commitStaged`, `finish`, `writeFile`, `Digest`.
- Produces: `storage.PendingEntry{Path string, Committed, HasBackup, HasStaged bool}`.
- Produces: `storage.Pending{ID, Operation, Status string, StartedAt time.Time, Committed int, Entries []PendingEntry, CanComplete bool}`.
- Produces: `(*Manager).Pending() ([]Pending, error)`, `(*Manager).Complete(id string) error`, `(*Manager).Rollback(id string) error`.
- Produces: `storage.HistoryRecord{ID, Operation, Status string, StartedAt, FinishedAt time.Time, Paths []string, BackupDir string}` and `(*Manager).History() ([]HistoryRecord, error)`.
- Produces: errors `ErrUnknownTransaction`, `ErrCannotComplete`.

- [ ] **Step 1: Write the failing recovery tests**

```go
// internal/storage/journal_test.go
package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// interruptedCommit runs a two-file commit whose second rename fails and
// returns the workspace with a healthy filesystem restored.
func interruptedCommit(t *testing.T) (*Manager, *Workspace, string, string) {
	t.Helper()
	workspace := newTestWorkspace(t)
	first := writeWorkspaceFile(t, workspace, "first.conf", "Host first\n", 0o600)
	second := writeWorkspaceFile(t, workspace, "second.conf", "Host second\n", 0o600)
	failure := errors.New("injected rename failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "rename" && path == second {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: first, Contents: []byte("Host first changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host first\n"))}},
			{Path: second, Contents: []byte("Host second changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host second\n"))}},
		},
	}); !errors.Is(err, failure) {
		t.Fatalf("commit error = %v, want the injected failure", err)
	}
	workspace.fileSystem = OSFileSystem{}
	return manager, workspace, first, second
}

func TestPendingDescribesTheInterruptedTransaction(t *testing.T) {
	manager, _, first, second := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %#v", pending)
	}
	item := pending[0]
	if item.Committed != 1 || item.Status != statusStaged || !item.CanComplete {
		t.Fatalf("pending item = %#v", item)
	}
	if len(item.Entries) != 2 {
		t.Fatalf("entries = %#v", item.Entries)
	}
	if item.Entries[0].Path != first || !item.Entries[0].Committed || !item.Entries[0].HasBackup {
		t.Errorf("entry 0 = %#v", item.Entries[0])
	}
	if item.Entries[1].Path != second || item.Entries[1].Committed || !item.Entries[1].HasStaged {
		t.Errorf("entry 1 = %#v", item.Entries[1])
	}
}

func TestCompleteFinishesTheRemainingRenames(t *testing.T) {
	manager, workspace, first, second := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Complete(pending[0].ID); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{first: "Host first changed\n", second: "Host second changed\n"} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, readErr)
		}
	}
	remaining, err := manager.Pending()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("pending after completion = %#v, %v", remaining, err)
	}
	history, err := manager.History()
	if err != nil || len(history) != 1 || history[0].Status != statusCompleted {
		t.Fatalf("history = %#v, %v", history, err)
	}
	assertNoTemporaryFiles(t, workspace.Root())
}

func TestRollbackRestoresEveryCommittedFile(t *testing.T) {
	manager, workspace, first, second := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(pending[0].ID); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{first: "Host first\n", second: "Host second\n"} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, readErr)
		}
	}
	history, err := manager.History()
	if err != nil || len(history) != 1 || history[0].Status != statusRolledBack {
		t.Fatalf("history = %#v, %v", history, err)
	}
	assertNoTemporaryFiles(t, workspace.Root())
}

func TestRollbackRemovesFilesTheTransactionCreated(t *testing.T) {
	workspace := newTestWorkspace(t)
	created := filepath.Join(workspace.Root(), "created.conf")
	existing := writeWorkspaceFile(t, workspace, "existing.conf", "Host existing\n", 0o600)
	failure := errors.New("injected rename failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "rename" && path == existing {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	if _, err := manager.Commit(Request{
		Operation: "config.save",
		Changes: []Change{
			{Path: created, Contents: []byte("Host created\n")},
			{Path: existing, Contents: []byte("Host changed\n"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("Host existing\n"))}},
		},
	}); !errors.Is(err, failure) {
		t.Fatalf("commit error = %v", err)
	}
	workspace.fileSystem = OSFileSystem{}

	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(pending[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created file still exists: %v", err)
	}
	contents, err := os.ReadFile(existing)
	if err != nil || string(contents) != "Host existing\n" {
		t.Fatalf("existing file = %q, %v", contents, err)
	}
}

func TestCompleteRefusesAlteredStagedContents(t *testing.T) {
	manager, _, _, _ := interruptedCommit(t)
	pending, err := manager.Pending()
	if err != nil {
		t.Fatal(err)
	}
	staged := stagedPathFor(t, manager, pending[0].ID, 1)
	if err := os.WriteFile(staged, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Complete(pending[0].ID); !errors.Is(err, ErrCannotComplete) {
		t.Fatalf("Complete error = %v, want ErrCannotComplete", err)
	}
	refreshed, err := manager.Pending()
	if err != nil || len(refreshed) != 1 || refreshed[0].CanComplete {
		t.Fatalf("pending = %#v, %v", refreshed, err)
	}
}

func TestPendingAndHistoryAreEmptyForAFreshWorkspace(t *testing.T) {
	manager, _ := newTestManager(t)
	pending, err := manager.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	history, err := manager.History()
	if err != nil || len(history) != 0 {
		t.Fatalf("history = %#v, %v", history, err)
	}
	if err := manager.Complete("../escape"); !errors.Is(err, ErrUnknownTransaction) {
		t.Fatalf("Complete(traversal) error = %v", err)
	}
	if err := manager.Rollback("missing"); !errors.Is(err, ErrUnknownTransaction) {
		t.Fatalf("Rollback(missing) error = %v", err)
	}
}

func stagedPathFor(t *testing.T, manager *Manager, identifier string, index int) string {
	t.Helper()
	record, _, err := manager.loadPending(identifier)
	if err != nil {
		t.Fatal(err)
	}
	if record.Entries[index].Temp == "" {
		t.Fatalf("entry %d has no staged file", index)
	}
	return record.Entries[index].Temp
}

func assertNoTemporaryFiles(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(temporaryPrefix) && entry.Name()[:len(temporaryPrefix)] == temporaryPrefix {
			t.Fatalf("temporary file %q was left behind", entry.Name())
		}
	}
}
```

```go
// internal/storage/history_test.go
package storage

import (
	"bytes"
	"testing"
)

func TestHistoryListsNewestFirstWithoutFileContents(t *testing.T) {
	manager, workspace := newTestManager(t)
	path := writeWorkspaceFile(t, workspace, "config", "Host one\n", 0o600)
	for _, step := range []struct{ previous, next string }{
		{"Host one\n", "Host two\n"},
		{"Host two\n", "Host three\n"},
	} {
		if _, err := manager.Commit(Request{
			Operation: "config.save",
			Changes:   []Change{{Path: path, Contents: []byte(step.next), Precondition: Precondition{Exists: true, Digest: Digest([]byte(step.previous))}}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	history, err := manager.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("history = %#v", history)
	}
	if !history[0].StartedAt.After(history[1].StartedAt) {
		t.Fatalf("history is not newest first: %v then %v", history[0].StartedAt, history[1].StartedAt)
	}
	if history[0].Operation != "config.save" || len(history[0].Paths) != 1 || history[0].Paths[0] != path {
		t.Fatalf("record = %#v", history[0])
	}
	if history[0].FinishedAt.IsZero() || history[0].BackupDir == "" {
		t.Fatalf("record = %#v", history[0])
	}

	backup, err := manager.workspace.FileSystem().ReadFile(history[0].BackupDir + "/config")
	if err != nil || !bytes.Equal(backup, []byte("Host two\n")) {
		t.Fatalf("backup = %q, %v", backup, err)
	}
}
```

- [ ] **Step 2: Run the tests and verify recovery is absent**

Run: `go test ./internal/storage -run 'TestPending|TestComplete|TestRollback|TestHistory' -v`

Expected: FAIL with `manager.Pending undefined`.

- [ ] **Step 3: Implement journal recovery**

```go
// internal/storage/journal.go
package storage

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	ErrUnknownTransaction = errors.New("no pending transaction with that identifier")
	ErrCannotComplete     = errors.New("staged contents are missing or altered")
)

// PendingEntry is one file inside an interrupted transaction.
type PendingEntry struct {
	Path      string
	Committed bool
	HasBackup bool
	HasStaged bool
}

// Pending is an interrupted transaction found at startup. A partial state is
// reported as it is; it is never presented as a healthy result.
type Pending struct {
	ID          string
	Operation   string
	Status      string
	StartedAt   time.Time
	Committed   int
	Entries     []PendingEntry
	CanComplete bool
}

func (m *Manager) journalDirectory() string {
	return filepath.Join(m.workspace.StateDir(), journalDirectoryName)
}

func (m *Manager) historyDirectory() string {
	return filepath.Join(m.workspace.StateDir(), historyDirectoryName)
}

// Pending lists interrupted transactions, oldest first.
func (m *Manager) Pending() ([]Pending, error) {
	records, err := m.readRecords(m.journalDirectory())
	if err != nil {
		return nil, err
	}
	pending := make([]Pending, 0, len(records))
	for _, record := range records {
		item := Pending{
			ID:          record.ID,
			Operation:   record.Operation,
			Status:      record.Status,
			StartedAt:   record.StartedAt,
			Committed:   record.Committed,
			CanComplete: true,
		}
		for index, entry := range record.Entries {
			pendingEntry := PendingEntry{
				Path:      entry.Path,
				Committed: index < record.Committed,
				HasBackup: entry.Backup != "",
			}
			if !pendingEntry.Committed {
				pendingEntry.HasStaged = m.stagedMatches(entry)
				if !pendingEntry.HasStaged {
					item.CanComplete = false
				}
			}
			item.Entries = append(item.Entries, pendingEntry)
		}
		pending = append(pending, item)
	}
	return pending, nil
}

// Complete finishes an interrupted transaction using the staged contents.
func (m *Manager) Complete(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	for index := record.Committed; index < len(record.Entries); index++ {
		if !m.stagedMatches(record.Entries[index]) {
			return ErrCannotComplete
		}
	}
	if err := m.commitStaged(record, journalPath); err != nil {
		return err
	}
	return m.finish(record, journalPath, statusCompleted)
}

// Rollback restores every file the interrupted transaction had already
// replaced and discards the staged contents.
func (m *Manager) Rollback(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	fileSystem := m.workspace.FileSystem()
	for index := record.Committed - 1; index >= 0; index-- {
		entry := record.Entries[index]
		if entry.HadPrevious {
			contents, readErr := fileSystem.ReadFile(entry.Backup)
			if readErr != nil {
				return readErr
			}
			if err := m.writeFile(entry.Path, contents, fs.FileMode(entry.Mode)); err != nil {
				return err
			}
			continue
		}
		if err := fileSystem.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
			return err
		}
	}
	for _, entry := range record.Entries {
		if entry.Temp == "" {
			continue
		}
		if err := fileSystem.Remove(entry.Temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	record.Committed = 0
	return m.finish(record, journalPath, statusRolledBack)
}

func (m *Manager) stagedMatches(entry journalEntry) bool {
	if entry.Temp == "" {
		return false
	}
	contents, err := m.workspace.FileSystem().ReadFile(entry.Temp)
	if err != nil {
		return false
	}
	return Digest(contents) == entry.Digest
}

func (m *Manager) loadPending(identifier string) (*journalRecord, string, error) {
	if identifier == "" || identifier != filepath.Base(identifier) || strings.Contains(identifier, "..") {
		return nil, "", ErrUnknownTransaction
	}
	journalPath := filepath.Join(m.journalDirectory(), identifier+".json")
	contents, err := m.workspace.FileSystem().ReadFile(journalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", ErrUnknownTransaction
	}
	if err != nil {
		return nil, "", err
	}
	var record journalRecord
	if err := json.Unmarshal(contents, &record); err != nil {
		return nil, "", err
	}
	return &record, journalPath, nil
}

// readRecords loads every journal document in a directory, oldest first.
// Identifiers start with a UTC timestamp, so lexical order is chronological.
func (m *Manager) readRecords(directory string) ([]journalRecord, error) {
	entries, err := m.workspace.FileSystem().ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	records := make([]journalRecord, 0, len(names))
	for _, name := range names {
		contents, readErr := m.workspace.FileSystem().ReadFile(filepath.Join(directory, name))
		if readErr != nil {
			return nil, readErr
		}
		var record journalRecord
		if unmarshalErr := json.Unmarshal(contents, &record); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		records = append(records, record)
	}
	return records, nil
}
```

- [ ] **Step 4: Implement the history view**

```go
// internal/storage/history.go
package storage

import (
	"path/filepath"
	"time"
)

// HistoryRecord is a finished transaction. It holds paths and hashes only; it
// never stores file contents, and the engine never deletes a backup on its own.
type HistoryRecord struct {
	ID         string
	Operation  string
	Status     string
	StartedAt  time.Time
	FinishedAt time.Time
	Paths      []string
	BackupDir  string
}

// History returns finished transactions, newest first.
func (m *Manager) History() ([]HistoryRecord, error) {
	records, err := m.readRecords(m.historyDirectory())
	if err != nil {
		return nil, err
	}
	history := make([]HistoryRecord, 0, len(records))
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		item := HistoryRecord{
			ID:        record.ID,
			Operation: record.Operation,
			Status:    record.Status,
			StartedAt: record.StartedAt,
			BackupDir: filepath.Join(m.workspace.StateDir(), backupDirectoryName, record.ID),
		}
		if record.FinishedAt != nil {
			item.FinishedAt = *record.FinishedAt
		}
		for _, entry := range record.Entries {
			item.Paths = append(item.Paths, entry.Path)
		}
		history = append(history, item)
	}
	return history, nil
}
```

- [ ] **Step 5: Run recovery and history tests**

Run:

```bash
go test ./internal/storage -v
go test -race ./internal/storage
```

Expected: PASS.

- [ ] **Step 6: Commit journal recovery**

```bash
git add internal/storage/journal.go internal/storage/history.go internal/storage/journal_test.go internal/storage/history_test.go
git commit -m "feat: recover interrupted ssh config transactions"
```

## Task 8: Wire the engine to the workspace and verify the subsystem

**Files:**
- Create: `internal/storage/loader.go`
- Create: `internal/storage/integration_test.go`
- Modify: `Makefile`
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 4 `config.Resolver`, Task 5 `Workspace`, Task 6 `Manager`.
- Produces: `storage.ConfigLoader` implementing `config.Loader`.
- Produces: `storage.NewConfigLoader(workspace *Workspace) ConfigLoader`.
- Produces: `storage.NewResolver(workspace *Workspace) config.Resolver`.

- [ ] **Step 1: Write the failing end-to-end test**

```go
// internal/storage/integration_test.go
package storage_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ssh-ui/internal/config"
	"ssh-ui/internal/storage"
)

const mainConfig = `# personal config
Include conf.d/*.conf

Host bastion
	HostName=203.0.113.10
	Port 22

Host *
	ServerAliveInterval 30
`

func newIntegrationWorkspace(t *testing.T) *storage.Workspace {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"config":              mainConfig,
		"conf.d/20-work.conf": "Host work\n\tUser ops\n",
		"conf.d/10-home.conf": "Host home\n\tUser aida\t# personal\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestResolveEditAndCommitPreservesEveryOtherByte(t *testing.T) {
	workspace := newIntegrationWorkspace(t)
	resolver := storage.NewResolver(workspace)
	entry := filepath.Join(workspace.Root(), "config")

	graph, err := resolver.Resolve(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Severity == config.SeverityError {
			t.Fatalf("unexpected diagnostic: %#v", diagnostic)
		}
	}
	want := []string{
		entry,
		filepath.Join(workspace.Root(), "conf.d", "10-home.conf"),
		filepath.Join(workspace.Root(), "conf.d", "20-work.conf"),
	}
	if len(graph.Order) != len(want) {
		t.Fatalf("order = %#v", graph.Order)
	}
	for index := range want {
		if graph.Order[index] != want[index] {
			t.Fatalf("order[%d] = %q, want %q", index, graph.Order[index], want[index])
		}
	}
	for path, node := range graph.Nodes {
		original, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(node.File.Render(), original) {
			t.Fatalf("%s did not round-trip", path)
		}
	}

	// Change one argument through the structured model and keep everything else.
	node := graph.Nodes[entry]
	original := node.File.Render()
	changed := false
	for index := range node.File.Lines {
		line := &node.File.Lines[index]
		if line.Kind == config.LineDirective && config.EqualKeyword(line.Keyword, "Port") {
			line.Arguments[0].Raw = "2222"
			line.Arguments[0].Value = "2222"
			changed = true
		}
	}
	if !changed {
		t.Fatal("fixture no longer contains a Port directive")
	}
	updated := node.File.Render()
	if bytes.Equal(updated, original) {
		t.Fatal("edit produced no change")
	}
	if want := bytes.Replace(original, []byte("Port 22\n"), []byte("Port 2222\n"), 1); !bytes.Equal(updated, want) {
		t.Fatalf("edit changed more than the port:\n%q\n%q", updated, want)
	}

	manager := storage.NewManager(workspace, time.Now, deterministicRandom())
	result, err := manager.Commit(storage.Request{
		Operation: "config.save",
		Changes: []storage.Change{{
			Path:         entry,
			Contents:     updated,
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(original)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(entry)
	if err != nil || !bytes.Equal(after, updated) {
		t.Fatalf("config after commit = %q, %v", after, err)
	}
	for _, name := range []string{"conf.d/10-home.conf", "conf.d/20-work.conf"} {
		path := filepath.Join(workspace.Root(), name)
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(contents, graph.Nodes[path].File.Render()) {
			t.Fatalf("%s changed during an unrelated commit", name)
		}
	}
	backup, err := os.ReadFile(filepath.Join(result.BackupDir, "config"))
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup = %q, %v", backup, err)
	}

	// The engine's own state directory must never appear as configuration.
	regraph, err := resolver.Resolve(entry)
	if err != nil {
		t.Fatal(err)
	}
	for path := range regraph.Nodes {
		if filepath.Dir(path) == workspace.StateDir() {
			t.Fatalf("state directory leaked into the graph: %s", path)
		}
	}
}

func TestResolverReportsUnsupportedTokensInsteadOfGuessing(t *testing.T) {
	workspace := newIntegrationWorkspace(t)
	entry := filepath.Join(workspace.Root(), "config")
	if err := os.WriteFile(entry, []byte("Include %h/other.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := storage.NewResolver(workspace).Resolve(entry)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Code == config.DiagnosticIncludeUnsupported {
			found = true
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v", graph.Diagnostics)
	}
}

// deterministicRandom keeps transaction identifiers reproducible in tests.
func deterministicRandom() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x7f}, 4096))
}
```

- [ ] **Step 2: Run the test and verify the adapter is absent**

Run: `go test ./internal/storage -run TestResolveEditAndCommit -v`

Expected: FAIL with `undefined: storage.NewResolver`.

- [ ] **Step 3: Implement the loader adapter**

```go
// internal/storage/loader.go
package storage

import "ssh-ui/internal/config"

// ConfigLoader gives the Include graph read-only access to the disk.
//
// It deliberately reads files outside the workspace root, because the design
// requires showing an Include that points elsewhere, but it never follows a
// symbolic link and never writes. Only Workspace.ResolveForWrite decides what
// may be modified.
type ConfigLoader struct {
	fileSystem FileSystem
}

func NewConfigLoader(workspace *Workspace) ConfigLoader {
	return ConfigLoader{fileSystem: workspace.FileSystem()}
}

func (l ConfigLoader) ReadFile(path string) ([]byte, error) {
	return l.fileSystem.ReadFile(path)
}

func (l ConfigLoader) Glob(pattern string) ([]string, error) {
	return l.fileSystem.Glob(pattern)
}

// NewResolver builds the Include resolver for a workspace.
//
// Only '%d' is supplied as a percent token. '%u' and '%i' need the local user
// name and uid, which the platform layer provides in a later subsystem; until
// then those patterns are reported as unsupported instead of being guessed.
func NewResolver(workspace *Workspace) config.Resolver {
	return config.Resolver{
		Loader: NewConfigLoader(workspace),
		Home:   workspace.Home(),
		Root:   workspace.Root(),
		Tokens: map[byte]string{'d': workspace.Home()},
	}
}
```

- [ ] **Step 4: Add the fuzz command to the Makefile**

```make
.PHONY: generate test build fuzz

fuzz:
	go test ./internal/config -run '^$$' -fuzz FuzzParseRendersOriginalBytes -fuzztime 60s
```

Keep `generate`, `test` and `build` exactly as they are; only add the `fuzz` target and extend the `.PHONY` line.

- [ ] **Step 5: Document the engine boundary in README.md**

Add a section after the security boundary section, in the README's existing Japanese style:

```markdown
## SSH config エンジンの境界

- `~/.ssh/config` と `Include` 先を正本として読み書きします。無変更の parse/render は byte-for-byte で一致し、コメント、空行、引用、`key=value`、未知のディレクティブを保持します。
- 解釈できない行は `LineUnstructured` として原文のまま保持し、UI からは Raw 編集だけを許可します。推測による整形や削除は行いません。
- 書き込みは解決済みの `~/.ssh` 配下だけに限定します。`..`、シンボリックリンク、外部パスで書き込み範囲は広がりません。読み取りは `O_NOFOLLOW` を使います。
- `Include` が `~/.ssh` の外を指す場合は、グラフ表示と読み取りのみ許可します。
- `%h` など接続先が決まるまで確定しないトークンは展開せず、`include_unsupported_expansion` として報告します。
- 変更は `~/.ssh/ssh-ui/journal/` に予定を記録し、全ファイルを一時ファイルへ書き出して fsync した後に atomic rename します。中断した場合は `~/.ssh/ssh-ui/backups/<id>/` の世代バックアップから復旧するか、staged 内容で完了させるかを選べます。
- 完了した変更は `~/.ssh/ssh-ui/history/` に記録します。バックアップは自動削除しません。
- 複数ファイルの OS レベル完全 atomic commit は存在しないため、部分適用は隠さず pending として提示します。
- ディレクトリ構成要素の入れ替えに対する time-of-check/time-of-use 競合は best-effort でしか防げません。`O_NOFOLLOW` と構成要素ごとの検査を行いますが、同一ユーザー権限で動作する悪意あるプロセスからは完全には保護できません。
```

- [ ] **Step 6: Run the whole verification suite**

Run:

```bash
go test ./...
go test -race ./...
make fuzz
npm test --prefix web
npm run typecheck --prefix web
go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui
git diff --stat go.mod go.sum
git status --short
```

Expected:

- every Go, race, Vitest and TypeScript check passes;
- `make fuzz` finds no failing input;
- `go.mod` and `go.sum` show no change, proving no dependency was added;
- `git status --short` lists only files this plan intends to add.

- [ ] **Step 7: Verify no test touched the real home directory**

Run:

```bash
grep -rn "UserHomeDir\|os.Getenv(\"HOME\")\|\$HOME" internal/ cmd/ || echo "no home directory access"
ls -la ~/.ssh/ssh-ui 2>/dev/null || echo "no state directory in the real home"
```

Expected: the first command prints `no home directory access`; the second confirms the real `~/.ssh` gained no `ssh-ui` directory. If either check fails, fix the offending test before committing.

- [ ] **Step 8: Commit the wiring and documentation**

```bash
git add internal/storage/loader.go internal/storage/integration_test.go Makefile README.md
git commit -m "feat: connect the config engine to the workspace"
```

## Config Engine Acceptance Gate

Before starting the Connections UI plan, verify all of the following:

- `go test ./...` and `go test -race ./...` pass.
- `make fuzz` runs 60 seconds with no failing input, and `internal/config/testdata/fuzz` contains no crasher.
- The golden fixture and every fuzz seed round-trip byte-for-byte.
- Unknown directives, comments, blank lines, `key=value`, quoting and CRLF survive a parse/render cycle unchanged.
- The Include graph reports cycles, duplicates, missing matches, conditional includes, unsupported expansions and files outside the root, and terminates on a cyclic fixture.
- Writes outside the resolved root, through a symbolic link, or through `..` are rejected by `Workspace.ResolveForWrite`.
- A commit interrupted between renames leaves a pending journal that can be either completed or rolled back to the original bytes.
- A stricter existing file permission survives a commit; a looser one is tightened to `0600`; managed directories are `0700`.
- `ConflictError` carries the on-disk contents for a three-way diff and its message contains no file contents.
- A rejected `Manager.Validate` prevents every disk effect, including the state directories, leaving the syntax and Include checks of design §7 step 4 to the application layer that injects it.
- A failure injected while staging leaves every target file untouched and a pending journal behind.
- `go.mod` gained no dependency and the HTTP, OpenAPI and frontend surfaces are unchanged.
- No automated test read or wrote the real `~/.ssh`, Keychain, ssh-agent, Terminal or a remote host.
- `ssh -G` differential testing remains deferred to subsystem 5 and is recorded there, not silently dropped.
