# sshc Connections UI and Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the committed lossless config engine into a usable Connections UI: an application layer that projects `Host` blocks into a form model and writes edits back without losing a byte, a metadata store for groups, tags, notes and favourites, group inheritance compiled into ordinary `Host` blocks, and a React interface with form/Raw tabs, an Include explorer, save-preview diffs, conflict surfaces and history restore.

**Architecture:** A new `internal/application` package sits between `internal/config` (pure syntax) and `internal/storage` (all filesystem effects). It resolves the Include graph, walks directives in OpenSSH's reading order, projects hosts and form fields, applies edits to the same lossless syntax tree the parser produced, computes line diffs and explained effective values, and commits every change through one `storage.Manager` transaction whose `Validate` hook re-parses and re-resolves before a single byte reaches disk. `internal/httpserver` exposes those use cases as same-origin JSON endpoints declared in `api/openapi.yaml`, and `web/src` renders them with React and Tailwind only.

**Tech Stack:** Go 1.26.5 (standard library only), Echo v5.3.1, oapi-codegen v2.7.0, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, React Testing Library 16.3.2.

## Global Constraints

- macOS only. The server binds `127.0.0.1` on an OS-assigned port, never `0.0.0.0`, `::`, a fixed port, or a LaunchAgent.
- No CORS. API and UI are same-origin; every mutation carries the `X-SSHC-CSRF` header; every `/api/` response keeps `Cache-Control: no-store`.
- Same pinned versions as the foundation: Go 1.26.5, Echo v5.3.1, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1. **Add no new npm or Go dependency in this plan.** `go.mod` direct requirements and `web/package.json` must be byte-identical when the plan completes. If a future change genuinely needs a dependency, it must be justified in writing and pinned to an exact version — this plan needs none.
- Echo v5 handler signature is `func(c *echo.Context) error` with a pointer receiver argument. Do not write Echo v4 code.
- Automated tests must never touch the real `~/.ssh`, Keychain, ssh-agent, Terminal or a remote host. Use `t.TempDir()`, map-backed fakes and injected clocks.
- `os.UserHomeDir` may be called only from `cmd/sshc`. `internal/config`, `internal/storage`, `internal/application` and `internal/httpserver` must receive the home directory as a parameter. (This supersedes the subsystem 2 verification grep, which assumed no package needed a home directory yet.)
- Never log request bodies, cookies, tokens, file contents, configuration text or full paths. Error payloads returned to the UI may carry a workspace-relative path, a line number and a stable code — never file contents.
- The lossless guarantee survives every UI edit path: parsing and rendering an unchanged file returns the original bytes; unknown directives, comments, blank lines, quoting, `key=value` and CRLF are never dropped or reformatted; an edit changes only the lines the user changed.
- `api/openapi.yaml` is the contract. Add the endpoint and its schemas there first, then run `make generate` to regenerate `internal/api/models.gen.go` and `web/src/api/schema.d.ts`. Keep to the validated OpenAPI subset described in `api/README.md`: objects, strings, integers, booleans, arrays, `const`, `required`, `$ref`, responses and headers. No `oneOf`, `anyOf` or discriminators.
- Runtime input validation happens at the HTTP boundary in addition to generated types: bounded body size, bounded string lengths, explicit charset checks, rejection of unknown JSON fields.
- Never store key material, public key bodies, passphrases or Keychain secrets in `metadata.json`.
- Tailwind utility classes only. No external CDN, font, icon set, analytics or telemetry.

## Out of Scope

These belong to later subsystems and must not be implemented here. The UI may render a disabled tab or an explanatory placeholder, but no code path may execute them:

- Key inventory, generation, reveal, agent and Keychain integration, trash and restore of keys — subsystem 4.
- `ssh -G` effective configuration, ProxyJump reachability diagnostics, connection tests, macOS Terminal launch, Known Hosts, remote public-key registration — subsystem 5.
- Fuzzing beyond what subsystem 2 already runs, Playwright E2E, CSP/injection suite, single-binary packaging and acceptance checks — subsystem 6.
- `~/.ssh` **file and folder move, rename and delete** (design §6.2 second bullet). Creating a new configuration file is delivered here because a whole-file Raw save already expresses it exactly. Relocating and deleting *files* is blocked on missing storage primitives, not on UI work: `storage.Manager.Commit` only writes and creates, so the following must be built first, each with the backup, journal and rollback semantics the existing write path already has — (1) a journalled delete that records the previous contents and mode in the generation backup and can be rolled back into place, (2) a journalled rename that treats the source and destination as one entry so an interrupted rename is detectable and reversible, (3) a journalled directory create/remove, since `Workspace.EnsureDirectory` creates but never removes, and (4) an extension of `Pending`/`Complete`/`Rollback` to replay all three. Those belong in a named follow-up plan, **`sshc-file-operations`**, not in subsystem 6, which is hardening and release (fuzz, race, E2E, CSP and injection suite, packaging, acceptance checks) and is not a feature bucket.

  Cross-plan note added during review: the subsystem 4 key vault plan (`2026-08-05-sshc-key-vault-implementation-plan.md`, Task 4) already delivers items (1), (2) and (4) as general-purpose primitives, because the key trash needs them — `storage.Move{From, To, Precondition}`, `storage.Removal{Path, Precondition}`, the `Request.Moves`/`Request.Removals` fields, `PendingEntry.Action`/`Target`, `Pending.CanRollback` and `ErrIrreversibleRemoval`. Subsystem 4 runs after this plan, so nothing here depends on them. When `sshc-file-operations` is written it must build on those primitives rather than reinventing them, and its remaining gap is item (3), directory removal, plus the Config Explorer interface itself. Note that a committed `Removal` is deliberately not reversible, so a file delete in the explorer must either route through `Move` into a trash area or state plainly that it cannot be undone.
- The Host detail `Effective` and `Diagnostics` tabs render a placeholder that names the owning subsystem. The group preview shows this plan's *explained* values, which are an explanation of the engine's own first-value-wins walk and are labelled as such — design §5.5 keeps `ssh -G` as the authority.

---

## File Structure

```text
api/
└── openapi.yaml                        # + config, metadata and history endpoints
internal/
├── application/                        # use cases between config and storage
│   ├── paths.go                        # workspace-relative path normalisation
│   ├── notice.go                       # Notice model and stable codes
│   ├── metadata.go                     # metadata.json schema, store, orphans, renames
│   ├── walk.go                         # directive walk in OpenSSH reading order
│   ├── projection.go                   # host entries, form fields, diagnostic views
│   ├── edit.go                         # field, block-raw and file-raw edits
│   ├── diff.go                         # line diff, file diff, three-way conflict
│   ├── effective.go                    # explained first-value-wins values and diff
│   ├── groups.go                        # group compilation into Host blocks
│   ├── move.go                         # two-file host block move composition
│   ├── validate.go                     # storage.Manager.Validate implementation
│   ├── service.go                      # Overview/HostDetail/Preview/Save/History
│   ├── paths_test.go
│   ├── metadata_test.go
│   ├── walk_test.go
│   ├── projection_test.go
│   ├── edit_test.go
│   ├── diff_test.go
│   ├── effective_test.go
│   ├── groups_test.go
│   ├── move_test.go
│   ├── service_test.go
│   └── testsupport_test.go             # map-backed graph fixtures and helpers
├── httpserver/
│   ├── config_handlers.go              # config, metadata and history endpoints
│   ├── config_requests.go              # boundary validation and error mapping
│   ├── config_handlers_test.go
│   ├── config_requests_test.go
│   └── server.go                       # + route registration
└── app/run.go                          # + workspace, manager and service wiring
web/src/
├── api/client.ts                       # + typed read/mutate with ApiError
├── api/config.ts                       # config endpoints with runtime validation
├── api/config.test.ts
├── connections/ConnectionsPage.tsx     # tree + detail orchestration, host lifecycle
├── connections/ConnectionTree.tsx      # include hierarchy, groups, hosts, search
├── connections/HostDetail.tsx          # Basic/Jump/Advanced/Raw tabs
├── connections/SavePreview.tsx         # diff, notices, conflict surface
├── connections/values.ts               # OpenSSH-compatible value tokenizer
├── connections/blocks.ts               # create/duplicate/delete block composition
├── connections/*.test.ts(x)
├── explorer/ConfigExplorer.tsx         # include file tree, reference graph, file raw
├── explorer/ConfigExplorer.test.tsx
├── groups/GroupsPanel.tsx              # group hierarchy, settings, effective preview
├── groups/GroupsPanel.test.tsx
├── history/HistoryPanel.tsx            # history, restore, interrupted recovery
├── history/HistoryPanel.test.tsx
└── App.tsx                             # + section routing
```

---

## Task 1: Metadata store with stable host identity

**Files:**
- Create: `internal/application/paths.go`
- Create: `internal/application/notice.go`
- Create: `internal/application/metadata.go`
- Create: `internal/application/paths_test.go`
- Create: `internal/application/metadata_test.go`

**Interfaces:**
- Consumes: `storage.NewWorkspace`, `(*Workspace).Root/StateDir/FileSystem/EnsureDirectory`, `storage.Change`, `storage.Precondition`, `storage.Digest`, `storage.FilePermission`.
- Produces: `application.RelativePath(root, absolute string) (string, error)` and `application.AbsolutePath(root, relative string) (string, error)`, error `ErrExternalPath`.
- Produces: `application.Notice{Code, Path, Detail string, Line int}`, the `Notice*` code constants and `appendNotice`.
- Produces: `application.HostIdentity{Path, Alias string}`, `NewHostIdentity(root, absolute, alias string) (HostIdentity, error)`, `(HostIdentity).IsZero() bool`.
- Produces: `application.Setting{Keyword string, Values []string}`, `HostMetadata`, `GroupMetadata`, `Metadata`, `MetadataSchemaVersion`, `DefaultGroupsFile`.
- Produces: `NewMetadata()`, `DecodeMetadata([]byte) (Metadata, error)`, `EncodeMetadata(Metadata) ([]byte, error)`, `ValidateMetadata(Metadata) error`.
- Produces: `NewMetadataStore(workspace *storage.Workspace) *MetadataStore` with `Path()`, `Load() (Metadata, storage.Precondition, error)`, `Change(Metadata, storage.Precondition) (storage.Change, error)`, `EnsureDirectory() error`.
- Produces: `ReconcileMetadata(Metadata, []HostIdentity) (Metadata, []Notice)` and `RenameHostIdentity(Metadata, from, to HostIdentity) Metadata`.

- [ ] **Step 1: Write the failing path helper test**

```go
// internal/application/paths_test.go
package application

import (
	"errors"
	"testing"
)

func TestRelativePathRejectsEverythingOutsideTheRoot(t *testing.T) {
	const root = "/home/tester/.ssh"
	tests := []struct {
		name     string
		absolute string
		want     string
		wantErr  bool
	}{
		{"root child", "/home/tester/.ssh/config", "config", false},
		{"nested child", "/home/tester/.ssh/conf.d/10-home.conf", "conf.d/10-home.conf", false},
		{"uncleaned child", "/home/tester/.ssh/conf.d/../config", "config", false},
		{"the root itself", "/home/tester/.ssh", "", true},
		{"sibling directory", "/home/tester/.sshother/config", "", true},
		{"escaping parent", "/home/tester/.ssh/../.bashrc", "", true},
		{"unrelated absolute", "/etc/ssh/ssh_config", "", true},
		{"relative input", "conf.d/10-home.conf", "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relative, err := RelativePath(root, test.absolute)
			if test.wantErr {
				if !errors.Is(err, ErrExternalPath) {
					t.Fatalf("RelativePath(%q) = %q, %v; want ErrExternalPath", test.absolute, relative, err)
				}
				return
			}
			if err != nil || relative != test.want {
				t.Fatalf("RelativePath(%q) = %q, %v; want %q", test.absolute, relative, err, test.want)
			}
		})
	}
}

func TestAbsolutePathRefusesTraversalAndAbsoluteInput(t *testing.T) {
	const root = "/home/tester/.ssh"
	absolute, err := AbsolutePath(root, "conf.d/10-home.conf")
	if err != nil || absolute != "/home/tester/.ssh/conf.d/10-home.conf" {
		t.Fatalf("AbsolutePath = %q, %v", absolute, err)
	}
	for _, relative := range []string{"", ".", "..", "../.bashrc", "conf.d/../../escape", "/etc/passwd", "conf.d//../../x"} {
		if _, err := AbsolutePath(root, relative); !errors.Is(err, ErrExternalPath) {
			t.Errorf("AbsolutePath(%q) error = %v, want ErrExternalPath", relative, err)
		}
	}
}
```

- [ ] **Step 2: Run the test and verify the package is absent**

Run: `go test ./internal/application -run TestRelativePath -v`

Expected: FAIL — the `internal/application` package does not exist yet.

- [ ] **Step 3: Implement the path helpers**

```go
// internal/application/paths.go

// Package application holds the use cases that sit between the lossless
// configuration engine and the filesystem transaction manager. It never
// performs a syscall directly: every read and write goes through the storage
// workspace it is given.
package application

import (
	"errors"
	"path/filepath"
	"strings"
)

// ErrExternalPath reports a path that is not a real location inside the
// resolved ~/.ssh directory. The UI may display files outside the root, but no
// identifier the UI sends back may address one.
var ErrExternalPath = errors.New("path is outside the ssh directory")

// RelativePath converts an absolute path inside root into the slash-separated
// identifier used by metadata and the HTTP API.
func RelativePath(root, absolute string) (string, error) {
	if !filepath.IsAbs(absolute) {
		return "", ErrExternalPath
	}
	cleaned := filepath.Clean(absolute)
	if cleaned == filepath.Clean(root) {
		return "", ErrExternalPath
	}
	relative, err := filepath.Rel(filepath.Clean(root), cleaned)
	if err != nil {
		return "", ErrExternalPath
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", ErrExternalPath
	}
	return filepath.ToSlash(relative), nil
}

// AbsolutePath converts an identifier received from the UI back into an
// absolute path inside root. It rejects absolute input, empty input and any
// path that escapes the root after cleaning.
func AbsolutePath(root, relative string) (string, error) {
	if relative == "" || strings.HasPrefix(relative, "/") || strings.Contains(relative, "\x00") {
		return "", ErrExternalPath
	}
	joined := filepath.Join(filepath.Clean(root), filepath.FromSlash(relative))
	if _, err := RelativePath(root, joined); err != nil {
		return "", err
	}
	return joined, nil
}
```

- [ ] **Step 4: Run the path tests to verify they pass**

Run: `go test ./internal/application -run 'TestRelativePath|TestAbsolutePath' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing metadata tests**

```go
// internal/application/metadata_test.go
package application

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/storage"
)

func newTestWorkspace(t *testing.T) *storage.Workspace {
	t.Helper()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := workspace.EnsureDirectory(workspace.Root()); err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestDecodeMetadataAcceptsAnAbsentFileAndRejectsAFutureSchema(t *testing.T) {
	empty, err := DecodeMetadata(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.SchemaVersion != MetadataSchemaVersion || len(empty.Hosts) != 0 || len(empty.Groups) != 0 {
		t.Fatalf("empty metadata = %#v", empty)
	}
	if _, err := DecodeMetadata([]byte(`{"schemaVersion":99}`)); !errors.Is(err, ErrMetadataVersion) {
		t.Fatalf("future schema error = %v, want ErrMetadataVersion", err)
	}
	if _, err := DecodeMetadata([]byte(`{"schemaVersion":1,`)); err == nil {
		t.Fatal("truncated metadata was accepted")
	}
}

func TestValidateMetadataRefusesKeyMaterialAndUnknownPaths(t *testing.T) {
	withNote := NewMetadata()
	withNote.Hosts = []HostMetadata{{
		Identity: HostIdentity{Path: "config", Alias: "bastion"},
		Note:     "-----BEGIN OPENSSH PRIVATE KEY-----",
	}}
	if err := ValidateMetadata(withNote); !errors.Is(err, ErrMetadataSecret) {
		t.Fatalf("note error = %v, want ErrMetadataSecret", err)
	}

	withTag := NewMetadata()
	withTag.Hosts = []HostMetadata{{
		Identity: HostIdentity{Path: "config", Alias: "bastion"},
		Tags:     []string{"ssh-rsa AAAAB3NzaC1yc2EAAAA"},
	}}
	if err := ValidateMetadata(withTag); !errors.Is(err, ErrMetadataSecret) {
		t.Fatalf("tag error = %v, want ErrMetadataSecret", err)
	}

	withAbsolutePath := NewMetadata()
	withAbsolutePath.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "/etc/ssh/ssh_config", Alias: "x"}}}
	if err := ValidateMetadata(withAbsolutePath); !errors.Is(err, ErrMetadataPath) {
		t.Fatalf("path error = %v, want ErrMetadataPath", err)
	}

	withGroupCycleName := NewMetadata()
	withGroupCycleName.Groups = []GroupMetadata{{Name: "work", Parent: "work"}}
	if err := ValidateMetadata(withGroupCycleName); !errors.Is(err, ErrMetadataGroup) {
		t.Fatalf("self parent error = %v, want ErrMetadataGroup", err)
	}
}

func TestMetadataStoreRoundTripsThroughOneTransaction(t *testing.T) {
	workspace := newTestWorkspace(t)
	store := NewMetadataStore(workspace)

	loaded, precondition, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if precondition.Exists {
		t.Fatalf("precondition for an absent file = %#v", precondition)
	}
	loaded.Groups = []GroupMetadata{{Name: "home", Settings: []Setting{{Keyword: "User", Values: []string{"aida"}}}}}
	loaded.Hosts = []HostMetadata{{
		Identity:  HostIdentity{Path: "config", Alias: "bastion"},
		Group:     "home",
		Tags:      []string{"personal"},
		Colour:    "#22d3ee",
		Note:      "office jump host",
		Favourite: true,
		Order:     1,
	}}

	change, err := store.Change(loaded, precondition)
	if err != nil {
		t.Fatal(err)
	}
	if change.Path != store.Path() || change.Precondition.Exists {
		t.Fatalf("change = %#v", change)
	}
	if err := store.EnsureDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(change.Path, change.Contents, 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, reloadedPrecondition, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reloadedPrecondition.Exists || reloadedPrecondition.Digest != storage.Digest(change.Contents) {
		t.Fatalf("reloaded precondition = %#v", reloadedPrecondition)
	}
	if len(reloaded.Hosts) != 1 || reloaded.Hosts[0].Alias() != "bastion" || !reloaded.Hosts[0].Favourite {
		t.Fatalf("reloaded hosts = %#v", reloaded.Hosts)
	}
	if got := string(change.Contents); !strings.HasSuffix(got, "\n") {
		t.Fatal("encoded metadata must end with a newline")
	}
	if store.Path() != filepath.Join(workspace.StateDir(), MetadataFileName) {
		t.Fatalf("store path = %q", store.Path())
	}
}

func TestReconcileMetadataMarksVanishedTargetsAsOrphansWithoutGuessing(t *testing.T) {
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{
		{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "kept"},
		{Identity: HostIdentity{Path: "conf.d/10-home.conf", Alias: "nas"}, Note: "vanished"},
	}
	present := []HostIdentity{
		{Path: "config", Alias: "bastion"},
		{Path: "conf.d/10-home.conf", Alias: "nas-new"},
	}

	reconciled, notices := ReconcileMetadata(metadata, present)
	if reconciled.Hosts[0].Orphan {
		t.Fatalf("present host became an orphan: %#v", reconciled.Hosts[0])
	}
	if !reconciled.Hosts[1].Orphan || reconciled.Hosts[1].Note != "vanished" {
		t.Fatalf("orphan entry = %#v", reconciled.Hosts[1])
	}
	if reconciled.Hosts[1].Identity.Alias != "nas" {
		t.Fatal("an orphan must keep its original identity instead of being re-pointed")
	}
	if len(notices) != 1 || notices[0].Code != NoticeOrphanMetadata || notices[0].Path != "conf.d/10-home.conf" {
		t.Fatalf("notices = %#v", notices)
	}
}

func TestRenameHostIdentityMovesExactlyOneEntry(t *testing.T) {
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{
		{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "renamed"},
		{Identity: HostIdentity{Path: "config", Alias: "nas"}, Note: "untouched"},
	}
	renamed := RenameHostIdentity(metadata,
		HostIdentity{Path: "config", Alias: "bastion"},
		HostIdentity{Path: "config", Alias: "jump"},
	)
	if renamed.Hosts[0].Identity.Alias != "jump" || renamed.Hosts[0].Note != "renamed" || renamed.Hosts[0].Orphan {
		t.Fatalf("renamed entry = %#v", renamed.Hosts[0])
	}
	if renamed.Hosts[1].Identity.Alias != "nas" {
		t.Fatalf("second entry = %#v", renamed.Hosts[1])
	}
	if metadata.Hosts[0].Identity.Alias != "bastion" {
		t.Fatal("RenameHostIdentity must not mutate its input")
	}
}
```

- [ ] **Step 6: Run the metadata tests to verify they fail**

Run: `go test ./internal/application -run 'Metadata|Reconcile|Rename' -v`

Expected: FAIL with `undefined: DecodeMetadata`.

- [ ] **Step 7: Implement the notice model**

```go
// internal/application/notice.go
package application

// Notice explains something the UI must show instead of inventing an answer.
// Diagnostics come from the configuration engine and describe file structure;
// notices come from this package and describe why a projection is incomplete.
type Notice struct {
	Code   string `json:"code"`
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Notice codes are stable identifiers the UI maps to its own copy.
const (
	// NoticeComplexExternalRule marks a host whose value cannot be projected
	// into a simple inheritance model. The UI shows the real source instead.
	NoticeComplexExternalRule = "complex_external_rule"
	NoticeDuplicateAlias      = "duplicate_alias"
	NoticeWildcardShadow      = "wildcard_shadow"
	NoticeNegatedPattern      = "negated_pattern"
	NoticeUnnamedHostBlock    = "unnamed_host_block"
	NoticeMatchBlock          = "match_block"
	NoticeDangerousDirective  = "dangerous_directive"
	NoticeUnstructuredLine    = "unstructured_line"
	NoticeExternalFile        = "external_file"
	NoticeOrphanMetadata      = "orphan_metadata"
	NoticeGroupCycle          = "group_cycle"
	NoticeGroupMemberMissing  = "group_member_missing"
	NoticeExplainedValuesOnly = "explained_values_only"
)

// appendNotice adds a notice unless the identical notice is already present.
func appendNotice(notices []Notice, notice Notice) []Notice {
	for _, existing := range notices {
		if existing == notice {
			return notices
		}
	}
	return append(notices, notice)
}
```

- [ ] **Step 8: Implement the metadata model and store**

```go
// internal/application/metadata.go
package application

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"sshc/internal/storage"
)

const (
	// MetadataSchemaVersion is the only version this build writes. A file
	// carrying a higher version is refused rather than silently downgraded.
	MetadataSchemaVersion = 1
	// MetadataFileName lives in the workspace state directory, never in the
	// configuration tree, so it can never be read as SSH configuration.
	MetadataFileName = "metadata.json"
	// DefaultGroupsFile is the configuration file group inheritance compiles
	// into. It stays inside the configuration tree so it is ordinary, hand
	// editable OpenSSH configuration.
	DefaultGroupsFile = "groups.sshc.conf"
)

var (
	ErrMetadataVersion = errors.New("metadata schema version is newer than this build supports")
	ErrMetadataSecret  = errors.New("metadata may not contain key material")
	ErrMetadataPath    = errors.New("metadata host path must be relative to the ssh directory")
	ErrMetadataGroup   = errors.New("metadata group definition is invalid")
)

// secretMarkers are substrings that indicate someone tried to store key
// material in a field meant for organisation. Metadata has no field for a key,
// so any occurrence is a mistake worth refusing loudly.
var secretMarkers = []string{"-----BEGIN", "PRIVATE KEY", "ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-"}

// HostIdentity is the UI identity of a host: the normalised configuration file
// path plus the concrete primary Host alias declared in it.
type HostIdentity struct {
	Path  string `json:"path"`
	Alias string `json:"alias"`
}

// NewHostIdentity normalises an absolute configuration path into an identity.
func NewHostIdentity(root, absolute, alias string) (HostIdentity, error) {
	relative, err := RelativePath(root, absolute)
	if err != nil {
		return HostIdentity{}, err
	}
	if alias == "" {
		return HostIdentity{}, ErrMetadataPath
	}
	return HostIdentity{Path: relative, Alias: alias}, nil
}

func (identity HostIdentity) IsZero() bool { return identity.Path == "" || identity.Alias == "" }

// Setting is one directive a group contributes to its members.
type Setting struct {
	Keyword string   `json:"keyword"`
	Values  []string `json:"values"`
}

// HostMetadata is the UI-only information attached to one host.
type HostMetadata struct {
	Identity  HostIdentity `json:"identity"`
	Group     string       `json:"group,omitempty"`
	Tags      []string     `json:"tags,omitempty"`
	Colour    string       `json:"colour,omitempty"`
	Note      string       `json:"note,omitempty"`
	Favourite bool         `json:"favourite,omitempty"`
	Order     int          `json:"order,omitempty"`
	Orphan    bool         `json:"orphan,omitempty"`
}

func (host HostMetadata) Alias() string { return host.Identity.Alias }

// GroupMetadata is one primary group. Parent forms the inheritance hierarchy;
// Settings are compiled into an ordinary Host block.
type GroupMetadata struct {
	Name     string    `json:"name"`
	Parent   string    `json:"parent,omitempty"`
	Colour   string    `json:"colour,omitempty"`
	Note     string    `json:"note,omitempty"`
	Order    int       `json:"order,omitempty"`
	Settings []Setting `json:"settings,omitempty"`
}

// Metadata is the whole of ~/.ssh/sshc/metadata.json.
type Metadata struct {
	SchemaVersion int             `json:"schemaVersion"`
	GroupsFile    string          `json:"groupsFile,omitempty"`
	Groups        []GroupMetadata `json:"groups,omitempty"`
	Hosts         []HostMetadata  `json:"hosts,omitempty"`
}

func NewMetadata() Metadata {
	return Metadata{SchemaVersion: MetadataSchemaVersion, GroupsFile: DefaultGroupsFile}
}

// GroupsPath returns the configured groups file, falling back to the default.
func (metadata Metadata) GroupsPath() string {
	if metadata.GroupsFile == "" {
		return DefaultGroupsFile
	}
	return metadata.GroupsFile
}

// DecodeMetadata parses metadata.json. Absent or empty contents produce a fresh
// document; a newer schema version is refused instead of being rewritten.
func DecodeMetadata(contents []byte) (Metadata, error) {
	if len(strings.TrimSpace(string(contents))) == 0 {
		return NewMetadata(), nil
	}
	var metadata Metadata
	if err := json.Unmarshal(contents, &metadata); err != nil {
		return Metadata{}, err
	}
	if metadata.SchemaVersion > MetadataSchemaVersion {
		return Metadata{}, ErrMetadataVersion
	}
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = MetadataSchemaVersion
	}
	if metadata.GroupsFile == "" {
		metadata.GroupsFile = DefaultGroupsFile
	}
	return metadata, nil
}

// EncodeMetadata validates and serialises metadata deterministically.
func EncodeMetadata(metadata Metadata) ([]byte, error) {
	metadata.SchemaVersion = MetadataSchemaVersion
	if metadata.GroupsFile == "" {
		metadata.GroupsFile = DefaultGroupsFile
	}
	if err := ValidateMetadata(metadata); err != nil {
		return nil, err
	}
	sorted := metadata
	sorted.Groups = append([]GroupMetadata(nil), metadata.Groups...)
	sorted.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	sort.SliceStable(sorted.Groups, func(first, second int) bool {
		return sorted.Groups[first].Name < sorted.Groups[second].Name
	})
	sort.SliceStable(sorted.Hosts, func(first, second int) bool {
		if sorted.Hosts[first].Identity.Path != sorted.Hosts[second].Identity.Path {
			return sorted.Hosts[first].Identity.Path < sorted.Hosts[second].Identity.Path
		}
		return sorted.Hosts[first].Identity.Alias < sorted.Hosts[second].Identity.Alias
	})
	encoded, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ValidateMetadata refuses documents that break the design's invariants.
func ValidateMetadata(metadata Metadata) error {
	if _, err := checkRelative(metadata.GroupsPath()); err != nil {
		return err
	}
	names := make(map[string]bool, len(metadata.Groups))
	for _, group := range metadata.Groups {
		if group.Name == "" || names[group.Name] || group.Name == group.Parent {
			return ErrMetadataGroup
		}
		names[group.Name] = true
		for _, setting := range group.Settings {
			if containsSecretMarker(setting.Keyword) {
				return ErrMetadataSecret
			}
			for _, value := range setting.Values {
				if containsSecretMarker(value) {
					return ErrMetadataSecret
				}
			}
		}
	}
	for _, group := range metadata.Groups {
		if group.Parent != "" && !names[group.Parent] {
			return ErrMetadataGroup
		}
	}
	for _, host := range metadata.Hosts {
		if _, err := checkRelative(host.Identity.Path); err != nil {
			return err
		}
		if host.Identity.Alias == "" {
			return ErrMetadataPath
		}
		if host.Group != "" && !names[host.Group] {
			return ErrMetadataGroup
		}
		for _, text := range append([]string{host.Note, host.Colour}, host.Tags...) {
			if containsSecretMarker(text) {
				return ErrMetadataSecret
			}
		}
	}
	return nil
}

func checkRelative(candidate string) (string, error) {
	if candidate == "" || strings.HasPrefix(candidate, "/") {
		return "", ErrMetadataPath
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(candidate)))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", ErrMetadataPath
	}
	return cleaned, nil
}

func containsSecretMarker(text string) bool {
	for _, marker := range secretMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// MetadataStore reads and stages metadata.json inside the workspace state
// directory. It never writes directly: a change is committed by the same
// storage transaction that writes the configuration files it describes.
type MetadataStore struct {
	workspace *storage.Workspace
}

func NewMetadataStore(workspace *storage.Workspace) *MetadataStore {
	return &MetadataStore{workspace: workspace}
}

func (store *MetadataStore) Path() string {
	return filepath.Join(store.workspace.StateDir(), MetadataFileName)
}

// EnsureDirectory creates the state directory so a first metadata write can
// resolve its parent.
func (store *MetadataStore) EnsureDirectory() error {
	return store.workspace.EnsureDirectory(store.workspace.StateDir())
}

// Load reads the current document and the precondition a later commit needs.
func (store *MetadataStore) Load() (Metadata, storage.Precondition, error) {
	contents, err := store.workspace.FileSystem().ReadFile(store.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return NewMetadata(), storage.Precondition{}, nil
	}
	if err != nil {
		return Metadata{}, storage.Precondition{}, err
	}
	metadata, err := DecodeMetadata(contents)
	if err != nil {
		return Metadata{}, storage.Precondition{}, err
	}
	return metadata, storage.Precondition{Exists: true, Digest: storage.Digest(contents)}, nil
}

// Change turns metadata into one file change for a storage transaction.
func (store *MetadataStore) Change(metadata Metadata, precondition storage.Precondition) (storage.Change, error) {
	contents, err := EncodeMetadata(metadata)
	if err != nil {
		return storage.Change{}, err
	}
	return storage.Change{Path: store.Path(), Contents: contents, Precondition: precondition}, nil
}

// ReconcileMetadata marks entries whose host disappeared. It never re-points an
// entry at a different host: a vanished target becomes an orphan the user must
// re-associate deliberately.
func ReconcileMetadata(metadata Metadata, present []HostIdentity) (Metadata, []Notice) {
	known := make(map[HostIdentity]bool, len(present))
	for _, identity := range present {
		known[identity] = true
	}
	reconciled := metadata
	reconciled.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	var notices []Notice
	for index := range reconciled.Hosts {
		host := &reconciled.Hosts[index]
		host.Orphan = !known[host.Identity]
		if !host.Orphan {
			continue
		}
		notices = appendNotice(notices, Notice{
			Code:   NoticeOrphanMetadata,
			Path:   host.Identity.Path,
			Detail: host.Identity.Alias,
		})
	}
	return reconciled, notices
}

// RenameHostIdentity moves the entry for one host and leaves every other entry
// untouched. The caller commits the result in the same transaction as the
// configuration change that performed the rename.
func RenameHostIdentity(metadata Metadata, from, to HostIdentity) Metadata {
	renamed := metadata
	renamed.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	for index := range renamed.Hosts {
		if renamed.Hosts[index].Identity != from {
			continue
		}
		renamed.Hosts[index].Identity = to
		renamed.Hosts[index].Orphan = false
	}
	return renamed
}
```

- [ ] **Step 9: Run the metadata tests to verify they pass**

Run: `go test ./internal/application -v`

Expected: PASS for every test in the package.

- [ ] **Step 10: Commit the metadata store**

```bash
git add internal/application/paths.go internal/application/paths_test.go \
  internal/application/notice.go internal/application/metadata.go internal/application/metadata_test.go
git commit -m "feat: add sshc metadata store with stable host identity"
```

---

## Task 2: Directive walk, host projection and form model

**Files:**
- Create: `internal/application/walk.go`
- Create: `internal/application/projection.go`
- Create: `internal/application/testsupport_test.go`
- Create: `internal/application/walk_test.go`
- Create: `internal/application/projection_test.go`

**Interfaces:**
- Consumes: `config.Graph/Node/Edge/File/Line/Block/Pattern`, `config.Parse`, `config.EqualKeyword`, `config.LineDirective`, `config.LineUnstructured`, `config.BlockGlobal/BlockHost/BlockMatch`, `config.Diagnostic`, `config.Severity*`, Task 1 `HostIdentity`, `Notice`, `RelativePath`.
- Produces: `application.Visit{Path string, Index int, Line config.Line, Block config.Block, Condition string}` and `WalkDirectives(graph *config.Graph, visit func(Visit) bool)`.
- Produces: `application.MatchesPattern(pattern, candidate string) bool` and `MatchHostLine(patterns []config.Pattern, candidate string) bool`.
- Produces: `application.PrimaryAlias(patterns []config.Pattern) string`.
- Produces: `application.FieldCategory` constants `CategoryBasic`, `CategoryJump`, `CategoryAdvanced`; `CategoryFor(keyword string) FieldCategory`; `IsDangerousKeyword(keyword string) bool`.
- Produces: `application.FormField{Line int, Keyword string, Values []string, Category FieldCategory, Dangerous, Duplicate, Editable bool}`.
- Produces: `application.FileRef{Path, Absolute string, External bool}` and `NewFileRef(root, absolute string) FileRef`.
- Produces: `application.HostEntry{Identity HostIdentity, File FileRef, Line int, Patterns []string, Wildcard, Negated, Duplicate, Editable bool}`.
- Produces: `application.HostForm{Entry HostEntry, Fields []FormField, Raw string, Notices []Notice}`.
- Produces: `ProjectHosts(graph *config.Graph, root string) ([]HostEntry, []Notice)`, `ProjectHostForm(graph *config.Graph, root string, identity HostIdentity) (HostForm, error)`, `ErrHostNotFound`.
- Produces: `application.DiagnosticView{Severity, Code, Path, Absolute, Detail string, Line int}` and `NewDiagnosticView(root string, diagnostic config.Diagnostic) DiagnosticView`.

- [ ] **Step 1: Write the shared graph fixture helper**

```go
// internal/application/testsupport_test.go
package application

import (
	"io/fs"
	"path"
	"sort"
	"testing"

	"sshc/internal/config"
)

const testRoot = "/home/tester/.ssh"
const testHome = "/home/tester"

// fakeLoader serves configuration files from memory so projection tests never
// touch a disk. Keys are absolute, slash-separated paths.
type fakeLoader struct{ files map[string]string }

func (loader fakeLoader) ReadFile(name string) ([]byte, error) {
	contents, ok := loader.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(contents), nil
}

func (loader fakeLoader) Glob(pattern string) ([]string, error) {
	var matches []string
	for name := range loader.files {
		matched, err := path.Match(pattern, name)
		if err != nil {
			return nil, err
		}
		if matched {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

// newTestGraph resolves an in-memory configuration tree. Keys are relative to
// testRoot.
func newTestGraph(t *testing.T, files map[string]string) *config.Graph {
	t.Helper()
	absolute := make(map[string]string, len(files))
	for name, contents := range files {
		absolute[path.Join(testRoot, name)] = contents
	}
	resolver := config.Resolver{
		Loader: fakeLoader{files: absolute},
		Home:   testHome,
		Root:   testRoot,
		Tokens: map[byte]string{'d': testHome},
	}
	graph, err := resolver.Resolve(path.Join(testRoot, "config"))
	if err != nil {
		t.Fatal(err)
	}
	return graph
}
```

- [ ] **Step 2: Write the failing walk test**

```go
// internal/application/walk_test.go
package application

import (
	"testing"

	"sshc/internal/config"
)

func TestWalkDirectivesFollowsIncludesAtTheirLinePosition(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "Host early\n\tUser first\n" +
			"Include conf.d/*.conf\n" +
			"Host late\n\tUser last\n",
		"conf.d/10-home.conf": "Host home\n\tUser home-user\n",
		"conf.d/20-work.conf": "Host work\n\tUser work-user\n",
	})

	var order []string
	WalkDirectives(graph, func(visit Visit) bool {
		order = append(order, visit.Line.Keyword+" "+joinValues(visit.Line.Values()))
		return true
	})

	want := []string{
		"Host early",
		"User first",
		"Include conf.d/*.conf",
		"Host home",
		"User home-user",
		"Host work",
		"User work-user",
		"Host late",
		"User last",
	}
	if len(order) != len(want) {
		t.Fatalf("order = %#v", order)
	}
	for index := range want {
		if order[index] != want[index] {
			t.Fatalf("order[%d] = %q, want %q", index, order[index], want[index])
		}
	}
}

func TestWalkDirectivesReportsTheOwningBlockAndStopsEarly(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "ServerAliveInterval 30\nHost bastion\n\tUser ops\nMatch host nas\n\tUser nas-user\n",
	})

	var kinds []config.BlockKind
	var conditions []string
	WalkDirectives(graph, func(visit Visit) bool {
		kinds = append(kinds, visit.Block.Kind)
		conditions = append(conditions, visit.Condition)
		return visit.Line.Keyword != "Match"
	})

	wantKinds := []config.BlockKind{config.BlockGlobal, config.BlockHost, config.BlockHost, config.BlockMatch}
	if len(kinds) != len(wantKinds) {
		t.Fatalf("kinds = %#v", kinds)
	}
	for index := range wantKinds {
		if kinds[index] != wantKinds[index] {
			t.Fatalf("kinds[%d] = %v, want %v", index, kinds[index], wantKinds[index])
		}
	}
	if conditions[0] != "" || conditions[1] != "Host bastion" || conditions[3] != "Match host nas" {
		t.Fatalf("conditions = %#v", conditions)
	}
}

func TestWalkDirectivesTerminatesOnAnIncludeCycle(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":  "Include loop.conf\nHost after\n",
		"loop.conf": "Include config\nHost inside\n",
	})

	visits := 0
	WalkDirectives(graph, func(Visit) bool {
		visits++
		return visits < 100
	})
	if visits == 0 || visits >= 100 {
		t.Fatalf("walk visited %d directives; a cycle guard is missing", visits)
	}
}

func joinValues(values []string) string {
	joined := ""
	for index, value := range values {
		if index > 0 {
			joined += " "
		}
		joined += value
	}
	return joined
}
```

- [ ] **Step 3: Run the walk test and verify it fails**

Run: `go test ./internal/application -run TestWalkDirectives -v`

Expected: FAIL with `undefined: WalkDirectives`.

- [ ] **Step 4: Implement the ordered directive walk**

```go
// internal/application/walk.go
package application

import "sshc/internal/config"

// Visit is one directive line reached while reading the configuration the way
// OpenSSH reads it.
type Visit struct {
	// Path is the absolute path of the file the line belongs to.
	Path string
	// Index is the 0-based line index inside that file.
	Index int
	Line  config.Line
	Block config.Block
	// Condition is the rendered Host or Match header governing the line, or
	// the empty string in the global block.
	Condition string
}

// WalkDirectives visits every directive in reading order: each file top to
// bottom, descending into an Include exactly where the Include line appears and
// in the lexical order the resolver recorded. A file already on the current
// chain is skipped, so a cyclic Include terminates; the resolver has already
// reported the cycle as a diagnostic. The walk stops when visit returns false.
func WalkDirectives(graph *config.Graph, visit func(Visit) bool) {
	if graph == nil || graph.Root == "" {
		return
	}
	walkNode(graph, graph.Root, map[string]bool{}, visit)
}

func walkNode(graph *config.Graph, filePath string, chain map[string]bool, visit func(Visit) bool) bool {
	node, ok := graph.Nodes[filePath]
	if !ok || node.File == nil || chain[filePath] {
		return true
	}
	chain[filePath] = true
	defer delete(chain, filePath)

	includedAtLine := make(map[int][]string, len(node.Includes))
	for _, edge := range node.Includes {
		includedAtLine[edge.Line] = append(includedAtLine[edge.Line], edge.Matches...)
	}

	blocks := node.File.Blocks()
	current := 0
	for index := range node.File.Lines {
		for current+1 < len(blocks) && blocks[current+1].Header <= index {
			current++
		}
		line := node.File.Lines[index]
		if line.Kind == config.LineDirective {
			if !visit(Visit{
				Path:      filePath,
				Index:     index,
				Line:      line,
				Block:     blocks[current],
				Condition: node.File.Condition(blocks[current]),
			}) {
				return false
			}
		}
		for _, match := range includedAtLine[index+1] {
			if !walkNode(graph, match, chain, visit) {
				return false
			}
		}
	}
	return true
}
```

- [ ] **Step 5: Run the walk test to verify it passes**

Run: `go test ./internal/application -run TestWalkDirectives -v`

Expected: PASS.

- [ ] **Step 6: Write the failing projection tests**

```go
// internal/application/projection_test.go
package application

import (
	"errors"
	"testing"

	"sshc/internal/config"
)

const projectionConfig = `# personal configuration
Include conf.d/*.conf

Host bastion jump.example.com
	HostName=203.0.113.10
	User ops
	Port 22
	ProxyJump edge
	UnknownFutureDirective yes
	# keep this comment
	SetEnv EDITOR=vi

Host !secret *.internal
	User internal-user

Host *
	ServerAliveInterval 30
`

func TestProjectHostsListsEveryBlockWithItsRealNature(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":              projectionConfig,
		"conf.d/10-home.conf": "Host nas\n\tUser aida\nHost nas\n\tUser duplicate\n",
	})

	hosts, notices := ProjectHosts(graph, testRoot)
	if len(hosts) != 5 {
		t.Fatalf("hosts = %#v", hosts)
	}

	first := hosts[0]
	if first.Identity.Alias != "nas" || first.Identity.Path != "conf.d/10-home.conf" {
		t.Fatalf("first host = %#v", first)
	}
	if !first.Editable || first.Wildcard || first.Negated || first.Duplicate {
		t.Fatalf("first host flags = %#v", first)
	}
	if hosts[1].Identity.Alias != "nas" || !hosts[1].Duplicate {
		t.Fatalf("duplicate host = %#v", hosts[1])
	}
	if hosts[2].Identity.Alias != "bastion" || hosts[2].Line != 4 {
		t.Fatalf("bastion host = %#v", hosts[2])
	}
	if len(hosts[2].Patterns) != 2 || hosts[2].Patterns[1] != "jump.example.com" {
		t.Fatalf("bastion patterns = %#v", hosts[2].Patterns)
	}
	if !hosts[3].Negated || !hosts[3].Wildcard || !hosts[3].Identity.IsZero() {
		t.Fatalf("negated host = %#v", hosts[3])
	}
	if !hosts[4].Wildcard || !hosts[4].Identity.IsZero() {
		t.Fatalf("wildcard host = %#v", hosts[4])
	}

	codes := map[string]bool{}
	for _, notice := range notices {
		codes[notice.Code] = true
	}
	for _, want := range []string{NoticeDuplicateAlias, NoticeNegatedPattern, NoticeUnnamedHostBlock, NoticeWildcardShadow} {
		if !codes[want] {
			t.Errorf("missing notice %q in %#v", want, notices)
		}
	}
}

func TestProjectHostFormKeepsEveryDirectiveIncludingUnknownOnes(t *testing.T) {
	graph := newTestGraph(t, map[string]string{"config": projectionConfig})

	form, err := ProjectHostForm(graph, testRoot, HostIdentity{Path: "config", Alias: "bastion"})
	if err != nil {
		t.Fatal(err)
	}
	if len(form.Fields) != 6 {
		t.Fatalf("fields = %#v", form.Fields)
	}
	wantFields := []struct {
		keyword  string
		category FieldCategory
		values   []string
		line     int
	}{
		{"HostName", CategoryBasic, []string{"203.0.113.10"}, 5},
		{"User", CategoryBasic, []string{"ops"}, 6},
		{"Port", CategoryBasic, []string{"22"}, 7},
		{"ProxyJump", CategoryJump, []string{"edge"}, 8},
		{"UnknownFutureDirective", CategoryAdvanced, []string{"yes"}, 9},
		{"SetEnv", CategoryAdvanced, []string{"EDITOR=vi"}, 11},
	}
	for index, want := range wantFields {
		field := form.Fields[index]
		if field.Keyword != want.keyword || field.Category != want.category || field.Line != want.line {
			t.Fatalf("field[%d] = %#v, want %q %q line %d", index, field, want.keyword, want.category, want.line)
		}
		if len(field.Values) != len(want.values) || field.Values[0] != want.values[0] {
			t.Fatalf("field[%d] values = %#v, want %#v", index, field.Values, want.values)
		}
		if !field.Editable {
			t.Fatalf("field[%d] must be editable", index)
		}
	}
	if form.Raw != "Host bastion jump.example.com\n\tHostName=203.0.113.10\n\tUser ops\n\tPort 22\n\tProxyJump edge\n\tUnknownFutureDirective yes\n\t# keep this comment\n\tSetEnv EDITOR=vi\n\n" {
		t.Fatalf("raw block = %q", form.Raw)
	}
}

func TestProjectHostFormFlagsDangerousDirectivesAndUnstructuredLines(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "Host risky\n\tProxyCommand /usr/bin/nc %h %p\n\tLocalCommand echo hi\n\tSendEnv \"broken\n",
	})

	form, err := ProjectHostForm(graph, testRoot, HostIdentity{Path: "config", Alias: "risky"})
	if err != nil {
		t.Fatal(err)
	}
	if len(form.Fields) != 2 || !form.Fields[0].Dangerous || !form.Fields[1].Dangerous {
		t.Fatalf("fields = %#v", form.Fields)
	}
	if form.Fields[0].Category != CategoryJump || form.Fields[1].Category != CategoryAdvanced {
		t.Fatalf("categories = %#v", form.Fields)
	}
	codes := map[string]bool{}
	for _, notice := range form.Notices {
		codes[notice.Code] = true
	}
	if !codes[NoticeDangerousDirective] || !codes[NoticeUnstructuredLine] {
		t.Fatalf("notices = %#v", form.Notices)
	}
}

func TestProjectHostFormRejectsAnUnknownIdentity(t *testing.T) {
	graph := newTestGraph(t, map[string]string{"config": "Host bastion\n\tUser ops\n"})
	if _, err := ProjectHostForm(graph, testRoot, HostIdentity{Path: "config", Alias: "absent"}); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("error = %v, want ErrHostNotFound", err)
	}
}

func TestMatchHostLineFollowsOpenSSHPatternRules(t *testing.T) {
	tests := []struct {
		patterns  string
		candidate string
		want      bool
	}{
		{"bastion", "bastion", true},
		{"bastion", "Bastion", false},
		{"*.internal", "db.internal", true},
		{"*.internal", "internal", false},
		{"web?", "web1", true},
		{"web?", "web12", false},
		{"*", "anything", true},
		{"!secret *.internal", "secret", false},
		{"!secret *.internal", "db.internal", true},
		{"a* !ab", "ab", false},
		{"a* !ab", "ac", true},
	}
	for _, test := range tests {
		header := config.Parse([]byte("Host " + test.patterns + "\n"))
		block := header.Blocks()[1]
		if got := MatchHostLine(block.Patterns, test.candidate); got != test.want {
			t.Errorf("MatchHostLine(%q, %q) = %v, want %v", test.patterns, test.candidate, got, test.want)
		}
	}
}

func TestNewDiagnosticViewKeepsExternalPathsVisible(t *testing.T) {
	inside := NewDiagnosticView(testRoot, config.Diagnostic{
		Severity: config.SeverityWarning,
		Code:     config.DiagnosticIncludeNoMatch,
		Path:     testRoot + "/config",
		Line:     3,
		Detail:   testRoot + "/conf.d/*.conf",
	})
	if inside.Severity != "warning" || inside.Path != "config" || inside.External {
		t.Fatalf("inside view = %#v", inside)
	}
	outside := NewDiagnosticView(testRoot, config.Diagnostic{
		Severity: config.SeverityInfo,
		Code:     config.DiagnosticIncludeOutsideRoot,
		Path:     "/etc/ssh/ssh_config",
	})
	if !outside.External || outside.Path != "" || outside.Absolute != "/etc/ssh/ssh_config" {
		t.Fatalf("outside view = %#v", outside)
	}
}
```

- [ ] **Step 7: Run the projection tests and verify they fail**

Run: `go test ./internal/application -run 'TestProject|TestMatchHostLine|TestNewDiagnosticView' -v`

Expected: FAIL with `undefined: ProjectHosts`.

- [ ] **Step 8: Implement the projection**

```go
// internal/application/projection.go
package application

import (
	"errors"
	"strings"

	"sshc/internal/config"
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
```

- [ ] **Step 9: Run the whole package and verify it is green**

Run: `go test ./internal/application -v`

Expected: PASS.

- [ ] **Step 10: Commit the projection**

```bash
git add internal/application/walk.go internal/application/walk_test.go \
  internal/application/projection.go internal/application/projection_test.go \
  internal/application/testsupport_test.go
git commit -m "feat: project ssh host blocks into an editable form model"
```

---

## Task 3: Lossless edits and save-preview diffs

**Files:**
- Create: `internal/application/edit.go`
- Create: `internal/application/diff.go`
- Create: `internal/application/edit_test.go`
- Create: `internal/application/diff_test.go`

**Interfaces:**
- Consumes: `config.File/Line/Argument/Block/Pattern`, `config.Parse`, `(*File).Blocks/BlockAt/Render`, `config.EqualKeyword`, `storage.Digest`, Task 2 `FindHostBlock`, `PrimaryAlias`, `ErrHostNotFound`.
- Produces: `application.EditAction` constants `ActionSet`, `ActionAdd`, `ActionRemove` and `FieldEdit{Action EditAction, Line int, Keyword string, Values []string}`.
- Produces: `ApplyFieldEdits(file *config.File, block config.Block, edits []FieldEdit) error`.
- Produces: `ReplaceBlock(file *config.File, block config.Block, raw string) error`.
- Produces: `RenameHostAlias(file *config.File, block config.Block, oldAlias, newAlias string) error` and `ValidateAlias(alias string) error`.
- Produces: errors `ErrUnknownEditAction`, `ErrEditLineOutsideBlock`, `ErrEditLineNotDirective`, `ErrDuplicateEditLine`, `ErrUnquotableValue`, `ErrEmptyKeyword`, `ErrInvalidKeyword`, `ErrStructuralKeyword`, `ErrRawBlockHeader`, `ErrRawBlockStructure`, `ErrInvalidAlias`.
- Produces: `buildDirectiveLine`, `buildLine`, `rebuildLine`, `dominantEnding` for Task 4 and Task 5.
- Produces: `DiffOp` constants `DiffContext`, `DiffInsert`, `DiffDelete`; `DiffLine{Op DiffOp, Text string, OldLine, NewLine int}`; `SplitLines([]byte) []string`; `DiffLines(before, after []string) []DiffLine`; `MaxDiffLines`.
- Produces: `FileDiff{Path string, Created, Removed bool, OldDigest, NewDigest string, Lines []DiffLine, Truncated bool}` and `BuildFileDiff(path string, before, after []byte) FileDiff`.
- Produces: `ConflictReport{Path, BaseDigest, DiskDigest string, ExternalChange, LocalChange []DiffLine}` and `BuildConflictReport(path string, base, disk, edited []byte) ConflictReport`.

- [ ] **Step 1: Write the failing edit tests**

```go
// internal/application/edit_test.go
package application

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/config"
)

const editConfig = `Host bastion
	HostName 203.0.113.10
	User ops
	Port 22 # inherited from the old server
	# keep this comment

Host nas
	User aida
`

func parseEditFixture(t *testing.T, source string) (*config.File, config.Block) {
	t.Helper()
	file := config.Parse([]byte(source))
	block, ok := FindHostBlock(file, "bastion")
	if !ok {
		t.Fatal("fixture has no bastion block")
	}
	return file, block
}

func TestApplyFieldEditsChangesOnlyTheEditedLines(t *testing.T) {
	file, block := parseEditFixture(t, editConfig)

	err := ApplyFieldEdits(file, block, []FieldEdit{
		{Action: ActionSet, Line: 4, Values: []string{"2222"}},
		{Action: ActionRemove, Line: 3},
		{Action: ActionAdd, Keyword: "IdentityFile", Values: []string{"~/.ssh/id_ed25519"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	const want = `Host bastion
	HostName 203.0.113.10
	Port 2222 # inherited from the old server
	IdentityFile ~/.ssh/id_ed25519
	# keep this comment

Host nas
	User aida
`
	if got := string(file.Render()); got != want {
		t.Fatalf("render =\n%q\nwant\n%q", got, want)
	}
}

func TestApplyFieldEditsWithNoEditsRendersTheOriginalBytes(t *testing.T) {
	file, block := parseEditFixture(t, editConfig)
	if err := ApplyFieldEdits(file, block, nil); err != nil {
		t.Fatal(err)
	}
	if got := string(file.Render()); got != editConfig {
		t.Fatalf("render = %q", got)
	}
}

func TestApplyFieldEditsQuotesValuesAndRefusesUnrepresentableOnes(t *testing.T) {
	file, block := parseEditFixture(t, editConfig)
	if err := ApplyFieldEdits(file, block, []FieldEdit{
		{Action: ActionAdd, Keyword: "RemoteCommand", Values: []string{"tmux new -A -s main"}},
		{Action: ActionAdd, Keyword: "SetEnv", Values: []string{"EMPTY="}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := string(file.Render()); !strings.Contains(got, "\tRemoteCommand \"tmux new -A -s main\"\n\tSetEnv EMPTY=\n") {
		t.Fatalf("render = %q", got)
	}

	fresh, freshBlock := parseEditFixture(t, editConfig)
	if err := ApplyFieldEdits(fresh, freshBlock, []FieldEdit{
		{Action: ActionAdd, Keyword: "RemoteCommand", Values: []string{`echo "hi"`}},
	}); !errors.Is(err, ErrUnquotableValue) {
		t.Fatalf("error = %v, want ErrUnquotableValue", err)
	}
	if got := string(fresh.Render()); got != editConfig {
		t.Fatal("a rejected edit must leave the file untouched")
	}
}

func TestApplyFieldEditsRejectsStructuralAndOutOfBlockEdits(t *testing.T) {
	tests := []struct {
		name string
		edit FieldEdit
		want error
	}{
		{"new Host line", FieldEdit{Action: ActionAdd, Keyword: "Host", Values: []string{"evil"}}, ErrStructuralKeyword},
		{"new Include line", FieldEdit{Action: ActionAdd, Keyword: "Include", Values: []string{"/etc/ssh/ssh_config"}}, ErrStructuralKeyword},
		{"new Match line", FieldEdit{Action: ActionAdd, Keyword: "Match", Values: []string{"all"}}, ErrStructuralKeyword},
		{"empty keyword", FieldEdit{Action: ActionAdd, Values: []string{"x"}}, ErrEmptyKeyword},
		{"keyword with a space", FieldEdit{Action: ActionAdd, Keyword: "User Name", Values: []string{"x"}}, ErrInvalidKeyword},
		{"line in another block", FieldEdit{Action: ActionSet, Line: 8, Values: []string{"root"}}, ErrEditLineOutsideBlock},
		{"the header line", FieldEdit{Action: ActionSet, Line: 1, Values: []string{"other"}}, ErrEditLineOutsideBlock},
		{"a comment line", FieldEdit{Action: ActionSet, Line: 5, Values: []string{"x"}}, ErrEditLineNotDirective},
		{"unknown action", FieldEdit{Action: "replace", Line: 3, Values: []string{"x"}}, ErrUnknownEditAction},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, block := parseEditFixture(t, editConfig)
			if err := ApplyFieldEdits(file, block, []FieldEdit{test.edit}); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if got := string(file.Render()); got != editConfig {
				t.Fatalf("a rejected edit changed the file: %q", got)
			}
		})
	}
}

func TestApplyFieldEditsKeepsCarriageReturnLineEndings(t *testing.T) {
	source := "Host bastion\r\n\tUser ops\r\n"
	file, block := parseEditFixture(t, source)
	if err := ApplyFieldEdits(file, block, []FieldEdit{
		{Action: ActionAdd, Keyword: "Port", Values: []string{"2222"}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := string(file.Render()); got != "Host bastion\r\n\tUser ops\r\n\tPort 2222\r\n" {
		t.Fatalf("render = %q", got)
	}
}

func TestReplaceBlockSwapsExactlyOneBlock(t *testing.T) {
	file, block := parseEditFixture(t, editConfig)
	if err := ReplaceBlock(file, block, "Host bastion\n\tUser root\n\n"); err != nil {
		t.Fatal(err)
	}
	const want = `Host bastion
	User root

Host nas
	User aida
`
	if got := string(file.Render()); got != want {
		t.Fatalf("render =\n%q\nwant\n%q", got, want)
	}
}

func TestReplaceBlockRefusesRawTextThatMovesTheBlockBoundary(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"no header", "\tUser root\n", ErrRawBlockHeader},
		{"empty", "", ErrRawBlockHeader},
		{"two headers", "Host bastion\n\tUser root\nHost extra\n\tUser other\n", ErrRawBlockStructure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, block := parseEditFixture(t, editConfig)
			if err := ReplaceBlock(file, block, test.raw); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if got := string(file.Render()); got != editConfig {
				t.Fatal("a rejected raw block changed the file")
			}
		})
	}
}

func TestRenameHostAliasRewritesOnlyThePrimaryPattern(t *testing.T) {
	file := config.Parse([]byte("Host bastion jump.example.com # main\n\tUser ops\n"))
	block, ok := FindHostBlock(file, "bastion")
	if !ok {
		t.Fatal("fixture has no bastion block")
	}
	if err := RenameHostAlias(file, block, "bastion", "jump"); err != nil {
		t.Fatal(err)
	}
	if got := string(file.Render()); got != "Host jump jump.example.com # main\n\tUser ops\n" {
		t.Fatalf("render = %q", got)
	}
	for _, alias := range []string{"", "with space", "star*", "!negated", "../escape", "a" + strings.Repeat("b", 100)} {
		if err := ValidateAlias(alias); !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("ValidateAlias(%q) = %v, want ErrInvalidAlias", alias, err)
		}
	}
}
```

- [ ] **Step 2: Run the edit tests and verify they fail**

Run: `go test ./internal/application -run 'TestApplyFieldEdits|TestReplaceBlock|TestRenameHostAlias' -v`

Expected: FAIL with `undefined: ApplyFieldEdits`.

- [ ] **Step 3: Implement the lossless edit operations**

```go
// internal/application/edit.go
package application

import (
	"errors"
	"sort"
	"strings"

	"sshc/internal/config"
)

// EditAction names one change to a host block's directives.
type EditAction string

const (
	ActionSet    EditAction = "set"
	ActionAdd    EditAction = "add"
	ActionRemove EditAction = "remove"
)

var (
	ErrUnknownEditAction    = errors.New("unknown field edit action")
	ErrEditLineOutsideBlock = errors.New("edited line is outside the host block")
	ErrEditLineNotDirective = errors.New("edited line is not an editable directive")
	ErrDuplicateEditLine    = errors.New("the same line is edited twice")
	ErrUnquotableValue      = errors.New("value cannot be written in OpenSSH configuration quoting")
	ErrEmptyKeyword         = errors.New("directive keyword is required")
	ErrInvalidKeyword       = errors.New("directive keyword contains an unsupported character")
	ErrStructuralKeyword    = errors.New("Host, Match and Include are changed through their own operations")
	ErrRawBlockHeader       = errors.New("raw block must begin with a Host or Match line")
	ErrRawBlockStructure    = errors.New("raw block must contain exactly one Host or Match header")
	ErrInvalidAlias         = errors.New("alias must be 1-64 characters of letters, digits, dot, dash or underscore")
)

// structuralKeywords change the block structure of a file. A field edit may
// never introduce or rewrite one, because that would silently move directives
// between blocks or widen the set of files the application reads.
var structuralKeywords = map[string]bool{"host": true, "match": true, "include": true}

// FieldEdit is one requested change. Line is 1-based and required for set and
// remove; Keyword is required for add and optional for set.
type FieldEdit struct {
	Action  EditAction `json:"action"`
	Line    int        `json:"line,omitempty"`
	Keyword string     `json:"keyword,omitempty"`
	Values  []string   `json:"values,omitempty"`
}

// ApplyFieldEdits rewrites only the lines the user changed. Comments, blank
// lines, indentation, separators, trailing comments and line endings of every
// other line are preserved exactly. The file is left untouched when any edit is
// rejected, so a partial application can never reach disk.
func ApplyFieldEdits(file *config.File, block config.Block, edits []FieldEdit) error {
	if err := validateFieldEdits(file, block, edits); err != nil {
		return err
	}
	staged := &config.File{Lines: append([]config.Line(nil), file.Lines...)}

	for _, edit := range edits {
		if edit.Action != ActionSet {
			continue
		}
		index := edit.Line - 1
		keyword := staged.Lines[index].Keyword
		if edit.Keyword != "" {
			keyword = edit.Keyword
		}
		rebuilt, err := rebuildDirective(staged.Lines[index], keyword, edit.Values)
		if err != nil {
			return err
		}
		staged.Lines[index] = rebuilt
	}

	removals := make([]int, 0, len(edits))
	for _, edit := range edits {
		if edit.Action == ActionRemove {
			removals = append(removals, edit.Line-1)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(removals)))
	for _, index := range removals {
		staged.Lines = append(staged.Lines[:index], staged.Lines[index+1:]...)
	}

	for _, edit := range edits {
		if edit.Action != ActionAdd {
			continue
		}
		current := staged.BlockAt(block.Header)
		line, err := buildDirectiveLine(blockIndent(staged, current), edit.Keyword, edit.Values, blockEnding(staged, current))
		if err != nil {
			return err
		}
		insertLine(staged, appendPosition(staged, current), line)
	}

	file.Lines = staged.Lines
	return nil
}

func validateFieldEdits(file *config.File, block config.Block, edits []FieldEdit) error {
	touched := make(map[int]bool, len(edits))
	for _, edit := range edits {
		switch edit.Action {
		case ActionSet, ActionRemove:
			index := edit.Line - 1
			if index < block.Start || index >= block.End || index >= len(file.Lines) {
				return ErrEditLineOutsideBlock
			}
			if touched[index] {
				return ErrDuplicateEditLine
			}
			touched[index] = true
			line := file.Lines[index]
			if line.Kind != config.LineDirective {
				return ErrEditLineNotDirective
			}
			if structuralKeywords[strings.ToLower(line.Keyword)] {
				return ErrStructuralKeyword
			}
			if edit.Action == ActionSet && edit.Keyword != "" {
				if err := validateKeyword(edit.Keyword); err != nil {
					return err
				}
			}
		case ActionAdd:
			if err := validateKeyword(edit.Keyword); err != nil {
				return err
			}
		default:
			return ErrUnknownEditAction
		}
	}
	return nil
}

func validateKeyword(keyword string) error {
	if keyword == "" {
		return ErrEmptyKeyword
	}
	if structuralKeywords[strings.ToLower(keyword)] {
		return ErrStructuralKeyword
	}
	if len(keyword) > 64 {
		return ErrInvalidKeyword
	}
	for index := 0; index < len(keyword); index++ {
		character := keyword[index]
		isLetter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		isTail := index > 0 && (character >= '0' && character <= '9' || character == '-')
		if !isLetter && !isTail {
			return ErrInvalidKeyword
		}
	}
	return nil
}

// ValidateAlias limits aliases created through the UI to a conservative set, so
// a new Host line can never carry a pattern, a negation or whitespace. Aliases
// that already exist in a file are displayed as written and never rewritten.
func ValidateAlias(alias string) error {
	if len(alias) == 0 || len(alias) > 64 {
		return ErrInvalidAlias
	}
	for index := 0; index < len(alias); index++ {
		character := alias[index]
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9':
		case index > 0 && (character == '.' || character == '-' || character == '_'):
		default:
			return ErrInvalidAlias
		}
	}
	return nil
}

// splitCommentArguments separates the value arguments of a directive from a
// trailing comment so rewriting the values keeps the comment.
func splitCommentArguments(arguments []config.Argument) (values, comment []config.Argument) {
	for index, argument := range arguments {
		if strings.HasPrefix(argument.Raw, "#") {
			return arguments[:index], arguments[index:]
		}
	}
	return arguments, nil
}

func rebuildDirective(line config.Line, keyword string, values []string) (config.Line, error) {
	if err := validateKeyword(keyword); err != nil {
		return config.Line{}, err
	}
	return rebuildLine(line, keyword, values)
}

// rebuildLine replaces the value arguments of a directive line while keeping
// its indent, separator, trailing comment and line ending. It performs no
// keyword policy check, so Host header rewrites can use it.
func rebuildLine(line config.Line, keyword string, values []string) (config.Line, error) {
	existing, comment := splitCommentArguments(line.Arguments)
	rebuilt := line
	rebuilt.Keyword = keyword
	if rebuilt.Separator == "" {
		rebuilt.Separator = " "
	}

	arguments := make([]config.Argument, 0, len(values)+len(comment))
	for index, value := range values {
		lead := " "
		if index == 0 {
			lead = ""
		}
		if index < len(existing) {
			lead = existing[index].Lead
		}
		argument, err := renderArgument(lead, value)
		if err != nil {
			return config.Line{}, err
		}
		arguments = append(arguments, argument)
	}
	for index, argument := range comment {
		copied := argument
		if index == 0 && len(arguments) == 0 && copied.Lead == "" {
			copied.Lead = " "
		}
		arguments = append(arguments, copied)
	}
	rebuilt.Arguments = arguments
	return rebuilt, nil
}

// renderArgument writes one value using OpenSSH's quoting rules. OpenSSH has no
// backslash escape inside a quoted argument, so a value containing a double
// quote, a newline or a NUL cannot be represented and is refused instead of
// being mangled.
func renderArgument(lead, value string) (config.Argument, error) {
	if strings.ContainsAny(value, "\n\r\x00\"") {
		return config.Argument{}, ErrUnquotableValue
	}
	raw := value
	if value == "" || strings.ContainsAny(value, " \t") || strings.HasPrefix(value, "#") {
		raw = `"` + value + `"`
	}
	return config.Argument{Lead: lead, Raw: raw, Value: value}, nil
}

func buildDirectiveLine(indent, keyword string, values []string, ending string) (config.Line, error) {
	if err := validateKeyword(keyword); err != nil {
		return config.Line{}, err
	}
	return buildLine(indent, keyword, values, ending)
}

// buildLine composes a directive line without a keyword policy check.
func buildLine(indent, keyword string, values []string, ending string) (config.Line, error) {
	line := config.Line{
		Kind:      config.LineDirective,
		Indent:    indent,
		Keyword:   keyword,
		Separator: " ",
		Ending:    ending,
	}
	for index, value := range values {
		lead := " "
		if index == 0 {
			lead = ""
		}
		argument, err := renderArgument(lead, value)
		if err != nil {
			return config.Line{}, err
		}
		line.Arguments = append(line.Arguments, argument)
	}
	return line, nil
}

// appendPosition returns the index at which a new directive belongs: directly
// after the block's last directive so trailing comments and blank lines keep
// their place.
func appendPosition(file *config.File, block config.Block) int {
	position := block.Start
	for index := block.Start; index < block.End && index < len(file.Lines); index++ {
		if file.Lines[index].Kind == config.LineDirective {
			position = index + 1
		}
	}
	return position
}

func blockIndent(file *config.File, block config.Block) string {
	for index := block.End - 1; index >= block.Start; index-- {
		if index < len(file.Lines) && file.Lines[index].Kind == config.LineDirective {
			return file.Lines[index].Indent
		}
	}
	return "\t"
}

func blockEnding(file *config.File, block config.Block) string {
	for index := block.End - 1; index >= block.Start; index-- {
		if index < len(file.Lines) && file.Lines[index].Kind == config.LineDirective && file.Lines[index].Ending != "" {
			return file.Lines[index].Ending
		}
	}
	return dominantEnding(file)
}

// dominantEnding reports the line ending the file already uses, so an edit to a
// CRLF file does not introduce a lone newline.
func dominantEnding(file *config.File) string {
	for _, line := range file.Lines {
		if line.Ending != "" {
			return line.Ending
		}
	}
	return "\n"
}

// insertLine inserts a line at position, giving the preceding line an ending
// first when the file previously stopped without one.
func insertLine(file *config.File, position int, line config.Line) {
	if position > 0 && file.Lines[position-1].Ending == "" {
		file.Lines[position-1].Ending = line.Ending
	}
	file.Lines = append(file.Lines, config.Line{})
	copy(file.Lines[position+1:], file.Lines[position:])
	file.Lines[position] = line
}

// ReplaceBlock swaps the whole text of one Host or Match block. The raw text
// must describe exactly one block so the surrounding file keeps its structure;
// everything before and after the block is preserved byte for byte.
func ReplaceBlock(file *config.File, block config.Block, raw string) error {
	if block.Header < 0 || block.Header >= len(file.Lines) {
		return ErrRawBlockHeader
	}
	replacement := config.Parse([]byte(raw))

	headers := 0
	firstDirective := -1
	for index, line := range replacement.Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		if firstDirective < 0 {
			firstDirective = index
		}
		if config.EqualKeyword(line.Keyword, "Host") || config.EqualKeyword(line.Keyword, "Match") {
			headers++
		}
	}
	if firstDirective < 0 {
		return ErrRawBlockHeader
	}
	header := replacement.Lines[firstDirective]
	if !config.EqualKeyword(header.Keyword, "Host") && !config.EqualKeyword(header.Keyword, "Match") {
		return ErrRawBlockHeader
	}
	if headers != 1 {
		return ErrRawBlockStructure
	}

	if block.End < len(file.Lines) {
		last := &replacement.Lines[len(replacement.Lines)-1]
		if last.Ending == "" {
			last.Ending = dominantEnding(file)
		}
	}
	updated := make([]config.Line, 0, len(file.Lines)+len(replacement.Lines))
	updated = append(updated, file.Lines[:block.Header]...)
	updated = append(updated, replacement.Lines...)
	updated = append(updated, file.Lines[block.End:]...)
	file.Lines = updated
	return nil
}

// RenameHostAlias replaces one alias on a Host header line and leaves every
// other pattern, the trailing comment and the line ending untouched.
func RenameHostAlias(file *config.File, block config.Block, oldAlias, newAlias string) error {
	if err := ValidateAlias(newAlias); err != nil {
		return err
	}
	if block.Kind != config.BlockHost || block.Header < 0 || block.Header >= len(file.Lines) {
		return ErrRawBlockHeader
	}
	header := file.Lines[block.Header]
	values := header.Values()
	replaced := false
	updated := make([]string, 0, len(values))
	for _, value := range values {
		if !replaced && value == oldAlias {
			value = newAlias
			replaced = true
		}
		updated = append(updated, value)
	}
	if !replaced {
		return ErrHostNotFound
	}
	rebuilt, err := rebuildLine(header, header.Keyword, updated)
	if err != nil {
		return err
	}
	file.Lines[block.Header] = rebuilt
	return nil
}
```

- [ ] **Step 4: Run the edit tests to verify they pass**

Run: `go test ./internal/application -run 'TestApplyFieldEdits|TestReplaceBlock|TestRenameHostAlias' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing diff tests**

```go
// internal/application/diff_test.go
package application

import (
	"testing"

	"sshc/internal/storage"
)

func TestBuildFileDiffMarksOnlyTheChangedLines(t *testing.T) {
	before := []byte("Host bastion\n\tUser ops\n\tPort 22\n")
	after := []byte("Host bastion\n\tUser ops\n\tPort 2222\n")

	diff := BuildFileDiff("config", before, after)
	if diff.Path != "config" || diff.Created || diff.Removed || diff.Truncated {
		t.Fatalf("diff = %#v", diff)
	}
	if diff.OldDigest != storage.Digest(before) || diff.NewDigest != storage.Digest(after) {
		t.Fatalf("digests = %q %q", diff.OldDigest, diff.NewDigest)
	}
	want := []DiffLine{
		{Op: DiffContext, Text: "Host bastion", OldLine: 1, NewLine: 1},
		{Op: DiffContext, Text: "\tUser ops", OldLine: 2, NewLine: 2},
		{Op: DiffDelete, Text: "\tPort 22", OldLine: 3},
		{Op: DiffInsert, Text: "\tPort 2222", NewLine: 3},
	}
	if len(diff.Lines) != len(want) {
		t.Fatalf("lines = %#v", diff.Lines)
	}
	for index := range want {
		if diff.Lines[index] != want[index] {
			t.Fatalf("line[%d] = %#v, want %#v", index, diff.Lines[index], want[index])
		}
	}
}

func TestBuildFileDiffReportsCreationAndTruncation(t *testing.T) {
	created := BuildFileDiff("groups.sshc.conf", nil, []byte("Host build01\n\tUser ops\n"))
	if !created.Created || created.OldDigest != "" || len(created.Lines) != 2 {
		t.Fatalf("created diff = %#v", created)
	}
	if created.Lines[0].Op != DiffInsert {
		t.Fatalf("created lines = %#v", created.Lines)
	}

	large := make([]byte, 0, MaxDiffLines*8)
	for counter := 0; counter <= MaxDiffLines; counter++ {
		large = append(large, []byte("\tUser ops\n")...)
	}
	truncated := BuildFileDiff("config", large, append(large, []byte("\tPort 22\n")...))
	if !truncated.Truncated {
		t.Fatal("an oversized diff must be reported as truncated instead of silently trimmed")
	}
}

func TestBuildConflictReportShowsBothSidesOfAnExternalChange(t *testing.T) {
	base := []byte("Host bastion\n\tUser ops\n")
	disk := []byte("Host bastion\n\tUser ops\n\tPort 22\n")
	edited := []byte("Host bastion\n\tUser admin\n")

	report := BuildConflictReport("config", base, disk, edited)
	if report.Path != "config" || report.BaseDigest != storage.Digest(base) || report.DiskDigest != storage.Digest(disk) {
		t.Fatalf("report = %#v", report)
	}
	if len(report.ExternalChange) != 3 || report.ExternalChange[2].Op != DiffInsert {
		t.Fatalf("external change = %#v", report.ExternalChange)
	}
	if len(report.LocalChange) != 3 || report.LocalChange[1].Op != DiffDelete || report.LocalChange[2].Op != DiffInsert {
		t.Fatalf("local change = %#v", report.LocalChange)
	}
}

func TestSplitLinesDropsOnlyTheTrailingNewline(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"one", []string{"one"}},
		{"one\n", []string{"one"}},
		{"one\ntwo\n", []string{"one", "two"}},
		{"one\r\ntwo\r\n", []string{"one", "two"}},
		{"one\n\n", []string{"one", ""}},
	}
	for _, test := range tests {
		got := SplitLines([]byte(test.input))
		if len(got) != len(test.want) {
			t.Fatalf("SplitLines(%q) = %#v, want %#v", test.input, got, test.want)
		}
		for index := range test.want {
			if got[index] != test.want[index] {
				t.Fatalf("SplitLines(%q)[%d] = %q, want %q", test.input, index, got[index], test.want[index])
			}
		}
	}
}
```

- [ ] **Step 6: Run the diff tests and verify they fail**

Run: `go test ./internal/application -run 'TestBuildFileDiff|TestBuildConflictReport|TestSplitLines' -v`

Expected: FAIL with `undefined: BuildFileDiff`.

- [ ] **Step 7: Implement the diff**

```go
// internal/application/diff.go
package application

import (
	"strings"

	"sshc/internal/storage"
)

// MaxDiffLines bounds the quadratic longest-common-subsequence table. A file
// larger than this is reported as a wholesale replacement with Truncated set,
// so the UI can say so instead of pretending to show a minimal diff.
const MaxDiffLines = 4000

// DiffOp classifies one line of a save preview.
type DiffOp string

const (
	DiffContext DiffOp = "context"
	DiffInsert  DiffOp = "insert"
	DiffDelete  DiffOp = "delete"
)

// DiffLine is one displayed line. OldLine and NewLine are 1-based and zero when
// the line exists on only one side.
type DiffLine struct {
	Op      DiffOp `json:"op"`
	Text    string `json:"text"`
	OldLine int    `json:"oldLine,omitempty"`
	NewLine int    `json:"newLine,omitempty"`
}

// FileDiff is the preview of one file in a pending transaction.
type FileDiff struct {
	Path      string     `json:"path"`
	Created   bool       `json:"created,omitempty"`
	Removed   bool       `json:"removed,omitempty"`
	OldDigest string     `json:"oldDigest,omitempty"`
	NewDigest string     `json:"newDigest,omitempty"`
	Lines     []DiffLine `json:"lines"`
	Truncated bool       `json:"truncated,omitempty"`
}

// ConflictReport is the three-way view design §9 requires when the file on disk
// is no longer the file the user edited.
type ConflictReport struct {
	Path           string     `json:"path"`
	BaseDigest     string     `json:"baseDigest,omitempty"`
	DiskDigest     string     `json:"diskDigest,omitempty"`
	ExternalChange []DiffLine `json:"externalChange"`
	LocalChange    []DiffLine `json:"localChange"`
}

// SplitLines splits file contents for display. It drops the final newline and
// the carriage returns of CRLF files, because the diff view shows text; the
// bytes written to disk always come from the syntax tree, never from here.
func SplitLines(contents []byte) []string {
	if len(contents) == 0 {
		return nil
	}
	text := strings.TrimSuffix(string(contents), "\n")
	parts := strings.Split(text, "\n")
	for index := range parts {
		parts[index] = strings.TrimSuffix(parts[index], "\r")
	}
	return parts
}

// DiffLines computes a minimal line diff through a longest common subsequence.
func DiffLines(before, after []string) []DiffLine {
	if len(before) > MaxDiffLines || len(after) > MaxDiffLines {
		return replacementDiff(before, after)
	}
	table := make([][]int, len(before)+1)
	for index := range table {
		table[index] = make([]int, len(after)+1)
	}
	for beforeIndex := len(before) - 1; beforeIndex >= 0; beforeIndex-- {
		for afterIndex := len(after) - 1; afterIndex >= 0; afterIndex-- {
			switch {
			case before[beforeIndex] == after[afterIndex]:
				table[beforeIndex][afterIndex] = table[beforeIndex+1][afterIndex+1] + 1
			case table[beforeIndex+1][afterIndex] >= table[beforeIndex][afterIndex+1]:
				table[beforeIndex][afterIndex] = table[beforeIndex+1][afterIndex]
			default:
				table[beforeIndex][afterIndex] = table[beforeIndex][afterIndex+1]
			}
		}
	}

	lines := make([]DiffLine, 0, len(before)+len(after))
	beforeIndex, afterIndex := 0, 0
	for beforeIndex < len(before) && afterIndex < len(after) {
		switch {
		case before[beforeIndex] == after[afterIndex]:
			lines = append(lines, DiffLine{Op: DiffContext, Text: before[beforeIndex], OldLine: beforeIndex + 1, NewLine: afterIndex + 1})
			beforeIndex++
			afterIndex++
		case table[beforeIndex+1][afterIndex] >= table[beforeIndex][afterIndex+1]:
			lines = append(lines, DiffLine{Op: DiffDelete, Text: before[beforeIndex], OldLine: beforeIndex + 1})
			beforeIndex++
		default:
			lines = append(lines, DiffLine{Op: DiffInsert, Text: after[afterIndex], NewLine: afterIndex + 1})
			afterIndex++
		}
	}
	for ; beforeIndex < len(before); beforeIndex++ {
		lines = append(lines, DiffLine{Op: DiffDelete, Text: before[beforeIndex], OldLine: beforeIndex + 1})
	}
	for ; afterIndex < len(after); afterIndex++ {
		lines = append(lines, DiffLine{Op: DiffInsert, Text: after[afterIndex], NewLine: afterIndex + 1})
	}
	return lines
}

func replacementDiff(before, after []string) []DiffLine {
	lines := make([]DiffLine, 0, len(before)+len(after))
	for index, text := range before {
		lines = append(lines, DiffLine{Op: DiffDelete, Text: text, OldLine: index + 1})
	}
	for index, text := range after {
		lines = append(lines, DiffLine{Op: DiffInsert, Text: text, NewLine: index + 1})
	}
	return lines
}

// BuildFileDiff previews one file change.
func BuildFileDiff(path string, before, after []byte) FileDiff {
	beforeLines := SplitLines(before)
	afterLines := SplitLines(after)
	diff := FileDiff{
		Path:      path,
		Created:   before == nil,
		Removed:   after == nil,
		Lines:     DiffLines(beforeLines, afterLines),
		Truncated: len(beforeLines) > MaxDiffLines || len(afterLines) > MaxDiffLines,
	}
	if before != nil {
		diff.OldDigest = storage.Digest(before)
	}
	if after != nil {
		diff.NewDigest = storage.Digest(after)
	}
	return diff
}

// BuildConflictReport explains an external change: what the other writer did to
// the base, and what the user's pending edit would have done to the same base.
func BuildConflictReport(path string, base, disk, edited []byte) ConflictReport {
	return ConflictReport{
		Path:           path,
		BaseDigest:     storage.Digest(base),
		DiskDigest:     storage.Digest(disk),
		ExternalChange: DiffLines(SplitLines(base), SplitLines(disk)),
		LocalChange:    DiffLines(SplitLines(base), SplitLines(edited)),
	}
}
```

- [ ] **Step 8: Run the whole package and verify it is green**

Run: `go test ./internal/application -v`

Expected: PASS.

- [ ] **Step 9: Commit the edit and diff engine**

```bash
git add internal/application/edit.go internal/application/edit_test.go \
  internal/application/diff.go internal/application/diff_test.go
git commit -m "feat: apply host edits without losing surrounding bytes"
```

---

## Task 4: Explained effective values and group compilation

**Files:**
- Create: `internal/application/effective.go`
- Create: `internal/application/groups.go`
- Create: `internal/application/effective_test.go`
- Create: `internal/application/groups_test.go`

**Interfaces:**
- Consumes: Task 2 `WalkDirectives`, `Visit`, `MatchHostLine`, `HostEntry`, `Notice`; Task 1 `Metadata`, `GroupMetadata`, `Setting`, `HostIdentity`; Task 3 `buildLine`, `buildDirectiveLine`, `renderArgument`.
- Produces: `application.Source{Path string, Line int, Condition string}`.
- Produces: `application.EffectiveEntry{Keyword string, Values []string, Source Source}` and `Effective{Alias string, Approximate bool, Entries []EffectiveEntry, Notices []Notice}`.
- Produces: `ComputeEffective(graph *config.Graph, root, alias string) Effective`.
- Produces: `application.EffectiveChange{Keyword string, Before, After []string, BeforeSources, AfterSources []Source}` and `EffectiveDiff{Alias string, Changes []EffectiveChange}`; `DiffEffective(before, after Effective) EffectiveDiff`.
- Produces: `GroupDepthOrder(groups []GroupMetadata) ([]GroupMetadata, []Notice)`.
- Produces: `CompileGroups(metadata Metadata, hosts []HostEntry, ending string) ([]byte, []Notice)`.
- Produces: `PlanGroupInclude(file *config.File, relative string) (index int, present bool)`.
- Produces: `InsertIncludeLine(file *config.File, relative string, index int) error`.

- [ ] **Step 1: Write the failing effective-value tests**

```go
// internal/application/effective_test.go
package application

import "testing"

const effectiveFiles = `Include conf.d/*.conf
Host bastion
	User ops
	IdentityFile ~/.ssh/id_a
	IdentityFile ~/.ssh/id_b
Match host bastion
	User match-user
Host *
	User fallback
	ServerAliveInterval 30
`

func TestComputeEffectiveTakesTheFirstValueAndKeepsItsSource(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":               effectiveFiles,
		"conf.d/10-first.conf": "Host bastion\n\tPort 2200\n",
	})

	effective := ComputeEffective(graph, testRoot, "bastion")
	if !effective.Approximate {
		t.Fatal("explained values must be marked approximate until ssh -G arrives")
	}
	want := []struct {
		keyword string
		value   string
		path    string
		line    int
	}{
		{"IdentityFile", "~/.ssh/id_a", "config", 4},
		{"IdentityFile", "~/.ssh/id_b", "config", 5},
		{"Port", "2200", "conf.d/10-first.conf", 2},
		{"ServerAliveInterval", "30", "config", 10},
		{"User", "ops", "config", 3},
	}
	if len(effective.Entries) != len(want) {
		t.Fatalf("entries = %#v", effective.Entries)
	}
	for index, expected := range want {
		entry := effective.Entries[index]
		if entry.Keyword != expected.keyword || entry.Values[0] != expected.value {
			t.Fatalf("entry[%d] = %#v, want %q %q", index, entry, expected.keyword, expected.value)
		}
		if entry.Source.Path != expected.path || entry.Source.Line != expected.line {
			t.Fatalf("entry[%d] source = %#v, want %q line %d", index, entry.Source, expected.path, expected.line)
		}
	}

	codes := map[string]bool{}
	for _, notice := range effective.Notices {
		codes[notice.Code] = true
	}
	if !codes[NoticeMatchBlock] || !codes[NoticeComplexExternalRule] || !codes[NoticeExplainedValuesOnly] {
		t.Fatalf("notices = %#v", effective.Notices)
	}
}

func TestComputeEffectiveIgnoresBlocksThatDoNotMatch(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "Host other\n\tUser other-user\nHost !bastion *\n\tUser negated\n",
	})
	effective := ComputeEffective(graph, testRoot, "bastion")
	if len(effective.Entries) != 0 {
		t.Fatalf("entries = %#v", effective.Entries)
	}
}

func TestDiffEffectiveReportsAddedChangedAndRemovedValues(t *testing.T) {
	before := Effective{Alias: "build01", Entries: []EffectiveEntry{
		{Keyword: "User", Values: []string{"ops"}, Source: Source{Path: "config", Line: 3}},
		{Keyword: "Port", Values: []string{"22"}, Source: Source{Path: "config", Line: 4}},
	}}
	after := Effective{Alias: "build01", Entries: []EffectiveEntry{
		{Keyword: "User", Values: []string{"ops"}, Source: Source{Path: "config", Line: 3}},
		{Keyword: "Port", Values: []string{"2222"}, Source: Source{Path: "groups.sshc.conf", Line: 5}},
		{Keyword: "ServerAliveInterval", Values: []string{"30"}, Source: Source{Path: "groups.sshc.conf", Line: 6}},
	}}

	diff := DiffEffective(before, after)
	if diff.Alias != "build01" || len(diff.Changes) != 2 {
		t.Fatalf("diff = %#v", diff)
	}
	if diff.Changes[0].Keyword != "Port" || diff.Changes[0].Before[0] != "22" || diff.Changes[0].After[0] != "2222" {
		t.Fatalf("port change = %#v", diff.Changes[0])
	}
	if diff.Changes[0].AfterSources[0].Path != "groups.sshc.conf" {
		t.Fatalf("port source = %#v", diff.Changes[0].AfterSources)
	}
	if diff.Changes[1].Keyword != "ServerAliveInterval" || len(diff.Changes[1].Before) != 0 {
		t.Fatalf("added change = %#v", diff.Changes[1])
	}
}
```

- [ ] **Step 2: Run the effective tests and verify they fail**

Run: `go test ./internal/application -run 'TestComputeEffective|TestDiffEffective' -v`

Expected: FAIL with `undefined: ComputeEffective`.

- [ ] **Step 3: Implement explained effective values**

```go
// internal/application/effective.go
package application

import (
	"sort"
	"strings"

	"sshc/internal/config"
)

// cumulativeKeywords are the directives OpenSSH accumulates instead of keeping
// only the first value. Every other keyword follows first-value-wins.
var cumulativeKeywords = map[string]bool{
	"identityfile": true, "certificatefile": true, "localforward": true,
	"remoteforward": true, "dynamicforward": true, "sendenv": true, "setenv": true,
}

// Source is where a value came from.
type Source struct {
	Path      string `json:"path,omitempty"`
	Absolute  string `json:"absolute,omitempty"`
	Line      int    `json:"line,omitempty"`
	Condition string `json:"condition,omitempty"`
}

// EffectiveEntry is one explained value.
type EffectiveEntry struct {
	Keyword string   `json:"keyword"`
	Values  []string `json:"values"`
	Source  Source   `json:"source"`
}

// Effective is this engine's explanation of the values an alias receives.
//
// Approximate is always true: design §5.5 makes the installed OpenSSH's
// `ssh -G` the authority, and that evaluation belongs to a later subsystem
// because it can execute user commands. This view exists to show where a value
// comes from, and it says so instead of claiming to be the final answer.
type Effective struct {
	Alias       string           `json:"alias"`
	Approximate bool             `json:"approximate"`
	Entries     []EffectiveEntry `json:"entries"`
	Notices     []Notice         `json:"notices,omitempty"`
}

// ComputeEffective walks the graph in reading order and records the first value
// for each keyword, accumulating the keywords OpenSSH accumulates. Match blocks
// are never evaluated, because `Match exec` can run the user's shell; their
// presence is reported as a complex external rule instead.
func ComputeEffective(graph *config.Graph, root, alias string) Effective {
	effective := Effective{Alias: alias, Approximate: true, Entries: []EffectiveEntry{}}
	effective.Notices = appendNotice(effective.Notices, Notice{Code: NoticeExplainedValuesOnly})
	seen := map[string]bool{}

	WalkDirectives(graph, func(visit Visit) bool {
		if visit.Block.Header == visit.Index {
			return true
		}
		if config.EqualKeyword(visit.Line.Keyword, "Include") {
			return true
		}
		reference := NewFileRef(root, visit.Path)

		switch visit.Block.Kind {
		case config.BlockMatch:
			effective.Notices = appendNotice(effective.Notices, Notice{
				Code: NoticeMatchBlock, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
			})
			effective.Notices = appendNotice(effective.Notices, Notice{
				Code: NoticeComplexExternalRule, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
			})
			return true
		case config.BlockHost:
			if !MatchHostLine(visit.Block.Patterns, alias) {
				return true
			}
			for _, pattern := range visit.Block.Patterns {
				if !pattern.Negated {
					continue
				}
				effective.Notices = appendNotice(effective.Notices, Notice{
					Code: NoticeNegatedPattern, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
				})
			}
		}

		lowered := strings.ToLower(visit.Line.Keyword)
		if seen[lowered] && !cumulativeKeywords[lowered] {
			return true
		}
		seen[lowered] = true
		effective.Entries = append(effective.Entries, EffectiveEntry{
			Keyword: visit.Line.Keyword,
			Values:  visit.Line.Values(),
			Source: Source{
				Path:      reference.Path,
				Absolute:  reference.Absolute,
				Line:      visit.Index + 1,
				Condition: visit.Condition,
			},
		})
		return true
	})

	sort.SliceStable(effective.Entries, func(first, second int) bool {
		return strings.ToLower(effective.Entries[first].Keyword) < strings.ToLower(effective.Entries[second].Keyword)
	})
	return effective
}

// EffectiveChange is one keyword whose explained value changes.
type EffectiveChange struct {
	Keyword       string   `json:"keyword"`
	Before        []string `json:"before"`
	After         []string `json:"after"`
	BeforeSources []Source `json:"beforeSources,omitempty"`
	AfterSources  []Source `json:"afterSources,omitempty"`
}

// EffectiveDiff is the before/after view design §5.4 requires before a group
// change is saved.
type EffectiveDiff struct {
	Alias   string            `json:"alias"`
	Changes []EffectiveChange `json:"changes"`
}

// DiffEffective compares two explanations keyword by keyword.
func DiffEffective(before, after Effective) EffectiveDiff {
	diff := EffectiveDiff{Alias: after.Alias, Changes: []EffectiveChange{}}
	if diff.Alias == "" {
		diff.Alias = before.Alias
	}
	beforeIndex := indexEffective(before)
	afterIndex := indexEffective(after)

	keywords := make([]string, 0, len(beforeIndex)+len(afterIndex))
	for keyword := range beforeIndex {
		keywords = append(keywords, keyword)
	}
	for keyword := range afterIndex {
		if _, ok := beforeIndex[keyword]; !ok {
			keywords = append(keywords, keyword)
		}
	}
	sort.Strings(keywords)

	for _, keyword := range keywords {
		beforeValues, beforeSources, display := renderEffective(beforeIndex[keyword])
		afterValues, afterSources, afterDisplay := renderEffective(afterIndex[keyword])
		if afterDisplay != "" {
			display = afterDisplay
		}
		if equalStrings(beforeValues, afterValues) && equalSources(beforeSources, afterSources) {
			continue
		}
		diff.Changes = append(diff.Changes, EffectiveChange{
			Keyword:       display,
			Before:        beforeValues,
			After:         afterValues,
			BeforeSources: beforeSources,
			AfterSources:  afterSources,
		})
	}
	return diff
}

func indexEffective(effective Effective) map[string][]EffectiveEntry {
	index := make(map[string][]EffectiveEntry, len(effective.Entries))
	for _, entry := range effective.Entries {
		lowered := strings.ToLower(entry.Keyword)
		index[lowered] = append(index[lowered], entry)
	}
	return index
}

func renderEffective(entries []EffectiveEntry) (values []string, sources []Source, display string) {
	values = []string{}
	sources = []Source{}
	for _, entry := range entries {
		if display == "" {
			display = entry.Keyword
		}
		values = append(values, strings.Join(entry.Values, " "))
		sources = append(sources, entry.Source)
	}
	return values, sources, display
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func equalSources(first, second []Source) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run the effective tests to verify they pass**

Run: `go test ./internal/application -run 'TestComputeEffective|TestDiffEffective' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing group tests**

```go
// internal/application/groups_test.go
package application

import (
	"testing"

	"sshc/internal/config"
)

func groupFixture() (Metadata, []HostEntry) {
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{
		{Name: "company", Settings: []Setting{{Keyword: "ServerAliveInterval", Values: []string{"30"}}}},
		{Name: "work", Parent: "company", Settings: []Setting{
			{Keyword: "User", Values: []string{"ops"}},
			{Keyword: "Port", Values: []string{"2222"}},
		}},
	}
	metadata.Hosts = []HostMetadata{
		{Identity: HostIdentity{Path: "config", Alias: "build01"}, Group: "work"},
		{Identity: HostIdentity{Path: "config", Alias: "web01"}, Group: "company"},
		{Identity: HostIdentity{Path: "config", Alias: "ghost"}, Group: "work"},
	}
	hosts := []HostEntry{
		{Identity: HostIdentity{Path: "config", Alias: "build01"}},
		{Identity: HostIdentity{Path: "config", Alias: "web01"}},
	}
	return metadata, hosts
}

func TestCompileGroupsPutsChildrenBeforeParentsAndInheritsMembers(t *testing.T) {
	metadata, hosts := groupFixture()

	contents, notices := CompileGroups(metadata, hosts, "\n")
	const want = `# Generated by sshc from ~/.ssh/sshc/metadata.json.
# Child groups come first because OpenSSH keeps the first value it reads.
# Edit groups in the UI; hand edits to this file are replaced on the next save.

# group work (parent company)
Host build01
	User ops
	Port 2222

# group company
Host build01 web01
	ServerAliveInterval 30
`
	if got := string(contents); got != want {
		t.Fatalf("contents =\n%q\nwant\n%q", got, want)
	}
	if len(notices) != 1 || notices[0].Code != NoticeGroupMemberMissing || notices[0].Detail != "ghost" {
		t.Fatalf("notices = %#v", notices)
	}
}

func TestCompileGroupsRendersParsableLosslessConfiguration(t *testing.T) {
	metadata, hosts := groupFixture()
	contents, _ := CompileGroups(metadata, hosts, "\n")
	parsed := config.Parse(contents)
	if string(parsed.Render()) != string(contents) {
		t.Fatal("generated group configuration does not round-trip")
	}
	for index, line := range parsed.Lines {
		if line.Kind == config.LineUnstructured {
			t.Fatalf("generated line %d is unstructured: %q", index+1, line.Text)
		}
	}
}

func TestGroupDepthOrderExcludesCyclesInsteadOfLooping(t *testing.T) {
	groups := []GroupMetadata{
		{Name: "a", Parent: "b"},
		{Name: "b", Parent: "a"},
		{Name: "standalone"},
	}
	ordered, notices := GroupDepthOrder(groups)
	if len(ordered) != 1 || ordered[0].Name != "standalone" {
		t.Fatalf("ordered = %#v", ordered)
	}
	if len(notices) != 2 || notices[0].Code != NoticeGroupCycle {
		t.Fatalf("notices = %#v", notices)
	}
}

func TestPlanGroupIncludePlacesTheIncludeBeforeCatchAllDefaults(t *testing.T) {
	file := config.Parse([]byte("Host bastion\n\tUser ops\nHost *\n\tServerAliveInterval 30\n"))
	index, present := PlanGroupInclude(file, DefaultGroupsFile)
	if present || index != 2 {
		t.Fatalf("index = %d, present = %v", index, present)
	}
	if err := InsertIncludeLine(file, DefaultGroupsFile, index); err != nil {
		t.Fatal(err)
	}
	const want = "Host bastion\n\tUser ops\nInclude groups.sshc.conf\nHost *\n\tServerAliveInterval 30\n"
	if got := string(file.Render()); got != want {
		t.Fatalf("render = %q", got)
	}

	again, presentNow := PlanGroupInclude(file, DefaultGroupsFile)
	if !presentNow || again != -1 {
		t.Fatalf("second plan = %d, %v", again, presentNow)
	}
}

func TestPlanGroupIncludeAppendsWhenThereIsNoCatchAllBlock(t *testing.T) {
	file := config.Parse([]byte("Host bastion\n\tUser ops\n"))
	index, present := PlanGroupInclude(file, DefaultGroupsFile)
	if present || index != len(file.Lines) {
		t.Fatalf("index = %d, present = %v, lines = %d", index, present, len(file.Lines))
	}
	if err := InsertIncludeLine(file, DefaultGroupsFile, index); err != nil {
		t.Fatal(err)
	}
	if got := string(file.Render()); got != "Host bastion\n\tUser ops\nInclude groups.sshc.conf\n" {
		t.Fatalf("render = %q", got)
	}
}
```

- [ ] **Step 6: Run the group tests and verify they fail**

Run: `go test ./internal/application -run 'TestCompileGroups|TestGroupDepthOrder|TestPlanGroupInclude' -v`

Expected: FAIL with `undefined: CompileGroups`.

- [ ] **Step 7: Implement group compilation**

```go
// internal/application/groups.go
package application

import (
	"sort"
	"strings"

	"sshc/internal/config"
)

// maxGroupDepth bounds the parent walk so a malformed hierarchy cannot loop.
const maxGroupDepth = 32

// GroupDepthOrder sorts groups deepest first, which is the order OpenSSH needs:
// a child's Host block must be read before its parent's so the child's value is
// the first value found. Groups in a parent cycle are excluded and reported.
func GroupDepthOrder(groups []GroupMetadata) ([]GroupMetadata, []Notice) {
	byName := make(map[string]GroupMetadata, len(groups))
	for _, group := range groups {
		byName[group.Name] = group
	}
	depths := make(map[string]int, len(groups))
	ordered := make([]GroupMetadata, 0, len(groups))
	var notices []Notice
	for _, group := range groups {
		depth, ok := groupDepth(byName, group.Name, map[string]bool{})
		if !ok {
			notices = appendNotice(notices, Notice{Code: NoticeGroupCycle, Detail: group.Name})
			continue
		}
		depths[group.Name] = depth
		ordered = append(ordered, group)
	}
	sort.SliceStable(ordered, func(first, second int) bool {
		firstDepth, secondDepth := depths[ordered[first].Name], depths[ordered[second].Name]
		if firstDepth != secondDepth {
			return firstDepth > secondDepth
		}
		if ordered[first].Order != ordered[second].Order {
			return ordered[first].Order < ordered[second].Order
		}
		return ordered[first].Name < ordered[second].Name
	})
	return ordered, notices
}

func groupDepth(byName map[string]GroupMetadata, name string, seen map[string]bool) (int, bool) {
	if seen[name] || len(seen) > maxGroupDepth {
		return 0, false
	}
	group, ok := byName[name]
	if !ok || group.Parent == "" {
		return 0, true
	}
	seen[name] = true
	parentDepth, ok := groupDepth(byName, group.Parent, seen)
	if !ok {
		return 0, false
	}
	return parentDepth + 1, true
}

func isDescendantGroup(byName map[string]GroupMetadata, candidate, ancestor string) bool {
	current := candidate
	for depth := 0; depth < maxGroupDepth; depth++ {
		group, ok := byName[current]
		if !ok || group.Parent == "" {
			return false
		}
		if group.Parent == ancestor {
			return true
		}
		current = group.Parent
	}
	return false
}

// CompileGroups renders the group hierarchy as ordinary Host blocks. A parent
// block lists its own members and every member of its descendants, so a child
// inherits by being named in both blocks while its own block is read first.
func CompileGroups(metadata Metadata, hosts []HostEntry, ending string) ([]byte, []Notice) {
	if ending == "" {
		ending = "\n"
	}
	ordered, notices := GroupDepthOrder(metadata.Groups)
	byName := make(map[string]GroupMetadata, len(metadata.Groups))
	for _, group := range metadata.Groups {
		byName[group.Name] = group
	}

	aliasOrder := make([]string, 0, len(hosts))
	known := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if host.Identity.IsZero() || known[host.Identity.Alias] {
			continue
		}
		known[host.Identity.Alias] = true
		aliasOrder = append(aliasOrder, host.Identity.Alias)
	}

	direct := make(map[string][]string, len(ordered))
	for _, host := range metadata.Hosts {
		if host.Group == "" {
			continue
		}
		if !known[host.Identity.Alias] {
			notices = appendNotice(notices, Notice{
				Code: NoticeGroupMemberMissing, Path: host.Identity.Path, Detail: host.Identity.Alias,
			})
			continue
		}
		direct[host.Group] = append(direct[host.Group], host.Identity.Alias)
	}

	var builder strings.Builder
	for _, comment := range []string{
		"# Generated by sshc from ~/.ssh/sshc/metadata.json.",
		"# Child groups come first because OpenSSH keeps the first value it reads.",
		"# Edit groups in the UI; hand edits to this file are replaced on the next save.",
	} {
		builder.WriteString(comment)
		builder.WriteString(ending)
	}

	for _, group := range ordered {
		members := groupMembers(byName, direct, aliasOrder, group.Name)
		if len(members) == 0 || len(group.Settings) == 0 {
			continue
		}
		header, err := buildLine("", "Host", members, ending)
		if err != nil {
			notices = appendNotice(notices, Notice{Code: NoticeGroupMemberMissing, Detail: group.Name})
			continue
		}
		var block strings.Builder
		valid := true
		for _, setting := range group.Settings {
			line, settingErr := buildDirectiveLine("\t", setting.Keyword, setting.Values, ending)
			if settingErr != nil {
				notices = appendNotice(notices, Notice{
					Code: NoticeComplexExternalRule, Detail: group.Name + ": " + setting.Keyword,
				})
				valid = false
				break
			}
			block.WriteString(line.Render())
		}
		if !valid {
			continue
		}

		builder.WriteString(ending)
		builder.WriteString("# group " + group.Name)
		if group.Parent != "" {
			builder.WriteString(" (parent " + group.Parent + ")")
		}
		builder.WriteString(ending)
		builder.WriteString(header.Render())
		builder.WriteString(block.String())
	}
	return []byte(builder.String()), notices
}

func groupMembers(byName map[string]GroupMetadata, direct map[string][]string, aliasOrder []string, name string) []string {
	collected := make(map[string]bool)
	for candidate := range byName {
		if candidate != name && !isDescendantGroup(byName, candidate, name) {
			continue
		}
		for _, alias := range direct[candidate] {
			collected[alias] = true
		}
	}
	members := make([]string, 0, len(collected))
	for _, alias := range aliasOrder {
		if collected[alias] {
			members = append(members, alias)
		}
	}
	return members
}

// PlanGroupInclude decides where the generated groups file must be included.
//
// The Include goes after the user's own specific Host blocks and before the
// first catch-all block, so the priority is host, then child group, then parent
// group, then global default. An Include naming the file exactly is treated as
// already present; a glob that happens to match it is not, because guessing
// which glob covers which file is exactly what this application must not do.
func PlanGroupInclude(file *config.File, relative string) (int, bool) {
	insertAt := len(file.Lines)
	found := false
	for index, line := range file.Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		if config.EqualKeyword(line.Keyword, "Include") {
			for _, value := range line.Values() {
				if value == relative {
					return -1, true
				}
			}
			continue
		}
		if found {
			continue
		}
		if config.EqualKeyword(line.Keyword, "Match") {
			insertAt, found = index, true
			continue
		}
		if !config.EqualKeyword(line.Keyword, "Host") {
			continue
		}
		for _, pattern := range line.Values() {
			if pattern == "*" {
				insertAt, found = index, true
				break
			}
		}
	}
	return insertAt, false
}

// InsertIncludeLine writes the Include directive at the planned index.
func InsertIncludeLine(file *config.File, relative string, index int) error {
	line, err := buildLine("", "Include", []string{relative}, dominantEnding(file))
	if err != nil {
		return err
	}
	if index < 0 || index > len(file.Lines) {
		return ErrEditLineOutsideBlock
	}
	insertLine(file, index, line)
	return nil
}
```

- [ ] **Step 8: Run the whole package and verify it is green**

Run: `go test ./internal/application -v && go test -race ./internal/application`

Expected: PASS.

- [ ] **Step 9: Commit group compilation**

```bash
git add internal/application/effective.go internal/application/effective_test.go \
  internal/application/groups.go internal/application/groups_test.go
git commit -m "feat: compile sshc groups into ordinary host blocks"
```

---

## Task 5: Application service with validated, journalled commits

**Files:**
- Create: `internal/application/validate.go`
- Create: `internal/application/service.go`
- Create: `internal/application/service_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-4; `storage.NewResolver`, `storage.NewManager`, `(*Manager).Commit/Pending/Complete/Rollback/History`, `storage.Request/Change/Precondition/Result/ConflictError/Digest`, `storage.HistoryRecord`, `storage.Pending`.
- Produces: `application.SyntaxError{Path string, Line, Column int, Detail string}`, `GraphError{Diagnostics []DiagnosticView}`, `ConflictError{Report ConflictReport}`.
- Produces: `application.NewService(workspace *storage.Workspace, manager *storage.Manager) *Service`.
- Produces: `Overview`, `FileNode`, `IncludeReference`, `FileContents`, `HostDetail`, `PendingView`, `HistoryEntry`, `EditKind` constants, `EditRequest`, `SavePreview`, `SaveResult`.
- Produces: `(*Service).Overview()`, `HostDetail(path, alias string)`, `FileContents(path string)`, `Preview(EditRequest)`, `Save(EditRequest)`, `Pending()`, `Recover(id, action string)`, `History()`, `Restore(id, path string)`.
- Produces: errors `ErrUnknownEditKind`, `ErrUnknownRecoveryAction`, `ErrNotEditable`.

- [ ] **Step 1: Write the failing service tests**

```go
// internal/application/service_test.go
package application

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sshc/internal/storage"
)

const serviceMainConfig = `# personal configuration
Include conf.d/*.conf

Host bastion
	HostName 203.0.113.10
	User ops
	Port 22

Host *
	ServerAliveInterval 30
`

func newTestService(t *testing.T) (*Service, *storage.Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	if err := workspace.EnsureDirectory(filepath.Join(workspace.Root(), "conf.d")); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"config":              serviceMainConfig,
		"conf.d/10-home.conf": "Host nas\n\tUser aida\t# personal\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(workspace.Root(), filepath.FromSlash(name)), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager := storage.NewManager(workspace, time.Now, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	return NewService(workspace, manager), workspace
}

func readFile(t *testing.T, workspace *storage.Workspace, relative string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(workspace.Root(), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestOverviewListsIncludeTreeHostsAndDiagnostics(t *testing.T) {
	service, _ := newTestService(t)

	overview, err := service.Overview()
	if err != nil {
		t.Fatal(err)
	}
	if overview.Entry.Path != "config" || len(overview.Files) != 2 {
		t.Fatalf("overview files = %#v", overview.Files)
	}
	if overview.Files[0].File.Path != "config" || len(overview.Files[0].Includes) != 1 {
		t.Fatalf("entry node = %#v", overview.Files[0])
	}
	if overview.Files[0].Includes[0].Matches[0].Path != "conf.d/10-home.conf" {
		t.Fatalf("include matches = %#v", overview.Files[0].Includes[0].Matches)
	}
	aliases := []string{}
	for _, host := range overview.Hosts {
		aliases = append(aliases, host.Identity.Alias)
	}
	if len(aliases) != 3 || aliases[0] != "nas" || aliases[1] != "bastion" || aliases[2] != "" {
		t.Fatalf("aliases = %#v", aliases)
	}
	if overview.Metadata.SchemaVersion != MetadataSchemaVersion {
		t.Fatalf("metadata = %#v", overview.Metadata)
	}
	if len(overview.Pending) != 0 {
		t.Fatalf("pending = %#v", overview.Pending)
	}
}

func TestSaveHostFieldsWritesOnlyTheEditedFile(t *testing.T) {
	service, workspace := newTestService(t)

	preview, err := service.Preview(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Diffs) != 1 || preview.Diffs[0].Path != "config" {
		t.Fatalf("preview = %#v", preview)
	}
	changed := 0
	for _, line := range preview.Diffs[0].Lines {
		if line.Op != DiffContext {
			changed++
		}
	}
	if changed != 2 {
		t.Fatalf("preview changed %d lines, want one delete and one insert", changed)
	}
	if readFile(t, workspace, "config") != serviceMainConfig {
		t.Fatal("preview must not write to disk")
	}

	result, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TransactionID == "" || len(result.Written) != 1 || result.Written[0] != "config" {
		t.Fatalf("result = %#v", result)
	}
	want := bytes.Replace([]byte(serviceMainConfig), []byte("Port 22\n"), []byte("Port 2222\n"), 1)
	if readFile(t, workspace, "config") != string(want) {
		t.Fatalf("config = %q", readFile(t, workspace, "config"))
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "Host nas\n\tUser aida\t# personal\n" {
		t.Fatal("an unrelated file changed during the commit")
	}
}

func TestSaveRejectsAStaleBaseWithAThreeWayReport(t *testing.T) {
	service, workspace := newTestService(t)
	externallyChanged := serviceMainConfig + "\nHost added-elsewhere\n\tUser other\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(externallyChanged), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *ConflictError", err)
	}
	if conflict.Report.Path != "config" || len(conflict.Report.ExternalChange) == 0 || len(conflict.Report.LocalChange) == 0 {
		t.Fatalf("report = %#v", conflict.Report)
	}
	if readFile(t, workspace, "config") != externallyChanged {
		t.Fatal("a conflicting save must not write")
	}
}

func TestSaveRejectsRawTextThatBreaksQuotingAndWritesNothing(t *testing.T) {
	service, workspace := newTestService(t)

	_, err := service.Save(EditRequest{
		Kind: EditFileRaw,
		Path: "conf.d/10-home.conf",
		Base: "Host nas\n\tUser aida\t# personal\n",
		Raw:  "Host nas\n\tUser \"unbalanced\n",
	})
	var syntax *SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("error = %v, want *SyntaxError", err)
	}
	if syntax.Path != "conf.d/10-home.conf" || syntax.Line != 2 || syntax.Column == 0 {
		t.Fatalf("syntax error = %#v", syntax)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "Host nas\n\tUser aida\t# personal\n" {
		t.Fatal("a rejected raw save must not write")
	}
}

func TestSaveRejectsAnEditThatIntroducesAnIncludeCycle(t *testing.T) {
	service, workspace := newTestService(t)

	_, err := service.Save(EditRequest{
		Kind: EditFileRaw,
		Path: "conf.d/10-home.conf",
		Base: "Host nas\n\tUser aida\t# personal\n",
		Raw:  "Include config\nHost nas\n\tUser aida\n",
	})
	var graphError *GraphError
	if !errors.As(err, &graphError) {
		t.Fatalf("error = %v, want *GraphError", err)
	}
	if len(graphError.Diagnostics) == 0 || graphError.Diagnostics[0].Severity != "error" {
		t.Fatalf("diagnostics = %#v", graphError.Diagnostics)
	}
	if readFile(t, workspace, "conf.d/10-home.conf") != "Host nas\n\tUser aida\t# personal\n" {
		t.Fatal("a rejected save must not write")
	}
}

func TestSaveGroupsWritesConfigurationAndMetadataInOneTransaction(t *testing.T) {
	service, workspace := newTestService(t)
	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{
		Name:     "home",
		Settings: []Setting{{Keyword: "Port", Values: []string{"2222"}}},
	}}
	metadata.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "conf.d/10-home.conf", Alias: "nas"}, Group: "home"}}

	preview, err := service.Preview(EditRequest{Kind: EditGroups, Metadata: &metadata})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Diffs) != 3 {
		t.Fatalf("group preview diffs = %#v", preview.Diffs)
	}
	if len(preview.Effective) != 1 || preview.Effective[0].Alias != "nas" {
		t.Fatalf("effective preview = %#v", preview.Effective)
	}
	if len(preview.Effective[0].Changes) != 1 || preview.Effective[0].Changes[0].Keyword != "Port" {
		t.Fatalf("effective changes = %#v", preview.Effective[0].Changes)
	}

	if _, err := service.Save(EditRequest{Kind: EditGroups, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}
	groups := readFile(t, workspace, DefaultGroupsFile)
	if !bytes.Contains([]byte(groups), []byte("Host nas\n\tPort 2222\n")) {
		t.Fatalf("groups file = %q", groups)
	}
	if !bytes.Contains([]byte(readFile(t, workspace, "config")), []byte("Include "+DefaultGroupsFile+"\n")) {
		t.Fatalf("entry config = %q", readFile(t, workspace, "config"))
	}
	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Groups) != 1 || stored.Groups[0].Name != "home" {
		t.Fatalf("stored metadata = %#v", stored)
	}

	detail, err := service.HostDetail("conf.d/10-home.conf", "nas")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range detail.Effective.Entries {
		if entry.Keyword == "Port" && entry.Values[0] == "2222" && entry.Source.Path == DefaultGroupsFile {
			found = true
		}
	}
	if !found {
		t.Fatalf("effective entries = %#v", detail.Effective.Entries)
	}
}

func TestSaveRenameUpdatesTheHostLineAndMetadataTogether(t *testing.T) {
	service, workspace := newTestService(t)
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "keep me"}}
	if _, err := service.Save(EditRequest{Kind: EditMetadata, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Save(EditRequest{
		Kind:     EditRename,
		Path:     "config",
		Base:     serviceMainConfig,
		Alias:    "bastion",
		NewAlias: "jump",
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(readFile(t, workspace, "config")), []byte("Host jump\n")) {
		t.Fatalf("config = %q", readFile(t, workspace, "config"))
	}
	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Hosts) != 1 || stored.Hosts[0].Identity.Alias != "jump" || stored.Hosts[0].Note != "keep me" || stored.Hosts[0].Orphan {
		t.Fatalf("stored metadata = %#v", stored.Hosts)
	}
}

func TestHistoryListsCommitsAndRestoreRevertsOneFile(t *testing.T) {
	service, workspace := newTestService(t)
	if _, err := service.Save(EditRequest{
		Kind:   EditHostFields,
		Path:   "config",
		Base:   serviceMainConfig,
		Alias:  "bastion",
		Fields: []FieldEdit{{Action: ActionSet, Line: 7, Values: []string{"2222"}}},
	}); err != nil {
		t.Fatal(err)
	}

	history, err := service.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Operation != "config.host_fields" || len(history[0].Restorable) != 1 {
		t.Fatalf("history = %#v", history)
	}
	if _, err := service.Restore(history[0].ID, "config"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, workspace, "config") != serviceMainConfig {
		t.Fatalf("config after restore = %q", readFile(t, workspace, "config"))
	}
	if _, err := service.Restore("no-such-transaction", "config"); !errors.Is(err, storage.ErrUnknownTransaction) {
		t.Fatalf("unknown restore error = %v", err)
	}
}
```

- [ ] **Step 2: Run the service tests and verify they fail**

Run: `go test ./internal/application -run 'TestOverview|TestSave|TestHistory' -v`

Expected: FAIL with `undefined: NewService`.

- [ ] **Step 3: Implement validation for the transaction manager**

```go
// internal/application/validate.go
package application

import (
	"bytes"
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
```

- [ ] **Step 4: Implement the service use cases**

```go
// internal/application/service.go
package application

import (
	"bytes"
	"errors"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"sshc/internal/config"
	"sshc/internal/storage"
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
)

// EditRequest is one requested change.
//
// Base carries the exact bytes the client loaded for Path. Every file-targeted
// edit is applied to those bytes and committed with their digest as the
// precondition, so the user always edits what they saw and an external change
// produces a real three-way diff instead of a silent overwrite.
type EditRequest struct {
	Kind     EditKind    `json:"kind"`
	Path     string      `json:"path,omitempty"`
	Base     string      `json:"base,omitempty"`
	Alias    string      `json:"alias,omitempty"`
	NewAlias string      `json:"newAlias,omitempty"`
	Fields   []FieldEdit `json:"fields,omitempty"`
	Raw      string      `json:"raw,omitempty"`
	Metadata *Metadata   `json:"metadata,omitempty"`
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

	overview := Overview{
		Entry:    NewFileRef(root, s.entryPath),
		Hosts:    hosts,
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
type planned struct {
	operation string
	changes   []storage.Change
	base      map[string][]byte
	baseline  map[string]bool
	preview   SavePreview
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
	// Only a metadata change needs the state directory before Commit resolves
	// its write paths; a rejected save must leave the disk untouched.
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

	result, err := s.manager.Commit(storage.Request{Operation: prepared.operation, Changes: prepared.changes})
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
	case EditHostFields, EditBlockRaw, EditRename, EditFileRaw:
		return s.planFileEdit(graph, request)
	case EditGroups, EditMetadata:
		return s.planMetadataEdit(graph, request)
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
	case EditHostFields, EditBlockRaw, EditRename:
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
		case EditRename:
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
	groupContents, groupNotices := CompileGroups(reconciled, hosts, dominantEnding(entryFile))
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

	pending := map[string][]byte{filepath.Clean(groupsAbsolute): groupContents}
	if index, present := PlanGroupInclude(entryFile, groupsRelative); !present {
		if err := InsertIncludeLine(entryFile, groupsRelative, index); err != nil {
			return planned{}, err
		}
		entryUpdated := entryFile.Render()
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

	after, err := s.resolveWith(pending)
	if err != nil {
		return planned{}, err
	}
	for _, host := range reconciled.Hosts {
		if host.Group == "" || host.Orphan || len(prepared.preview.Effective) >= maxEffectivePreviews {
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
	contents, err := s.workspace.FileSystem().ReadFile(filepath.Join(record.BackupDir, filepath.FromSlash(relative)))
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
```

- [ ] **Step 5: Run the service tests to verify they pass**

Run: `go test ./internal/application -v`

Expected: PASS. If `TestSaveGroupsWrites...` reports a different diff count, check that the group save produced exactly three changes: `metadata.json`, `groups.sshc.conf` and the entry `config` that gained the `Include` line.

- [ ] **Step 6: Run the race detector over the package**

Run: `go test -race ./internal/application`

Expected: PASS.

- [ ] **Step 7: Commit the application service**

```bash
git add internal/application/validate.go internal/application/service.go internal/application/service_test.go
git commit -m "feat: commit ssh config edits through a validated transaction"
```

---

## Task 6: OpenAPI contract and same-origin HTTP endpoints

**Files:**
- Modify: `api/openapi.yaml`
- Modify: `internal/api/models.gen.go` (regenerated, never hand-edited)
- Modify: `web/src/api/schema.d.ts` (regenerated, never hand-edited)
- Create: `internal/httpserver/config_requests.go`
- Create: `internal/httpserver/config_handlers.go`
- Create: `internal/httpserver/config_requests_test.go`
- Create: `internal/httpserver/config_handlers_test.go`
- Modify: `internal/httpserver/server.go`
- Modify: `internal/app/run.go`
- Modify: `internal/app/run_test.go`
- Modify: `cmd/sshc/main.go`

**Interfaces:**
- Consumes: Task 5 `application.Service` and every exported type it returns; `storage.NewWorkspace`, `storage.NewManager`, `storage.OSFileSystem`.
- Produces: `httpserver.ConfigHandlers{Service *application.Service}` with methods `Overview`, `Host`, `File`, `Preview`, `Save`, `Metadata`, `History`, `Restore`, `Recover`.
- Produces: `httpserver.Options.Config *application.Service`.
- Produces: `app.Dependencies.Home string`.
- Produces: generated `api.Overview`, `api.HostDetail`, `api.FileContents`, `api.SavePreview`, `api.SaveResult`, `api.EditRequest`, `api.Metadata`, `api.HistoryList`, `api.Problem` (extended).

- [ ] **Step 1: Add the endpoints to the OpenAPI contract**

Insert these path items into `api/openapi.yaml` after the existing `/api/v1/health` entry, keeping the file's flow style:

```yaml
  /api/v1/config/overview:
    get:
      operationId: getConfigOverview
      responses:
        "200":
          description: Include tree, hosts, groups and diagnostics
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Overview" }
        "401": { $ref: "#/components/responses/Problem" }
        "500": { $ref: "#/components/responses/Problem" }
  /api/v1/config/host:
    get:
      operationId: getConfigHost
      parameters:
        - name: path
          in: query
          required: true
          schema: { type: string, minLength: 1, maxLength: 512 }
        - name: alias
          in: query
          required: true
          schema: { type: string, minLength: 1, maxLength: 255 }
      responses:
        "200":
          description: One host block with its explained values
          content:
            application/json:
              schema: { $ref: "#/components/schemas/HostDetail" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
  /api/v1/config/file:
    get:
      operationId: getConfigFile
      parameters:
        - name: path
          in: query
          required: true
          schema: { type: string, minLength: 1, maxLength: 512 }
      responses:
        "200":
          description: One configuration file for the raw editor
          content:
            application/json:
              schema: { $ref: "#/components/schemas/FileContents" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/config/preview:
    post:
      operationId: previewConfigEdit
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/EditRequest" }
      responses:
        "200":
          description: Exactly what a save would write
          content:
            application/json:
              schema: { $ref: "#/components/schemas/SavePreview" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
        "422": { $ref: "#/components/responses/Problem" }
  /api/v1/config/save:
    post:
      operationId: saveConfigEdit
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/EditRequest" }
      responses:
        "200":
          description: Committed transaction
          content:
            application/json:
              schema: { $ref: "#/components/schemas/SaveResult" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
        "422": { $ref: "#/components/responses/Problem" }
  /api/v1/metadata:
    get:
      operationId: getMetadata
      responses:
        "200":
          description: UI-only organisation data
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Metadata" }
        "401": { $ref: "#/components/responses/Problem" }
  /api/v1/history:
    get:
      operationId: getHistory
      responses:
        "200":
          description: Completed transactions
          content:
            application/json:
              schema: { $ref: "#/components/schemas/HistoryList" }
        "401": { $ref: "#/components/responses/Problem" }
  /api/v1/history/restore:
    post:
      operationId: restoreHistoryEntry
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RestoreRequest" }
      responses:
        "200":
          description: Restored file committed as a new transaction
          content:
            application/json:
              schema: { $ref: "#/components/schemas/SaveResult" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
  /api/v1/history/recover:
    post:
      operationId: recoverTransaction
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RecoverRequest" }
      responses:
        "200":
          description: Interrupted transaction completed or rolled back
          content:
            application/json:
              schema: { $ref: "#/components/schemas/RecoverResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
```

- [ ] **Step 2: Add the schemas to the OpenAPI contract**

Replace the existing `Problem` schema and add the rest under `components.schemas`:

```yaml
    Problem:
      type: object
      additionalProperties: false
      required: [code, message]
      properties:
        code: { type: string }
        message: { type: string }
        detail: { type: string }
        path: { type: string }
        line: { type: integer }
        column: { type: integer }
        diagnostics: { type: array, items: { $ref: "#/components/schemas/Diagnostic" } }
        conflict: { $ref: "#/components/schemas/ConflictReport" }
    FileRef:
      type: object
      additionalProperties: false
      required: [absolute]
      properties:
        path: { type: string }
        absolute: { type: string }
        external: { type: boolean }
    Notice:
      type: object
      additionalProperties: false
      required: [code]
      properties:
        code: { type: string }
        path: { type: string }
        line: { type: integer }
        detail: { type: string }
    Diagnostic:
      type: object
      additionalProperties: false
      required: [severity, code]
      properties:
        severity: { type: string }
        code: { type: string }
        path: { type: string }
        absolute: { type: string }
        external: { type: boolean }
        line: { type: integer }
        detail: { type: string }
    HostIdentity:
      type: object
      additionalProperties: false
      required: [path, alias]
      properties:
        path: { type: string }
        alias: { type: string }
    HostEntry:
      type: object
      additionalProperties: false
      required: [identity, file, line, patterns, editable]
      properties:
        identity: { $ref: "#/components/schemas/HostIdentity" }
        file: { $ref: "#/components/schemas/FileRef" }
        line: { type: integer }
        patterns: { type: array, items: { type: string } }
        wildcard: { type: boolean }
        negated: { type: boolean }
        duplicate: { type: boolean }
        editable: { type: boolean }
    IncludeReference:
      type: object
      additionalProperties: false
      required: [line, pattern]
      properties:
        line: { type: integer }
        pattern: { type: string }
        condition: { type: string }
        matches: { type: array, items: { $ref: "#/components/schemas/FileRef" } }
    FileNode:
      type: object
      additionalProperties: false
      required: [file, editable, loads]
      properties:
        file: { $ref: "#/components/schemas/FileRef" }
        missing: { type: boolean }
        editable: { type: boolean }
        loads: { type: integer }
        includes: { type: array, items: { $ref: "#/components/schemas/IncludeReference" } }
    Setting:
      type: object
      additionalProperties: false
      required: [keyword, values]
      properties:
        keyword: { type: string }
        values: { type: array, items: { type: string } }
    HostMetadata:
      type: object
      additionalProperties: false
      required: [identity]
      properties:
        identity: { $ref: "#/components/schemas/HostIdentity" }
        group: { type: string }
        tags: { type: array, items: { type: string } }
        colour: { type: string }
        note: { type: string }
        favourite: { type: boolean }
        order: { type: integer }
        orphan: { type: boolean }
    GroupMetadata:
      type: object
      additionalProperties: false
      required: [name]
      properties:
        name: { type: string }
        parent: { type: string }
        colour: { type: string }
        note: { type: string }
        order: { type: integer }
        settings: { type: array, items: { $ref: "#/components/schemas/Setting" } }
    Metadata:
      type: object
      additionalProperties: false
      required: [schemaVersion]
      properties:
        schemaVersion: { type: integer }
        groupsFile: { type: string }
        groups: { type: array, items: { $ref: "#/components/schemas/GroupMetadata" } }
        hosts: { type: array, items: { $ref: "#/components/schemas/HostMetadata" } }
    PendingTransaction:
      type: object
      additionalProperties: false
      required: [id, operation, status, startedAt, committed, paths, canComplete]
      properties:
        id: { type: string }
        operation: { type: string }
        status: { type: string }
        startedAt: { type: string }
        committed: { type: integer }
        paths: { type: array, items: { type: string } }
        canComplete: { type: boolean }
    Overview:
      type: object
      additionalProperties: false
      required: [entry, files, hosts, metadata, diagnostics, notices]
      properties:
        entry: { $ref: "#/components/schemas/FileRef" }
        files: { type: array, items: { $ref: "#/components/schemas/FileNode" } }
        hosts: { type: array, items: { $ref: "#/components/schemas/HostEntry" } }
        metadata: { $ref: "#/components/schemas/Metadata" }
        diagnostics: { type: array, items: { $ref: "#/components/schemas/Diagnostic" } }
        notices: { type: array, items: { $ref: "#/components/schemas/Notice" } }
        pending: { type: array, items: { $ref: "#/components/schemas/PendingTransaction" } }
    FormField:
      type: object
      additionalProperties: false
      required: [line, keyword, values, category, editable]
      properties:
        line: { type: integer }
        keyword: { type: string }
        values: { type: array, items: { type: string } }
        category: { type: string }
        dangerous: { type: boolean }
        duplicate: { type: boolean }
        editable: { type: boolean }
    HostForm:
      type: object
      additionalProperties: false
      required: [entry, fields, raw]
      properties:
        entry: { $ref: "#/components/schemas/HostEntry" }
        fields: { type: array, items: { $ref: "#/components/schemas/FormField" } }
        raw: { type: string }
        notices: { type: array, items: { $ref: "#/components/schemas/Notice" } }
    Source:
      type: object
      additionalProperties: false
      properties:
        path: { type: string }
        absolute: { type: string }
        line: { type: integer }
        condition: { type: string }
    EffectiveEntry:
      type: object
      additionalProperties: false
      required: [keyword, values, source]
      properties:
        keyword: { type: string }
        values: { type: array, items: { type: string } }
        source: { $ref: "#/components/schemas/Source" }
    Effective:
      type: object
      additionalProperties: false
      required: [alias, approximate, entries]
      properties:
        alias: { type: string }
        approximate: { type: boolean }
        entries: { type: array, items: { $ref: "#/components/schemas/EffectiveEntry" } }
        notices: { type: array, items: { $ref: "#/components/schemas/Notice" } }
    FileContents:
      type: object
      additionalProperties: false
      required: [file, contents, digest, editable, exists]
      properties:
        file: { $ref: "#/components/schemas/FileRef" }
        contents: { type: string }
        digest: { type: string }
        editable: { type: boolean }
        exists: { type: boolean }
    HostDetail:
      type: object
      additionalProperties: false
      required: [form, metadata, effective, file]
      properties:
        form: { $ref: "#/components/schemas/HostForm" }
        metadata: { $ref: "#/components/schemas/HostMetadata" }
        effective: { $ref: "#/components/schemas/Effective" }
        file: { $ref: "#/components/schemas/FileContents" }
    FieldEdit:
      type: object
      additionalProperties: false
      required: [action]
      properties:
        action: { type: string }
        line: { type: integer }
        keyword: { type: string }
        values: { type: array, items: { type: string } }
    EditRequest:
      type: object
      additionalProperties: false
      required: [kind]
      properties:
        kind: { type: string }
        path: { type: string }
        base: { type: string }
        alias: { type: string }
        newAlias: { type: string }
        fields: { type: array, items: { $ref: "#/components/schemas/FieldEdit" } }
        raw: { type: string }
        metadata: { $ref: "#/components/schemas/Metadata" }
    DiffLine:
      type: object
      additionalProperties: false
      required: [op, text]
      properties:
        op: { type: string }
        text: { type: string }
        oldLine: { type: integer }
        newLine: { type: integer }
    FileDiff:
      type: object
      additionalProperties: false
      required: [path, lines]
      properties:
        path: { type: string }
        created: { type: boolean }
        removed: { type: boolean }
        oldDigest: { type: string }
        newDigest: { type: string }
        lines: { type: array, items: { $ref: "#/components/schemas/DiffLine" } }
        truncated: { type: boolean }
    EffectiveChange:
      type: object
      additionalProperties: false
      required: [keyword, before, after]
      properties:
        keyword: { type: string }
        before: { type: array, items: { type: string } }
        after: { type: array, items: { type: string } }
        beforeSources: { type: array, items: { $ref: "#/components/schemas/Source" } }
        afterSources: { type: array, items: { $ref: "#/components/schemas/Source" } }
    EffectiveDiff:
      type: object
      additionalProperties: false
      required: [alias, changes]
      properties:
        alias: { type: string }
        changes: { type: array, items: { $ref: "#/components/schemas/EffectiveChange" } }
    SavePreview:
      type: object
      additionalProperties: false
      required: [operation, diffs]
      properties:
        operation: { type: string }
        diffs: { type: array, items: { $ref: "#/components/schemas/FileDiff" } }
        effective: { type: array, items: { $ref: "#/components/schemas/EffectiveDiff" } }
        notices: { type: array, items: { $ref: "#/components/schemas/Notice" } }
    SaveResult:
      type: object
      additionalProperties: false
      required: [transactionId, written, preview]
      properties:
        transactionId: { type: string }
        written: { type: array, items: { type: string } }
        preview: { $ref: "#/components/schemas/SavePreview" }
    ConflictReport:
      type: object
      additionalProperties: false
      required: [path, externalChange, localChange]
      properties:
        path: { type: string }
        baseDigest: { type: string }
        diskDigest: { type: string }
        externalChange: { type: array, items: { $ref: "#/components/schemas/DiffLine" } }
        localChange: { type: array, items: { $ref: "#/components/schemas/DiffLine" } }
    HistoryEntry:
      type: object
      additionalProperties: false
      required: [id, operation, status, startedAt, paths]
      properties:
        id: { type: string }
        operation: { type: string }
        status: { type: string }
        startedAt: { type: string }
        finishedAt: { type: string }
        paths: { type: array, items: { type: string } }
        restorable: { type: array, items: { type: string } }
    HistoryList:
      type: object
      additionalProperties: false
      required: [entries]
      properties:
        entries: { type: array, items: { $ref: "#/components/schemas/HistoryEntry" } }
    RestoreRequest:
      type: object
      additionalProperties: false
      required: [transactionId, path]
      properties:
        transactionId: { type: string, minLength: 1, maxLength: 128 }
        path: { type: string, minLength: 1, maxLength: 512 }
    RecoverRequest:
      type: object
      additionalProperties: false
      required: [transactionId, action]
      properties:
        transactionId: { type: string, minLength: 1, maxLength: 128 }
        action: { type: string, minLength: 1, maxLength: 16 }
    RecoverResponse:
      type: object
      additionalProperties: false
      required: [status]
      properties:
        status: { type: string, const: ok }
```

- [ ] **Step 3: Regenerate both sides of the contract and confirm the models exist**

Run:

```bash
make generate
go build ./...
npm run typecheck --prefix web
git diff --stat api/openapi.yaml internal/api/models.gen.go web/src/api/schema.d.ts
```

Expected: `internal/api/models.gen.go` gains `Overview`, `HostDetail`, `EditRequest`, `SavePreview`, `SaveResult`, `Metadata`, `HistoryList`, and `Problem` gains the optional fields; `web/src/api/schema.d.ts` gains the same schemas. Never hand-edit either generated file.

- [ ] **Step 4: Write the failing boundary validation tests**

```go
// internal/httpserver/config_requests_test.go
package httpserver

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/application"
)

func TestValidatePathParameterRejectsTraversalAndControlCharacters(t *testing.T) {
	for _, valid := range []string{"config", "conf.d/10-home.conf", "a..b.conf"} {
		if err := validatePathParameter(valid); err != nil {
			t.Errorf("validatePathParameter(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", "/etc/ssh/ssh_config", "../.bashrc", "conf.d/../../escape", "conf.d/./x", "a\x00b", "a\nb", strings.Repeat("a", 600)} {
		if err := validatePathParameter(invalid); !errors.Is(err, errInvalidPath) {
			t.Errorf("validatePathParameter(%q) = %v, want errInvalidPath", invalid, err)
		}
	}
}

func TestValidateEditRequestEnforcesEveryKindsRequirements(t *testing.T) {
	tests := []struct {
		name    string
		request application.EditRequest
		wantErr bool
	}{
		{"valid field edit", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
			Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 2, Values: []string{"22"}}},
		}, false},
		{"unknown kind", application.EditRequest{Kind: "delete_everything", Path: "config"}, true},
		{"field edit without an alias", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n",
			Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 2}},
		}, true},
		{"field edit without any edit", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
		}, true},
		{"unknown field action", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
			Fields: []application.FieldEdit{{Action: "wipe", Line: 2}},
		}, true},
		{"oversized value", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
			Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 2, Values: []string{strings.Repeat("v", maxValueLength+1)}}},
		}, true},
		{"rename with a pattern alias", application.EditRequest{
			Kind: application.EditRename, Path: "config", Base: "Host a\n", Alias: "a", NewAlias: "b*",
		}, true},
		{"valid rename", application.EditRequest{
			Kind: application.EditRename, Path: "config", Base: "Host a\n", Alias: "a", NewAlias: "b",
		}, false},
		{"raw edit without a path", application.EditRequest{Kind: application.EditFileRaw, Raw: "Host a\n"}, true},
		{"emptying a file is allowed", application.EditRequest{
			Kind: application.EditFileRaw, Path: "config", Base: "Host a\n", Raw: "",
		}, false},
		{"groups without metadata", application.EditRequest{Kind: application.EditGroups}, true},
		{"metadata with key material", application.EditRequest{
			Kind: application.EditMetadata,
			Metadata: &application.Metadata{
				SchemaVersion: application.MetadataSchemaVersion,
				GroupsFile:    application.DefaultGroupsFile,
				Hosts: []application.HostMetadata{{
					Identity: application.HostIdentity{Path: "config", Alias: "a"},
					Note:     "-----BEGIN OPENSSH PRIVATE KEY-----",
				}},
			},
		}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateEditRequest(test.request)
			if test.wantErr != (err != nil) {
				t.Fatalf("validateEditRequest = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}
```

- [ ] **Step 5: Run the boundary tests and verify they fail**

Run: `go test ./internal/httpserver -run 'TestValidatePathParameter|TestValidateEditRequest' -v`

Expected: FAIL with `undefined: validatePathParameter`.

- [ ] **Step 6: Implement boundary validation and error mapping**

```go
// internal/httpserver/config_requests.go
package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"sshc/internal/application"
	"sshc/internal/storage"
)

// Runtime limits at the HTTP boundary. Generated types describe shapes; these
// bound sizes, because a local API is still an API.
const (
	maxRequestBody = 2 << 20
	maxPathLength  = 512
	maxAliasLength = 255
	maxFieldEdits  = 256
	maxFieldValues = 64
	maxValueLength = 1024
	maxRawLength   = 1 << 20
	maxGroupCount  = 256
	maxHostCount   = 4096
	maxIDLength    = 128
)

var (
	errInvalidBody  = errors.New("invalid_request_body")
	errInvalidPath  = errors.New("invalid_path")
	errInvalidAlias = errors.New("invalid_alias")
	errInvalidEdit  = errors.New("invalid_edit")
)

// problemPayload is the wire form of the OpenAPI Problem schema. It carries a
// location and a stable code, never file contents.
type problemPayload struct {
	Code        string                         `json:"code"`
	Message     string                         `json:"message"`
	Detail      string                         `json:"detail,omitempty"`
	Path        string                         `json:"path,omitempty"`
	Line        int                            `json:"line,omitempty"`
	Column      int                            `json:"column,omitempty"`
	Diagnostics []application.DiagnosticView   `json:"diagnostics,omitempty"`
	Conflict    *application.ConflictReport    `json:"conflict,omitempty"`
}

func problemWith(c *echo.Context, status int, payload problemPayload) error {
	if payload.Message == "" {
		payload.Message = "request rejected"
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, payload)
}

// decodeJSON reads a bounded, strict JSON body. Unknown fields are rejected so
// a typo cannot silently become a default.
func decodeJSON(c *echo.Context, target any) error {
	body := c.Request().Body
	if body == nil {
		return errInvalidBody
	}
	decoder := json.NewDecoder(io.LimitReader(body, maxRequestBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidBody
	}
	if decoder.More() {
		return errInvalidBody
	}
	return nil
}

// validatePathParameter accepts only a relative, single-rooted path with no
// traversal or control characters. The workspace performs the authoritative
// check; this keeps obviously hostile input out of the application layer.
func validatePathParameter(value string) error {
	if value == "" || len(value) > maxPathLength {
		return errInvalidPath
	}
	if strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\n\r") {
		return errInvalidPath
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errInvalidPath
		}
	}
	return nil
}

func validateAliasParameter(value string) error {
	if value == "" || len(value) > maxAliasLength {
		return errInvalidAlias
	}
	for _, character := range value {
		if character <= ' ' || character == 0x7f {
			return errInvalidAlias
		}
	}
	return nil
}

func validateIdentifier(value string) error {
	if value == "" || len(value) > maxIDLength {
		return errInvalidEdit
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		isAllowed := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '.'
		if !isAllowed {
			return errInvalidEdit
		}
	}
	return nil
}

// validateEditRequest enforces per-kind requirements before the request reaches
// the application layer.
func validateEditRequest(request application.EditRequest) error {
	if len(request.Raw) > maxRawLength || len(request.Base) > maxRawLength {
		return errInvalidEdit
	}
	switch request.Kind {
	case application.EditHostFields, application.EditBlockRaw, application.EditFileRaw, application.EditRename:
		if err := validatePathParameter(request.Path); err != nil {
			return err
		}
	case application.EditGroups, application.EditMetadata:
	default:
		return errInvalidEdit
	}

	switch request.Kind {
	case application.EditHostFields:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		if len(request.Fields) == 0 || len(request.Fields) > maxFieldEdits {
			return errInvalidEdit
		}
		for _, edit := range request.Fields {
			if err := validateFieldEdit(edit); err != nil {
				return err
			}
		}
	case application.EditBlockRaw:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		if request.Raw == "" {
			return errInvalidEdit
		}
	case application.EditFileRaw:
		// An empty file is a legitimate result of deleting the last block. The
		// base digest precondition, not a length check, is what protects an
		// existing file from an accidental empty write.
	case application.EditRename:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		if err := application.ValidateAlias(request.NewAlias); err != nil {
			return errInvalidAlias
		}
	case application.EditGroups, application.EditMetadata:
		if request.Metadata == nil {
			return errInvalidEdit
		}
		if len(request.Metadata.Groups) > maxGroupCount || len(request.Metadata.Hosts) > maxHostCount {
			return errInvalidEdit
		}
		if err := application.ValidateMetadata(*request.Metadata); err != nil {
			return err
		}
	}
	return nil
}

func validateFieldEdit(edit application.FieldEdit) error {
	switch edit.Action {
	case application.ActionSet, application.ActionRemove:
		if edit.Line <= 0 {
			return errInvalidEdit
		}
	case application.ActionAdd:
		if edit.Keyword == "" {
			return errInvalidEdit
		}
	default:
		return errInvalidEdit
	}
	if len(edit.Keyword) > 64 || len(edit.Values) > maxFieldValues {
		return errInvalidEdit
	}
	for _, value := range edit.Values {
		if len(value) > maxValueLength {
			return errInvalidEdit
		}
	}
	return nil
}

// serviceProblem maps an application error onto an HTTP problem response. The
// mapping never includes file contents, and the default is a generic 500 so an
// unexpected error cannot leak its message.
func serviceProblem(c *echo.Context, err error) error {
	var syntaxError *application.SyntaxError
	var graphError *application.GraphError
	var conflictError *application.ConflictError
	switch {
	case errors.As(err, &syntaxError):
		return problemWith(c, http.StatusUnprocessableEntity, problemPayload{
			Code:   "config_syntax_error",
			Path:   syntaxError.Path,
			Line:   syntaxError.Line,
			Column: syntaxError.Column,
			Detail: syntaxError.Detail,
		})
	case errors.As(err, &graphError):
		return problemWith(c, http.StatusUnprocessableEntity, problemPayload{
			Code:        "config_graph_error",
			Diagnostics: graphError.Diagnostics,
		})
	case errors.As(err, &conflictError):
		report := conflictError.Report
		return problemWith(c, http.StatusConflict, problemPayload{
			Code:     "config_conflict",
			Path:     report.Path,
			Conflict: &report,
		})
	case errors.Is(err, application.ErrHostNotFound), errors.Is(err, storage.ErrUnknownTransaction):
		return problemWith(c, http.StatusNotFound, problemPayload{Code: "not_found"})
	case errors.Is(err, application.ErrExternalPath), errors.Is(err, storage.ErrOutsideWorkspace),
		errors.Is(err, storage.ErrSymlinkPath), errors.Is(err, storage.ErrNotRegularFile),
		errors.Is(err, application.ErrNotEditable):
		return problemWith(c, http.StatusForbidden, problemPayload{Code: "path_not_editable"})
	case errors.Is(err, application.ErrUnknownEditKind), errors.Is(err, application.ErrUnknownRecoveryAction),
		errors.Is(err, application.ErrMetadataSecret), errors.Is(err, application.ErrMetadataPath),
		errors.Is(err, application.ErrMetadataGroup), errors.Is(err, application.ErrMetadataVersion),
		errors.Is(err, errInvalidBody), errors.Is(err, errInvalidPath),
		errors.Is(err, errInvalidAlias), errors.Is(err, errInvalidEdit):
		return problemWith(c, http.StatusBadRequest, problemPayload{Code: "invalid_request"})
	case errors.Is(err, application.ErrUnquotableValue), errors.Is(err, application.ErrStructuralKeyword),
		errors.Is(err, application.ErrInvalidKeyword), errors.Is(err, application.ErrEmptyKeyword),
		errors.Is(err, application.ErrInvalidAlias), errors.Is(err, application.ErrRawBlockHeader),
		errors.Is(err, application.ErrRawBlockStructure), errors.Is(err, application.ErrEditLineOutsideBlock),
		errors.Is(err, application.ErrEditLineNotDirective), errors.Is(err, application.ErrDuplicateEditLine),
		errors.Is(err, application.ErrUnknownEditAction):
		return problemWith(c, http.StatusUnprocessableEntity, problemPayload{Code: "invalid_edit"})
	default:
		return problemWith(c, http.StatusInternalServerError, problemPayload{Code: "internal_error"})
	}
}
```

- [ ] **Step 7: Run the boundary tests to verify they pass**

Run: `go test ./internal/httpserver -run 'TestValidatePathParameter|TestValidateEditRequest' -v`

Expected: PASS.

- [ ] **Step 8: Write the failing handler tests**

```go
// internal/httpserver/config_handlers_test.go
package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/application"
	"sshc/internal/session"
	"sshc/internal/storage"
)

const handlerConfig = "Host bastion\n\tHostName 203.0.113.10\n\tPort 22\n"

type testHarness struct {
	echo    *echo.Echo
	cookie  *http.Cookie
	csrf    string
	root    string
	service *application.Service
}

func newConfigHarness(t *testing.T) *testHarness {
	t.Helper()
	home := t.TempDir()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	if err := workspace.EnsureDirectory(workspace.Root()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(handlerConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := storage.NewManager(workspace, time.Now, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	service := application.NewService(workspace, manager)

	sessions, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0xa1}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := sessions.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	engine := echo.New()
	engine.Use((Security{
		ExpectedHost:   "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions:       sessions,
	}).Middleware)
	registerConfigRoutes(engine, ConfigHandlers{Service: service})

	return &testHarness{
		echo:    engine,
		cookie:  &http.Cookie{Name: SessionCookie, Value: credentials.SessionID},
		csrf:    credentials.CSRFToken,
		root:    workspace.Root(),
		service: service,
	}
}

func (h *testHarness) call(t *testing.T, method, target string, body any, authenticated, withCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(encoded))
	} else {
		reader = strings.NewReader("")
	}
	request := httptest.NewRequest(method, target, reader)
	request.Host = "127.0.0.1:43123"
	request.Header.Set(echo.HeaderContentType, "application/json")
	if method != http.MethodGet {
		request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if authenticated {
		request.AddCookie(h.cookie)
	}
	if withCSRF {
		request.Header.Set(CSRFHeader, h.csrf)
	}
	response := httptest.NewRecorder()
	h.echo.ServeHTTP(response, request)
	return response
}

func TestConfigEndpointsRequireASessionAndCSRF(t *testing.T) {
	harness := newConfigHarness(t)

	if got := harness.call(t, http.MethodGet, "/api/v1/config/overview", nil, false, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("overview without a session = %d", got)
	}
	save := application.EditRequest{Kind: application.EditFileRaw, Path: "config", Base: handlerConfig, Raw: handlerConfig}
	if got := harness.call(t, http.MethodPost, "/api/v1/config/save", save, true, false).Code; got != http.StatusForbidden {
		t.Fatalf("save without CSRF = %d", got)
	}
	response := harness.call(t, http.MethodGet, "/api/v1/config/overview", nil, true, false)
	if response.Code != http.StatusOK {
		t.Fatalf("overview = %d, body %s", response.Code, response.Body.String())
	}
	if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
}

func TestOverviewAndHostResponsesMatchTheGeneratedContract(t *testing.T) {
	harness := newConfigHarness(t)

	overview := harness.call(t, http.MethodGet, "/api/v1/config/overview", nil, true, false)
	var generatedOverview api.Overview
	decoder := json.NewDecoder(bytes.NewReader(overview.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&generatedOverview); err != nil {
		t.Fatalf("overview does not match the contract: %v", err)
	}
	if len(generatedOverview.Hosts) != 1 {
		t.Fatalf("hosts = %#v", generatedOverview.Hosts)
	}

	host := harness.call(t, http.MethodGet, "/api/v1/config/host?path=config&alias=bastion", nil, true, false)
	if host.Code != http.StatusOK {
		t.Fatalf("host = %d, body %s", host.Code, host.Body.String())
	}
	var generatedHost api.HostDetail
	hostDecoder := json.NewDecoder(bytes.NewReader(host.Body.Bytes()))
	hostDecoder.DisallowUnknownFields()
	if err := hostDecoder.Decode(&generatedHost); err != nil {
		t.Fatalf("host detail does not match the contract: %v", err)
	}
}

func TestHostEndpointRejectsTraversalAndUnknownAliases(t *testing.T) {
	harness := newConfigHarness(t)

	if got := harness.call(t, http.MethodGet, "/api/v1/config/host?path=../.bashrc&alias=x", nil, true, false).Code; got != http.StatusBadRequest {
		t.Fatalf("traversal path = %d", got)
	}
	if got := harness.call(t, http.MethodGet, "/api/v1/config/host?path=config&alias=absent", nil, true, false).Code; got != http.StatusNotFound {
		t.Fatalf("unknown alias = %d", got)
	}
}

func TestSaveReportsSyntaxErrorsWithoutLeakingFileContents(t *testing.T) {
	harness := newConfigHarness(t)

	response := harness.call(t, http.MethodPost, "/api/v1/config/save", application.EditRequest{
		Kind: application.EditFileRaw,
		Path: "config",
		Base: handlerConfig,
		Raw:  "Host bastion\n\tHostName \"unbalanced\n",
	}, true, true)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body %s", response.Code, response.Body.String())
	}
	var payload problemPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "config_syntax_error" || payload.Path != "config" || payload.Line != 2 {
		t.Fatalf("payload = %#v", payload)
	}
	if strings.Contains(response.Body.String(), "203.0.113.10") {
		t.Fatal("problem response leaked file contents")
	}
	if got := response.Result().Header.Get(echo.HeaderContentType); !strings.HasPrefix(got, "application/problem+json") {
		t.Fatalf("content type = %q", got)
	}
}

func TestSaveReportsAConflictWithBothSides(t *testing.T) {
	harness := newConfigHarness(t)
	if err := os.WriteFile(filepath.Join(harness.root, "config"), []byte(handlerConfig+"Host later\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	response := harness.call(t, http.MethodPost, "/api/v1/config/save", application.EditRequest{
		Kind:   application.EditHostFields,
		Path:   "config",
		Base:   handlerConfig,
		Alias:  "bastion",
		Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 3, Values: []string{"2222"}}},
	}, true, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body %s", response.Code, response.Body.String())
	}
	var payload problemPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "config_conflict" || payload.Conflict == nil || len(payload.Conflict.ExternalChange) == 0 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestPreviewAndSaveRoundTripThroughTheContract(t *testing.T) {
	harness := newConfigHarness(t)
	request := application.EditRequest{
		Kind:   application.EditHostFields,
		Path:   "config",
		Base:   handlerConfig,
		Alias:  "bastion",
		Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 3, Values: []string{"2222"}}},
	}

	preview := harness.call(t, http.MethodPost, "/api/v1/config/preview", request, true, true)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview = %d, body %s", preview.Code, preview.Body.String())
	}
	var generatedPreview api.SavePreview
	previewDecoder := json.NewDecoder(bytes.NewReader(preview.Body.Bytes()))
	previewDecoder.DisallowUnknownFields()
	if err := previewDecoder.Decode(&generatedPreview); err != nil {
		t.Fatalf("preview does not match the contract: %v", err)
	}

	save := harness.call(t, http.MethodPost, "/api/v1/config/save", request, true, true)
	if save.Code != http.StatusOK {
		t.Fatalf("save = %d, body %s", save.Code, save.Body.String())
	}
	contents, err := os.ReadFile(filepath.Join(harness.root, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "Host bastion\n\tHostName 203.0.113.10\n\tPort 2222\n" {
		t.Fatalf("config = %q", contents)
	}

	history := harness.call(t, http.MethodGet, "/api/v1/history", nil, true, false)
	var generatedHistory api.HistoryList
	historyDecoder := json.NewDecoder(bytes.NewReader(history.Body.Bytes()))
	historyDecoder.DisallowUnknownFields()
	if err := historyDecoder.Decode(&generatedHistory); err != nil {
		t.Fatalf("history does not match the contract: %v", err)
	}
	if len(generatedHistory.Entries) != 1 {
		t.Fatalf("history entries = %#v", generatedHistory.Entries)
	}
}

func TestSaveRejectsAnUnknownJSONFieldAndAnOversizedBody(t *testing.T) {
	harness := newConfigHarness(t)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/config/save",
		strings.NewReader(`{"kind":"file_raw","path":"config","raw":"Host a\n","surprise":true}`))
	request.Host = "127.0.0.1:43123"
	request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set(echo.HeaderContentType, "application/json")
	request.Header.Set(CSRFHeader, harness.csrf)
	request.AddCookie(harness.cookie)
	response := httptest.NewRecorder()
	harness.echo.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, body %s", response.Code, response.Body.String())
	}

	oversized := application.EditRequest{
		Kind: application.EditFileRaw,
		Path: "config",
		Raw:  strings.Repeat("a", maxRawLength+1),
	}
	if got := harness.call(t, http.MethodPost, "/api/v1/config/save", oversized, true, true).Code; got != http.StatusBadRequest {
		t.Fatalf("oversized raw = %d", got)
	}
}
```

- [ ] **Step 9: Run the handler tests and verify they fail**

Run: `go test ./internal/httpserver -run TestConfig -v`

Expected: FAIL with `undefined: registerConfigRoutes`.

- [ ] **Step 10: Implement the handlers**

```go
// internal/httpserver/config_handlers.go
package httpserver

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/application"
)

// ConfigHandlers serves the configuration, metadata and history endpoints.
// Every route is same-origin, session authenticated, and — for mutations —
// behind the CSRF header enforced by Security.Middleware.
type ConfigHandlers struct {
	Service *application.Service
}

type historyList struct {
	Entries []application.HistoryEntry `json:"entries"`
}

type restoreRequest struct {
	TransactionID string `json:"transactionId"`
	Path          string `json:"path"`
}

type recoverRequest struct {
	TransactionID string `json:"transactionId"`
	Action        string `json:"action"`
}

type recoverResponse struct {
	Status string `json:"status"`
}

// registerConfigRoutes wires the endpoints onto an Echo instance.
func registerConfigRoutes(engine *echo.Echo, handlers ConfigHandlers) {
	engine.GET("/api/v1/config/overview", handlers.Overview)
	engine.GET("/api/v1/config/host", handlers.Host)
	engine.GET("/api/v1/config/file", handlers.File)
	engine.POST("/api/v1/config/preview", handlers.Preview)
	engine.POST("/api/v1/config/save", handlers.Save)
	engine.GET("/api/v1/metadata", handlers.Metadata)
	engine.GET("/api/v1/history", handlers.History)
	engine.POST("/api/v1/history/restore", handlers.Restore)
	engine.POST("/api/v1/history/recover", handlers.Recover)
}

func (h ConfigHandlers) Overview(c *echo.Context) error {
	overview, err := h.Service.Overview()
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, overview)
}

func (h ConfigHandlers) Host(c *echo.Context) error {
	query := c.Request().URL.Query()
	path, alias := query.Get("path"), query.Get("alias")
	if err := validatePathParameter(path); err != nil {
		return serviceProblem(c, err)
	}
	if err := validateAliasParameter(alias); err != nil {
		return serviceProblem(c, err)
	}
	detail, err := h.Service.HostDetail(path, alias)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, detail)
}

func (h ConfigHandlers) File(c *echo.Context) error {
	path := c.Request().URL.Query().Get("path")
	if err := validatePathParameter(path); err != nil {
		return serviceProblem(c, err)
	}
	contents, err := h.Service.FileContents(path)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, contents)
}

func (h ConfigHandlers) Preview(c *echo.Context) error {
	request, err := h.decodeEdit(c)
	if err != nil {
		return serviceProblem(c, err)
	}
	preview, err := h.Service.Preview(request)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, preview)
}

func (h ConfigHandlers) Save(c *echo.Context) error {
	request, err := h.decodeEdit(c)
	if err != nil {
		return serviceProblem(c, err)
	}
	result, err := h.Service.Save(request)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, result)
}

func (h ConfigHandlers) decodeEdit(c *echo.Context) (application.EditRequest, error) {
	var request application.EditRequest
	if err := decodeJSON(c, &request); err != nil {
		return application.EditRequest{}, err
	}
	if err := validateEditRequest(request); err != nil {
		return application.EditRequest{}, err
	}
	return request, nil
}

func (h ConfigHandlers) Metadata(c *echo.Context) error {
	overview, err := h.Service.Overview()
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, overview.Metadata)
}

func (h ConfigHandlers) History(c *echo.Context) error {
	entries, err := h.Service.History()
	if err != nil {
		return serviceProblem(c, err)
	}
	if entries == nil {
		entries = []application.HistoryEntry{}
	}
	return c.JSON(http.StatusOK, historyList{Entries: entries})
}

func (h ConfigHandlers) Restore(c *echo.Context) error {
	var request restoreRequest
	if err := decodeJSON(c, &request); err != nil {
		return serviceProblem(c, err)
	}
	if err := validateIdentifier(request.TransactionID); err != nil {
		return serviceProblem(c, err)
	}
	if err := validatePathParameter(request.Path); err != nil {
		return serviceProblem(c, err)
	}
	result, err := h.Service.Restore(request.TransactionID, request.Path)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, result)
}

func (h ConfigHandlers) Recover(c *echo.Context) error {
	var request recoverRequest
	if err := decodeJSON(c, &request); err != nil {
		return serviceProblem(c, err)
	}
	if err := validateIdentifier(request.TransactionID); err != nil {
		return serviceProblem(c, err)
	}
	if request.Action != "complete" && request.Action != "rollback" {
		return serviceProblem(c, errInvalidEdit)
	}
	if err := h.Service.Recover(request.TransactionID, request.Action); err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, recoverResponse{Status: "ok"})
}
```

- [ ] **Step 11: Register the routes and wire the service**

In `internal/httpserver/server.go`, add the field to `Options` and register the routes right after the health route:

```go
type Options struct {
	Listener net.Listener
	Sessions *session.Manager
	UI       fs.FS
	Version  string
	Logger   *slog.Logger
	Config   *application.Service
}
```

```go
	handlers := Handlers{Sessions: options.Sessions, Version: options.Version}
	e.POST("/api/v1/session/bootstrap", handlers.Bootstrap)
	e.GET("/api/v1/health", handlers.Health)
	if options.Config != nil {
		registerConfigRoutes(e, ConfigHandlers{Service: options.Config})
	}
```

Add `"sshc/internal/application"` to the file's imports.

In `internal/app/run.go`, add the home directory and build the workspace, transaction manager and service:

```go
type Dependencies struct {
	Random  io.Reader
	Browser platform.BrowserLauncher
	Listen  ListenFunc
	UI      fs.FS
	Logger  *slog.Logger
	// Home is the user's home directory. Only cmd/sshc may read it from the
	// operating system; every test injects a temporary directory.
	Home string
}
```

```go
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, dependencies.Home)
	if err != nil {
		listener.Close()
		return fmt.Errorf("workspace: %w", err)
	}
	transactions := storage.NewManager(workspace, time.Now, dependencies.Random)
	configService := application.NewService(workspace, transactions)

	server, err := httpserver.New(httpserver.Options{
		Listener: listener,
		Sessions: sessions,
		UI:       dependencies.UI,
		Version:  version,
		Logger:   dependencies.Logger,
		Config:   configService,
	})
```

Add `"time"`, `"sshc/internal/application"` and `"sshc/internal/storage"` to the imports. `Random` must be safe for concurrent use because both the session manager and the transaction manager read from it; production passes `crypto/rand.Reader`, which is.

In `internal/app/run_test.go`, add `Home: t.TempDir(),` to each of the three `Dependencies` literals so no test touches a real home directory.

In `cmd/sshc/main.go`, resolve the home directory before building the dependencies:

```go
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("resolve home directory", "error", err)
		os.Exit(1)
	}

	dependencies := app.Dependencies{
		Random:  rand.Reader,
		Browser: macos.NewBrowser(macos.NewExecRunner()),
		Listen:  net.Listen,
		UI:      assets,
		Logger:  logger,
		Home:    home,
	}
```

- [ ] **Step 12: Run the whole Go suite**

Run:

```bash
go test ./...
go test -race ./...
```

Expected: PASS, including the existing foundation and engine tests.

- [ ] **Step 13: Confirm no dependency was added and no package reads the real home**

Run:

```bash
git diff --stat go.mod go.sum web/package.json
grep -rn "UserHomeDir" internal/ || echo "no internal package reads the home directory"
```

Expected: no change to `go.mod`, `go.sum` or `web/package.json`; the grep prints the "no internal package" line.

- [ ] **Step 14: Commit the API surface**

```bash
git add api/openapi.yaml internal/api/models.gen.go web/src/api/schema.d.ts \
  internal/httpserver/config_requests.go internal/httpserver/config_requests_test.go \
  internal/httpserver/config_handlers.go internal/httpserver/config_handlers_test.go \
  internal/httpserver/server.go internal/app/run.go internal/app/run_test.go cmd/sshc/main.go
git commit -m "feat: expose config, metadata and history over the local API"
```

---

## Task 7: Typed config client and the Connections tree

**Files:**
- Modify: `web/src/api/client.ts`
- Create: `web/src/api/config.ts`
- Create: `web/src/api/config.test.ts`
- Create: `web/src/connections/ConnectionTree.tsx`
- Create: `web/src/connections/ConnectionTree.test.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/App.test.tsx`

**Interfaces:**
- Consumes: generated `components["schemas"][...]` from Task 6.
- Produces: `ApiError` with `code`, `status` and `problem`; `apiClient.read(path): Promise<unknown>`; `apiClient.mutate<T>` throwing `ApiError`.
- Produces: `configApi.overview()`, `host(path, alias)`, `file(path)`, `preview(request)`, `save(request)`, `history()`, `restore(transactionId, path)`, `recover(transactionId, action)`.
- Produces: exported types `Overview`, `HostDetail`, `HostEntry`, `FormField`, `FieldEdit`, `EditRequest`, `SavePreview`, `SaveResult`, `FileContents`, `FileDiff`, `ConflictReport`, `HistoryEntry`, `Metadata`, `Notice`, `Diagnostic`.
- Produces: `<ConnectionTree overview selected onSelect />`.
- Produces: `App` section routing with Connections, Config and History enabled.

- [ ] **Step 1: Write the failing client test**

```ts
// web/src/api/config.test.ts
import { afterEach, describe, expect, it, vi } from "vitest";
import { apiClient, ApiError } from "./client";
import { configApi } from "./config";

const overviewPayload = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [{ file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 }],
  hosts: [{
    identity: { path: "config", alias: "bastion" },
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    line: 1,
    patterns: ["bastion"],
    editable: true,
  }],
  metadata: { schemaVersion: 1 },
  diagnostics: [],
  notices: [],
};

afterEach(() => {
  apiClient.clear();
  vi.unstubAllGlobals();
});

describe("configApi", () => {
  it("returns a runtime-validated overview", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify(overviewPayload),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));

    const overview = await configApi.overview();

    expect(overview.hosts[0]?.identity.alias).toBe("bastion");
  });

  it("rejects an overview whose shape does not match the contract", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ entry: {}, files: [], hosts: "not-an-array", metadata: {}, diagnostics: [], notices: [] }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));

    await expect(configApi.overview()).rejects.toThrow("invalid_response");
  });

  it("escapes query parameters instead of concatenating them", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({
        form: { entry: overviewPayload.hosts[0], fields: [], raw: "" },
        metadata: { identity: { path: "config", alias: "a b" } },
        effective: { alias: "a b", approximate: true, entries: [] },
        file: {
          file: { path: "config", absolute: "/home/tester/.ssh/config" },
          contents: "", digest: "", editable: true, exists: true,
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetcher);

    await configApi.host("conf.d/10 home.conf", "a b");

    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/config/host?path=conf.d%2F10+home.conf&alias=a+b");
  });

  it("surfaces the problem code and conflict report of a rejected save", async () => {
    const conflict = {
      path: "config",
      externalChange: [{ op: "insert", text: "Host other", newLine: 4 }],
      localChange: [{ op: "delete", text: "\tPort 22", oldLine: 3 }],
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ code: "config_conflict", message: "request rejected", path: "config", conflict }),
      { status: 409, headers: { "Content-Type": "application/problem+json" } },
    )));
    apiClient.setCSRF("c".repeat(43));

    const failure = await configApi.save({ kind: "file_raw", path: "config", raw: "Host a\n" }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ApiError);
    const apiError = failure as ApiError;
    expect(apiError.code).toBe("config_conflict");
    expect(apiError.status).toBe(409);
    expect(apiError.problem?.conflict?.externalChange).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run the client test and verify it fails**

Run: `npm test --prefix web -- src/api/config.test.ts`

Expected: FAIL because `./config` does not exist.

- [ ] **Step 3: Extend the shared client with typed errors**

Replace the response-failure handling in `web/src/api/client.ts`. Keep `setCSRF`, `clear`, `health` and the cross-origin guard exactly as they are, and add:

```ts
export type Problem = components["schemas"]["Problem"];

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly problem: Problem | null;

  constructor(code: string, status: number, problem: Problem | null) {
    super(code);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.problem = problem;
  }
}

async function readProblem(response: Response): Promise<Problem | null> {
  try {
    const payload: unknown = await response.json();
    if (typeof payload !== "object" || payload === null) return null;
    const record = payload as Record<string, unknown>;
    if (typeof record.code !== "string" || typeof record.message !== "string") return null;
    return record as Problem;
  } catch {
    return null;
  }
}

async function failure(response: Response): Promise<ApiError> {
  const problem = await readProblem(response);
  return new ApiError(problem?.code ?? "request_failed", response.status, problem);
}
```

Add a `read` method and make `mutate` throw `ApiError`:

```ts
  async read(path: string): Promise<unknown> {
    const response = await fetch(path, { credentials: "same-origin" });
    if (!response.ok) throw await failure(response);
    return response.json() as Promise<unknown>;
  },
  async mutate<T>(path: string, init: RequestInit): Promise<T> {
    const target = new URL(path, window.location.origin);
    if (target.origin !== window.location.origin) {
      throw new Error("cross_origin_api_mutation");
    }
    if (!csrfToken) throw new Error("csrf_unavailable");

    const headers = new Headers(init.headers);
    headers.set("X-SSHC-CSRF", csrfToken);
    const response = await fetch(path, { ...init, credentials: "same-origin", headers });
    if (!response.ok) throw await failure(response);
    return response.json() as Promise<T>;
  },
```

- [ ] **Step 4: Implement the typed config client**

```ts
// web/src/api/config.ts
import { apiClient } from "./client";
import type { components } from "./schema";

export type Overview = components["schemas"]["Overview"];
export type HostEntry = components["schemas"]["HostEntry"];
export type HostDetail = components["schemas"]["HostDetail"];
export type HostForm = components["schemas"]["HostForm"];
export type FormField = components["schemas"]["FormField"];
export type FieldEdit = components["schemas"]["FieldEdit"];
export type EditRequest = components["schemas"]["EditRequest"];
export type SavePreview = components["schemas"]["SavePreview"];
export type SaveResult = components["schemas"]["SaveResult"];
export type FileContents = components["schemas"]["FileContents"];
export type FileNode = components["schemas"]["FileNode"];
export type FileDiff = components["schemas"]["FileDiff"];
export type DiffLine = components["schemas"]["DiffLine"];
export type ConflictReport = components["schemas"]["ConflictReport"];
export type HistoryEntry = components["schemas"]["HistoryEntry"];
export type PendingTransaction = components["schemas"]["PendingTransaction"];
export type Metadata = components["schemas"]["Metadata"];
export type GroupMetadata = components["schemas"]["GroupMetadata"];
export type HostMetadata = components["schemas"]["HostMetadata"];
export type Notice = components["schemas"]["Notice"];
export type Diagnostic = components["schemas"]["Diagnostic"];
export type EffectiveDiff = components["schemas"]["EffectiveDiff"];

// The generated types describe the contract; these guards check the payload the
// UI actually received, because a type assertion proves nothing at runtime.
function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid_response");
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("invalid_response");
  return value;
}

function asString(value: unknown): string {
  if (typeof value !== "string") throw new Error("invalid_response");
  return value;
}

function validateOverview(value: unknown): Overview {
  const record = asRecord(value);
  asString(asRecord(record.entry).absolute);
  for (const file of asArray(record.files)) {
    asString(asRecord(asRecord(file).file).absolute);
  }
  for (const host of asArray(record.hosts)) {
    const entry = asRecord(host);
    asString(asRecord(entry.identity).alias);
    asString(asRecord(entry.file).absolute);
    asArray(entry.patterns);
  }
  asRecord(record.metadata);
  asArray(record.diagnostics);
  asArray(record.notices);
  return record as unknown as Overview;
}

function validateHostDetail(value: unknown): HostDetail {
  const record = asRecord(value);
  const form = asRecord(record.form);
  asArray(form.fields);
  asString(form.raw);
  asRecord(record.metadata);
  asRecord(record.effective);
  validateFileContents(record.file);
  return record as unknown as HostDetail;
}

function validateFileContents(value: unknown): FileContents {
  const record = asRecord(value);
  asString(asRecord(record.file).absolute);
  asString(record.contents);
  asString(record.digest);
  return record as unknown as FileContents;
}

function validateSavePreview(value: unknown): SavePreview {
  const record = asRecord(value);
  asString(record.operation);
  for (const diff of asArray(record.diffs)) {
    const entry = asRecord(diff);
    asString(entry.path);
    asArray(entry.lines);
  }
  return record as unknown as SavePreview;
}

function validateSaveResult(value: unknown): SaveResult {
  const record = asRecord(value);
  asString(record.transactionId);
  asArray(record.written);
  validateSavePreview(record.preview);
  return record as unknown as SaveResult;
}

function validateHistory(value: unknown): HistoryEntry[] {
  const record = asRecord(value);
  const entries = asArray(record.entries);
  for (const entry of entries) {
    const item = asRecord(entry);
    asString(item.id);
    asString(item.operation);
    asArray(item.paths);
  }
  return entries as unknown as HistoryEntry[];
}

function postJSON<T>(path: string, body: unknown): Promise<T> {
  return apiClient.mutate<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export const configApi = {
  async overview(): Promise<Overview> {
    return validateOverview(await apiClient.read("/api/v1/config/overview"));
  },
  async host(path: string, alias: string): Promise<HostDetail> {
    const query = new URLSearchParams({ path, alias });
    return validateHostDetail(await apiClient.read(`/api/v1/config/host?${query.toString()}`));
  },
  async file(path: string): Promise<FileContents> {
    const query = new URLSearchParams({ path });
    return validateFileContents(await apiClient.read(`/api/v1/config/file?${query.toString()}`));
  },
  async preview(request: EditRequest): Promise<SavePreview> {
    return validateSavePreview(await postJSON<unknown>("/api/v1/config/preview", request));
  },
  async save(request: EditRequest): Promise<SaveResult> {
    return validateSaveResult(await postJSON<unknown>("/api/v1/config/save", request));
  },
  async history(): Promise<HistoryEntry[]> {
    return validateHistory(await apiClient.read("/api/v1/history"));
  },
  async restore(transactionId: string, path: string): Promise<SaveResult> {
    return validateSaveResult(await postJSON<unknown>("/api/v1/history/restore", { transactionId, path }));
  },
  async recover(transactionId: string, action: "complete" | "rollback"): Promise<void> {
    await postJSON<unknown>("/api/v1/history/recover", { transactionId, action });
  },
};
```

- [ ] **Step 5: Run the client test to verify it passes**

Run: `npm test --prefix web -- src/api/config.test.ts`

Expected: PASS.

- [ ] **Step 6: Write the failing tree test**

```tsx
// web/src/connections/ConnectionTree.test.tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConnectionTree } from "./ConnectionTree";
import type { Overview } from "../api/config";

const overview: Overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [
    { file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 },
    { file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }, editable: true, loads: 1 },
  ],
  hosts: [
    {
      identity: { path: "conf.d/10-home.conf", alias: "nas" },
      file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" },
      line: 1, patterns: ["nas"], editable: true,
    },
    {
      identity: { path: "config", alias: "bastion" },
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      line: 4, patterns: ["bastion"], editable: true,
    },
    {
      identity: { path: "", alias: "" },
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      line: 9, patterns: ["*"], wildcard: true, editable: true,
    },
  ],
  metadata: {
    schemaVersion: 1,
    groups: [{ name: "home" }],
    hosts: [{ identity: { path: "conf.d/10-home.conf", alias: "nas" }, group: "home", favourite: true }],
  },
  diagnostics: [],
  notices: [],
};

describe("ConnectionTree", () => {
  it("groups hosts by their primary group and marks favourites", () => {
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "home" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toHaveAccessibleDescription(/favourite/i);
    expect(screen.getByRole("heading", { name: "Ungrouped" })).toBeInTheDocument();
  });

  it("shows a wildcard block as a pattern rule rather than a host", () => {
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    expect(screen.getByText("Host *")).toBeInTheDocument();
  });

  it("switches to the Include file hierarchy", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Files" }));

    expect(screen.getByRole("heading", { name: "conf.d/10-home.conf" })).toBeInTheDocument();
  });

  it("filters hosts as the user searches and reports an empty result", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    await user.type(screen.getByRole("searchbox", { name: "Filter connections" }), "bast");

    expect(screen.getByRole("button", { name: /bastion/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /nas/ })).not.toBeInTheDocument();
  });

  it("selects a host", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<ConnectionTree overview={overview} selected={null} onSelect={onSelect} />);

    await user.click(screen.getByRole("button", { name: /bastion/ }));

    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({
      identity: { path: "config", alias: "bastion" },
    }));
  });
});
```

- [ ] **Step 7: Run the tree test and verify it fails**

Run: `npm test --prefix web -- src/connections/ConnectionTree.test.tsx`

Expected: FAIL because `./ConnectionTree` does not exist.

- [ ] **Step 8: Implement the Connections tree**

```tsx
// web/src/connections/ConnectionTree.tsx
import { useMemo, useState } from "react";
import type { HostEntry, Overview } from "../api/config";

export type HostSelection = { path: string; alias: string };

type ConnectionTreeProps = {
  overview: Overview;
  selected: HostSelection | null;
  onSelect: (host: HostEntry) => void;
};

const ungrouped = "Ungrouped";

function hostLabel(host: HostEntry): string {
  return host.identity.alias === "" ? `Host ${host.patterns.join(" ")}` : host.identity.alias;
}

function matchesQuery(host: HostEntry, tags: string[], query: string): boolean {
  if (query === "") return true;
  const needle = query.toLowerCase();
  if (host.identity.alias.toLowerCase().includes(needle)) return true;
  if (host.patterns.some((pattern) => pattern.toLowerCase().includes(needle))) return true;
  return tags.some((tag) => tag.toLowerCase().includes(needle));
}

export function ConnectionTree({ overview, selected, onSelect }: ConnectionTreeProps) {
  const [query, setQuery] = useState("");
  const [grouping, setGrouping] = useState<"groups" | "files">("groups");

  const metadataByAlias = useMemo(() => {
    const index = new Map<string, { group: string; tags: string[]; favourite: boolean }>();
    for (const host of overview.metadata.hosts ?? []) {
      index.set(`${host.identity.path}\u0000${host.identity.alias}`, {
        group: host.group ?? "",
        tags: host.tags ?? [],
        favourite: host.favourite === true,
      });
    }
    return index;
  }, [overview.metadata.hosts]);

  const decorated = useMemo(
    () =>
      overview.hosts.map((host) => {
        const entry = metadataByAlias.get(`${host.identity.path}\u0000${host.identity.alias}`);
        return {
          host,
          group: entry?.group ?? "",
          tags: entry?.tags ?? [],
          favourite: entry?.favourite ?? false,
        };
      }),
    [overview.hosts, metadataByAlias],
  );

  const visible = decorated.filter((item) => matchesQuery(item.host, item.tags, query));

  const sections = useMemo(() => {
    if (grouping === "files") {
      return overview.files.map((file) => ({
        title: file.file.path ?? file.file.absolute,
        items: visible.filter((item) => item.host.file.absolute === file.file.absolute),
      }));
    }
    const names = [...(overview.metadata.groups ?? []).map((group) => group.name), ungrouped];
    return names.map((name) => ({
      title: name,
      items: visible.filter((item) => (item.group === "" ? name === ungrouped : item.group === name)),
    }));
  }, [grouping, overview.files, overview.metadata.groups, visible]);

  return (
    <nav aria-label="Connections" className="flex h-full flex-col gap-3 border-r border-zinc-800 p-4">
      <div className="flex gap-2">
        {(["groups", "files"] as const).map((mode) => (
          <button
            key={mode}
            type="button"
            onClick={() => setGrouping(mode)}
            aria-pressed={grouping === mode}
            className={`rounded px-2 py-1 text-xs ${grouping === mode ? "bg-zinc-800 text-zinc-100" : "text-zinc-400"}`}
          >
            {mode === "groups" ? "Groups" : "Files"}
          </button>
        ))}
      </div>
      <label className="text-xs text-zinc-400" htmlFor="connection-filter">
        Filter connections
      </label>
      <input
        id="connection-filter"
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="alias, pattern or tag"
        className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
      />

      {visible.length === 0 ? (
        <p role="status" className="text-sm text-zinc-400">
          No connection matches this filter.
        </p>
      ) : null}

      {sections.map((section) => (
        section.items.length === 0 ? null : (
          <section key={section.title} className="flex flex-col gap-1">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">{section.title}</h2>
            <ul>
              {section.items.map((item) => {
                const active =
                  selected !== null &&
                  selected.path === item.host.identity.path &&
                  selected.alias === item.host.identity.alias;
                const descriptionId = `host-${item.host.file.absolute}-${item.host.line}-description`;
                return (
                  <li key={`${item.host.file.absolute}:${item.host.line}`}>
                    <button
                      type="button"
                      onClick={() => onSelect(item.host)}
                      aria-current={active ? "true" : undefined}
                      aria-describedby={descriptionId}
                      className={`w-full rounded px-2 py-1 text-left text-sm ${active ? "bg-zinc-800" : "hover:bg-zinc-900"}`}
                    >
                      {hostLabel(item.host)}
                    </button>
                    <span id={descriptionId} className="sr-only">
                      {[
                        item.favourite ? "favourite" : "",
                        item.host.duplicate === true ? "duplicate alias" : "",
                        item.host.wildcard === true ? "pattern rule" : "",
                        item.host.file.path ?? item.host.file.absolute,
                      ]
                        .filter((part) => part !== "")
                        .join(", ")}
                    </span>
                  </li>
                );
              })}
            </ul>
          </section>
        )
      ))}
    </nav>
  );
}
```

- [ ] **Step 9: Add section routing to the application shell**

Replace the navigation and main area of `web/src/App.tsx`, keeping the existing bootstrap effect and error screen exactly as they are:

```tsx
const sections = ["Connections", "Config", "Groups", "Keys", "Known Hosts", "History"] as const;
type Section = (typeof sections)[number];
const enabledSections: Section[] = ["Connections", "Config", "Groups", "History"];
```

```tsx
  const [section, setSection] = useState<Section>("Connections");
```

The single `role="status"` element moves into the header so exactly one status
line exists whatever section is open. Section panels never add another one:

```tsx
      <header className="flex items-baseline gap-3 border-b border-zinc-800 px-6 py-4">
        <h1 className="text-xl font-semibold">sshc</h1>
        <p role="status" className="text-sm text-zinc-300">
          {state === "ready" ? `Local session active · ${version}` : "Starting secure local session…"}
        </p>
      </header>
      <div className="grid grid-cols-[15rem_1fr]">
        <nav aria-label="Primary" className="border-r border-zinc-800 p-4">
          <ul>
            {sections.map((name) => (
              <li key={name}>
                <button
                  type="button"
                  disabled={!enabledSections.includes(name)}
                  aria-current={section === name ? "page" : undefined}
                  onClick={() => setSection(name)}
                  className={`w-full px-3 py-2 text-left ${
                    enabledSections.includes(name) ? "text-zinc-200 hover:bg-zinc-900" : "text-zinc-500"
                  }`}
                >
                  {name}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <main className="p-6">{state === "ready" ? <SectionView section={section} /> : null}</main>
      </div>
```

Add the placeholder view below the component; Tasks 8 and 9 replace each branch with a real panel:

```tsx
function SectionView({ section }: { section: Section }) {
  if (section === "Keys" || section === "Known Hosts") {
    return (
      <p className="text-sm text-zinc-400">{`${section} arrives with a later subsystem.`}</p>
    );
  }
  return (
    <section aria-labelledby="section-heading" className="flex flex-col gap-4">
      <h2 id="section-heading" className="font-medium">{section}</h2>
    </section>
  );
}
```

- [ ] **Step 10: Update the shell test for the enabled sections**

In `web/src/App.test.tsx`, replace the loop that asserts every navigation button is disabled:

```tsx
    for (const label of ["Connections", "Config", "Groups", "History"]) {
      expect(screen.getByRole("button", { name: label })).toBeEnabled();
    }
    for (const label of ["Keys", "Known Hosts"]) {
      expect(screen.getByRole("button", { name: label })).toBeDisabled();
    }
```

Keep every other assertion in the file unchanged, including the status text and the absence of the CSRF token from the DOM.

- [ ] **Step 11: Run the frontend suite**

Run:

```bash
npm test --prefix web
npm run typecheck --prefix web
```

Expected: PASS.

- [ ] **Step 12: Commit the client and the tree**

```bash
git add web/src/api/client.ts web/src/api/config.ts web/src/api/config.test.ts \
  web/src/connections/ConnectionTree.tsx web/src/connections/ConnectionTree.test.tsx \
  web/src/App.tsx web/src/App.test.tsx
git commit -m "feat: add the typed config client and connections tree"
```

---

## Task 8: Host detail tabs, save preview and conflicts

**Files:**
- Create: `web/src/connections/values.ts`
- Create: `web/src/connections/values.test.ts`
- Create: `web/src/connections/SavePreview.tsx`
- Create: `web/src/connections/HostDetail.tsx`
- Create: `web/src/connections/HostDetail.test.tsx`
- Create: `web/src/connections/ConnectionsPage.tsx`
- Create: `web/src/connections/ConnectionsPage.test.tsx`
- Modify: `web/src/App.tsx`

**Interfaces:**
- Consumes: Task 7 `configApi`, `ApiError`, `ConnectionTree`, and the generated types.
- Produces: `parseValues(text: string): string[]` and `formatValues(values: string[]): string`.
- Produces: `<SavePreviewPanel preview conflict problem />`.
- Produces: `<HostDetailPanel detail groups onFieldEdits onBlockRaw onRename onMetadata onPreviewFieldEdits />`.
- Produces: `<ConnectionsPage />` used by `App`.

- [ ] **Step 1: Write the failing value tokenizer test**

```ts
// web/src/connections/values.test.ts
import { describe, expect, it } from "vitest";
import { formatValues, parseValues } from "./values";

describe("parseValues", () => {
  it.each([
    ["single", "22", ["22"]],
    ["several", "one two   three", ["one", "two", "three"]],
    ["quoted with spaces", 'tmux "new session" end', ["tmux", "new session", "end"]],
    ["empty quotes", '""', [""]],
    ["only whitespace", "   ", []],
    ["tabs", "a\tb", ["a", "b"]],
  ])("splits %s the way OpenSSH does", (_name, input, expected) => {
    expect(parseValues(input)).toEqual(expected);
  });

  it("throws when a quote is never closed, because OpenSSH has no escape", () => {
    expect(() => parseValues('"unbalanced')).toThrow("unbalanced_quote");
  });
});

describe("formatValues", () => {
  it("quotes only the values that need it and round-trips", () => {
    const values = ["tmux", "new session", "", "plain"];
    expect(formatValues(values)).toBe('tmux "new session" "" plain');
    expect(parseValues(formatValues(values))).toEqual(values);
  });
});
```

- [ ] **Step 2: Run the tokenizer test and verify it fails**

Run: `npm test --prefix web -- src/connections/values.test.ts`

Expected: FAIL because `./values` does not exist.

- [ ] **Step 3: Implement the tokenizer**

```ts
// web/src/connections/values.ts

// OpenSSH's argv_split treats a leading double quote as the start of a quoted
// token that runs to the next double quote and supports no backslash escapes.
// The editor mirrors that rule exactly so what the user types is what the
// engine will write.
export function parseValues(text: string): string[] {
  const values: string[] = [];
  let index = 0;
  while (index < text.length) {
    while (index < text.length && (text[index] === " " || text[index] === "\t")) index += 1;
    if (index >= text.length) break;

    if (text[index] === '"') {
      const closing = text.indexOf('"', index + 1);
      if (closing < 0) throw new Error("unbalanced_quote");
      values.push(text.slice(index + 1, closing));
      index = closing + 1;
      if (index < text.length && text[index] !== " " && text[index] !== "\t") {
        throw new Error("unbalanced_quote");
      }
      continue;
    }

    let end = index;
    while (end < text.length && text[end] !== " " && text[end] !== "\t") {
      if (text[end] === '"') throw new Error("unbalanced_quote");
      end += 1;
    }
    values.push(text.slice(index, end));
    index = end;
  }
  return values;
}

export function formatValues(values: string[]): string {
  return values
    .map((value) => (value === "" || /[ \t]/.test(value) || value.startsWith("#") ? `"${value}"` : value))
    .join(" ");
}
```

- [ ] **Step 4: Run the tokenizer test to verify it passes**

Run: `npm test --prefix web -- src/connections/values.test.ts`

Expected: PASS.

- [ ] **Step 5: Write the failing host detail test**

```tsx
// web/src/connections/HostDetail.test.tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HostDetailPanel } from "./HostDetail";
import type { HostDetail } from "../api/config";

const detail: HostDetail = {
  form: {
    entry: {
      identity: { path: "config", alias: "bastion" },
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      line: 1,
      patterns: ["bastion"],
      editable: true,
    },
    fields: [
      { line: 2, keyword: "HostName", values: ["203.0.113.10"], category: "basic", editable: true },
      { line: 3, keyword: "ProxyJump", values: ["edge"], category: "jump", editable: true },
      { line: 4, keyword: "UnknownFutureDirective", values: ["yes"], category: "advanced", editable: true },
      { line: 5, keyword: "ProxyCommand", values: ["/usr/bin/nc %h %p"], category: "jump", dangerous: true, editable: true },
    ],
    raw: "Host bastion\n\tHostName 203.0.113.10\n",
    notices: [{ code: "dangerous_directive", path: "config", line: 5, detail: "ProxyCommand" }],
  },
  metadata: { identity: { path: "config", alias: "bastion" }, group: "work", favourite: false },
  effective: {
    alias: "bastion",
    approximate: true,
    entries: [{ keyword: "HostName", values: ["203.0.113.10"], source: { path: "config", line: 2 } }],
  },
  file: {
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    contents: "Host bastion\n\tHostName 203.0.113.10\n",
    digest: "digest",
    editable: true,
    exists: true,
  },
};

function renderPanel(overrides: Partial<Parameters<typeof HostDetailPanel>[0]> = {}) {
  const handlers = {
    detail,
    groups: [{ name: "work" }],
    preview: null,
    problem: null,
    onFieldEdits: vi.fn(),
    onBlockRaw: vi.fn(),
    onRename: vi.fn(),
    onMetadata: vi.fn(),
    ...overrides,
  };
  render(<HostDetailPanel {...handlers} />);
  return handlers;
}

describe("HostDetailPanel", () => {
  it("shows basic fields first and keeps unknown directives editable", async () => {
    const user = userEvent.setup();
    renderPanel();

    expect(screen.getByLabelText("HostName")).toHaveValue("203.0.113.10");

    await user.click(screen.getByRole("tab", { name: "Advanced" }));

    expect(screen.getByLabelText("UnknownFutureDirective")).toHaveValue("yes");
  });

  it("marks executable directives instead of hiding them", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("tab", { name: "Jump" }));

    expect(screen.getByText(/ProxyCommand can run a command/i)).toBeInTheDocument();
  });

  it("sends a set edit with the parsed values", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    const input = screen.getByLabelText("HostName");
    await user.clear(input);
    await user.type(input, "198.51.100.7");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(handlers.onFieldEdits).toHaveBeenCalledWith([
      { action: "set", line: 2, values: ["198.51.100.7"] },
    ]);
  });

  it("sends an add edit for a new arbitrary directive", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    await user.click(screen.getByRole("tab", { name: "Advanced" }));
    await user.type(screen.getByLabelText("New directive"), "SetEnv");
    await user.type(screen.getByLabelText("New value"), "EDITOR=vi");
    await user.click(screen.getByRole("button", { name: "Add directive" }));
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(handlers.onFieldEdits).toHaveBeenCalledWith([
      { action: "add", keyword: "SetEnv", values: ["EDITOR=vi"] },
    ]);
  });

  it("keeps an unbalanced quote in the editor and refuses to submit it", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    const input = screen.getByLabelText("HostName");
    await user.clear(input);
    await user.type(input, '"unbalanced');
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(handlers.onFieldEdits).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/quote/i);
    expect(input).toHaveValue('"unbalanced');
  });

  it("labels the explained values as not being ssh -G", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("tab", { name: "Effective" }));

    expect(screen.getByRole("status")).toHaveTextContent(/ssh -G/);
  });

  it("submits the block raw editor unchanged", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    await user.click(screen.getByRole("tab", { name: "Raw" }));
    await user.click(screen.getByRole("button", { name: "Save block" }));

    expect(handlers.onBlockRaw).toHaveBeenCalledWith("Host bastion\n\tHostName 203.0.113.10\n");
  });
});
```

- [ ] **Step 6: Run the host detail test and verify it fails**

Run: `npm test --prefix web -- src/connections/HostDetail.test.tsx`

Expected: FAIL because `./HostDetail` does not exist.

- [ ] **Step 7: Implement the save preview panel**

```tsx
// web/src/connections/SavePreview.tsx
import type { ConflictReport, DiffLine, FileDiff, Notice, SavePreview } from "../api/config";
import type { Problem } from "../api/client";

const noticeCopy: Record<string, string> = {
  complex_external_rule: "A wildcard, negation, Match block or duplicate alias makes this value come from a rule this editor will not simplify. The source is shown instead.",
  duplicate_alias: "Another block declares the same alias. OpenSSH uses the first one it reads.",
  wildcard_shadow: "A catch-all block can override values for this host.",
  negated_pattern: "A negated pattern applies here.",
  unnamed_host_block: "This block has no concrete alias and can only be edited as raw text.",
  match_block: "A Match block was found. It is never evaluated here because Match exec can run a command.",
  dangerous_directive: "This directive can run a command. It is saved as written and never executed by this application.",
  unstructured_line: "This line has unbalanced quoting and is preserved exactly as written.",
  external_file: "This file is outside ~/.ssh. It is shown but never written.",
  orphan_metadata: "The host this note belonged to is gone. Re-associate it deliberately.",
  group_cycle: "This group's parents form a cycle, so it was skipped.",
  group_member_missing: "This group member has no host block in the configuration.",
  explained_values_only: "These values explain what this engine reads. The authoritative ssh -G check arrives with the diagnostics subsystem.",
};

function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <pre className="max-h-72 overflow-auto rounded bg-zinc-950 p-3 text-xs leading-5">
      {lines.map((line, index) => (
        <div
          key={`${line.op}-${line.oldLine ?? 0}-${line.newLine ?? 0}-${index}`}
          className={
            line.op === "insert" ? "text-emerald-300" : line.op === "delete" ? "text-rose-300" : "text-zinc-400"
          }
        >
          {`${line.op === "insert" ? "+" : line.op === "delete" ? "-" : " "} ${line.text}`}
        </div>
      ))}
    </pre>
  );
}

function FileDiffView({ diff }: { diff: FileDiff }) {
  return (
    <section className="flex flex-col gap-1">
      <h4 className="text-xs font-semibold text-zinc-300">
        {diff.path}
        {diff.created === true ? " (new file)" : ""}
      </h4>
      {diff.truncated === true ? (
        <p className="text-xs text-amber-300">
          This file is too large for a line-by-line preview, so the whole file is shown as replaced.
        </p>
      ) : null}
      <DiffView lines={diff.lines} />
    </section>
  );
}

export function NoticeList({ notices }: { notices: Notice[] }) {
  if (notices.length === 0) return null;
  return (
    <ul className="flex flex-col gap-1">
      {notices.map((notice, index) => (
        <li key={`${notice.code}-${notice.path ?? ""}-${notice.line ?? 0}-${index}`} className="text-xs text-amber-300">
          {noticeCopy[notice.code] ?? notice.code}
          {notice.path === undefined ? "" : ` (${notice.path}${notice.line === undefined ? "" : `:${notice.line}`})`}
        </li>
      ))}
    </ul>
  );
}

export function SavePreviewPanel({
  preview,
  conflict,
  problem,
}: {
  preview: SavePreview | null;
  conflict: ConflictReport | null;
  problem: Problem | null;
}) {
  return (
    <section aria-labelledby="preview-heading" className="flex flex-col gap-3 rounded border border-zinc-800 p-4">
      <h3 id="preview-heading" className="text-sm font-medium">Save preview</h3>

      {problem === null ? null : (
        <p role="alert" className="text-sm text-rose-300">
          {problem.code === "config_syntax_error"
            ? `Syntax error in ${problem.path ?? "the file"} at line ${problem.line ?? 0}, column ${problem.column ?? 0}. The edit is kept here and was not written.`
            : problem.code === "config_graph_error"
              ? "This change would break the Include graph. Nothing was written."
              : problem.code === "config_conflict"
                ? "The file changed outside this application. Nothing was written."
                : `The request was rejected (${problem.code}). Nothing was written.`}
        </p>
      )}

      {problem?.diagnostics === undefined ? null : (
        <ul className="flex flex-col gap-1">
          {problem.diagnostics.map((diagnostic, index) => (
            <li key={`${diagnostic.code}-${index}`} className="text-xs text-rose-300">
              {`${diagnostic.severity}: ${diagnostic.code} ${diagnostic.path ?? ""}${diagnostic.line === undefined ? "" : `:${diagnostic.line}`}`}
            </li>
          ))}
        </ul>
      )}

      {conflict === null ? null : (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-semibold text-zinc-300">Changed on disk since you loaded it</h4>
          <DiffView lines={conflict.externalChange} />
          <h4 className="text-xs font-semibold text-zinc-300">Your pending change</h4>
          <DiffView lines={conflict.localChange} />
          <p className="text-xs text-zinc-400">
            Reload the file to merge the two changes by hand. Nothing was written.
          </p>
        </div>
      )}

      {preview === null ? (
        conflict === null && problem === null ? (
          <p className="text-xs text-zinc-400">Change a value to see exactly what would be written.</p>
        ) : null
      ) : (
        <div className="flex flex-col gap-3">
          {preview.diffs.map((diff) => (
            <FileDiffView key={diff.path} diff={diff} />
          ))}
          {(preview.effective ?? []).map((effective) => (
            <section key={effective.alias} className="flex flex-col gap-1">
              <h4 className="text-xs font-semibold text-zinc-300">{`Explained values for ${effective.alias}`}</h4>
              <ul>
                {effective.changes.map((change) => (
                  <li key={change.keyword} className="text-xs text-zinc-300">
                    {`${change.keyword}: ${change.before.join(", ") || "unset"} → ${change.after.join(", ") || "unset"}`}
                  </li>
                ))}
              </ul>
            </section>
          ))}
          <NoticeList notices={preview.notices ?? []} />
        </div>
      )}
    </section>
  );
}
```

- [ ] **Step 8: Implement the host detail panel**

```tsx
// web/src/connections/HostDetail.tsx
import { useEffect, useMemo, useState } from "react";
import type { FieldEdit, FormField, GroupMetadata, HostDetail, HostMetadata, SavePreview } from "../api/config";
import type { Problem } from "../api/client";
import { formatValues, parseValues } from "./values";
import { NoticeList, SavePreviewPanel } from "./SavePreview";

const tabs = ["Basic", "Jump", "Advanced", "Raw", "Effective", "Diagnostics"] as const;
type Tab = (typeof tabs)[number];

const categoryForTab: Record<string, string> = { Basic: "basic", Jump: "jump", Advanced: "advanced" };

type HostDetailPanelProps = {
  detail: HostDetail;
  groups: GroupMetadata[];
  preview: SavePreview | null;
  problem: Problem | null;
  onFieldEdits: (edits: FieldEdit[]) => void;
  onBlockRaw: (raw: string) => void;
  onRename: (newAlias: string) => void;
  onMetadata: (metadata: HostMetadata) => void;
};

function fieldKey(field: FormField): string {
  return `${field.line}-${field.keyword}`;
}

export function HostDetailPanel({
  detail,
  groups,
  preview,
  problem,
  onFieldEdits,
  onBlockRaw,
  onRename,
  onMetadata,
}: HostDetailPanelProps) {
  const [tab, setTab] = useState<Tab>("Basic");
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [removed, setRemoved] = useState<number[]>([]);
  const [additions, setAdditions] = useState<FieldEdit[]>([]);
  const [newKeyword, setNewKeyword] = useState("");
  const [newValue, setNewValue] = useState("");
  const [blockRaw, setBlockRaw] = useState(detail.form.raw);
  const [renameTo, setRenameTo] = useState(detail.form.entry.identity.alias);
  const [localError, setLocalError] = useState("");

  const identityKey = `${detail.form.entry.identity.path}\u0000${detail.form.entry.identity.alias}`;
  useEffect(() => {
    setDrafts({});
    setRemoved([]);
    setAdditions([]);
    setNewKeyword("");
    setNewValue("");
    setBlockRaw(detail.form.raw);
    setRenameTo(detail.form.entry.identity.alias);
    setLocalError("");
  }, [identityKey, detail.form.raw, detail.form.entry.identity.alias]);

  const visibleFields = useMemo(
    () => detail.form.fields.filter((field) => field.category === categoryForTab[tab]),
    [detail.form.fields, tab],
  );

  function draftFor(field: FormField): string {
    return drafts[fieldKey(field)] ?? formatValues(field.values);
  }

  function submitFieldEdits() {
    const edits: FieldEdit[] = [];
    try {
      for (const field of detail.form.fields) {
        if (removed.includes(field.line)) {
          edits.push({ action: "remove", line: field.line });
          continue;
        }
        const draft = drafts[fieldKey(field)];
        if (draft === undefined) continue;
        edits.push({ action: "set", line: field.line, values: parseValues(draft) });
      }
      edits.push(...additions);
    } catch {
      setLocalError("A value has an unbalanced quote. OpenSSH has no escape inside quotes, so this cannot be saved.");
      return;
    }
    if (edits.length === 0) {
      setLocalError("Nothing changed yet.");
      return;
    }
    setLocalError("");
    onFieldEdits(edits);
  }

  function addDirective() {
    if (newKeyword === "") {
      setLocalError("A directive needs a keyword.");
      return;
    }
    try {
      setAdditions([...additions, { action: "add", keyword: newKeyword, values: parseValues(newValue) }]);
    } catch {
      setLocalError("A value has an unbalanced quote. OpenSSH has no escape inside quotes, so this cannot be saved.");
      return;
    }
    setNewKeyword("");
    setNewValue("");
    setLocalError("");
  }

  return (
    <section className="flex flex-col gap-4">
      <header className="flex flex-col gap-1">
        <h2 className="text-lg font-medium">{detail.form.entry.identity.alias || detail.form.entry.patterns.join(" ")}</h2>
        <p className="text-xs text-zinc-400">
          {`${detail.form.entry.file.path ?? detail.form.entry.file.absolute}:${detail.form.entry.line}`}
        </p>
        <NoticeList notices={detail.form.notices ?? []} />
      </header>

      <div role="tablist" aria-label="Host editor" className="flex gap-1 border-b border-zinc-800">
        {tabs.map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
            className={`px-3 py-2 text-sm ${tab === name ? "border-b-2 border-zinc-200 text-zinc-100" : "text-zinc-400"}`}
          >
            {name}
          </button>
        ))}
      </div>

      {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}

      {tab === "Basic" || tab === "Jump" || tab === "Advanced" ? (
        <div className="flex flex-col gap-3">
          {visibleFields.map((field) => (
            <div key={fieldKey(field)} className="flex flex-col gap-1">
              <label htmlFor={`field-${fieldKey(field)}`} className="text-xs text-zinc-400">
                {field.keyword}
              </label>
              <div className="flex gap-2">
                <input
                  id={`field-${fieldKey(field)}`}
                  value={draftFor(field)}
                  disabled={!field.editable || removed.includes(field.line)}
                  onChange={(event) => setDrafts({ ...drafts, [fieldKey(field)]: event.target.value })}
                  className="flex-1 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
                />
                <button
                  type="button"
                  onClick={() =>
                    setRemoved(removed.includes(field.line)
                      ? removed.filter((line) => line !== field.line)
                      : [...removed, field.line])
                  }
                  className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300"
                >
                  {removed.includes(field.line) ? "Keep" : "Remove"}
                </button>
              </div>
              {field.dangerous === true ? (
                <p className="text-xs text-amber-300">
                  {`${field.keyword} can run a command when OpenSSH evaluates this host. It is stored as written and never executed here.`}
                </p>
              ) : null}
              {field.duplicate === true ? (
                <p className="text-xs text-amber-300">
                  A previous line in this block uses the same keyword. OpenSSH keeps the first one.
                </p>
              ) : null}
            </div>
          ))}

          {tab === "Advanced" ? (
            <div className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
              <label htmlFor="new-directive" className="text-xs text-zinc-400">New directive</label>
              <input
                id="new-directive"
                value={newKeyword}
                onChange={(event) => setNewKeyword(event.target.value)}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
              />
              <label htmlFor="new-value" className="text-xs text-zinc-400">New value</label>
              <input
                id="new-value"
                value={newValue}
                onChange={(event) => setNewValue(event.target.value)}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
              />
              <button type="button" onClick={addDirective} className="self-start rounded bg-zinc-800 px-3 py-1 text-sm">
                Add directive
              </button>
              {additions.length === 0 ? null : (
                <ul className="text-xs text-zinc-300">
                  {additions.map((addition, index) => (
                    <li key={`${addition.keyword ?? ""}-${index}`}>
                      {`${addition.keyword ?? ""} ${formatValues(addition.values ?? [])}`}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}

          <button type="button" onClick={submitFieldEdits} className="self-start rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900">
            Save changes
          </button>
        </div>
      ) : null}

      {tab === "Raw" ? (
        <div className="flex flex-col gap-2">
          <label htmlFor="block-raw" className="text-xs text-zinc-400">
            Block text. Comments, blank lines and unknown directives are written back exactly as typed.
          </label>
          <textarea
            id="block-raw"
            value={blockRaw}
            onChange={(event) => setBlockRaw(event.target.value)}
            rows={16}
            spellCheck={false}
            className="rounded border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs"
          />
          <button type="button" onClick={() => onBlockRaw(blockRaw)} className="self-start rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900">
            Save block
          </button>
        </div>
      ) : null}

      {tab === "Effective" ? (
        <div className="flex flex-col gap-2">
          <p role="status" className="text-xs text-amber-300">
            These are the values this engine reads, with their source. They are not `ssh -G` output; the authoritative
            check arrives with the diagnostics subsystem.
          </p>
          <ul className="flex flex-col gap-1">
            {detail.effective.entries.map((entry, index) => (
              <li key={`${entry.keyword}-${index}`} className="text-xs text-zinc-300">
                {`${entry.keyword} ${entry.values.join(" ")} — ${entry.source.path ?? entry.source.absolute ?? ""}:${entry.source.line ?? 0}`}
              </li>
            ))}
          </ul>
          <NoticeList notices={detail.effective.notices ?? []} />
        </div>
      ) : null}

      {tab === "Diagnostics" ? (
        <p role="status" className="text-sm text-zinc-400">
          Reachability, authentication and `ssh -G` diagnostics arrive with a later subsystem.
        </p>
      ) : null}

      <section className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
        <h3 className="text-sm font-medium">Organisation</h3>
        <label htmlFor="host-group" className="text-xs text-zinc-400">Primary group</label>
        <select
          id="host-group"
          value={detail.metadata.group ?? ""}
          onChange={(event) => onMetadata({ ...detail.metadata, group: event.target.value })}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          <option value="">None</option>
          {groups.map((group) => (
            <option key={group.name} value={group.name}>{group.name}</option>
          ))}
        </select>
        <label className="flex items-center gap-2 text-xs text-zinc-400">
          <input
            type="checkbox"
            checked={detail.metadata.favourite === true}
            onChange={(event) => onMetadata({ ...detail.metadata, favourite: event.target.checked })}
          />
          Favourite
        </label>
        <label htmlFor="host-note" className="text-xs text-zinc-400">Note</label>
        <input
          id="host-note"
          value={detail.metadata.note ?? ""}
          onChange={(event) => onMetadata({ ...detail.metadata, note: event.target.value })}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="host-rename" className="text-xs text-zinc-400">Rename alias</label>
        <div className="flex gap-2">
          <input
            id="host-rename"
            value={renameTo}
            onChange={(event) => setRenameTo(event.target.value)}
            className="flex-1 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
          />
          <button type="button" onClick={() => onRename(renameTo)} className="rounded border border-zinc-700 px-2 py-1 text-xs">
            Rename
          </button>
        </div>
      </section>

      <SavePreviewPanel
        preview={preview}
        conflict={problem?.conflict ?? null}
        problem={problem}
      />
    </section>
  );
}
```

- [ ] **Step 9: Run the host detail test to verify it passes**

Run: `npm test --prefix web -- src/connections/HostDetail.test.tsx`

Expected: PASS.

- [ ] **Step 10: Write the failing page test**

```tsx
// web/src/connections/ConnectionsPage.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConnectionsPage } from "./ConnectionsPage";
import { ApiError } from "../api/client";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), host: vi.fn(), preview: vi.fn(), save: vi.fn() } };
});

const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [{ file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 }],
  hosts: [{
    identity: { path: "config", alias: "bastion" },
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    line: 1, patterns: ["bastion"], editable: true,
  }],
  metadata: { schemaVersion: 1 },
  diagnostics: [],
  notices: [],
};

const detail = {
  form: {
    entry: overview.hosts[0],
    fields: [{ line: 2, keyword: "Port", values: ["22"], category: "basic", editable: true }],
    raw: "Host bastion\n\tPort 22\n",
  },
  metadata: { identity: { path: "config", alias: "bastion" } },
  effective: { alias: "bastion", approximate: true, entries: [] },
  file: {
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    contents: "Host bastion\n\tPort 22\n", digest: "digest", editable: true, exists: true,
  },
};

beforeEach(() => {
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.host).mockResolvedValue(detail as never);
});

describe("ConnectionsPage", () => {
  it("loads the tree, opens a host and saves a field edit with the loaded base", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["config"], preview: { operation: "config.host_fields", diffs: [] },
    } as never);

    render(<ConnectionsPage />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    const input = await screen.findByLabelText("Port");
    await user.clear(input);
    await user.type(input, "2222");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "host_fields",
      path: "config",
      alias: "bastion",
      base: "Host bastion\n\tPort 22\n",
      fields: [{ action: "set", line: 2, values: ["2222"] }],
    }));
  });

  it("keeps the edit visible and shows the conflict when the file changed on disk", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockRejectedValue(new ApiError("config_conflict", 409, {
      code: "config_conflict",
      message: "request rejected",
      path: "config",
      conflict: {
        path: "config",
        externalChange: [{ op: "insert", text: "Host other", newLine: 3 }],
        localChange: [{ op: "delete", text: "\tPort 22", oldLine: 2 }],
      },
    }));

    render(<ConnectionsPage />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    const input = await screen.findByLabelText("Port");
    await user.clear(input);
    await user.type(input, "2222");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/changed outside this application/i);
    expect(screen.getByText("Changed on disk since you loaded it")).toBeInTheDocument();
    expect(screen.getByLabelText("Port")).toHaveValue("2222");
  });
});
```

- [ ] **Step 11: Run the page test and verify it fails**

Run: `npm test --prefix web -- src/connections/ConnectionsPage.test.tsx`

Expected: FAIL because `./ConnectionsPage` does not exist.

- [ ] **Step 12: Implement the Connections page**

```tsx
// web/src/connections/ConnectionsPage.tsx
import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import {
  configApi,
  type EditRequest,
  type FieldEdit,
  type HostDetail,
  type HostEntry,
  type HostMetadata,
  type Metadata,
  type Overview,
  type SavePreview,
} from "../api/config";
import { ConnectionTree, type HostSelection } from "./ConnectionTree";
import { HostDetailPanel } from "./HostDetail";
import { NoticeList } from "./SavePreview";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function ConnectionsPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [selection, setSelection] = useState<HostSelection | null>(null);
  const [detail, setDetail] = useState<HostDetail | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);

  const reload = useCallback(async () => {
    try {
      setOverview(await configApi.overview());
    } catch (error) {
      setProblem(toProblem(error));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    if (selection === null) return;
    let active = true;
    void configApi
      .host(selection.path, selection.alias)
      .then((loaded) => {
        if (active) {
          setDetail(loaded);
          setPreview(null);
          setProblem(null);
        }
      })
      .catch((error: unknown) => {
        if (active) setProblem(toProblem(error));
      });
    return () => {
      active = false;
    };
  }, [selection]);

  // reselect is false when the edit removed the host that is open, so the page
  // does not immediately ask the server for a block it just deleted.
  async function submit(request: EditRequest, reselect = true) {
    try {
      const result = await configApi.save(request);
      setPreview(result.preview);
      setProblem(null);
      await reload();
      if (reselect && selection !== null) {
        const nextAlias = request.kind === "rename" ? request.newAlias ?? selection.alias : selection.alias;
        setSelection({ path: selection.path, alias: nextAlias });
        setDetail(await configApi.host(selection.path, nextAlias));
      }
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  function onSelect(host: HostEntry) {
    if (host.identity.alias === "") return;
    setSelection({ path: host.identity.path, alias: host.identity.alias });
  }

  function onFieldEdits(fields: FieldEdit[]) {
    if (detail === null || selection === null) return;
    void submit({
      kind: "host_fields",
      path: selection.path,
      alias: selection.alias,
      base: detail.file.contents,
      fields,
    });
  }

  function onBlockRaw(raw: string) {
    if (detail === null || selection === null) return;
    void submit({ kind: "block_raw", path: selection.path, alias: selection.alias, base: detail.file.contents, raw });
  }

  function onRename(newAlias: string) {
    if (detail === null || selection === null) return;
    void submit({
      kind: "rename",
      path: selection.path,
      alias: selection.alias,
      base: detail.file.contents,
      newAlias,
    });
  }

  function onMetadata(host: HostMetadata) {
    if (overview === null) return;
    const others = (overview.metadata.hosts ?? []).filter(
      (entry) => entry.identity.path !== host.identity.path || entry.identity.alias !== host.identity.alias,
    );
    const metadata: Metadata = { ...overview.metadata, hosts: [...others, host] };
    void submit({ kind: "metadata", metadata });
  }

  if (overview === null) {
    return <p role="status" className="text-sm text-zinc-300">Loading connections…</p>;
  }

  return (
    <div className="grid grid-cols-[18rem_1fr] gap-6">
      <ConnectionTree overview={overview} selected={selection} onSelect={onSelect} />
      <div className="flex flex-col gap-4">
        <NoticeList notices={overview.notices} />
        {detail === null ? (
          <p role="status" className="text-sm text-zinc-400">Select a connection to edit it.</p>
        ) : (
          <HostDetailPanel
            detail={detail}
            groups={overview.metadata.groups ?? []}
            preview={preview}
            problem={problem}
            onFieldEdits={onFieldEdits}
            onBlockRaw={onBlockRaw}
            onRename={onRename}
            onMetadata={onMetadata}
          />
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 13: Render the page from the shell**

In `web/src/App.tsx`, import `ConnectionsPage` and return it from `SectionView` for the Connections section:

```tsx
  if (section === "Connections") {
    return <ConnectionsPage />;
  }
```

Keep the Keys and Known Hosts placeholders unchanged.

In `web/src/App.test.tsx`, stub the panel so the shell test stays about the shell and performs no network call:

```tsx
vi.mock("./connections/ConnectionsPage", () => ({
  ConnectionsPage: () => <div>connections panel</div>,
}));
```

- [ ] **Step 14: Run the frontend suite**

Run:

```bash
npm test --prefix web
npm run typecheck --prefix web
```

Expected: PASS.

- [ ] **Step 15: Commit the host editor**

```bash
git add web/src/connections web/src/App.tsx web/src/App.test.tsx
git commit -m "feat: edit hosts through form, raw and preview tabs"
```

- [ ] **Step 16: Write the failing block helper test**

```ts
// web/src/connections/blocks.test.ts
import { describe, expect, it } from "vitest";
import { appendHostBlock, duplicateHostBlock, removeHostBlock } from "./blocks";

const contents = "# top\nHost bastion\n\tUser ops\n\nHost nas\n\tUser aida\n";

describe("appendHostBlock", () => {
  it("adds a block at the end and keeps every existing byte", () => {
    expect(appendHostBlock(contents, "build01")).toBe(
      "# top\nHost bastion\n\tUser ops\n\nHost nas\n\tUser aida\n\nHost build01\n\tHostName build01\n",
    );
  });

  it("adds the missing final newline before appending", () => {
    expect(appendHostBlock("Host nas\n\tUser aida", "build01")).toBe(
      "Host nas\n\tUser aida\n\nHost build01\n\tHostName build01\n",
    );
  });

  it("creates the first block of an empty file without a leading blank line", () => {
    expect(appendHostBlock("", "build01")).toBe("Host build01\n\tHostName build01\n");
  });
});

describe("duplicateHostBlock", () => {
  it("copies a block and renames only the alias on the header line", () => {
    const raw = "Host bastion jump.example.com\n\tUser bastion\n";
    expect(duplicateHostBlock(contents, raw, "bastion", "bastion-copy")).toBe(
      `${contents}\nHost bastion-copy jump.example.com\n\tUser bastion\n`,
    );
  });
});

describe("removeHostBlock", () => {
  it("removes exactly the block that starts at the given line", () => {
    expect(removeHostBlock(contents, 2, "Host bastion\n\tUser ops\n\n")).toBe("# top\nHost nas\n\tUser aida\n");
  });

  it("refuses to remove when the text at that line is not the block", () => {
    expect(() => removeHostBlock(contents, 2, "Host other\n")).toThrow("block_moved");
  });
});
```

- [ ] **Step 17: Run the block helper test and verify it fails**

Run: `npm test --prefix web -- src/connections/blocks.test.ts`

Expected: FAIL because `./blocks` does not exist.

- [ ] **Step 18: Implement the block helpers**

```ts
// web/src/connections/blocks.ts

// These helpers compose the exact text of a whole-file raw edit. They never
// reformat anything they did not add, so the server's byte-for-byte guarantee
// still holds for creating, duplicating and deleting a host.

function offsetOfLine(contents: string, line: number): number {
  let offset = 0;
  for (let current = 1; current < line; current += 1) {
    const next = contents.indexOf("\n", offset);
    if (next < 0) throw new Error("block_moved");
    offset = next + 1;
  }
  return offset;
}

export function appendHostBlock(contents: string, alias: string): string {
  const block = `Host ${alias}\n\tHostName ${alias}\n`;
  if (contents === "") return block;
  const terminated = contents.endsWith("\n") ? contents : `${contents}\n`;
  return `${terminated}\n${block}`;
}

export function duplicateHostBlock(contents: string, raw: string, alias: string, newAlias: string): string {
  const lineBreak = raw.indexOf("\n");
  const header = lineBreak < 0 ? raw : raw.slice(0, lineBreak);
  const rest = lineBreak < 0 ? "" : raw.slice(lineBreak);
  const tokens = header.split(" ");
  const aliasIndex = tokens.indexOf(alias);
  if (aliasIndex < 0) throw new Error("block_moved");
  tokens[aliasIndex] = newAlias;
  const copied = `${tokens.join(" ")}${rest}`;
  const terminated = contents.endsWith("\n") ? contents : `${contents}\n`;
  return `${terminated}\n${copied.endsWith("\n") ? copied : `${copied}\n`}`;
}

export function removeHostBlock(contents: string, line: number, raw: string): string {
  const offset = offsetOfLine(contents, line);
  if (!contents.startsWith(raw, offset)) throw new Error("block_moved");
  return contents.slice(0, offset) + contents.slice(offset + raw.length);
}
```

- [ ] **Step 19: Run the block helper test to verify it passes**

Run: `npm test --prefix web -- src/connections/blocks.test.ts`

Expected: PASS.

- [ ] **Step 20: Write the failing host lifecycle test**

Append to `web/src/connections/ConnectionsPage.test.tsx`:

```tsx
  it("creates a host by appending a block to the chosen file", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["config"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);
    vi.mocked(configApi.file).mockResolvedValue({
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      contents: "Host bastion\n\tPort 22\n", digest: "digest", editable: true, exists: true,
    } as never);

    render(<ConnectionsPage />);

    await user.type(await screen.findByLabelText("New connection alias"), "build01");
    await user.click(screen.getByRole("button", { name: "Create connection" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "config",
      base: "Host bastion\n\tPort 22\n",
      raw: "Host bastion\n\tPort 22\n\nHost build01\n\tHostName build01\n",
    }));
  });

  it("deletes the selected host block without touching the rest of the file", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["config"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);

    render(<ConnectionsPage />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    await user.click(await screen.findByRole("button", { name: "Delete connection" }));
    await user.click(screen.getByRole("button", { name: "Confirm delete" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "config",
      base: "Host bastion\n\tPort 22\n",
      raw: "",
    }));
  });
```

Add `file: vi.fn()` to the `configApi` mock object at the top of the file. The shared `detail` fixture already uses `Host bastion\n\tPort 22\n` for both the block raw and the file contents, so the block covers the whole file and deleting it yields an empty file.

- [ ] **Step 21: Implement the host lifecycle actions**

Add to `web/src/connections/ConnectionsPage.tsx`, importing the helpers:

```tsx
import { appendHostBlock, duplicateHostBlock, removeHostBlock } from "./blocks";
```

State and handlers:

```tsx
  const [newAlias, setNewAlias] = useState("");
  const [targetFile, setTargetFile] = useState("config");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [localError, setLocalError] = useState("");

  async function createHost() {
    if (newAlias === "") {
      setLocalError("A new connection needs an alias.");
      return;
    }
    try {
      const current = await configApi.file(targetFile);
      await submit({
        kind: "file_raw",
        path: targetFile,
        base: current.contents,
        raw: appendHostBlock(current.contents, newAlias),
      });
      setNewAlias("");
      setLocalError("");
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  function duplicateHost() {
    if (detail === null || selection === null) return;
    try {
      void submit({
        kind: "file_raw",
        path: selection.path,
        base: detail.file.contents,
        raw: duplicateHostBlock(detail.file.contents, detail.form.raw, selection.alias, `${selection.alias}-copy`),
      });
      setLocalError("");
    } catch {
      setLocalError("This block moved on disk. Reload the connection and try again.");
    }
  }

  async function deleteHost() {
    if (detail === null || selection === null) return;
    let raw: string;
    try {
      raw = removeHostBlock(detail.file.contents, detail.form.entry.line, detail.form.raw);
    } catch {
      setLocalError("This block moved on disk. Reload the connection and try again.");
      return;
    }
    setSelection(null);
    setDetail(null);
    setConfirmingDelete(false);
    setLocalError("");
    await submit({ kind: "file_raw", path: selection.path, base: detail.file.contents, raw }, false);
  }
```

Replace the bare `<ConnectionTree />` element with this toolbar, which keeps the tree as its last child, and add the delete controls at the top of the detail column:

```tsx
      <div className="flex flex-col gap-2">
        <label htmlFor="new-alias" className="text-xs text-zinc-400">New connection alias</label>
        <input
          id="new-alias"
          value={newAlias}
          onChange={(event) => setNewAlias(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="new-file" className="text-xs text-zinc-400">Target file</label>
        <select
          id="new-file"
          value={targetFile}
          onChange={(event) => setTargetFile(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          {overview.files
            .filter((node) => node.editable && node.file.path !== undefined)
            .map((node) => (
              <option key={node.file.absolute} value={node.file.path}>{node.file.path}</option>
            ))}
        </select>
        <button type="button" onClick={() => void createHost()} className="rounded bg-zinc-800 px-3 py-1 text-sm">
          Create connection
        </button>
        <ConnectionTree overview={overview} selected={selection} onSelect={onSelect} />
      </div>
```

```tsx
            {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}
            <div className="flex gap-2">
              <button type="button" onClick={duplicateHost} className="rounded border border-zinc-700 px-2 py-1 text-xs">
                Duplicate connection
              </button>
              {confirmingDelete ? (
                <button type="button" onClick={() => void deleteHost()} className="rounded bg-rose-700 px-2 py-1 text-xs text-zinc-100">
                  Confirm delete
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmingDelete(true)}
                  className="rounded border border-rose-700 px-2 py-1 text-xs text-rose-300"
                >
                  Delete connection
                </button>
              )}
            </div>
```

Moving a host block to another file is not composed on the client: Task 10 adds
it as one server-side two-file transaction, because the server holds the block
boundaries and the destination's duplicate-alias check.

- [ ] **Step 22: Add the tag editor to the organisation section**

In `web/src/connections/HostDetail.tsx`, add a tags input to the Organisation section, immediately after the note field. Tags are metadata only and never influence the configuration:

```tsx
        <label htmlFor="host-tags" className="text-xs text-zinc-400">Tags, comma separated</label>
        <input
          id="host-tags"
          value={(detail.metadata.tags ?? []).join(", ")}
          onChange={(event) =>
            onMetadata({
              ...detail.metadata,
              tags: event.target.value
                .split(",")
                .map((tag) => tag.trim())
                .filter((tag) => tag !== ""),
            })
          }
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
```

- [ ] **Step 23: Run the frontend suite and commit the host lifecycle**

Run:

```bash
npm test --prefix web
npm run typecheck --prefix web
```

Expected: PASS.

```bash
git add web/src/connections
git commit -m "feat: create, duplicate and delete connections losslessly"
```

---

## Task 9: Config Explorer, groups panel, history and subsystem verification

**Files:**
- Create: `web/src/explorer/ConfigExplorer.tsx`
- Create: `web/src/explorer/ConfigExplorer.test.tsx`
- Create: `web/src/groups/GroupsPanel.tsx`
- Create: `web/src/groups/GroupsPanel.test.tsx`
- Create: `web/src/history/HistoryPanel.tsx`
- Create: `web/src/history/HistoryPanel.test.tsx`
- Modify: `web/src/App.tsx`
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 7 `configApi`, `ApiError`; Task 8 `SavePreviewPanel`, `NoticeList`.
- Produces: `<ConfigExplorer />`, `<GroupsPanel />`, `<HistoryPanel />`, all rendered by `App`'s `SectionView`.

- [ ] **Step 1: Write the failing explorer test**

```tsx
// web/src/explorer/ConfigExplorer.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConfigExplorer } from "./ConfigExplorer";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), file: vi.fn(), preview: vi.fn(), save: vi.fn() } };
});

const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [
    {
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      editable: true,
      loads: 1,
      includes: [{
        line: 2,
        pattern: "conf.d/*.conf",
        matches: [{ path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }],
      }],
    },
    { file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }, editable: true, loads: 1 },
    { file: { absolute: "/etc/ssh/ssh_config", external: true }, editable: false, loads: 1 },
  ],
  hosts: [],
  metadata: { schemaVersion: 1 },
  diagnostics: [{ severity: "warning", code: "include_no_match", path: "config", line: 2, detail: "conf.d/*.conf" }],
  notices: [],
};

beforeEach(() => {
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.file).mockResolvedValue({
    file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" },
    contents: "Host nas\n\tUser aida\n",
    digest: "digest",
    editable: true,
    exists: true,
  } as never);
});

describe("ConfigExplorer", () => {
  it("shows the include hierarchy, the reference graph and the diagnostics", async () => {
    render(<ConfigExplorer />);

    expect(await screen.findByRole("button", { name: "config" })).toBeInTheDocument();
    expect(screen.getByText("conf.d/*.conf")).toBeInTheDocument();
    expect(screen.getByText(/include_no_match/)).toBeInTheDocument();
  });

  it("marks a file outside ~/.ssh as read only", async () => {
    render(<ConfigExplorer />);

    expect(await screen.findByText("/etc/ssh/ssh_config")).toBeInTheDocument();
    expect(screen.getByText(/outside ~\/\.ssh/i)).toBeInTheDocument();
  });

  it("edits a whole file and saves it with the loaded base", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["conf.d/10-home.conf"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);

    render(<ConfigExplorer />);

    await user.click(await screen.findByRole("button", { name: "conf.d/10-home.conf" }));
    const editor = await screen.findByLabelText(/File text/);
    await user.clear(editor);
    await user.type(editor, "Host nas\n\tUser root\n");
    await user.click(screen.getByRole("button", { name: "Save file" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "conf.d/10-home.conf",
      base: "Host nas\n\tUser aida\n",
      raw: "Host nas\n\tUser root\n",
    }));
  });

  it("creates a new configuration file inside ~/.ssh", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t2", written: ["conf.d/30-lab.conf"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);

    render(<ConfigExplorer />);

    await user.type(await screen.findByLabelText("New file path"), "conf.d/30-lab.conf");
    await user.click(screen.getByRole("button", { name: "Create file" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "conf.d/30-lab.conf",
      base: "",
      raw: "# created by sshc\n",
    }));
  });
});
```

- [ ] **Step 2: Run the explorer test and verify it fails**

Run: `npm test --prefix web -- src/explorer/ConfigExplorer.test.tsx`

Expected: FAIL because `./ConfigExplorer` does not exist.

- [ ] **Step 3: Implement the Config Explorer**

```tsx
// web/src/explorer/ConfigExplorer.tsx
import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type FileContents, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function ConfigExplorer() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [file, setFile] = useState<FileContents | null>(null);
  const [draft, setDraft] = useState("");
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newPath, setNewPath] = useState("");

  const reload = useCallback(async () => {
    try {
      setOverview(await configApi.overview());
    } catch (error) {
      setProblem(toProblem(error));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function createFile() {
    if (newPath === "") return;
    try {
      await configApi.save({ kind: "file_raw", path: newPath, base: "", raw: "# created by sshc\n" });
      setNewPath("");
      setProblem(null);
      await reload();
      await open(newPath);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function open(path: string) {
    try {
      const loaded = await configApi.file(path);
      setFile(loaded);
      setDraft(loaded.contents);
      setPreview(null);
      setProblem(null);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function run(action: "preview" | "save") {
    if (file === null || file.file.path === undefined) return;
    const request = {
      kind: "file_raw" as const,
      path: file.file.path,
      base: file.contents,
      raw: draft,
    };
    try {
      if (action === "preview") {
        setPreview(await configApi.preview(request));
        setProblem(null);
        return;
      }
      const result = await configApi.save(request);
      setPreview(result.preview);
      setProblem(null);
      await reload();
      await open(request.path);
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  if (overview === null) {
    return <p role="status" className="text-sm text-zinc-300">Loading configuration files…</p>;
  }

  return (
    <div className="grid grid-cols-[22rem_1fr] gap-6">
      <section aria-labelledby="explorer-heading" className="flex flex-col gap-3">
        <h3 id="explorer-heading" className="text-sm font-medium">Include hierarchy</h3>
        <ul className="flex flex-col gap-2">
          {overview.files.map((node) => (
            <li key={node.file.absolute} className="rounded border border-zinc-800 p-2">
              {node.file.path === undefined ? (
                <p className="text-sm text-zinc-400">
                  {node.file.absolute}
                  <span className="block text-xs text-amber-300">
                    This file is outside ~/.ssh. It is read and shown, never written.
                  </span>
                </p>
              ) : (
                <button
                  type="button"
                  onClick={() => void open(node.file.path ?? "")}
                  className="text-left text-sm text-zinc-200 hover:underline"
                >
                  {node.file.path}
                </button>
              )}
              <p className="text-xs text-zinc-500">
                {`${node.missing === true ? "missing · " : ""}${node.loads > 1 ? `read ${node.loads} times · ` : ""}${node.editable ? "editable" : "read only"}`}
              </p>
              {(node.includes ?? []).map((include) => (
                <div key={`${node.file.absolute}:${include.line}:${include.pattern}`} className="mt-1 text-xs text-zinc-400">
                  <span className="font-mono">{include.pattern}</span>
                  {include.condition === undefined ? null : (
                    <span className="ml-1 text-amber-300">{`inside ${include.condition}`}</span>
                  )}
                  <ul className="ml-3">
                    {(include.matches ?? []).map((match) => (
                      <li key={match.absolute} className="font-mono">
                        {`→ ${match.path ?? match.absolute}`}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </li>
          ))}
        </ul>

        <div className="flex flex-col gap-1 rounded border border-zinc-800 p-2">
          <label htmlFor="new-file-path" className="text-xs text-zinc-400">New file path</label>
          <input
            id="new-file-path"
            value={newPath}
            onChange={(event) => setNewPath(event.target.value)}
            placeholder="conf.d/30-lab.conf"
            className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
          />
          <button type="button" onClick={() => void createFile()} className="self-start rounded bg-zinc-800 px-2 py-1 text-xs">
            Create file
          </button>
          <p className="text-xs text-zinc-500">
            A new file is only read once an Include in ~/.ssh/config points at it. Add that line in the entry file
            below. Moving, renaming and deleting files needs journalled delete and rename primitives this version does
            not have yet.
          </p>
        </div>

        <h3 className="text-sm font-medium">Diagnostics</h3>
        {overview.diagnostics.length === 0 ? (
          <p className="text-xs text-zinc-500">No Include problem detected.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {overview.diagnostics.map((diagnostic, index) => (
              <li
                key={`${diagnostic.code}-${index}`}
                className={`text-xs ${diagnostic.severity === "error" ? "text-rose-300" : diagnostic.severity === "warning" ? "text-amber-300" : "text-zinc-400"}`}
              >
                {`${diagnostic.code} ${diagnostic.path ?? diagnostic.absolute ?? ""}${diagnostic.line === undefined ? "" : `:${diagnostic.line}`} ${diagnostic.detail ?? ""}`}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-3">
        {file === null ? (
          <p role="status" className="text-sm text-zinc-400">Select a file to edit its full text.</p>
        ) : (
          <div className="flex flex-col gap-2">
            <label htmlFor="file-raw" className="text-xs text-zinc-400">
              {`File text — ${file.file.path ?? file.file.absolute}. Every byte is written back exactly as typed.`}
            </label>
            <textarea
              id="file-raw"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              rows={24}
              spellCheck={false}
              disabled={!file.editable}
              className="rounded border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs"
            />
            <div className="flex gap-2">
              <button type="button" onClick={() => void run("preview")} className="rounded border border-zinc-700 px-3 py-1 text-sm">
                Preview
              </button>
              <button
                type="button"
                onClick={() => void run("save")}
                disabled={!file.editable}
                className="rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900 disabled:bg-zinc-700 disabled:text-zinc-400"
              >
                Save file
              </button>
            </div>
          </div>
        )}
        <SavePreviewPanel preview={preview} conflict={problem?.conflict ?? null} problem={problem} />
      </section>
    </div>
  );
}
```

- [ ] **Step 4: Write the failing groups test**

```tsx
// web/src/groups/GroupsPanel.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GroupsPanel } from "./GroupsPanel";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), preview: vi.fn(), save: vi.fn() } };
});

const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [],
  hosts: [{
    identity: { path: "config", alias: "build01" },
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    line: 1, patterns: ["build01"], editable: true,
  }],
  metadata: {
    schemaVersion: 1,
    groups: [{ name: "company", settings: [{ keyword: "ServerAliveInterval", values: ["30"] }] }],
    hosts: [{ identity: { path: "config", alias: "build01" }, group: "company" }],
  },
  diagnostics: [],
  notices: [],
};

beforeEach(() => {
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.preview).mockResolvedValue({
    operation: "config.groups",
    diffs: [{ path: "groups.sshc.conf", created: true, lines: [{ op: "insert", text: "Host build01", newLine: 1 }] }],
    effective: [{ alias: "build01", changes: [{ keyword: "Port", before: [], after: ["2222"] }] }],
  } as never);
});

describe("GroupsPanel", () => {
  it("lists groups with their members and settings", async () => {
    render(<GroupsPanel />);

    expect(await screen.findByRole("heading", { name: "company" })).toBeInTheDocument();
    expect(screen.getByText("ServerAliveInterval 30")).toBeInTheDocument();
    expect(screen.getByText("build01")).toBeInTheDocument();
  });

  it("adds a child group and previews the effective value change before saving", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("New group name"), "work");
    await user.selectOptions(screen.getByLabelText("Parent group"), "company");
    await user.click(screen.getByRole("button", { name: "Add group" }));
    await user.click(screen.getByRole("button", { name: "Preview group changes" }));

    await waitFor(() => expect(configApi.preview).toHaveBeenCalledWith(expect.objectContaining({ kind: "groups" })));
    expect(await screen.findByText(/Port: unset → 2222/)).toBeInTheDocument();

    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1",
      written: ["groups.sshc.conf"],
      preview: { operation: "config.groups", diffs: [] },
    } as never);
    await user.click(screen.getByRole("button", { name: "Save groups" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith(expect.objectContaining({
      kind: "groups",
      metadata: expect.objectContaining({
        groups: expect.arrayContaining([expect.objectContaining({ name: "work", parent: "company" })]),
      }),
    })));
  });
});
```

- [ ] **Step 5: Run the groups test and verify it fails**

Run: `npm test --prefix web -- src/groups/GroupsPanel.test.tsx`

Expected: FAIL because `./GroupsPanel` does not exist.

- [ ] **Step 6: Implement the groups panel**

```tsx
// web/src/groups/GroupsPanel.tsx
import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type GroupMetadata, type Metadata, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";
import { formatValues, parseValues } from "../connections/values";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function GroupsPanel() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [metadata, setMetadata] = useState<Metadata | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newName, setNewName] = useState("");
  const [newParent, setNewParent] = useState("");
  const [settingGroup, setSettingGroup] = useState("");
  const [settingKeyword, setSettingKeyword] = useState("");
  const [settingValue, setSettingValue] = useState("");
  const [localError, setLocalError] = useState("");

  const reload = useCallback(async () => {
    try {
      const loaded = await configApi.overview();
      setOverview(loaded);
      setMetadata(loaded.metadata);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  if (overview === null || metadata === null) {
    return <p role="status" className="text-sm text-zinc-300">Loading groups…</p>;
  }

  const groups = metadata.groups ?? [];

  function membersOf(name: string): string[] {
    return (metadata?.hosts ?? [])
      .filter((host) => host.group === name)
      .map((host) => host.identity.alias);
  }

  function addGroup() {
    if (newName === "" || groups.some((group) => group.name === newName)) {
      setLocalError("A group needs a name that is not already used.");
      return;
    }
    const added: GroupMetadata = newParent === "" ? { name: newName } : { name: newName, parent: newParent };
    setMetadata({ ...metadata, groups: [...groups, added] });
    setNewName("");
    setNewParent("");
    setLocalError("");
  }

  function addSetting() {
    if (settingGroup === "" || settingKeyword === "") {
      setLocalError("Choose a group and a directive keyword.");
      return;
    }
    let values: string[];
    try {
      values = parseValues(settingValue);
    } catch {
      setLocalError("A value has an unbalanced quote. OpenSSH has no escape inside quotes, so this cannot be saved.");
      return;
    }
    setMetadata({
      ...metadata,
      groups: groups.map((group) =>
        group.name === settingGroup
          ? { ...group, settings: [...(group.settings ?? []), { keyword: settingKeyword, values }] }
          : group,
      ),
    });
    setSettingKeyword("");
    setSettingValue("");
    setLocalError("");
  }

  function removeGroup(name: string) {
    setMetadata({
      ...metadata,
      groups: groups.filter((group) => group.name !== name && group.parent !== name),
      hosts: (metadata?.hosts ?? []).map((host) => (host.group === name ? { ...host, group: "" } : host)),
    });
  }

  async function run(action: "preview" | "save") {
    try {
      if (action === "preview") {
        setPreview(await configApi.preview({ kind: "groups", metadata }));
        setProblem(null);
        return;
      }
      const result = await configApi.save({ kind: "groups", metadata });
      setPreview(result.preview);
      setProblem(null);
      await reload();
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs text-zinc-400">
        Groups compile into ordinary Host blocks in {metadata.groupsFile ?? "groups.sshc.conf"}, with child groups
        written before their parents so OpenSSH keeps the most specific value it reads first.
      </p>
      {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}

      <ul className="flex flex-col gap-3">
        {groups.map((group) => (
          <li key={group.name} className="rounded border border-zinc-800 p-3">
            <h3 className="text-sm font-medium">{group.name}</h3>
            {group.parent === undefined ? null : (
              <p className="text-xs text-zinc-400">{`inherits from ${group.parent}`}</p>
            )}
            <ul className="mt-1 text-xs text-zinc-300">
              {(group.settings ?? []).map((setting, index) => (
                <li key={`${setting.keyword}-${index}`}>{`${setting.keyword} ${formatValues(setting.values)}`}</li>
              ))}
            </ul>
            <p className="mt-1 text-xs text-zinc-400">
              Members: {membersOf(group.name).length === 0 ? "none" : membersOf(group.name).join(", ")}
            </p>
            <button
              type="button"
              onClick={() => removeGroup(group.name)}
              className="mt-2 rounded border border-zinc-700 px-2 py-1 text-xs"
            >
              {`Remove ${group.name}`}
            </button>
          </li>
        ))}
      </ul>

      <section className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
        <label htmlFor="group-name" className="text-xs text-zinc-400">New group name</label>
        <input
          id="group-name"
          value={newName}
          onChange={(event) => setNewName(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="group-parent" className="text-xs text-zinc-400">Parent group</label>
        <select
          id="group-parent"
          value={newParent}
          onChange={(event) => setNewParent(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          <option value="">None</option>
          {groups.map((group) => (
            <option key={group.name} value={group.name}>{group.name}</option>
          ))}
        </select>
        <button type="button" onClick={addGroup} className="self-start rounded bg-zinc-800 px-3 py-1 text-sm">
          Add group
        </button>
      </section>

      <section className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
        <label htmlFor="setting-group" className="text-xs text-zinc-400">Group</label>
        <select
          id="setting-group"
          value={settingGroup}
          onChange={(event) => setSettingGroup(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          <option value="">Choose a group</option>
          {groups.map((group) => (
            <option key={group.name} value={group.name}>{group.name}</option>
          ))}
        </select>
        <label htmlFor="setting-keyword" className="text-xs text-zinc-400">Directive</label>
        <input
          id="setting-keyword"
          value={settingKeyword}
          onChange={(event) => setSettingKeyword(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="setting-value" className="text-xs text-zinc-400">Value</label>
        <input
          id="setting-value"
          value={settingValue}
          onChange={(event) => setSettingValue(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <button type="button" onClick={addSetting} className="self-start rounded bg-zinc-800 px-3 py-1 text-sm">
          Add setting
        </button>
      </section>

      <div className="flex gap-2">
        <button type="button" onClick={() => void run("preview")} className="rounded border border-zinc-700 px-3 py-1 text-sm">
          Preview group changes
        </button>
        <button type="button" onClick={() => void run("save")} className="rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900">
          Save groups
        </button>
      </div>

      <SavePreviewPanel preview={preview} conflict={problem?.conflict ?? null} problem={problem} />
    </div>
  );
}
```

- [ ] **Step 7: Write the failing history test**

```tsx
// web/src/history/HistoryPanel.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { HistoryPanel } from "./HistoryPanel";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), history: vi.fn(), restore: vi.fn(), recover: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(configApi.history).mockResolvedValue([{
    id: "20260805T120000.000-abcd",
    operation: "config.host_fields",
    status: "completed",
    startedAt: "2026-08-05T12:00:00Z",
    finishedAt: "2026-08-05T12:00:01Z",
    paths: ["config"],
    restorable: ["config"],
  }] as never);
  vi.mocked(configApi.overview).mockResolvedValue({
    entry: { path: "config", absolute: "/home/tester/.ssh/config" },
    files: [], hosts: [], metadata: { schemaVersion: 1 }, diagnostics: [], notices: [],
    pending: [{
      id: "20260805T115900.000-ffff",
      operation: "config.file_raw",
      status: "staged",
      startedAt: "2026-08-05T11:59:00Z",
      committed: 1,
      paths: ["config", "conf.d/10-home.conf"],
      canComplete: true,
    }],
  } as never);
});

describe("HistoryPanel", () => {
  it("lists completed transactions and restores one file", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.restore).mockResolvedValue({
      transactionId: "t2", written: ["config"], preview: { operation: "config.restore", diffs: [] },
    } as never);

    render(<HistoryPanel />);

    expect(await screen.findByText("config.host_fields")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Restore config" }));

    await waitFor(() => expect(configApi.restore).toHaveBeenCalledWith("20260805T120000.000-abcd", "config"));
  });

  it("shows an interrupted transaction as unfinished and offers both recoveries", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.recover).mockResolvedValue(undefined as never);

    render(<HistoryPanel />);

    expect(await screen.findByText(/1 of 2 files were written/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Roll back" }));

    await waitFor(() => expect(configApi.recover).toHaveBeenCalledWith("20260805T115900.000-ffff", "rollback"));
  });
});
```

- [ ] **Step 8: Run the history test and verify it fails**

Run: `npm test --prefix web -- src/history/HistoryPanel.test.tsx`

Expected: FAIL because `./HistoryPanel` does not exist.

- [ ] **Step 9: Implement the history panel**

```tsx
// web/src/history/HistoryPanel.tsx
import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type HistoryEntry, type PendingTransaction } from "../api/config";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function HistoryPanel() {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [pending, setPending] = useState<PendingTransaction[]>([]);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [message, setMessage] = useState("");

  const reload = useCallback(async () => {
    try {
      const [history, overview] = await Promise.all([configApi.history(), configApi.overview()]);
      setEntries(history);
      setPending(overview.pending ?? []);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function restore(transactionId: string, path: string) {
    try {
      const result = await configApi.restore(transactionId, path);
      setMessage(`Restored ${path} as transaction ${result.transactionId}.`);
      setProblem(null);
      await reload();
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function recover(transactionId: string, action: "complete" | "rollback") {
    try {
      await configApi.recover(transactionId, action);
      setMessage(action === "complete" ? "The interrupted transaction was completed." : "The interrupted transaction was rolled back.");
      setProblem(null);
      await reload();
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  if (entries === null) {
    return <p role="status" className="text-sm text-zinc-300">Loading history…</p>;
  }

  return (
    <div className="flex flex-col gap-4">
      {problem === null ? null : (
        <p role="alert" className="text-sm text-rose-300">{`The request was rejected (${problem.code}).`}</p>
      )}
      {message === "" ? null : <p role="status" className="text-sm text-emerald-300">{message}</p>}

      {pending.length === 0 ? null : (
        <section aria-labelledby="pending-heading" className="flex flex-col gap-2 rounded border border-amber-700 p-3">
          <h3 id="pending-heading" className="text-sm font-medium text-amber-300">Interrupted transactions</h3>
          {pending.map((item) => (
            <div key={item.id} className="flex flex-col gap-1">
              <p className="text-xs text-zinc-300">
                {`${item.operation} started ${item.startedAt}: ${item.committed} of ${item.paths.length} files were written.`}
              </p>
              <p className="text-xs text-zinc-400">{item.paths.join(", ")}</p>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={!item.canComplete}
                  onClick={() => void recover(item.id, "complete")}
                  className="rounded border border-zinc-700 px-2 py-1 text-xs disabled:text-zinc-500"
                >
                  Complete
                </button>
                <button
                  type="button"
                  onClick={() => void recover(item.id, "rollback")}
                  className="rounded border border-zinc-700 px-2 py-1 text-xs"
                >
                  Roll back
                </button>
              </div>
            </div>
          ))}
        </section>
      )}

      <section aria-labelledby="history-heading" className="flex flex-col gap-2">
        <h3 id="history-heading" className="text-sm font-medium">Completed changes</h3>
        {entries.length === 0 ? (
          <p className="text-xs text-zinc-500">No change has been made through this application yet.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {entries.map((entry) => (
              <li key={entry.id} className="rounded border border-zinc-800 p-3">
                <p className="text-sm text-zinc-200">{entry.operation}</p>
                <p className="text-xs text-zinc-400">{`${entry.startedAt} · ${entry.status} · ${entry.paths.join(", ")}`}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(entry.restorable ?? []).map((path) => (
                    <button
                      key={path}
                      type="button"
                      onClick={() => void restore(entry.id, path)}
                      className="rounded border border-zinc-700 px-2 py-1 text-xs"
                    >
                      {`Restore ${path}`}
                    </button>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-zinc-500">
          Generation backups are kept in ~/.ssh/sshc/backups and are never deleted automatically. A restore is itself
          a new transaction, so it can be undone the same way.
        </p>
      </section>
    </div>
  );
}
```

- [ ] **Step 10: Wire the remaining sections into the shell**

In `web/src/App.tsx`, extend `SectionView`:

```tsx
  if (section === "Connections") {
    return <ConnectionsPage />;
  }
  if (section === "Config") {
    return <ConfigExplorer />;
  }
  if (section === "Groups") {
    return <GroupsPanel />;
  }
  if (section === "History") {
    return <HistoryPanel />;
  }
```

Keep the Keys and Known Hosts placeholder branch as the fallback. The single
`role="status"` element already lives in the header from Task 7, so the existing
`Local session active · <version>` assertion keeps passing.

In `web/src/App.test.tsx`, extend the panel stubs so the shell test performs no
network call:

```tsx
vi.mock("./connections/ConnectionsPage", () => ({ ConnectionsPage: () => <div>connections panel</div> }));
vi.mock("./explorer/ConfigExplorer", () => ({ ConfigExplorer: () => <div>config panel</div> }));
vi.mock("./groups/GroupsPanel", () => ({ GroupsPanel: () => <div>groups panel</div> }));
vi.mock("./history/HistoryPanel", () => ({ HistoryPanel: () => <div>history panel</div> }));
```

Add one shell test proving the navigation switches panels:

```tsx
  it("switches to the history panel", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "History" }));

    expect(screen.getByText("history panel")).toBeInTheDocument();
  });
```

Import `userEvent` from `@testing-library/user-event` at the top of the file if it is not imported yet.

- [ ] **Step 11: Document the Connections UI boundary in README.md**

Add this section after the SSH config engine section, in the README's existing Japanese style:

```markdown
## Connections UI とグループの境界

- `~/.ssh/config` と `Include` 先を正本として編集します。フォーム編集、任意キー・値編集、ブロック Raw 編集、ファイル全体 Raw 編集はすべて同じ lossless 構文木を更新し、変更していない行は 1 バイトも書き換えません。
- 保存は必ず「読み込んだ内容」を base として送り、その SHA-256 を precondition にします。外部変更があった場合は書き込まず、三者差分を表示します。
- 保存前に再パースと Include グラフ再解決を行い、新たに壊れた行や新たな Include エラーが生じる変更は拒否します。既に存在していた問題は保存の障害にしません。
- UI 専用情報は `~/.ssh/sshc/metadata.json` に保存します。スキーマバージョン、グループ、タグ、色、メモ、お気に入り、表示順のみで、鍵本文やパスフレーズは保存しません。
- Host の識別は「正規化した相対パス + 具体的な主 alias」です。改名と別ファイルへの移動は config と metadata を同一トランザクションで更新し、対応先が消えた metadata は推測で付け替えず orphan として再関連付けを求めます。
- Host ブロックの移動は、移動元・移動先・metadata を 1 つの journal 付きトランザクションで書き込みます。ブロックは所有する行（末尾のコメントと空行を含む）ごと byte 単位で移し、読み込み順が変わるため移動前後の実効値差分を表示します。移動先に同じ alias が既にある場合は拒否します。
- ファイルとフォルダの移動・改名・削除はまだ提供していません。`storage` に journal 付きの削除・改名プリミティブが必要で、後続の `sshc-file-operations` 計画で対応します。
- グループは `groups.sshc.conf` に通常の `Host` ブロックとして生成し、子グループを親より先に配置します。`Include` は具体的な Host ブロックの後、最初の catch-all ブロックの前に挿入します。
- ワイルドカード、否定パターン、`Match`、alias 重複によって単純な継承へ投影できない場合は、結果を捏造せず「complex external rule」として出所を表示します。
- Effective タブと Diagnostics タブは値の出所説明のみです。`ssh -G` による実効設定判定、到達性診断、Terminal 起動、鍵管理、Known Hosts は後続サブシステムで実装します。
- API は同一オリジンのみです。CORS は有効化せず、状態変更 API は `X-SSHC-CSRF` header を要求し、`/api/` 応答は `Cache-Control: no-store` を返します。
```

- [ ] **Step 12: Run the whole verification suite**

Run:

```bash
go test ./...
go test -race ./...
make fuzz
npm test --prefix web
npm run typecheck --prefix web
npm run build --prefix web
go build -trimpath -o bin/sshc ./cmd/sshc
```

Expected: every command succeeds. `make fuzz` still finds no failing input, proving the parser guarantees this plan depends on are intact.

- [ ] **Step 13: Confirm the isolation and dependency constraints**

Run:

```bash
git diff --stat go.mod go.sum web/package.json web/package-lock.json
grep -rn "UserHomeDir" internal/ || echo "no internal package reads the home directory"
grep -rEn "https?://(?!127\.0\.0\.1)" web/src/ || echo "no external origin in the frontend"
ls -la ~/.ssh/sshc 2>/dev/null || echo "no state directory in the real home"
```

Expected: no dependency file changed; the grep for `UserHomeDir` prints the "no internal package" line; the frontend contains no external origin; the real `~/.ssh` gained no `sshc` directory. If the last check fails, find the test that used a real home directory and fix it before committing.

- [ ] **Step 14: Commit the explorer, groups and history panels**

```bash
git add web/src/explorer web/src/groups web/src/history web/src/App.tsx README.md
git commit -m "feat: add the config explorer, groups panel and history"
```

---

## Task 10: Move a Host block between configuration files

**Files:**
- Create: `internal/application/move.go`
- Create: `internal/application/move_test.go`
- Modify: `internal/application/notice.go`
- Modify: `internal/application/service.go`
- Modify: `internal/application/service_test.go`
- Modify: `api/openapi.yaml`
- Modify: `internal/api/models.gen.go` (regenerated)
- Modify: `web/src/api/schema.d.ts` (regenerated)
- Modify: `internal/httpserver/config_requests.go`
- Modify: `internal/httpserver/config_requests_test.go`
- Modify: `web/src/connections/ConnectionsPage.tsx`
- Modify: `web/src/connections/ConnectionsPage.test.tsx`

**Interfaces:**
- Consumes: Task 2 `FindHostBlock`, `ErrHostNotFound`; Task 3 `dominantEnding`; Task 4 `ComputeEffective`, `DiffEffective`; Task 5 `Service.plan`, `planned`, `diagnosticBaseline`, `resolveWith`, `displayPath`, `readFile`, `MetadataStore`, `RenameHostIdentity`; `storage.Request/Change/Precondition/ConflictError`.
- Produces: `ExtractHostBlock(file *config.File, alias string) ([]config.Line, error)`.
- Produces: `AppendHostBlock(file *config.File, lines []config.Line)`.
- Produces: `MoveHostBlock(source, destination *config.File, alias string) ([]config.Line, error)`.
- Produces: errors `ErrDuplicateDestinationAlias`, `ErrSameFileMove`; notice code `NoticeDestinationNotIncluded`.
- Produces: `EditMove EditKind = "move"` and `EditRequest.DestinationPath`, `EditRequest.DestinationBase`.
- Produces: `(*Service).planMoveHost(graph *config.Graph, request EditRequest) (planned, error)`.

**Block ownership rule (already established, not a new one):** Task 2's
`ProjectHostForm` builds a block's raw text from `block.Header` through
`block.End - 1`, where `block.End` is the index of the next `Host` or `Match`
header. A block therefore owns its header line plus every following line up to
that next header, **including the trailing comments and blank lines between
them**; a comment written *above* a header belongs to the block before it.
Task 3's `ReplaceBlock` replaces exactly that range and Task 8's
`removeHostBlock` removes exactly that text. This task moves exactly that same
range. Do not introduce a second attachment rule.

- [ ] **Step 1: Write the failing move composition test**

```go
// internal/application/move_test.go
package application

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/config"
)

// moveSource exercises every construct the move must carry across untouched:
// an inline trailing comment, a comment line inside the block, blank lines and
// a line the engine cannot decompose.
const moveSource = `# file comment above the first block
Host bastion
	User ops	# inline
	# comment inside the block

	SetEnv "broken

Host nas
	User aida
`

const movedBlock = "Host bastion\n\tUser ops\t# inline\n\t# comment inside the block\n\n\tSetEnv \"broken\n\n"

func TestMoveHostBlockCarriesTheBlockByteForByte(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host web\n\tUser www\n"))

	moved, err := MoveHostBlock(source, destination, "bastion")
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 6 {
		t.Fatalf("moved %d lines, want the header plus five owned lines", len(moved))
	}

	const wantSource = "# file comment above the first block\nHost nas\n\tUser aida\n"
	if got := string(source.Render()); got != wantSource {
		t.Fatalf("source =\n%q\nwant\n%q", got, wantSource)
	}
	const wantDestination = "Host web\n\tUser www\n\n" + movedBlock
	if got := string(destination.Render()); got != wantDestination {
		t.Fatalf("destination =\n%q\nwant\n%q", got, wantDestination)
	}
	if !strings.Contains(moveSource, movedBlock) {
		t.Fatal("the fixture no longer contains the moved block verbatim")
	}
	if !strings.Contains(string(destination.Render()), movedBlock) {
		t.Fatal("the destination did not receive the block byte for byte")
	}
}

func TestMoveHostBlockKeepsUnstructuredLinesUnstructured(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host web\n\tUser www\n"))

	if _, err := MoveHostBlock(source, destination, "bastion"); err != nil {
		t.Fatal(err)
	}
	unstructured := 0
	for _, line := range destination.Lines {
		if line.Kind == config.LineUnstructured {
			unstructured++
			if line.Text != "\tSetEnv \"broken" {
				t.Fatalf("unstructured line = %q", line.Text)
			}
		}
	}
	if unstructured != 1 {
		t.Fatalf("destination has %d unstructured lines, want 1", unstructured)
	}
}

func TestMoveHostBlockRefusesADuplicateAliasInTheDestination(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host bastion\n\tUser other\n"))

	if _, err := MoveHostBlock(source, destination, "bastion"); !errors.Is(err, ErrDuplicateDestinationAlias) {
		t.Fatalf("error = %v, want ErrDuplicateDestinationAlias", err)
	}
	if got := string(source.Render()); got != moveSource {
		t.Fatal("a refused move must leave the source untouched")
	}
	if got := string(destination.Render()); got != "Host bastion\n\tUser other\n" {
		t.Fatal("a refused move must leave the destination untouched")
	}
}

func TestMoveHostBlockRefusesAnUnknownAlias(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host web\n\tUser www\n"))

	if _, err := MoveHostBlock(source, destination, "absent"); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("error = %v, want ErrHostNotFound", err)
	}
	if got := string(source.Render()); got != moveSource {
		t.Fatal("a refused move must leave the source untouched")
	}
}

func TestAppendHostBlockDoesNotDoubleTheSeparatorOrLoseAFinalNewline(t *testing.T) {
	moved := config.Parse([]byte("Host bastion\n\tUser ops\n")).Lines

	endsBlank := config.Parse([]byte("Host web\n\tUser www\n\n"))
	AppendHostBlock(endsBlank, moved)
	if got := string(endsBlank.Render()); got != "Host web\n\tUser www\n\nHost bastion\n\tUser ops\n" {
		t.Fatalf("blank-terminated destination = %q", got)
	}

	noFinalNewline := config.Parse([]byte("Host web\n\tUser www"))
	AppendHostBlock(noFinalNewline, moved)
	if got := string(noFinalNewline.Render()); got != "Host web\n\tUser www\n\nHost bastion\n\tUser ops\n" {
		t.Fatalf("unterminated destination = %q", got)
	}

	empty := config.Parse(nil)
	AppendHostBlock(empty, moved)
	if got := string(empty.Render()); got != "Host bastion\n\tUser ops\n" {
		t.Fatalf("empty destination = %q", got)
	}
}
```

- [ ] **Step 2: Run the move composition test and verify it fails**

Run: `go test ./internal/application -run 'TestMoveHostBlock|TestAppendHostBlock' -v`

Expected: FAIL with `undefined: MoveHostBlock`.

- [ ] **Step 3: Implement the move composition**

```go
// internal/application/move.go
package application

import (
	"errors"

	"sshc/internal/config"
)

var (
	ErrDuplicateDestinationAlias = errors.New("the destination file already declares this alias")
	ErrSameFileMove              = errors.New("source and destination are the same file")
)

// ExtractHostBlock removes the block declaring alias and returns its lines.
//
// The removed range is exactly the range the projection shows as the block's
// raw text: the Host header line through the line before the next Host or Match
// header, including the trailing comments and blank lines the block owns. A
// comment written above a header belongs to the block before it and stays put.
func ExtractHostBlock(file *config.File, alias string) ([]config.Line, error) {
	block, ok := FindHostBlock(file, alias)
	if !ok {
		return nil, ErrHostNotFound
	}
	extracted := make([]config.Line, 0, block.End-block.Header)
	extracted = append(extracted, file.Lines[block.Header:block.End]...)

	remaining := make([]config.Line, 0, len(file.Lines)-len(extracted))
	remaining = append(remaining, file.Lines[:block.Header]...)
	remaining = append(remaining, file.Lines[block.End:]...)
	file.Lines = remaining
	return extracted, nil
}

// AppendHostBlock appends extracted lines to the end of file, separated by one
// blank line when the file does not already end with one. The appended lines
// are never rewritten, so the moved block keeps every byte, including lines the
// engine could not decompose.
func AppendHostBlock(file *config.File, lines []config.Line) {
	if len(lines) == 0 {
		return
	}
	if len(file.Lines) > 0 {
		ending := dominantEnding(file)
		last := &file.Lines[len(file.Lines)-1]
		if last.Ending == "" {
			last.Ending = ending
		}
		if last.Kind != config.LineBlank {
			file.Lines = append(file.Lines, config.Line{Kind: config.LineBlank, Ending: ending})
		}
	}
	file.Lines = append(file.Lines, lines...)
}

// MoveHostBlock moves one host block from source to destination.
//
// The destination is checked first so a refused move leaves both files exactly
// as they were. Both files are composed from the bytes the caller loaded, so
// the source loses only the block's lines and the destination gains exactly
// those lines.
func MoveHostBlock(source, destination *config.File, alias string) ([]config.Line, error) {
	if _, exists := FindHostBlock(destination, alias); exists {
		return nil, ErrDuplicateDestinationAlias
	}
	extracted, err := ExtractHostBlock(source, alias)
	if err != nil {
		return nil, err
	}
	AppendHostBlock(destination, extracted)
	return extracted, nil
}

// movedAliases lists the concrete aliases a moved block declares, so the caller
// can explain the reordering for every alias the move affects. Wildcards and
// negations are skipped because this engine never claims to resolve them.
func movedAliases(lines []config.Line) []string {
	block := &config.File{Lines: lines}
	var aliases []string
	for _, candidate := range block.Blocks() {
		if candidate.Kind != config.BlockHost {
			continue
		}
		for _, pattern := range candidate.Patterns {
			if pattern.Negated || pattern.Wildcard {
				continue
			}
			aliases = append(aliases, pattern.Value)
		}
	}
	return aliases
}
```

Add the notice code to `internal/application/notice.go`, next to the other codes:

```go
	// NoticeDestinationNotIncluded marks a destination file that no Include
	// reaches, so a block moved into it would stop being read by OpenSSH.
	NoticeDestinationNotIncluded = "destination_not_included"
```

- [ ] **Step 4: Run the move composition test to verify it passes**

Run: `go test ./internal/application -run 'TestMoveHostBlock|TestAppendHostBlock' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing service move test**

Append to `internal/application/service_test.go`:

```go
func TestSaveMoveCommitsBothFilesAndMetadataInOneTransaction(t *testing.T) {
	service, workspace := newTestService(t)
	const untouched = "Host work\n\tUser ops\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "20-work.conf"), []byte(untouched), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := NewMetadata()
	metadata.Hosts = []HostMetadata{{Identity: HostIdentity{Path: "config", Alias: "bastion"}, Note: "keep me"}}
	if _, err := service.Save(EditRequest{Kind: EditMetadata, Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}

	const homeConfig = "Host nas\n\tUser aida\t# personal\n"
	request := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "conf.d/10-home.conf",
		DestinationBase: homeConfig,
	}

	preview, err := service.Preview(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Diffs) != 3 {
		t.Fatalf("move preview diffs = %#v", preview.Diffs)
	}
	if len(preview.Effective) != 1 || preview.Effective[0].Alias != "bastion" {
		t.Fatalf("move preview effective = %#v", preview.Effective)
	}
	// Every explained value keeps its value and reports a new source. The three
	// moved directives now come from the destination; ServerAliveInterval still
	// comes from the entry file's Host * block, but its line moved up because
	// the block above it left, and the diff says so rather than hiding it.
	wantSource := map[string]string{
		"HostName":            "conf.d/10-home.conf",
		"Port":                "conf.d/10-home.conf",
		"User":                "conf.d/10-home.conf",
		"ServerAliveInterval": "config",
	}
	if len(preview.Effective[0].Changes) != len(wantSource) {
		t.Fatalf("effective changes = %#v", preview.Effective[0].Changes)
	}
	for _, change := range preview.Effective[0].Changes {
		if !equalStrings(change.Before, change.After) {
			t.Fatalf("moving a block must not change a value: %#v", change)
		}
		want, known := wantSource[change.Keyword]
		if !known {
			t.Fatalf("unexpected changed keyword: %#v", change)
		}
		if change.BeforeSources[0].Path != "config" || change.AfterSources[0].Path != want {
			t.Fatalf("%s source = %#v -> %#v, want it to end in %q", change.Keyword, change.BeforeSources[0], change.AfterSources[0], want)
		}
		if change.Keyword == "ServerAliveInterval" && change.BeforeSources[0].Line == change.AfterSources[0].Line {
			t.Fatal("the line shift caused by removing the block above must be visible")
		}
	}

	result, err := service.Save(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Written) != 3 {
		t.Fatalf("written = %#v", result.Written)
	}

	const wantSource = "# personal configuration\nInclude conf.d/*.conf\n\nHost *\n\tServerAliveInterval 30\n"
	if got := readFile(t, workspace, "config"); got != wantSource {
		t.Fatalf("source = %q", got)
	}
	wantDestination := homeConfig + "\nHost bastion\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 22\n\n"
	if got := readFile(t, workspace, "conf.d/10-home.conf"); got != wantDestination {
		t.Fatalf("destination = %q", got)
	}
	if got := readFile(t, workspace, "conf.d/20-work.conf"); got != untouched {
		t.Fatalf("an untouched file changed: %q", got)
	}

	stored, _, err := service.metadata.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Hosts) != 1 {
		t.Fatalf("stored hosts = %#v", stored.Hosts)
	}
	if stored.Hosts[0].Identity.Path != "conf.d/10-home.conf" || stored.Hosts[0].Note != "keep me" || stored.Hosts[0].Orphan {
		t.Fatalf("metadata after the move = %#v", stored.Hosts[0])
	}

	if _, err := service.HostDetail("conf.d/10-home.conf", "bastion"); err != nil {
		t.Fatalf("the moved host is not readable at its new path: %v", err)
	}
}

func TestSaveMoveRefusesADuplicateAliasAndANonEditableDestination(t *testing.T) {
	service, workspace := newTestService(t)
	const homeConfig = "Host nas\n\tUser aida\t# personal\n"

	duplicate := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "conf.d/10-home.conf",
		DestinationBase: homeConfig + "Host bastion\n\tUser other\n",
	}
	if _, err := service.Save(duplicate); !errors.Is(err, ErrDuplicateDestinationAlias) {
		t.Fatalf("duplicate alias error = %v", err)
	}

	outside := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "../.bashrc",
		DestinationBase: "",
	}
	if _, err := service.Save(outside); !errors.Is(err, ErrExternalPath) {
		t.Fatalf("outside destination error = %v", err)
	}

	same := EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "config",
		DestinationBase: serviceMainConfig,
	}
	if _, err := service.Save(same); !errors.Is(err, ErrSameFileMove) {
		t.Fatalf("same file error = %v", err)
	}

	if got := readFile(t, workspace, "config"); got != serviceMainConfig {
		t.Fatal("a refused move must write nothing")
	}
	if got := readFile(t, workspace, "conf.d/10-home.conf"); got != homeConfig {
		t.Fatal("a refused move must write nothing")
	}
}

func TestSaveMoveReportsAStaleDestinationBase(t *testing.T) {
	service, workspace := newTestService(t)
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "10-home.conf"), []byte("Host nas\n\tUser changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := service.Save(EditRequest{
		Kind:            EditMove,
		Path:            "config",
		Base:            serviceMainConfig,
		Alias:           "bastion",
		DestinationPath: "conf.d/10-home.conf",
		DestinationBase: "Host nas\n\tUser aida\t# personal\n",
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *ConflictError", err)
	}
	if conflict.Report.Path != "conf.d/10-home.conf" {
		t.Fatalf("conflict report = %#v", conflict.Report)
	}
	if got := readFile(t, workspace, "config"); got != serviceMainConfig {
		t.Fatal("a conflicting move must write nothing")
	}
}
```

- [ ] **Step 6: Run the service move test and verify it fails**

Run: `go test ./internal/application -run TestSaveMove -v`

Expected: FAIL with `undefined: EditMove`.

- [ ] **Step 7: Wire the move into the service**

In `internal/application/service.go`, add the kind and the two request fields:

```go
	EditMove       EditKind = "move"
```

```go
	// DestinationPath and DestinationBase describe the second file of a move.
	// DestinationBase carries the exact bytes the client loaded for it, so the
	// destination has the same precondition guarantee as the source.
	DestinationPath string `json:"destinationPath,omitempty"`
	DestinationBase string `json:"destinationBase,omitempty"`
```

Add the dispatch to `plan`:

```go
	case EditMove:
		return s.planMoveHost(graph, request)
```

Add the planner beside `planFileEdit`:

```go
// planMoveHost moves one host block into another file. Both configuration
// files and the metadata document are one storage.Request, so the move is a
// single journalled transaction: every precondition is checked before anything
// is staged, and a mismatch on either file writes nothing.
func (s *Service) planMoveHost(graph *config.Graph, request EditRequest) (planned, error) {
	root := s.workspace.Root()
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

	sourceBase := []byte(request.Base)
	destinationBase := []byte(request.DestinationBase)
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
	destinationDisk, destinationExists, err := s.readFile(destinationAbsolute)
	if err != nil {
		return planned{}, err
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

	if _, included := graph.Nodes[destinationAbsolute]; !included {
		prepared.preview.Notices = appendNotice(prepared.preview.Notices, Notice{
			Code:   NoticeDestinationNotIncluded,
			Path:   request.DestinationPath,
			Detail: request.Alias,
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
```

- [ ] **Step 8: Run the application suite and the race detector**

Run:

```bash
go test ./internal/application -v
go test -race ./internal/application
```

Expected: PASS. If `TestSaveMoveCommitsBothFiles...` reports two diffs instead of three, the metadata change was dropped from the transaction; the move must always carry it, because the host identity is `(path, alias)` and the path changed.

- [ ] **Step 9: Commit the move engine and use case**

```bash
git add internal/application/move.go internal/application/move_test.go \
  internal/application/notice.go internal/application/service.go internal/application/service_test.go
git commit -m "feat: move a host block between files in one transaction"
```

- [ ] **Step 10: Extend the OpenAPI contract and regenerate**

Add the two properties to the `EditRequest` schema in `api/openapi.yaml`, leaving every other property unchanged:

```yaml
        destinationPath: { type: string }
        destinationBase: { type: string }
```

Run:

```bash
make generate
go build ./...
npm run typecheck --prefix web
```

Expected: `internal/api/models.gen.go` and `web/src/api/schema.d.ts` both gain the optional fields; nothing else changes.

- [ ] **Step 11: Write the failing boundary validation test**

Add these cases to the table in `TestValidateEditRequestEnforcesEveryKindsRequirements` in `internal/httpserver/config_requests_test.go`:

```go
		{"valid move", application.EditRequest{
			Kind: application.EditMove, Path: "config", Base: "Host a\n", Alias: "a",
			DestinationPath: "conf.d/10-home.conf", DestinationBase: "",
		}, false},
		{"move without a destination", application.EditRequest{
			Kind: application.EditMove, Path: "config", Base: "Host a\n", Alias: "a",
		}, true},
		{"move to a traversal destination", application.EditRequest{
			Kind: application.EditMove, Path: "config", Base: "Host a\n", Alias: "a",
			DestinationPath: "../.bashrc",
		}, true},
		{"move without an alias", application.EditRequest{
			Kind: application.EditMove, Path: "config", Base: "Host a\n",
			DestinationPath: "conf.d/10-home.conf",
		}, true},
		{"move with an oversized destination base", application.EditRequest{
			Kind: application.EditMove, Path: "config", Base: "Host a\n", Alias: "a",
			DestinationPath: "conf.d/10-home.conf", DestinationBase: strings.Repeat("a", maxRawLength+1),
		}, true},
```

- [ ] **Step 12: Implement the boundary validation and error mapping**

In `internal/httpserver/config_requests.go`, bound the new field with the others:

```go
	if len(request.Raw) > maxRawLength || len(request.Base) > maxRawLength || len(request.DestinationBase) > maxRawLength {
		return errInvalidEdit
	}
```

Add `application.EditMove` to the kinds that require a source path:

```go
	case application.EditHostFields, application.EditBlockRaw, application.EditFileRaw, application.EditRename, application.EditMove:
		if err := validatePathParameter(request.Path); err != nil {
			return err
		}
```

Add the per-kind rule beside the others:

```go
	case application.EditMove:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		if err := validatePathParameter(request.DestinationPath); err != nil {
			return err
		}
```

Map the two new errors in `serviceProblem`: add `application.ErrSameFileMove` to the 400 `invalid_request` case, and `application.ErrDuplicateDestinationAlias` to the 422 `invalid_edit` case.

- [ ] **Step 13: Run the Go suite and commit the API surface**

Run:

```bash
go test ./...
go test -race ./...
```

Expected: PASS.

```bash
git add api/openapi.yaml internal/api/models.gen.go web/src/api/schema.d.ts \
  internal/httpserver/config_requests.go internal/httpserver/config_requests_test.go
git commit -m "feat: accept a host move over the local API"
```

- [ ] **Step 14: Write the failing UI move test**

Append to `web/src/connections/ConnectionsPage.test.tsx`:

```tsx
  it("moves a host to another file with both loaded bases", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      files: [
        { file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 },
        { file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }, editable: true, loads: 1 },
      ],
    } as never);
    vi.mocked(configApi.file).mockResolvedValue({
      file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" },
      contents: "Host nas\n\tUser aida\n", digest: "digest", editable: true, exists: true,
    } as never);
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1",
      written: ["config", "conf.d/10-home.conf"],
      preview: { operation: "config.move", diffs: [] },
    } as never);

    render(<ConnectionsPage />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    await user.selectOptions(await screen.findByLabelText("Move to file"), "conf.d/10-home.conf");
    await user.click(screen.getByRole("button", { name: "Move connection" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "move",
      path: "config",
      base: "Host bastion\n\tPort 22\n",
      alias: "bastion",
      destinationPath: "conf.d/10-home.conf",
      destinationBase: "Host nas\n\tUser aida\n",
    }));
  });
```

- [ ] **Step 15: Implement the move control**

In `web/src/connections/ConnectionsPage.tsx`, add the state and handler beside the other host actions:

```tsx
  const [moveTarget, setMoveTarget] = useState("");

  async function moveHost() {
    if (detail === null || selection === null || moveTarget === "") return;
    try {
      const destination = await configApi.file(moveTarget);
      const source = selection;
      await submit({
        kind: "move",
        path: source.path,
        base: detail.file.contents,
        alias: source.alias,
        destinationPath: moveTarget,
        destinationBase: destination.contents,
      }, false);
      setSelection({ path: moveTarget, alias: source.alias });
      setDetail(await configApi.host(moveTarget, source.alias));
      setMoveTarget("");
      setLocalError("");
    } catch (error) {
      setProblem(toProblem(error));
    }
  }
```

Render it next to the duplicate and delete buttons, offering only editable files other than the current one:

```tsx
              <label htmlFor="move-target" className="sr-only">Move to file</label>
              <select
                id="move-target"
                value={moveTarget}
                onChange={(event) => setMoveTarget(event.target.value)}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs"
              >
                <option value="">Move to file…</option>
                {overview.files
                  .filter((node) => node.editable && node.file.path !== undefined && node.file.path !== selection?.path)
                  .map((node) => (
                    <option key={node.file.absolute} value={node.file.path}>{node.file.path}</option>
                  ))}
              </select>
              <button type="button" onClick={() => void moveHost()} className="rounded border border-zinc-700 px-2 py-1 text-xs">
                Move connection
              </button>
```

The preview panel already renders the `destination_not_included` notice through
`NoticeList`; add its copy to `noticeCopy` in `web/src/connections/SavePreview.tsx`:

```ts
  destination_not_included: "No Include reaches this file yet, so OpenSSH will not read the moved connection until you add one.",
```

- [ ] **Step 16: Run the frontend suite and commit the move control**

Run:

```bash
npm test --prefix web
npm run typecheck --prefix web
```

Expected: PASS.

```bash
git add web/src/connections
git commit -m "feat: move a connection to another file from the UI"
```

- [ ] **Step 17: Re-run the subsystem verification**

Task 9 ran the full suite before the move existed, so run it again as the last
act of the subsystem:

```bash
go test ./...
go test -race ./...
make fuzz
npm test --prefix web
npm run typecheck --prefix web
npm run build --prefix web
go build -trimpath -o bin/sshc ./cmd/sshc
git diff --stat go.mod go.sum web/package.json web/package-lock.json
grep -rn "UserHomeDir" internal/ || echo "no internal package reads the home directory"
ls -la ~/.ssh/sshc 2>/dev/null || echo "no state directory in the real home"
```

Expected: every command succeeds, no dependency file changed, only
`cmd/sshc` reads the home directory, and the real `~/.ssh` gained no `sshc`
directory. Then work through the acceptance gate below.

---

## Connections UI Acceptance Gate

Before starting the key-vault plan, verify all of the following:

- `go test ./...`, `go test -race ./...`, `make fuzz`, `npm test --prefix web`, `npm run typecheck --prefix web` and `npm run build --prefix web` all pass.
- `go build -trimpath -o bin/sshc ./cmd/sshc` succeeds and the binary still serves the embedded UI.
- Loading a configuration, opening every tab and saving nothing leaves every file byte-for-byte unchanged.
- A form edit rewrites only the edited line: the trailing comment on that line, the surrounding comments, blank lines, indentation, `key=value` spelling and CRLF endings survive.
- An unknown directive is editable in the Advanced tab and in Raw, and is never reformatted or dropped.
- Creating, duplicating and deleting a connection rewrites only the block involved; every other byte of the file is preserved, and deleting the last block of a file is allowed and leaves an empty file rather than a broken one.
- Moving a host to another file commits the source, the destination and `metadata.json` as one journalled transaction; a stale base on either file writes nothing and names the file that changed.
- A moved block arrives byte-identical, including its inline and standalone comments, blank lines, indentation and any unstructured line; comments written above the `Host` header stay with the block above them, matching the ownership rule the projection and Raw editor already use.
- A move into a file that already declares the alias, into a file outside the resolved `~/.ssh`, or onto itself is refused and writes nothing.
- A move shows the before/after explained values for every concrete alias the block declares, so the reordering is visible even when no value changes — including the line shift the removal causes for the blocks below it — and warns when no `Include` reaches the destination.
- Every file in the Include graph other than the two the move touched is byte-identical afterwards.
- Tags, colour, note and favourite are editable, filter the tree, and never influence the generated configuration.
- Creating a new configuration file works, and the UI states that the file is only read once an `Include` points at it.
- A block Raw edit that contains zero or two `Host` headers is refused, and the file is unchanged.
- A whole-file Raw edit with unbalanced quoting is refused with a line and column, the editor keeps the text, and nothing is written.
- An edit that would introduce an Include cycle is refused; an Include problem that already existed does not block an unrelated save.
- Saving with a stale base returns a three-way conflict carrying both the external change and the pending change, and writes nothing.
- Group compilation writes `groups.sshc.conf` with child groups before parents, inserts the `Include` before the first catch-all block, and commits the generated file, the entry file and `metadata.json` in one transaction.
- The group preview shows the before/after explained values per member and labels them as not being `ssh -G`.
- A wildcard, negation, `Match` block or duplicate alias produces a `complex_external_rule` notice naming the real source instead of a fabricated inherited value.
- Renaming a host updates the `Host` line and the metadata entry in the same transaction; an entry whose target disappeared becomes an orphan and is never re-pointed.
- `metadata.json` contains only schema version, groups file, groups, tags, colour, note, favourite and order; a value carrying key material is refused.
- Every mutation requires the session cookie and the `X-SSHC-CSRF` header, every `/api/` response carries `Cache-Control: no-store`, and no CORS header is emitted.
- Problem responses carry a code, a workspace-relative path and a location — never file contents — and unknown JSON fields and oversized bodies are rejected at the boundary.
- Every response shape decodes into the generated `internal/api` models with `DisallowUnknownFields`, proving `api/openapi.yaml` is still the contract.
- The Include explorer shows external Includes as read-only, and no edit API accepts a path outside the resolved `~/.ssh`.
- An interrupted transaction is shown as unfinished with both recovery choices, and history restore commits the backup as a new, reversible transaction.
- `go.mod`, `go.sum`, `web/package.json` and `web/package-lock.json` are unchanged: this plan added no dependency.
- No automated test read or wrote the real `~/.ssh`, Keychain, ssh-agent, Terminal or a remote host, and only `cmd/sshc` calls `os.UserHomeDir`.
- Key management, `ssh -G`, ProxyJump diagnostics, Terminal launch, Known Hosts, remote key registration, packaging and E2E remain unimplemented and are recorded in this plan's Out of Scope section for their owning subsystems.
- `~/.ssh` file and folder move, rename and delete remain unimplemented, and the Out of Scope section names the four missing `storage` primitives and the `sshc-file-operations` follow-up plan that owns them. They are not parked in subsystem 6.
