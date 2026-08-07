# sshc Directory Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a group a real place on disk instead of a field in `metadata.json`. A group becomes a directory under `~/.ssh/connections/`, its keys a directory under `~/.ssh/keys/`, and the entry file gains one generated `Include` line per group so precedence is written down rather than inferred from glob order. Moving a host between groups becomes moving its file; moving a key rewrites the `IdentityFile` lines that name it, in the same transaction, or refuses. `metadata.json` stops carrying group membership.

**Architecture:** No new package. `internal/application` gains the group-path vocabulary (`grouppath.go`), the generated Include region (`region.go`, replacing `PlanGroupInclude`) and the key-move use case (`keymove.go`), which is the one place where a configuration rewrite and a key file move belong to the same `storage.Request`. `internal/keys` keeps ownership of what a key is and lends `BuildReferenceIndex`; the import direction `application → keys` is new and acyclic (`go list -deps ./internal/keys` contains no `sshc/internal/application`). Every write still goes through the single `storage.Manager` that `application.NewService` installs its `Validate` hook on, so nothing reaches disk without a re-parse and a re-resolve. `storage` gains nothing: `Move`, `Removal` and `Request{Changes, Moves, Removals}` already exist and are already proven by `internal/keys/trash.go`.

**Tech Stack:** Go 1.26.5 (standard library plus the already-committed `golang.org/x/crypto v0.54.0`), Echo v5.3.1, oapi-codegen v2.7.0, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, Playwright 1.62.1, OpenSSH 10.2p1 (the installed client; never invoked by an automated test except the existing `ssh -G -F` differential).

**A note on the level of detail.** The five delivered plans transcribe every test body. This one names each test, states exactly what it must assert and why, and transcribes code only where the exact shape is load-bearing — the Include region, the overlay that models a move, the key-move request, the metadata schema step. Everything else is specified precisely enough that two people would write the same test. That is a deliberate trade: this plan is long because the reasoning is long, and padding it with transcribed table tests would bury the parts that decide whether the feature is safe.

## Global Constraints

- macOS only. The server binds `127.0.0.1` on an OS-assigned port. No CORS, no LaunchAgent.
- Every mutation carries `X-SSHC-CSRF`; every `/api/` response keeps `Cache-Control: no-store`; every `/api/` request is checked for `Host`, `Origin` and Fetch Metadata by exact match, including GET (subsystem 6 Task 1).
- **Add no new npm or Go dependency.** `go.mod`, `go.sum`, `web/package.json` and `web/package-lock.json` must be byte-identical when the plan completes.
- Echo v5 handler signature is `func(c *echo.Context) error`. Do not write Echo v4 code.
- Automated tests must never touch the real `~/.ssh`, Keychain, ssh-agent, Terminal or a remote host. `t.TempDir()`, map-backed fakes and injected clocks only. `os.UserHomeDir` may be called only from `cmd/sshc`.
- The lossless guarantee survives every path added here. An `IdentityFile` rewrite changes the value arguments of one line and nothing else: indent, separator, trailing comment and line ending are preserved by `rebuildLine`, which already does exactly this for form edits.
- `api/openapi.yaml` is the contract. Add the schema there first, run `make generate`, keep to the subset `api/README.md` validates: objects, strings, integers, booleans, arrays, `const`, `required`, `$ref`. No `oneOf`, no `anyOf`, no `enum`.
- Never log request bodies, cookies, tokens, file contents, configuration text or absolute paths. Problem responses carry a stable code, a workspace-relative path and a location.
- New logging goes through the injected `slog.Logger`, never the global default — `TestNoLogLineCarriesASecret` only reads the injected one.
- Managed directories are `0700` (`storage.DirectoryPermission`), managed files `0600` (`storage.FilePermission`); a stricter existing permission is never relaxed.
- Rebuild `internal/ui/dist` in any change that touches `web/src`. `make build` embeds whatever is committed.

### A note on drift

This plan was written against the tree as it stands, and the tree is not clean. `git status` shows six uncommitted files: `web/src/i18n/messages.ts` and five components being converted to it. Every Go fact in this plan was read from files that are unmodified, and every line number quoted for Go code is a `main` line number. The frontend facts are not: the one that matters — the false statement in `ConfigExplorer.tsx` — is present on `main` and already deleted in the working copy. Task 11 says so explicitly. Anyone executing this plan should run `git status` first and reconcile rather than assuming either state.

---

## 1. Why a directory beats a metadata field

Today a group exists in exactly one place: `metadata.json`. `HostMetadata.Group` names it, `GroupMetadata.Parent` gives it a hierarchy, and `application.CompileGroups` regenerates the whole of `groups.sshc.conf` from that on every save. The generated file names the group only in a comment (`groups.go` line 152, `"# group " + group.Name`); the `Host` line lists member aliases. Nothing else on disk records that `web-1` and `web-2` are both "work".

That has one consequence worth the whole change: delete `~/.ssh/sshc/` and the grouping is gone. The configuration still works — that is the point of compiling groups into ordinary `Host` blocks — but the organisation the user built is an annotation on the side, in a format only this application reads. Design §2.3 rules out making an app-specific format the source of truth for SSH configuration, and today's grouping obeys that rule by being *not* the source of truth for anything. It is the source of truth only for itself.

A directory is different in kind. `~/.ssh/connections/work/web-1.conf` is an ordinary configuration file in an ordinary directory. `mv`, `ls`, `find`, `git`, another editor and a shell script all understand it. `Include connections/work/*.conf` is an ordinary OpenSSH directive. Uninstall this application and the layout survives, the Include lines survive, `ssh web-1` keeps working, and a human reading `~/.ssh` can see the grouping without being told what a `groups[]` array means.

The second reason is precedence. OpenSSH keeps the **first** value it reads. With a single wildcard Include the reading order is the glob's lexical order, which means group precedence would be alphabetical — an accident. Worse, `connections/*/*.conf` cannot reach a nested group at all: neither `filepath.Glob` (used by `storage.OSFileSystem.Glob`) nor OpenSSH's `glob(3)` lets `*` cross a `/`. One Include line per group, emitted in a stated order, turns precedence into something written down in the file the user can read.

## 2. The tension with design §2.3, stated honestly

Design §2.3 lists, among the things the initial version will not do:

> アプリ独自形式を SSH 設定の正本にすること

Does a directory convention cross that line? Partly. The honest answer has three parts.

**What does not cross it.** Every artefact this change produces is ordinary OpenSSH. The files under `connections/` are `ssh_config`. The Include lines are `Include`. The group settings still compile into ordinary `Host` blocks in `groups.sshc.conf`, as §5.4 and §13 already require ("UI のグループは標準 Host ブロックと順序へコンパイルし"). Nothing needs this application to be installed in order to be read, and design §6.2 already promises file and folder creation, move and rename inside `~/.ssh`, so arranging files is squarely inside the accepted scope.

**What does cross it.** OpenSSH does not know that `connections/work/` is a group. It knows only that a line says to read those files at that point. The *meaning* of the directory is this application's convention, and a second tool reading `~/.ssh` would see a tree with no declaration of what it means. Today, deleting `metadata.json` loses an annotation and breaks nothing. After this change, flattening the directories by hand loses the grouping *and* breaks the configuration unless the Include lines are fixed too. The failure mode moves from "lose a label" to "break the config if you reorganise carelessly". Calling that a non-issue would be dishonest.

**How the tension is reduced rather than denied.** The set of groups is not inferred from the filesystem. It is declared, in ordinary OpenSSH syntax, by the generated Include region in `~/.ssh/config`:

```
# >>> sshc groups (generated). Child groups first: OpenSSH keeps the first value it reads.
# Edit through the UI; lines between these markers are replaced on the next save.
Include connections/work/eu/*.conf
Include connections/work/*.conf
Include connections/home/*.conf
Include groups.sshc.conf
# <<< sshc groups
```

The group names are in the file, in plain text, in the order that decides precedence. A directory under `connections/` with no Include line is **not** a group; it is reported as `group_not_declared` and left alone. This matters concretely: `~/.ssh/keys/` is a layout many people already have, and inferring group membership from a directory that happens to exist would silently relabel a stranger's files. Declaration removes the guessing while keeping membership itself a fact about where the file sits — because the Include glob is literally what makes it so.

This refines the settled decision rather than contradicting it. The directory remains the source of truth for *which group a host is in*. The entry file's Include region is the source of truth for *which groups exist and in what order*. Neither is `metadata.json`, which is what decision 4 asks for, and both are ordinary OpenSSH.

**What the design document would have to say instead.** §2.3 keeps its bullet unchanged — an app-specific *format* is still out of scope. §4.2 gains one sentence naming the directory layout and the Include region as the source of truth for grouping, and reduces metadata to presentation. §5.4 gains the layout and the ordering rule. §13 gains a fourth answer, "ディレクトリ規約は独自形式か", carrying the three paragraphs above. Exact wording is in section 12 of this plan.

## 3. The layout

```text
~/.ssh/
├── config                              # entry file; carries the generated Include region
├── connections/
│   ├── work/
│   │   ├── web-1.conf                  # ordinary ssh_config, one or more Host blocks
│   │   └── eu/                         # nested group "work/eu"
│   │       └── lon-1.conf
│   └── home/
│       └── nas.conf
├── keys/
│   ├── work/
│   │   ├── id_ed25519
│   │   └── id_ed25519.pub
│   └── home/
├── groups.sshc.conf                  # generated group-settings blocks (unchanged location)
├── id_ed25519                          # ungrouped key
├── conf.d/10-legacy.conf               # ungrouped: whatever the user already had
└── sshc/                             # engine state; never scanned, never a group
```

- A group name is its slash-separated path under `connections/`: `work`, `work/eu`. The parent is the parent directory. `GroupMetadata.Parent` disappears because the name already contains it.
- `keys/<group>/` mirrors a declared connection group. It is created on demand, never speculatively.
- A `.conf` file directly under `connections/` belongs to no group. No Include is generated for it, so nothing reads it; the UI reports `group_file_unreached` naming the file. That is deliberate: inventing a fourth precedence tier for "managed but ungrouped" would make the ordering rule harder to state than it is worth, and the ungrouped case already has a home — the root of `~/.ssh` and whatever Includes the user already wrote.
- Directory permission is `storage.DirectoryPermission` (`0700`), applied by `Workspace.EnsureDirectory`, which also refuses to traverse a symbolic link. A user who symlinks `connections/work` elsewhere gets `storage.ErrSymlinkPath`, mapped to `403 path_not_editable` by `serviceProblem`. That is correct and must not be softened.

## 4. The Include ordering rule, spelled out

OpenSSH keeps the first value it reads for a given keyword and a matching `Host`. Design §5.4 turns that into the display priority: individual Host, child group, parent group, global default. On disk that means the reading order must be:

1. **The user's own material above the region.** Anything they wrote before the insertion point — their own `Host` blocks, their own `Include` lines — is read first and keeps winning. This plan never reorders a line the user wrote.
2. **The per-group Includes, deepest group first.** `connections/work/eu/*.conf` before `connections/work/*.conf` before `connections/home/*.conf`. Groups at equal depth are ordered by `GroupMetadata.Order`, then by name, reusing the comparator `GroupDepthOrder` already implements for the settings file.
3. **`Include groups.sshc.conf`.** The generated settings blocks must be read *after* every concrete host block, otherwise a group setting would beat the host's own value. Inside that file `CompileGroups` already emits child groups before parents, and that stays.
4. **The user's catch-all.** The first `Host` block containing an exact `*` pattern, or the first `Match` block, whichever comes first — the position `PlanGroupInclude` already computes. The region is inserted immediately before it. With no catch-all and no `Match`, the region is appended at the end of the file.

**Why child before parent among the connections Includes.** For concrete host blocks it is not a semantic necessity: a host file sits in exactly one directory, so no alias is normally reachable from two group Includes. It matters in exactly one case — the same alias declared in two group directories — and there the deeper group wins, which is the same rule the settings file uses, so a user does not have to hold two different precedence rules in their head. `HostEntry.Duplicate` already marks that case and the UI already shows it; the ordering makes the outcome deterministic instead of alphabetical.

**Where nested groups get their Include.** Every declared group gets its own line. `connections/work/*.conf` does not match `connections/work/eu/lon-1.conf`, because `*` does not cross a separator in `filepath.Glob` or in `glob(3)`. This is the whole reason the brief asks for one line per group rather than one wildcard, and it must be asserted by a test rather than assumed.

**An empty group.** `Include connections/work/*.conf` matching nothing produces `config.DiagnosticIncludeNoMatch`, severity warning (`graph.go` line 160). The application must not suppress it. It maps the diagnostic on a generated group Include to the notice `group_empty` and shows it as "group work has no connections yet". Hiding a real diagnostic because we generated the line that caused it is exactly the kind of convenience this codebase refuses elsewhere.

### What happens when the user's config already has its own ordering

This is where a generated insertion can silently change behaviour, so each case gets a stated answer and a refusal rather than a guess.

- **Catch-all at the end (the common case).** The region lands after every concrete block and before `Host *`. Nothing the user wrote changes meaning. Proceed.
- **Catch-all at the top.** Some configurations open with `Host *`, which in OpenSSH means those defaults win over everything below — usually not what the author intended, but it is what they wrote. `PlanGroupInclude` would insert at line 0, putting the group Includes *before* the user's own concrete blocks, so any alias declared both by hand and in a group directory would flip its winner. **Refuse.** If any `Host` block with a concrete (non-wildcard, non-negated) pattern appears after the computed insertion point, answer `422 include_position_ambiguous` carrying both candidate positions and, for every alias declared in both places, the before/after explained values from `DiffEffective`. The user picks a position; the application does not.
- **An early `Match` block.** Same rule, same refusal. `PlanGroupInclude` already stops at the first `Match`, and the same "concrete Host block after the insertion point" test applies.
- **The user already includes the connections tree by hand.** If any existing Include edge in the graph resolves to a file under `connections/`, the generated region would read those files a second time. OpenSSH would apply the first read and the graph would report `include_duplicate`. **Refuse** with `group_include_already_present`, naming the file and line of the existing Include, and offer to replace that line with the region. Detectable directly from `graph.Nodes[path].Includes[].Matches`.
- **`Host *.internal` at the top.** Not a catch-all by `PlanGroupInclude`'s test (it looks for an exact `*`), and not one by OpenSSH's either — but it does win for every matching alias, and the region will be inserted below it. That is the correct outcome and it needs no refusal; it is recorded here because it is the case where the heuristic and the truth agree by luck rather than by design, and a reader should know the heuristic is `pattern == "*"` and nothing more.
- **The markers were edited or half-deleted.** The region is located by its two marker comments. Both present: replace the lines between them. Neither present: insert fresh at the computed position. Exactly one present: **refuse** with `generated_region_damaged`. Repairing a half-marked region means guessing where it ended.
- **A conditional `Include groups.sshc.conf`.** See section 6 — this is a defect in the current code, found while planning, and the region logic must not inherit it.

## 5. Host identity, and why nothing is orphaned

A host's identity in this application is `application.HostIdentity{Path, Alias}` — the workspace-relative path of the file plus the concrete primary alias declared in it (design §4.2, `metadata.go` lines 39-56). A group is now a directory, so **changing a host's group changes its path, and therefore changes its identity.** That is not a problem to work around; it is the mechanism.

The existing move path already handles it. `Service.planMoveHost` (`service.go` lines 530-656) builds one `storage.Request` containing the source file, the destination file and `metadata.json`, and at line 591 calls:

```go
relocated := RenameHostIdentity(stored,
    HostIdentity{Path: request.Path, Alias: request.Alias},
    HostIdentity{Path: request.DestinationPath, Alias: request.Alias},
)
```

`RenameHostIdentity` replaces `Identity` and clears `Orphan`, keeping the rest of the `HostMetadata` struct, so colour, tags, note, favourite and order travel with the host. Because the identity change and the file change are entries in the same journalled transaction, there is no moment at which metadata names an identity the graph does not project — except an interrupted transaction, which `Manager.Pending` reports and `Rollback` reverses (it restores a written file from its generational backup and renames a moved file back; `journal.go` lines 135-148).

`ReconcileMetadata` marks an entry orphan when its identity is absent from the identities `ProjectHosts` currently yields. It never re-points an entry at a different host. That behaviour is unchanged and is exactly what should happen when the user moves a file with `mv` instead of through the UI: the entry becomes an orphan and the existing orphan panel asks them to re-associate it. This plan does not try to be cleverer than that.

**One genuine gap.** `RenameHostIdentity` matches on an exact `{Path, Alias}` pair. Moving a *file* into a group directory — which is what a group rename and the migration do — changes the path of every alias declared in that file. A new function is needed:

```go
// RelocateHostIdentities rewrites the path of every entry whose identity names
// fromPath, keeping the alias. It is the file-level counterpart of
// RenameHostIdentity, which moves exactly one identity.
func RelocateHostIdentities(metadata Metadata, fromPath, toPath string) Metadata
```

It must not touch an entry whose path merely has `fromPath` as a prefix unless the move is a directory move, in which case the caller passes each file individually. Guessing at prefixes is how a "work" rename would eat "workshop".

## 6. Defects and gaps found while planning, confirmed against the tree

Recorded here so they cannot be lost between plans, in the roadmap's convention.

- **`PlanGroupInclude` treats a conditional Include as a top-level one.** `groups.go` lines 189-222 scan every line of the entry file and return `(-1, true)` when any `Include` argument equals the groups file, without consulting `File.Condition(File.BlockAt(index))`. An `Include groups.sshc.conf` written inside a `Host bastion` block therefore counts as present, so no top-level Include is ever inserted and the generated settings file is read only when connecting to `bastion`. The graph already reports `include_conditional` as a warning, so the symptom is visible, but the planner should not have been fooled. The region logic in Task 3 must count only an Include whose governing block is the global block. **Owned by this plan, Task 3.**
- **`overlayLoader` cannot model a move or a removal.** `validate.go` lines 43-78 overlays pending *contents* and its `Glob` only *adds* pending paths. `Service.validate` builds the overlay from `request.Changes` alone (line 132). A transaction containing a `storage.Move` or a `storage.Removal` is therefore validated and previewed against a world where the file is in two places at once — or still in the old one. Nothing exercises this today because `Service.Save` commits `storage.Request{Operation, Changes}` and nothing else (line 385): the application layer has never issued a move. It must before any file-level move is previewed. **Owned by this plan, Task 4, and it blocks Tasks 5, 8 and 10.**
- **`Service.Save` cannot commit a move at all.** The `planned` struct carries `changes` only. Extending it with `moves` and `removals`, and passing them to `Commit`, is a precondition for everything in this plan that relocates a file. **Owned by this plan, Task 4.**
- **Directory creation is not journalled.** `Workspace.ResolveForWrite` returns `ErrMissingDirectory` when a parent does not exist (`workspace.go` line 89), and `Manager.Commit` calls `EnsureDirectory` only for its own journal, history and backup directories. Creating `connections/work/` therefore happens *before* `Commit`, outside the journal — the same shape `keys.Trash` already uses for its entry directory (`trash.go` line 140) and `keys.Restore` for a restore target (line 373). A crash between the `mkdir` and the commit leaves an empty group directory. It is harmless — an Include matching nothing is one warning — but "a rejected save leaves the disk untouched" becomes "a rejected save leaves the disk untouched except possibly for an empty directory", and the acceptance gate must say so. Item (3) of the connections plan's four missing primitives, journalled directory create and remove, is still open and this plan does not close it.
- **`web/src/explorer/ConfigExplorer.tsx` line 189 is false on `main`.** It tells the user that moving, renaming and deleting files "needs journalled delete and rename primitives this version does not have yet". `storage.Move`, `storage.Removal` and `Request.Moves`/`Request.Removals` were delivered by subsystem 4 and are in production use in `internal/keys/trash.go` for trash, restore and purge. What is actually missing is journalled *directory* create, remove and rename, plus a Config Explorer interface.

  Found while checking this: the working tree carries an **uncommitted** i18n refactor (`web/src/i18n/messages.ts`, plus five modified components) that has already deleted the sentence — `explorer.newFileNote` now ends at "Add that line in the entry file below." in both locales. So the false statement is on `main` and gone in the working copy. Whoever executes this plan must check which state the tree is in rather than trusting either. **Corrected in Task 11, in whichever form is present.**
- **`README.md` line 68 is already false, in two ways.** "ファイルとフォルダの移動・改名・削除はまだ提供していません。`storage` に journal 付きの削除・改名プリミティブが必要で" — the primitives exist. "Host ブロックの別ファイルへの移動も同様に後続タスクです" — moving a Host block between files shipped with the connections subsystem (Task 10 of that plan; the roadmap records it at status line 18) and `Service.planMoveHost` implements it. This is stale documentation on `main` today, independent of this plan. **Corrected in Task 12.**
- **`keys.maxScanDepth` bounds how deep a key group can nest.** `inventory.go` line 56 sets it to 8, counted from `~/.ssh`. `keys/` is level 1, so a key more than seven group segments deep is reported as `depth_exceeded` and vanishes from the inventory rather than being listed. Nobody will nest seven groups, but the limit is real and the group-segment validator should refuse a path that would exceed it rather than let the inventory quietly drop the file.

### Corrections to the facts in the brief

Verified by reading, as instructed. Two corrections, neither material:

- The key-reference type is `keys.Reference{Directive, ConfigPath, Line, Condition, HostPatterns, Value}` in `internal/keys/references.go`, not `KeyReference`. `KeyReference` is the *wire* name — the OpenAPI schema in `api/openapi.yaml` and the generated `api.KeyReference` in `internal/api/models.gen.go`, mapped in `internal/httpserver/keys.go`. The substance of the claim holds: the six fields are exactly what an `IdentityFile` rewrite needs, and `Reference.ConfigPath` is what makes the "reference lives outside `~/.ssh`" refusal decidable.
- `internal/application/groups.go` regenerates `groups.sshc.conf` from metadata on every save, as stated — but only on an `EditGroups` save (`service.go` line 697 returns early for `EditMetadata`). A tags-or-colour-only edit does not rewrite the generated file. That is correct behaviour and the plan preserves it.

Everything else in the brief checked out: `storage.Move`/`Removal`/`Request` with journalling, generational backups and `ErrIrreversibleRemoval` (`transaction.go` lines 34-94, 251-313); `internal/keys/trash.go` using them for trash, restore and purge; `service.go` line 591 relocating the metadata entry through `RenameHostIdentity` in the same transaction; `config/include.go` `expandPattern` producing an absolute glob and `graph.go` line 152 delegating to `Loader.Glob`, so `connections/<group>/*.conf` needs no engine change; `ConfigExplorer.tsx` line 189 carrying the false statement.

One fact the brief asserts that this repository can only half-confirm: the macOS Keychain entry is keyed by absolute path as `SSH: <path>`. Nothing in this tree reads or writes the Keychain — `ssh-add --apple-use-keychain` is the only Keychain path (`internal/platform/macos/keyagent.go` lines 77-79), and there is no use of `security(1)` anywhere. The `SSH: <path>` naming is already recorded in `docs/manual-acceptance.md` M3 step 4 as the manual check (`security find-generic-password -s "SSH: <path>"`), so the claim is documented in the repository but is not, and cannot be, verified by any automated test here. The warning this plan shows must therefore say that the application cannot check the Keychain entry, only warn about it.

## 7. Moving a key

### The transaction

One `storage.Request`, committed through the **configuration** service's `storage.Manager` — the one `application.NewService` installs `Validate` on — not the key vault's second manager. The reason is stated in `internal/app/run.go` lines 56-66: the key vault has its own manager precisely because its writes are not configuration and would be rejected as syntax errors. A key move is the inverse case. Its dangerous half is a configuration rewrite that must be re-parsed and re-resolved before a byte lands; its key half is a `Move`, and `Service.validate` inspects `request.Changes` only, so a private key travelling as a `Move` is never parsed as configuration.

```go
storage.Request{
    Operation: "key.move",
    Changes: []storage.Change{
        // one per rewritten configuration file, Precondition = digest of the
        // bytes the preview was computed from
    },
    Moves: []storage.Move{
        // the private key, its .pub and its certificate, each with the digest
        // read at plan time; rename(2) copies no bytes and keeps the mode
    },
    // Removals: never. A Removal makes the transaction irreversible
    // (ErrIrreversibleRemoval); a move must stay undoable.
}
```

`Commit` applies Changes, then Moves, then Removals. There is therefore a window — two `rename(2)` calls wide — in which the configuration names the new path and the key has not arrived. The reverse order would produce an equally broken intermediate state, and the order is not configurable, so the honest statement is: the window exists, it is bounded by two renames, the journal records both entries, `Pending` reports the transaction, `Complete` finishes it and `Rollback` reverses it. Unlike a passphrase change (`SkipBackup`) or a purge (`Removal`), a key move is fully reversible: `Rollback` renames a committed `Move` back (`journal.go` lines 137-147) and restores a written configuration file from its generational backup.

Which files move: the fingerprint-derived group from `Inventory.Group(item)` — the private key plus every public key with the same fingerprint and every certificate whose `SignedKeyFingerprint` matches. Membership by name is never used; that rule already exists for trash and the same reasoning applies. When the private key is encrypted and its fingerprint is unavailable (`NoteFingerprintUnavailable`), the group is the key alone and the preview lists what stays behind, reusing the shape of `skippedSiblings`.

### What the preview shows

Every one of these, before anything is written:

- **Each file that moves**, as workspace-relative from → to, with its permission, and the statement that `rename(2)` preserves the mode exactly.
- **Each configuration line that changes**: the configuration file's workspace-relative path, the 1-based line number, the current text of the line, the text it becomes, the `Host` patterns of the governing block and its `Match` condition if any. Every field comes straight from `keys.Reference`. The user sees which hosts are affected, not just which files.
- **A `FileDiff` per touched configuration file**, built with the existing `BuildFileDiff`, so a key move's preview looks like every other save preview and the same `SavePreview` component renders it.
- **The Keychain warning**, unconditionally, naming the absolute source path in the form `SSH: <path>` and stating three things: the login Keychain entry is keyed by the old absolute path; this application does not read or write the Keychain and cannot check whether an entry exists or repair it; after the move, re-register the key from the Keys screen (which runs `ssh-add --apple-use-keychain`) and delete the stale entry by hand.
- **The agent note.** An identity already loaded into `ssh-agent` keeps working until the agent forgets it; only a re-add needs the new path. `Inventory.AgentDelegations` and the agent identity list already exist on the Keys screen, so if the key's fingerprint is currently loaded, say so.
- **The scope note.** The rewrite covers the `IdentityFile` and `CertificateFile` directives the Include graph from `~/.ssh/config` reaches, and nothing else. It does not cover `ssh -i` in a shell alias, `core.sshCommand` in `~/.gitconfig`, `rsync -e`, a LaunchAgent, `/etc/ssh/ssh_config`, or a second configuration invoked with `ssh -F`. This is not a hedge; it is the boundary of what a configuration reader can know, and the user is the only one who can check the rest.

### The refusals

Each refuses the whole transaction and writes nothing.

| Code | Condition | Why refuse rather than proceed |
|---|---|---|
| `key_reference_outside_workspace` | Any `Reference` for a moved file whose `ConfigPath` is not inside `Workspace.Contains` | Design §2.3 and §5.3 forbid writing outside `~/.ssh`. Proceeding would move the key and leave that file naming a path that no longer exists — a half-applied move. This is settled decision 1. |
| `key_reference_unresolved` | An `UnresolvedReference` for `IdentityFile` or `CertificateFile` exists whose final path segment equals the base name of a file being moved | `keys.expandKeyPath` refuses to guess a relative path (`ReasonRelativePath`) or an unknown token (`ReasonUnsupportedToken`), so such a directive is never indexed and cannot be rewritten. The engine cannot prove it does *not* name the moved key. See the open question — the base-name test is a proposal, not a settled rule. |
| `key_destination_is_config` | After the move, the destination path would be matched by an Include glob in the graph | A private key read as `ssh_config` is the worst outcome available. Checked by re-resolving with the destination overlaid and asserting it is absent from `graph.Nodes`. |
| `key_destination_occupied` | The target path exists | `Commit` would answer `ErrMoveTargetExists` anyway; refusing early gives a named reason and a preview that says so. |
| `key_group_not_declared` | The destination group has no Include line in the generated region | A key group mirrors a connection group. Creating `keys/marketing/` for a group that does not exist would be the inference this plan avoids. |
| `key_in_state_directory` | Source or destination is under `~/.ssh/sshc/` | Trash, backups and journal are engine state. The inventory already excludes them; this is defence in depth. |
| `config_conflict` | Any configuration file's digest changed since the preview | The existing precondition machinery, unchanged. |
| `action_token_invalid` | The evidence digest recomputed at spend time differs from the one at issue time | The confirmation authorises exactly the change the dialog displayed. |

The operation requires a one-time action token, kind `key.move`, added to `session.knownActionKinds` alongside the ten existing kinds. The evidence is a digest over: the moved files' relative paths and digests, the destination paths, and for each rewritten line the configuration path, line number and current line text. If any of that changes between the confirmation and the request, the token stops matching — the same construction `keys.revealEvidence` and `purgeEvidence` already use.

## 8. Renaming a group

A group name is a directory path, so a rename is:

1. `EnsureDirectory(connections/<new>)`, and `connections/<new>/<child>` for every nested group, before the transaction.
2. One `storage.Move` per `.conf` file under `connections/<old>`, recursively, into the mirrored path under `connections/<new>`.
3. One `storage.Move` per file under `keys/<old>`, if that directory exists, into `keys/<new>`.
4. One `storage.Change` per configuration file containing an `IdentityFile` or `CertificateFile` that resolves under `keys/<old>`, with the value rewritten — the same rewrite the key move uses, and the same refusals.
5. One `storage.Change` for `~/.ssh/config`, regenerating the Include region so every line naming `<old>` names `<new>`, in the same order.
6. One `storage.Change` for `metadata.json`: `GroupMetadata.Name` for the group and every descendant (the name contains the path), and `RelocateHostIdentities` for every moved file.
7. One `storage.Change` for `groups.sshc.conf`, since `CompileGroups` keys its comment on the group name.

All in one `storage.Request`. Every precondition is checked before anything is staged, so a stale file anywhere writes nothing.

**Directories are not renamed; their files are.** `storage.Move` moves files. `Workspace.ResolveForWrite` refuses a final component that exists and is not a regular file (`ErrNotRegularFile`), and `Manager.sourceState` hashes the source, which a directory has no answer for. A journalled directory rename would need its own journal action, its own precondition semantics and its own rollback story — a storage-layer design decision, not a group-feature one. This plan therefore does N file moves, exactly as `keys.Restore` already does, and inherits its consequence, stated in that function's own comment: *the empty entry directory is left behind, because the transaction manager owns files, not directories.*

So after a rename, `connections/<old>/` remains as an empty directory. Nothing points at it — the Include line was rewritten in the same transaction — so it is inert. The UI reports it as `group_directory_leftover` and tells the user they can remove it with `rmdir`. This plan does not delete directories, because an unjournalled `rmdir` is a filesystem effect with no recovery record, and adding one would be the fifth primitive the connections plan listed and nobody has designed. A single atomic `rename(2)` on the directory would be strictly better than N file renames and should be built eventually; it is recorded as the named follow-up `sshc-file-operations`, whose remaining scope is now exactly: journalled directory create, journalled directory remove, journalled directory rename, and the Config Explorer interface.

**Deleting a group** is the same shape with the destination being the workspace root or another group, plus removing the Include line. A group whose files would be deleted rather than relocated is not offered: the trash is for keys, and there is no config trash. The UI offers "move these connections to <group> and remove the group", never "delete the group".

## 9. Migration

Explicit, previewable, opt-in. Never automatic. Nothing in this plan reorganises an existing layout at startup, on first load, or as a side effect of any other save. A workspace with no `connections/` directory and no generated region behaves exactly as it does today, and the application emits no group Include for it.

`POST /api/v1/config/migration/preview` and `POST /api/v1/config/migration/apply`, the latter guarded by an action token of kind `config.migrate` whose evidence is a digest of the whole proposed plan.

The proposal is deliberately conservative. It **moves whole files, never splits one**:

- For each file in the Include graph, inside `~/.ssh`, whose hosts all carry the same `HostMetadata.Group`: propose a `Move` to `connections/<group>/<base name>`.
- List every file it will not touch, with a reason: `mixed_groups` (its hosts belong to more than one), `external_file` (outside `~/.ssh`, read-only by §5.3), `no_group` (nothing to do), `entry_file` (`config` itself is never moved), `wildcard_only` (the block declares no concrete alias). The user moves those hosts one at a time afterwards with the move-host operation that already exists.
- Propose the generated Include region, subject to every refusal in section 4.
- Propose the metadata rewrite: schema version 2, `hosts[].group` and `groups[].parent` dropped, `RelocateHostIdentities` applied per moved file, group names rewritten to their directory paths.

Keys are a **separate** migration, run separately, for a stated reason: the key half can be refused for causes the configuration half cannot (a reference outside `~/.ssh`, an unresolvable `IdentityFile`), and a refusal on one key must not block the configuration migration. Two operations, two previews, two confirmations.

Everything in the preview is reversible in the ordinary way: one journalled transaction, generational backups for every rewritten file, `Rollback` available because the request contains no `Removal`.

---

## Out of Scope

- Journalled directory create, remove and rename — still `sshc-file-operations`. This plan creates directories outside the journal, as `keys.Trash` and `keys.Restore` already do, and states the consequence.
- A file trash for configuration files. Keys have a trash; configuration files do not, and this plan does not build one. Group deletion relocates, it does not delete.
- Reading group membership back out of a hand-edited `groups.sshc.conf`. That file stays generated output, as its own header comment says.
- Making `connections` and `keys` configurable the way `metadata.GroupsFile` is. Two conventional names, fixed. Whether they should be configurable is an open question at the end.
- Any change to `ssh -G` evaluation, diagnostics, Terminal launch, Known Hosts or remote registration.
- Multiple groups per host. Design §5.4's single primary group is unchanged and is now enforced by the filesystem: a file sits in one directory.

---

## File Structure

```text
api/
└── openapi.yaml                          # + group, key-move and migration schemas and routes
internal/
├── application/
│   ├── grouppath.go                      # NEW group name/path vocabulary, validation, ordering
│   ├── grouppath_test.go                 # NEW
│   ├── region.go                          # NEW generated Include region; replaces PlanGroupInclude
│   ├── region_test.go                     # NEW
│   ├── keymove.go                         # NEW key move planning, refusals, preview
│   ├── keymove_test.go                    # NEW
│   ├── migrate.go                         # NEW opt-in migration proposal
│   ├── migrate_test.go                    # NEW
│   ├── groups.go                          # hierarchy from paths; PlanGroupInclude removed
│   ├── metadata.go                        # schema v2; Group/Parent dropped; RelocateHostIdentities
│   ├── validate.go                        # overlay models moves and removals
│   ├── service.go                         # planned{moves,removals}; group-aware move; group rename
│   └── projection.go                      # HostEntry gains Group
├── keys/
│   └── service.go                         # Generate accepts a group directory
├── httpserver/
│   ├── config_handlers.go                 # + groups, migration routes
│   ├── config_requests.go                 # + validation and problem mapping for the new codes
│   └── keys.go                            # + key move route and its action kind
├── session/action.go                      # + ActionKeyMove, ActionConfigMigrate
└── acceptance/conditions_test.go          # design §12 row 4 gains the new proofs
web/src/
├── groups/GroupsPanel.tsx                 # directory tree, rename, delete, region position
├── connections/ConnectionsPage.tsx        # move-to-group control
├── keys/KeysScreen.tsx                    # key move dialog, preview, Keychain warning
├── explorer/ConfigExplorer.tsx            # the false statement corrected
└── api/config.ts, keys/api.ts             # typed clients for the new endpoints
web/e2e/
└── groups.spec.ts                         # NEW end-to-end over the built binary
docs/
├── manual-acceptance.md                   # + M6, real Keychain after a key move
└── superpowers/specs/2026-08-04-sshc-design.md   # §4.2, §5.4, §6.2, §13 amended
README.md                                  # boundary sections corrected
```

---

## Task 1: Group path vocabulary

**Files:** Create `internal/application/grouppath.go`, `internal/application/grouppath_test.go`.

**Interfaces:**
- Produces: `ConnectionsDirectory = "connections"`, `KeysDirectory = "keys"`, `MaxGroupSegments = 6`.
- Produces: `ValidateGroupName(name string) error` and `ErrInvalidGroupName`.
- Produces: `GroupDirectory(name string) string`, `GroupKeyDirectory(name string) string` — workspace-relative, slash separated.
- Produces: `GroupOfPath(relative string) (name string, inGroup bool)` and `GroupOfKeyPath(relative string) (string, bool)`.
- Produces: `ParentGroupName(name string) string`, `GroupSegments(name string) []string`, `GroupDepth(name string) int`.
- Produces: `GroupNameOrder(names []string, order map[string]int) []string` — deepest first, then `Order`, then name.

**What it changes:** nothing outside the new file. Pure functions, no filesystem, no metadata.

**What it must not change:** `PlanGroupInclude`, `CompileGroups`, `GroupDepthOrder` or any existing signature. Task 3 retires `PlanGroupInclude`; this task only adds.

- [ ] **Step 1: Write `grouppath_test.go` first.** Table tests, one per function:
  - `TestValidateGroupNameRefusesEverythingThatIsNotASafeRelativeDirectory` — accept `work`, `work/eu`, `a-b_c.d`; refuse `""`, `/work`, `work/`, `work//eu`, `.`, `..`, `work/..`, `work/../home`, a segment with `\x00`, a segment starting with `.`, a segment longer than 64 bytes, a name deeper than `MaxGroupSegments`, and — case-insensitively — `sshc`, `config`, `known_hosts`, `authorized_keys`. The case-insensitive comparison exists for the same reason `keys.reservedFileNames` uses one: a default macOS volume treats `Config` and `config` as one file.
  - `TestGroupOfPathReadsMembershipFromTheDirectory` — `connections/work/web.conf` → `("work", true)`; `connections/work/eu/lon.conf` → `("work/eu", true)`; `connections/loose.conf` → `("", false)` (a file directly under `connections/` is in no group); `conf.d/10.conf` → `("", false)`; `config` → `("", false)`; `sshc/metadata.json` → `("", false)`.
  - `TestGroupNameOrderPutsChildrenBeforeParents` — `["work", "work/eu", "home"]` with equal `Order` yields `work/eu`, then `home`, then `work` sorted by depth then name; ties in depth broken by `Order` then name, matching `GroupDepthOrder`'s comparator exactly.
- [ ] **Step 2:** Run `go test ./internal/application -run TestValidateGroupName -v`. Expected: FAIL, the file does not compile.
- [ ] **Step 3:** Implement `grouppath.go`. `ValidateGroupName` splits on `/` and applies `keys.ValidateFileName`'s character policy per segment, without importing `internal/keys` (the two policies are deliberately separate: a group segment may not end in `.pub`, but neither may it be a key name). `MaxGroupSegments = 6` because `keys.maxScanDepth` is 8 counted from `~/.ssh` and `keys/` consumes one level, so a seventh segment would put the key file at the depth at which the scanner reports `depth_exceeded` and drops it from the inventory.
- [ ] **Step 4:** Run the tests. Expected: PASS.

**Verification:** `go test ./internal/application -run 'TestValidateGroupName|TestGroupOfPath|TestGroupNameOrder' -v`; `go vet ./internal/application`. The rest of the suite is untouched: `go test ./... ` still passes.

---

## Task 2: Groups derived from the declaration, not from metadata

**Files:** Modify `internal/application/groups.go`, `internal/application/metadata.go`, `internal/application/projection.go`, `internal/application/service.go`; modify `internal/application/groups_test.go`; create the new tests in `groups_test.go`.

**Interfaces:**
- Produces: `DeclaredGroups(entry *config.File) []string` — the group names named by Include lines in the generated region, in file order.
- Produces: `GroupsView{Name, Parent, Colour, Note, Order, Settings, Directory, KeyDirectory, MemberCount, Declared, DirectoryPresent bool}` and `BuildGroupsView(entry *config.File, hosts []HostEntry, metadata Metadata, present []string) ([]GroupsView, []Notice)`.
- Produces: notices `NoticeGroupNotDeclared = "group_not_declared"`, `NoticeGroupDirectoryMissing = "group_directory_missing"`, `NoticeGroupEmpty = "group_empty"`, `NoticeGroupFileUnreached = "group_file_unreached"`.
- Consumes: `GroupOfPath`, `GroupNameOrder`, `config.File.BlockAt`, `config.File.Condition`.
- Changes: `HostEntry` gains a `Group string` field, serialised as `group,omitempty`, filled by `GroupOfPath(entry.File.Path)`.
- Changes: `CompileGroups` derives the hierarchy from the name (`ParentGroupName`) and membership from `GroupOfPath(host.Identity.Path)` instead of from `HostMetadata.Group` and `GroupMetadata.Parent`.

**What it changes:** `Overview` starts reporting a group per host derived from its path, and the groups view is assembled from declaration plus directory plus metadata presentation. `metadata.json` is still read as it is today; nothing is written differently yet.

**What it must not change:** the shape of `groups.sshc.conf`. `TestCompileGroupsPutsChildrenBeforeParentsAndInheritsMembers` and `TestCompileGroupsRendersParsableLosslessConfiguration` must still pass, with their fixtures adapted to path-shaped group names (`work/eu` instead of a `parent: work` field) and the *rendered output* unchanged in structure: same three header comments, same `# group <name>` line, same member `Host` line, same tab-indented settings.

- [ ] **Step 1:** Adapt the two existing `CompileGroups` tests to path-shaped names and assert the rendered bytes are structurally identical to today's. Run them: FAIL.
- [ ] **Step 2:** Write `TestBuildGroupsViewReportsADirectoryThatWasNeverDeclared` — a `connections/marketing/` directory present on disk with no Include line yields a `group_not_declared` notice and **no** group. This is the test that proves the application does not adopt a stranger's directory.
- [ ] **Step 3:** Write `TestBuildGroupsViewReportsADeclaredGroupWithNoDirectory` (`group_directory_missing`) and `TestBuildGroupsViewReportsADeclaredGroupWithNoMembers` (`group_empty`, and the `include_no_match` diagnostic is still reported, not suppressed).
- [ ] **Step 4:** Write `TestHostEntryGroupComesFromTheDirectoryNotFromMetadata` — a host at `connections/work/web.conf` whose metadata entry says `group: "home"` reports `Group: "work"`. The directory wins, with no notice: metadata is about to stop carrying the field at all.
- [ ] **Step 5:** Implement. `CompileGroups` keeps its signature and its output shape; only where it reads membership and parentage changes.
- [ ] **Step 6:** Run the full application suite.

**Verification:** `go test ./internal/application -v`; `go test -race ./internal/application`. Manually diff a generated `groups.sshc.conf` before and after the change on the same fixture: it must be byte-identical when the group names are spelled the same way.

---

## Task 3: The generated Include region

**Files:** Create `internal/application/region.go`, `internal/application/region_test.go`. Modify `internal/application/groups.go` (delete `PlanGroupInclude`), `internal/application/service.go` (lines 734-751 call the new planner).

**Interfaces:**
- Produces: `RegionStartMarker`, `RegionEndMarker` (the two comment texts), `FindRegion(file *config.File) (start, end int, found bool, err error)` with `ErrRegionDamaged`.
- Produces: `PlanRegion(file *config.File, groups []string, groupsFile string) (RegionPlan, []Notice, error)`, `RegionPlan{InsertAt int, ReplaceFrom, ReplaceTo int, Lines []config.Line}`.
- Produces: `ApplyRegion(file *config.File, plan RegionPlan) error`.
- Produces: errors `ErrRegionPositionAmbiguous`, `ErrRegionIncludeAlreadyPresent`, `ErrRegionDamaged`; notices `include_position_ambiguous`, `group_include_already_present`, `generated_region_damaged`.
- Removes: `PlanGroupInclude`. `InsertIncludeLine` stays; the region planner uses it.

The emitted region, for declared groups `work/eu`, `work`, `home` and groups file `groups.sshc.conf`, using the file's dominant line ending:

```text
# >>> sshc groups (generated). Child groups first: OpenSSH keeps the first value it reads.
# Edit through the UI; lines between these markers are replaced on the next save.
Include connections/work/eu/*.conf
Include connections/work/*.conf
Include connections/home/*.conf
Include groups.sshc.conf
# <<< sshc groups
```

**What it changes:** where and how the entry file is edited when groups are saved.

**What it must not change:** one byte outside the region. Everything above `# >>>` and below `# <<<` is preserved exactly, including CRLF endings, indentation and comments. The insertion position rule is the one `PlanGroupInclude` already computed — before the first `Match` block or the first `Host` block with an exact `*` pattern, else at end of file.

- [ ] **Step 1:** Write `region_test.go`. The named tests, each asserting on rendered bytes:
  - `TestPlanRegionEmitsOneIncludePerGroupChildFirst` — the exact block above, in that order, for those three groups.
  - `TestPlanRegionPlacesTheRegionBeforeTheFirstCatchAll` — the connections plan's existing fixture `Host bastion\n\tUser ops\nHost *\n\tServerAliveInterval 30\n` gains the region between line 2 and `Host *`.
  - `TestPlanRegionAppendsWhenThereIsNoCatchAll` — appended at end, exactly as `TestPlanGroupIncludeAppendsWhenThereIsNoCatchAllBlock` asserts today.
  - `TestPlanRegionRefusesWhenAConcreteHostFollowsTheInsertionPoint` — `Host *\n\tUser ops\nHost bastion\n\tUser root\n` returns `ErrRegionPositionAmbiguous` and leaves the file untouched. **This is the catch-all-at-the-top case and it is the most important test in the task.**
  - `TestPlanRegionRefusesWhenAnExistingIncludeAlreadyReachesTheConnectionsTree` — `ErrRegionIncludeAlreadyPresent`, naming the line.
  - `TestPlanRegionIgnoresAConditionalIncludeOfTheGroupsFile` — the defect from section 6: `Host bastion\n\tInclude groups.sshc.conf\n` must **not** count as present, so a top-level region is planned. Assert the governing block is consulted via `File.Condition(File.BlockAt(index))`.
  - `TestPlanRegionReplacesAnExistingRegionInPlace` — a second save with one group added rewrites only the lines between the markers; the bytes before and after are identical.
  - `TestFindRegionRefusesAHalfMarkedRegion` — one marker present returns `ErrRegionDamaged` in both directions.
  - `TestPlanRegionPreservesCRLF` — a CRLF entry file gets CRLF region lines, through `dominantEnding`.
  - `TestApplyRegionChangesNothingOutsideTheMarkers` — a fixture with comments, blank lines, `key=value` spelling and an unstructured line round-trips outside the region byte for byte.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement `region.go`. `FindRegion` matches a `config.LineComment` whose trimmed text equals the marker. `PlanRegion` computes the catch-all position with the same rule as `PlanGroupInclude` — exact `*` in a `Host` line, or the first `Match` — then applies the ambiguity check by scanning for a later `Host` block with at least one non-wildcard, non-negated pattern.
- [ ] **Step 4:** Delete `PlanGroupInclude` and its two tests, replaced above. Update `service.go` lines 734-751.
- [ ] **Step 5:** Run the whole suite; fix the `EditGroups` service test whose fixture now produces a region rather than a bare Include line.

**Verification:** `go test ./internal/application -v`. Then a manual check that costs five minutes and is worth it: build a fixture `~/.ssh` in a temp `HOME` with three groups, run `ssh -G -F <tempdir>/.ssh/config web-1`, and confirm the value the projection explains is the value OpenSSH reports. `internal/effective/differential_test.go` is the place to automate this — see Task 12.

---

## Task 4: The transaction can move a file, and the overlay knows it

**Files:** Modify `internal/application/validate.go`, `internal/application/service.go`; modify `internal/application/service_test.go`, `internal/application/validate` coverage in `service_test.go`.

**Interfaces:**
- Changes: `overlayLoader` gains `removed map[string]bool`. `ReadFile` returns `fs.ErrNotExist` for a removed path; `Glob` filters removed paths out of the base matches before adding pending ones.
- Changes: `Service.resolveWith(pending map[string][]byte, removed map[string]bool)`. Every existing call site passes `nil` for the second argument.
- Changes: `Service.validate` builds `removed` from `request.Moves[].From` and `request.Removals[].Path`, and `pending` additionally from `request.Moves[].To` where the content is known.
- Changes: `planned` gains `moves []storage.Move` and `removals []storage.Removal`; `Service.Save` passes them to `Commit`.

This is the task that unblocks every file-level move in this plan, and it is a correctness fix to committed code, not new behaviour: today a transaction containing a move is validated against a world where the file is in two places at once. Nothing exercises it yet only because the application layer has never issued one.

```go
// overlayLoader lets the resolver see the contents a transaction is about to
// write, the files it is about to create, and — equally important — the files
// it is about to move away from or remove. Without the removed set a move is
// resolved as though the file were still at its old path and also at its new
// one, so every alias in it appears twice and the effective preview explains a
// state that will never exist.
type overlayLoader struct {
	base    config.Loader
	pending map[string][]byte
	removed map[string]bool
}

func (loader overlayLoader) ReadFile(name string) ([]byte, error) {
	cleaned := filepath.Clean(name)
	if contents, ok := loader.pending[cleaned]; ok {
		return contents, nil
	}
	if loader.removed[cleaned] {
		return nil, fs.ErrNotExist
	}
	return loader.base.ReadFile(name)
}
```

`Glob` gains the same filter before it appends pending paths, so a moved-away file stops matching the glob that used to reach it.

**What it must not change:** the existing validation contract. A save is still refused only for a diagnostic it *introduces* (`pendingBaseline`), a file must still render back to its own bytes, and an already-unparsable line must still be tolerated.

- [ ] **Step 1:** Write `TestValidateSeesAMovedFileAtItsNewPathOnly` — a request moving `conf.d/a.conf` to `connections/work/a.conf`, with the entry file's Include region already reaching both globs, resolves to a graph containing the destination and not the source, and reports no duplicate-alias notice. Without the fix the alias appears twice.
- [ ] **Step 2:** Write `TestValidateSeesARemovedFileAsGone` — same shape for `Removals`.
- [ ] **Step 3:** Write `TestSaveCommitsMovesAndRemovalsInTheSameTransaction` — a `planned` carrying one change and one move produces one `storage.Result` whose `Written` names both, and the journal record contains a `move` entry.
- [ ] **Step 4:** Run: FAIL. Implement. Run: PASS.
- [ ] **Step 5:** Re-run the storage suite untouched: `go test ./internal/storage -v`. This task adds nothing to `storage` and must not.

**Verification:** `go test ./internal/application ./internal/storage -v`; `go test -race ./...`.

---

## Task 5: Move a host into a group

**Files:** Modify `internal/application/service.go` (`EditRequest`, `planMoveHost`), `internal/application/metadata.go` (`RelocateHostIdentities`), `internal/httpserver/config_requests.go`, `api/openapi.yaml`.

**Interfaces:**
- Changes: `EditRequest` gains a `DestinationGroup string` field, serialised as `destinationGroup,omitempty`. When set, `DestinationPath` is derived as `GroupDirectory(group) + "/" + <base name>` and the request must not also carry `DestinationPath`.
- Produces: `RelocateHostIdentities(metadata Metadata, fromPath, toPath string) Metadata`.
- Produces: notice `NoticeGroupDirectoryCreated = "group_directory_created"`.

**What it changes:** `Service.planMoveHost` gains a group-derived destination and calls `Workspace.EnsureDirectory` for the destination directory in `Service.Save`, next to the existing `metadata.EnsureDirectory` call at line 376, before `Commit`.

**What it must not change:** `planMoveHost`'s existing guarantees, every one of which is already covered by the connections plan's acceptance gate — both files and `metadata.json` in one journalled transaction, a stale base on either file writing nothing, the moved block arriving byte-identical including comments and indentation, a duplicate alias in the destination refused with `ErrDuplicateDestinationAlias`, a move onto itself refused with `ErrSameFileMove`, and the before/after explained values shown for every alias the block declares.

- [ ] **Step 1:** `TestMoveHostIntoAGroupDerivesTheDestinationPath` — `{Kind: EditMove, Path: "conf.d/a.conf", Alias: "web-1", DestinationGroup: "work"}` writes `connections/work/a.conf`.
- [ ] **Step 2:** `TestMoveHostIntoAGroupUpdatesTheMetadataIdentityInTheSameTransaction` — colour, tags, note and favourite survive; the entry is not orphaned; the transaction contains exactly three changes.
- [ ] **Step 3:** `TestMoveHostIntoAnUndeclaredGroupIsRefused` — a group with no Include line answers `group_not_declared` and writes nothing. Also assert the destination directory was **not** created: a refusal must not leave debris.
- [ ] **Step 4:** `TestMoveHostIntoAGroupShowsTheEffectiveDiffForEveryAlias` — the existing `movedAliases` loop still runs, and the diff shows the reordering even when no value changes, because the block is now read at a different point.
- [ ] **Step 5:** `TestMoveHostRefusesBothDestinationPathAndDestinationGroup` at the HTTP boundary — `errInvalidEdit`, 400.
- [ ] **Step 6:** Implement, then run the connections plan's move tests unchanged.

**Verification:** `go test ./internal/application ./internal/httpserver -v`; `make verify-generated` after the OpenAPI edit.

---

## Task 6: `metadata.json` schema version 2

**Files:** Modify `internal/application/metadata.go`, `internal/application/metadata_test.go`, `api/openapi.yaml`, `internal/httpserver/config_requests.go`.

**Interfaces:**
- Changes: `MetadataSchemaVersion = 2`.
- Removes: `HostMetadata.Group`, `GroupMetadata.Parent`.
- Changes: `DecodeMetadata` accepts a version 1 document and **discards** `hosts[].group` and `groups[].parent` after using them for nothing — the directory is now authoritative, and a v1 document's group field describes a layout that does not exist yet. `json.Unmarshal` ignores unknown fields by default, so this needs no code; the test must prove it, because it is the moment decision 4 takes effect.
- Changes: `EncodeMetadata` writes version 2. `ValidateMetadata` drops the "host group must name a known group" and "parent must exist" rules, and gains "group name must pass `ValidateGroupName`".

**What it changes:** the persisted schema. This is the point of no return for decision 4.

**What it must not change:** `ErrMetadataSecret` and the `secretMarkers` scan; the deterministic sort in `EncodeMetadata`; refusal of a version *newer* than this build supports.

- [ ] **Step 1:** `TestDecodeMetadataAcceptsVersionOneAndDropsGroupMembership` — a v1 document with `hosts[0].group = "work"` decodes without error and the decoded `HostMetadata` has no group to carry. Re-encoding produces a version 2 document with no `group` key anywhere.
- [ ] **Step 2:** `TestDecodeMetadataStillRefusesAFutureVersion` — version 3 is `ErrMetadataVersion`. Unchanged behaviour, re-asserted because the constant moved.
- [ ] **Step 3:** `TestValidateMetadataRefusesAGroupNameThatIsNotASafeDirectory` — a group named `../escape` is `ErrMetadataGroup`.
- [ ] **Step 4:** `TestMetadataCarriesOnlyPresentation` — encode a fully populated document and assert the JSON keys are exactly `schemaVersion`, `groupsFile`, `groups` (`name`, `colour`, `note`, `order`, `settings`) and `hosts` (`identity`, `tags`, `colour`, `note`, `favourite`, `order`, `orphan`). No `group`, no `parent`.
- [ ] **Step 5:** Implement; update `api/openapi.yaml` (`HostMetadata` loses `group`, `GroupMetadata` loses `parent`); `make generate`.

**Verification:** `go test ./internal/application ./internal/api -v`; `make verify-generated` prints no diff; `TestRouteTableMatchesTheOpenAPIContract` passes.

**Note on `settings`.** Group settings stay in `metadata.json`, keyed by group name. A setting is not membership: it is the payload the group applies, and `groups.sshc.conf` is where it lands as ordinary configuration. Putting a per-group settings file *inside* the group directory would be picked up by that group's own `Include connections/<group>/*.conf` and read in lexical order among the host files — so the group's settings would beat its own hosts' values unless the file were named to sort last, which is a naming trick, not a design. See the open questions.

---

## Task 7: The key move

**Files:** Create `internal/application/keymove.go`, `internal/application/keymove_test.go`. Modify `internal/session/action.go`, `internal/httpserver/keys.go`, `internal/httpserver/config_requests.go`, `api/openapi.yaml`, `internal/app/run.go`.

**Interfaces:**
- Produces: `KeyMoveRequest{KeyID, DestinationGroup string}`, `KeyMovePreview{Files []KeyFileMove, Rewrites []KeyLineRewrite, Diffs []FileDiff, Warnings []Notice, Blockers []Notice}`, `KeyFileMove{FromPath, ToPath, Permission, Kind}`, `KeyLineRewrite{ConfigPath, Line int, Directive, Before, After string, HostPatterns []string, Condition string}`.
- Produces: `(*Service).PreviewKeyMove(inventory *keys.Inventory, index *keys.ReferenceIndex, request KeyMoveRequest) (KeyMovePreview, error)` and `(*Service).MoveKey(...) (SaveResult, error)`.
- Produces: `(*Service).KeyMoveEvidence(request KeyMoveRequest) (string, error)`.
- Produces: the blocker codes from the table in section 7.
- Consumes: `keys.Reference`, `keys.UnresolvedReference`, `keys.BuildReferenceIndex`, `keys.Inventory.Group`, `keys.ItemID`, `storage.Move`, `rebuildLine`.
- Adds: `session.ActionKeyMove = "key.move"` to the constant block and to `knownActionKinds`.
- Adds route: `POST /api/v1/keys/:keyId/move` (preview when `X-SSHC-Action` is absent, apply when present), registered in `keys.go` next to the existing key routes but served by the configuration service, because the transaction is a configuration write.

**What it changes:** the first operation in the codebase that writes configuration and moves a key in one transaction.

**What it must not change:** the key vault's own manager and its operations. `keys.Service` keeps its own `storage.Manager`; nothing in `internal/keys` gains a configuration write.

- [ ] **Step 1:** `TestKeyMoveRewritesEveryIdentityFileThatNamesTheKey` — two configuration files each naming `~/.ssh/id_work` from a different `Host` block; both lines are rewritten to `~/.ssh/keys/work/id_work`; every other byte of both files is unchanged, including a trailing comment on the rewritten line, which `rebuildLine` preserves.
- [ ] **Step 2:** `TestKeyMoveMovesTheWholeFingerprintGroup` — private key, `.pub` and certificate all move; membership comes from the fingerprint, never from the base name; a look-alike file with a different fingerprint stays.
- [ ] **Step 3:** `TestKeyMoveRefusesAReferenceInAFileOutsideTheWorkspace` — an Include reaching `/etc/ssh/ssh_config` which names the key: `key_reference_outside_workspace`, nothing written, and assert the external file is byte-identical afterwards.
- [ ] **Step 4:** `TestKeyMoveRefusesWhenAnUnresolvedReferenceCouldNameTheKey` — an `IdentityFile id_work` (relative, `ReasonRelativePath`) somewhere in the graph blocks a move of `id_work`; an `IdentityFile %u/other` does not.
- [ ] **Step 5:** `TestKeyMoveRefusesADestinationAnIncludeWouldRead` — a hand-written `Include keys/*/*` in the graph makes `keys/work/id_work` a configuration file; refuse with `key_destination_is_config`. This is the test that stops a private key being parsed as `ssh_config`.
- [ ] **Step 6:** `TestKeyMoveIsOneTransactionAndIsReversible` — one `storage.Request` with N changes and M moves and zero removals; after `Commit`, `Rollback` on the transaction restores every configuration file from its backup and renames every key file back; the key bytes are identical and the mode is unchanged.
- [ ] **Step 7:** `TestKeyMovePreviewCarriesTheKeychainWarningAlways` — present regardless of whether the key is loaded in the agent, naming `SSH: <absolute source path>`, and stating that the application cannot check the entry.
- [ ] **Step 8:** `TestKeyMoveTokenIsBoundToTheLinesTheDialogShowed` — editing one of the referenced configuration lines between issue and spend invalidates the token; `403 action_token_invalid`; nothing written.
- [ ] **Step 9:** `TestKeyMovePreviewNeverContainsKeyMaterial` — the preview payload, and every log line produced during it, contain no `-----BEGIN`, no base64 body and no passphrase. The log assertion uses the injected logger, as `TestNoLogLineCarriesASecret` requires.
- [ ] **Step 10:** Implement. Wire the action kind in `run.go` next to `addKeyActions`.

**Verification:** `go test ./internal/application ./internal/httpserver ./internal/session -v`; `go test -race ./...`; `make verify-generated`.

---

## Task 8: Group rename and group delete

**Files:** Modify `internal/application/service.go`, `internal/application/keymove.go` (share the rewrite), `internal/httpserver/config_handlers.go`, `api/openapi.yaml`.

**Interfaces:**
- Produces: `EditKind` values `EditGroupRename = "group_rename"` and `EditGroupDelete = "group_delete"`, with `EditRequest.GroupName` and `EditRequest.NewGroupName` / `EditRequest.DestinationGroup`.
- Produces: notice `NoticeGroupDirectoryLeftover = "group_directory_leftover"`.

**What it changes:** a rename becomes N file moves plus the Include region rewrite plus the `IdentityFile` rewrite plus the metadata rewrite, all in one `storage.Request`, exactly as section 8 describes.

**What it must not change:** nothing is deleted. A group delete relocates its connections to another group or to a file the user names; it never removes a configuration file.

- [ ] **Step 1:** `TestGroupRenameMovesEveryFileAndRewritesEveryIncludeLine` — three connection files and two keys under `work`, renamed to `client-a`: five moves, one entry-file change (the region), one metadata change, one `groups.sshc.conf` change, and one change per configuration file whose `IdentityFile` pointed under `keys/work/`.
- [ ] **Step 2:** `TestGroupRenameCarriesNestedGroupsWithIt` — renaming `work` also renames `work/eu` to `client-a/eu`, in the same transaction, with both Include lines rewritten and child-before-parent order preserved.
- [ ] **Step 3:** `TestGroupRenameReportsTheEmptyDirectoryItLeavesBehind` — `group_directory_leftover` names `connections/work`, and the plan asserts that the application did not attempt to remove it.
- [ ] **Step 4:** `TestGroupRenameRefusesWhenAKeyReferenceLivesOutsideTheWorkspace` — the same refusal as a key move, because it is the same rewrite. A rename that would half-apply is refused entirely.
- [ ] **Step 5:** `TestGroupRenameWithAStaleFileWritesNothing` — one file's digest changed since the plan: `ConflictError`, zero writes, and the group is still named `work`.
- [ ] **Step 6:** `TestGroupRenameOntoAnExistingGroupIsRefused` — refuse rather than merge, matching the rule the current `GroupsPanel` rename already applies in the UI ("Renaming onto an existing group would merge two sets of settings").
- [ ] **Step 7:** Implement, sharing the `IdentityFile` rewrite with Task 7 rather than copying it.

**Verification:** `go test ./internal/application -v`; `go test -race ./internal/application`.

---

## Task 9: Generating a key into a group

**Files:** Modify `internal/keys/service.go`, `internal/keys/service_test.go`, `internal/httpserver/keys.go`, `api/openapi.yaml`.

**Interfaces:**
- Changes: `keys.GenerateRequest` gains `Group string`. `Service.Generate` validates it with a group validator injected by the caller (a `func(string) error` field on `ServiceOptions`, so `internal/keys` does not import `internal/application`), calls `EnsureDirectory(keys/<group>)`, and writes to `keys/<group>/<name>` and `keys/<group>/<name>.pub`.
- Unchanged: `ValidateFileName` still accepts a single path segment only. The group is a separate, separately validated field. Concatenating a user-supplied group into the file name would defeat the segment rule that stops a key being written to `config`.

**What it must not change:** `reservedFileNames`, the `.pub` suffix refusal, `StateDirectoryName` exclusion, the case-insensitive comparison, and the rule that a passphrase never reaches argv or the environment.

- [ ] **Step 1:** `TestGenerateWritesIntoTheGroupDirectory` — `{FileName: "id_work", Group: "work"}` writes `keys/work/id_work` and `keys/work/id_work.pub`, both `0600`, in one transaction.
- [ ] **Step 2:** `TestGenerateRefusesAGroupThatIsNotDeclared` and `TestGenerateRefusesATraversalInTheGroup` — `../../etc` is refused before any directory is created.
- [ ] **Step 3:** `TestGenerateStillRefusesAReservedFileNameInsideAGroup` — `keys/work/config` is refused. The reserved-name rule is about names the application depends on, and it applies at every depth.
- [ ] **Step 4:** `TestHardwareCommandNamesTheGroupDirectory` — the displayed `ssh-keygen` command for a FIDO key names the full path under the group, so the user's hand-run command lands in the same place.
- [ ] **Step 5:** Implement.

**Verification:** `go test ./internal/keys ./internal/httpserver -v`.

---

## Task 10: Opt-in migration

**Files:** Create `internal/application/migrate.go`, `internal/application/migrate_test.go`. Modify `internal/httpserver/config_handlers.go`, `internal/session/action.go`, `api/openapi.yaml`.

**Interfaces:**
- Produces: `MigrationPlan{Moves []MigrationMove, Skipped []MigrationSkip, Region RegionPlan, Metadata Metadata, Diffs []FileDiff, Blockers []Notice}`, `MigrationSkip{Path, Reason string}`.
- Produces: `(*Service).PreviewMigration() (MigrationPlan, error)` and `(*Service).ApplyMigration() (SaveResult, error)`.
- Produces: `(*Service).PreviewKeyMigration()` / `ApplyKeyMigration()`, separate as section 9 requires.
- Adds: `session.ActionConfigMigrate = "config.migrate"`.
- Adds routes: `POST /api/v1/config/migration/preview`, `POST /api/v1/config/migration/apply`, and the two key equivalents.

**What it must not change:** nothing runs without an explicit request. No startup path, no `Overview`, no save may call any of these.

- [ ] **Step 1:** `TestMigrationMovesOnlyFilesWhoseHostsShareOneGroup` — a file with two hosts in different groups is skipped with `mixed_groups` and named in the plan.
- [ ] **Step 2:** `TestMigrationNeverSplitsAFile` — assert no `storage.Change` rewrites a source file's contents; every relocation is a `storage.Move` of the whole file.
- [ ] **Step 3:** `TestMigrationSkipsTheEntryFileAndExternalFiles` — `config` is never moved; a file reached by an Include outside `~/.ssh` is skipped with `external_file`.
- [ ] **Step 4:** `TestMigrationIsNeverRunImplicitly` — a grep-style test over the package: no call to `PreviewMigration` or `ApplyMigration` outside the two handlers and the tests. This is the test that enforces settled decision 3, and it must fail loudly if someone later "helpfully" calls it from `Overview`.
- [ ] **Step 5:** `TestMigrationPreviewIsRefusedWhenTheRegionPositionIsAmbiguous` — the whole migration refuses if the region cannot be placed safely, rather than migrating the files and leaving them unreachable.
- [ ] **Step 6:** `TestKeyMigrationIsSeparateFromConfigMigration` — a key blocked by an external reference does not prevent the configuration migration from being applied.
- [ ] **Step 7:** Implement.

**Verification:** `go test ./internal/application ./internal/httpserver -v`; `make verify-generated`.

---

## Task 11: The interface

**Files:** Modify `web/src/groups/GroupsPanel.tsx`, `web/src/connections/ConnectionsPage.tsx`, `web/src/connections/ConnectionTree.tsx`, `web/src/keys/KeysScreen.tsx`, `web/src/explorer/ConfigExplorer.tsx`, `web/src/api/config.ts`, `web/src/keys/api.ts` and their `.test.tsx` siblings. Create `web/e2e/groups.spec.ts`.

**What it changes:**
- `GroupsPanel` renders the group **tree** (nesting from the name), shows each group's directory and key directory, its declaration state, and where the region sits in `config` — including, when the position is ambiguous, the two candidate positions and the affected aliases' effective diffs, with the user choosing.
- `ConnectionTree` groups hosts by `HostEntry.Group`, which now comes from the path.
- `ConnectionsPage` gains a move-to-group control that sends `destinationGroup`.
- `KeysScreen` gains the key move dialog: destination group, the file list, the per-line rewrite table (path, line, before, after, host patterns), the diffs, the Keychain warning and the agent note, then the confirmation that mints the `key.move` token.
- `ConfigExplorer`: the explorer note. On `main` the false sentence is inline at line 189; in the current working tree it is already gone and the copy lives in `web/src/i18n/messages.ts` as `explorer.newFileNote` in both locales. Check which, then write the same replacement text into whichever is present: a new file is only read once an `Include` points at it; moving a connection between groups is done from the Connections screen; renaming and deleting arbitrary files and folders is still not offered, because journalled directory create, remove and rename do not exist. If the i18n refactor has landed, both the English and the Japanese message must change together — an English-only edit leaves the Japanese UI saying something different from the English one.

**What it must not change:** Tailwind utility classes only, no CDN, no icon set. Every new control keyboard reachable and labelled; the visible star/colour/duplicate markers stay `aria-hidden` with the `sr-only` description carrying them, as the roadmap's fix established.

- [ ] **Step 1:** Vitest: `GroupsPanel.test.tsx` renders a nested tree, shows `group_not_declared` for a stray directory, and refuses to submit a rename onto an existing group.
- [ ] **Step 2:** Vitest: `KeysScreen.test.tsx` shows every rewritten line and the Keychain warning before any request is sent, and does not enable the confirm control until the preview has loaded.
- [ ] **Step 3:** Vitest: `ConfigExplorer.test.tsx` asserts the new text and asserts the old sentence is gone — a string assertion, so nobody restores it by accident. If the i18n refactor has landed, assert it in both locales.
- [ ] **Step 4:** Playwright `web/e2e/groups.spec.ts` against the built binary with a temporary `HOME`: create a group, move a host into it, confirm `~/.ssh/config` gained the region with the Include in the right place, confirm the host file moved, and confirm the tree still shows the host under its group after a reload. Guard each assertion the way `shell.spec.ts` does — a control assertion that fails on the *unfixed* build, so a green spec proves something.
- [ ] **Step 5:** `npm run build --prefix web` and commit the rebuilt `internal/ui/dist`.

**Verification:** `npm test --prefix web`; `npm run typecheck --prefix web`; `PLAYWRIGHT_BROWSERS_PATH=./web/.playwright-browsers make e2e`, twice in a row.

---

## Task 12: Documentation, the design amendment and the audit

**Files:** Modify `README.md`, `docs/superpowers/specs/2026-08-04-sshc-design.md`, `docs/superpowers/plans/2026-08-04-sshc-roadmap.md`, `docs/manual-acceptance.md`, `internal/acceptance/conditions_test.go`, `internal/effective/differential_test.go`.

- [ ] **Step 1:** Apply every replacement in section 12 of this plan.
- [ ] **Step 2:** Extend `internal/effective/differential_test.go` with a fixture that uses the generated region and three groups, so the installed OpenSSH witnesses the ordering claim rather than only this application's own reading of it. It skips when `ssh` is absent, as it already does.
- [ ] **Step 3:** Design §12 row 4 in `conditions_test.go` gains `TestPlanRegionEmitsOneIncludePerGroupChildFirst`, `TestPlanRegionRefusesWhenAConcreteHostFollowsTheInsertionPoint`, `TestHostEntryGroupComesFromTheDirectoryNotFromMetadata` and the new Playwright spec, and its `Gap` records that the ordering is proven against real OpenSSH only when OpenSSH is installed.
- [ ] **Step 4:** Add manual test **M6** to `docs/manual-acceptance.md`: after moving a key that is registered in the login Keychain, confirm with `security find-generic-password -s "SSH: <old path>"` that the entry still names the old path, confirm `ssh` prompts for the passphrase again, re-register from the Keys screen, and confirm a new entry appears under the new path. Record it as 未実施 with the others until someone performs it.
- [ ] **Step 5:** Add a roadmap status line for this plan and move the two stale-README items into its "Known open defects" list as closed by this plan.

**Verification:**

```bash
go test ./internal/acceptance -run TestDesignCompletionConditions -v
grep -rn "journalled delete and rename primitives" web/src || echo "the false statement is gone"
grep -n "sshc-file-operations" README.md
```

The last command must print only the corrected sentence, which names journalled *directory* create, remove and rename as the remaining gap.

---

## Directory Groups Acceptance Gate

```bash
make verify-generated
make test
make fuzz
PLAYWRIGHT_BROWSERS_PATH=./web/.playwright-browsers make e2e
make build
go vet ./...
go test ./internal/acceptance -run TestDesignCompletionConditions -v
```

- `make verify-generated` prints no diff; `go.mod`, `go.sum`, `web/package.json` and `web/package-lock.json` are unchanged: this plan added no dependency.
- Loading a configuration with groups, opening every screen and saving nothing leaves every file byte-for-byte unchanged.
- A workspace with no `connections/` directory and no generated region behaves exactly as it did before this plan: no Include is emitted, no directory is created, no metadata field changes on a save that does not touch groups.
- The generated region contains one `Include` per declared group, deepest group first, then `Include groups.sshc.conf`, and sits immediately before the first catch-all `Host *` or the first `Match`.
- `connections/work/*.conf` does not match `connections/work/eu/lon.conf`, and the nested group has its own Include line. Asserted, not assumed.
- A configuration whose catch-all is at the top refuses the region with `include_position_ambiguous`, names both candidate positions and shows the affected aliases' effective diffs; the entry file is unchanged.
- An existing Include that already reaches `connections/` refuses with `group_include_already_present` naming the file and line.
- An `Include groups.sshc.conf` inside a `Host` block does not count as present; a top-level region is planned. The pre-existing `PlanGroupInclude` defect is gone with the function.
- A half-marked region refuses with `generated_region_damaged`.
- Everything outside the markers is byte-identical after a region rewrite, including CRLF, `key=value` spelling, comments and unstructured lines.
- A directory under `connections/` with no Include line is reported as `group_not_declared` and is never adopted, moved or written to.
- An empty declared group reports `group_empty` and its `include_no_match` diagnostic is still shown, not suppressed.
- Moving a host into a group commits the source file, the destination file and `metadata.json` as one journalled transaction; colour, tags, note, favourite and order survive; the entry is not orphaned; a stale base on either file writes nothing.
- A refused move creates no directory and writes no file.
- `metadata.json` contains no `group` and no `parent`; a version 1 document decodes, loses group membership, and re-encodes as version 2; a version 3 document is still refused.
- A key move rewrites every `IdentityFile` and `CertificateFile` line the Include graph reaches that names the key, preserves every other byte of those files including trailing comments, and moves the private key, its `.pub` and its certificate by fingerprint, never by name.
- A key move is refused, with nothing written, when a reference lives in a file outside `~/.ssh`, when an unresolved reference could name the key, when the destination would be read as configuration, when the destination exists, when the group is not declared, or when a configuration file changed since the preview.
- A key move contains no `storage.Removal`, and `Rollback` restores every configuration file and renames every key file back with its bytes and mode intact.
- The key move preview shows every changed line with its file, line number, before and after text and governing `Host` patterns, and always carries the Keychain warning naming `SSH: <old absolute path>` together with the statement that this application cannot check or repair the entry.
- The key move requires a `key.move` action token whose evidence covers the moved paths and the exact lines the dialog displayed; editing one of those lines between confirmation and request invalidates it.
- A group rename moves every file under `connections/<old>` and `keys/<old>`, rewrites every Include line and every `IdentityFile` naming them, rewrites the metadata identities and the group names, in one transaction; a stale file anywhere writes nothing; the empty source directory is reported as `group_directory_leftover` and is not removed.
- Renaming onto an existing group is refused rather than merged.
- No configuration file is ever deleted by any operation in this plan.
- Migration runs only when explicitly requested, moves whole files only, names every file it skips with a reason, and refuses entirely if the region cannot be placed safely. `TestMigrationIsNeverRunImplicitly` passes.
- Key migration is a separate operation from configuration migration and a blocked key does not block the configuration migration.
- `web/src/explorer/ConfigExplorer.tsx` no longer claims the journalled delete and rename primitives are missing; `README.md` no longer claims that moving a Host block between files is a later task.
- Every `/api/` route added here appears in `api/openapi.yaml` and vice versa; every mutation requires the session cookie and `X-SSHC-CSRF`; every response carries `Cache-Control: no-store`; no response contains key material or configuration bytes outside the diff payloads that exist for that purpose.
- No automated test read or wrote the real `~/.ssh`, Keychain, ssh-agent, Terminal or a remote host. Confirm with the roadmap's three commands.
- `make e2e` passes twice in a row on a freshly built binary, and `internal/ui/dist` was rebuilt in the same commit as the last `web/src` change.

---

## Limits

What the automated suite will *not* prove. None of these is a defect in what is built; each bounds what a green run means.

- **No test touches a real Keychain, and no code in this repository can.** `ssh-add --apple-use-keychain` is the only Keychain path in the tree and there is no use of `security(1)`. The warning shown before a key move is text: nothing verifies that an entry exists for the old path, that it breaks, or that re-registering repairs it. Manual test M6 is the only evidence there will be, and until it is performed the warning is a claim about macOS, not a tested behaviour of this application.
- **No test touches a real `~/.ssh`.** Every fixture is built by the test, so every fixture is regular, small and well-formed. The roadmap already records twice what that blindness cost — the wildcard-only `Host *` row that no fixture contained, and the panel that no fixture made taller than the viewport. A real `~/.ssh` has symlinked directories, files the scanner refuses, names that collide on a case-insensitive volume, and `IdentityFile` values written in forms nobody would think to write into a table test. Running the built binary against a throwaway copy of a real configuration remains the only way to find that class of gap, and it is manual test M5.
- **No test connects to a remote.** Whether a moved key still authenticates is M1's business, not this suite's.
- **The Include ordering is proven against real OpenSSH only when OpenSSH is installed.** `internal/effective/differential_test.go` skips when `ssh` is absent, so on a machine without it the ordering claim rests on this application's own reading of the first-value-wins rule. Design §12 condition 5 is already recorded as conditional for the same reason; condition 4 now joins it in part.
- **Case-insensitivity is asserted in code and not on the filesystem that matters.** `ValidateGroupName` compares reserved names case-insensitively because a default macOS volume treats `Work` and `work` as one directory. A CI filesystem that is case-sensitive will pass the same test for the wrong reason, and two groups differing only in case will behave differently on the two machines. Nothing automated closes that gap.
- **Partial failure is injected, not observed.** The two-`rename(2)` window in a key move is exercised by a fault-injecting fake `FileSystem`, not by killing the process between the two syscalls. Crash recovery is proven by inference from those tests, exactly as the roadmap already records for the write path.
- **Directory creation is outside the journal.** A crash between `EnsureDirectory` and `Commit` leaves an empty group directory. No test observes that crash; the acceptance gate asserts only that a *refused* save creates nothing, which is a weaker statement.
- **The empty directory left by a rename is never cleaned up**, and no test asserts it eventually goes away, because nothing removes it. `group_directory_leftover` is the whole of the mechanism.
- **The rewrite covers the Include graph and nothing else.** No test can prove a key is not named by `~/.gitconfig`, a shell alias, a LaunchAgent, `/etc/ssh/ssh_config` or an `ssh -F` invocation, because none of those is reachable from `~/.ssh/config`. The preview says so; the suite cannot.

---

## Risks that would stop this plan

Named because they were found, not because a risk section is expected.

1. **A move can leave the configuration naming a key that is not there, in three distinct ways, and only one of them is fully guarded.**
   - *An unresolvable reference.* `keys.expandKeyPath` refuses to guess a relative `IdentityFile` (`ReasonRelativePath`) or an unknown token such as `%u` or `~user/` (`ReasonUnsupportedToken`), so those directives are never indexed and cannot be rewritten. If one of them names the moved key, the move breaks it silently. The base-name refusal in Task 7 Step 4 catches the common spelling and nothing else.
   - *A reference in a file the graph never reaches.* The refusal in decision 1 is decidable only for files the Include graph resolved. A file reached by an `Include` with an unsupported expansion is not in the graph at all, so a reference inside it is invisible — not "outside the workspace", simply absent. The only honest coarse guard is to refuse a key move while the graph reports any `include_unsupported_expansion`, and that guard would block a whole feature because of one unrelated `%u` somewhere.
   - *`~/.ssh/config` is not the only reader.* `ssh -i`, `ssh -F`, `scp`, `rsync -e`, `core.sshCommand`, a LaunchAgent and `/etc/ssh/ssh_config` can all name a key path, and none is in scope for anything this application reads. The preview states it; nothing enforces it.

   This is the risk that most deserves a second opinion before Task 7 ships.

2. **A region inserted at the wrong place silently changes precedence.** The guard is a heuristic: an exact `*` pattern in a `Host` line, or the first `Match`. A configuration opening with `Host *.internal` is not a catch-all by that test and will have the region inserted below it — correct, but by luck. A configuration whose author intended their top block to be defaults, written as `Host * !bastion`, *is* caught. The ambiguity refusal exists precisely because the heuristic cannot be trusted alone, and if it fires often enough to annoy people the temptation will be to weaken it. It must not be weakened.

3. **`overlayLoader` currently models neither a move nor a removal**, so until Task 4 lands, every preview and every save-time validation of a file relocation describes a state that will never exist — the file in both places, or still in the old one. This is a correctness defect in committed code that nothing exercises today. It would stop me before anything else in this plan.

4. **Two groups whose names differ only in case are one directory on a default macOS volume.** `connections/Work` and `connections/work` merge silently, and the metadata would carry two entries pointing at the same place while the Include region carries two lines that glob the same files. The validator refuses reserved names case-insensitively; it must also refuse a new group whose name case-insensitively equals an existing one, and that check needs the existing set, not just the candidate.

5. **A group rename is N file moves, and N grows with the group.** Every file is read at plan time to compute its digest, every one is a journal entry, and any one of them changing between plan and commit aborts the whole rename. For a large group that is a wide window for a conflict. It is the correct behaviour — a partially renamed group would be worse — but it means renaming a 200-host group on a busy machine may need retrying, and the UI must say why rather than showing a bare conflict.

6. **Nothing stops a user putting a private key under `connections/`.** The Include glob would read it as configuration, `config.Parse` would keep every line as `LineUnstructured`, and the file would be preserved verbatim — no key material is destroyed, but the diagnostics would fill with `unstructured_line` and the user would see their key in a Raw editor. The key-move refusal `key_destination_is_config` guards the direction this plan controls; a hand `mv` is not guarded and cannot be.

---

## Documentation this change makes untrue

Every statement that must change, with its replacement.

### `README.md`

| Line | Current | Replacement |
|---|---|---|
| 66 | 「UI 専用情報は `~/.ssh/sshc/metadata.json` に保存します。スキーマバージョン、グループ、タグ、色、メモ、お気に入り、表示順のみで…」 | 「UI 専用情報は `~/.ssh/sshc/metadata.json` に保存します。スキーマバージョン、グループの表示情報（色、メモ、表示順、共通設定）、タグ、色、メモ、お気に入り、表示順のみで、鍵本文やパスフレーズは保存しません。**どの Host がどのグループに属するかは metadata に保存しません。ディレクトリがその正本です。**」 |
| 67 | 「Host の識別は「正規化した相対パス + 具体的な主 alias」です。」 | 同文に一文追加：「グループはディレクトリなので、グループを変えるとパスが変わり、識別も変わります。移動は config と metadata を同一トランザクションで更新するため、識別が変わっても orphan にはなりません。」 |
| 68 | 「ファイルとフォルダの移動・改名・削除はまだ提供していません。`storage` に journal 付きの削除・改名プリミティブが必要で、後続の `sshc-file-operations` 計画で対応します。Host ブロックの別ファイルへの移動も同様に後続タスクです。」 | **すでに二重に誤り。** 置換：「Host ブロックの別ファイルへの移動と、グループディレクトリ間のファイル移動・グループの改名は提供しています。journal 付きの削除・改名プリミティブ（`storage.Move`、`storage.Removal`）はサブシステム4で導入済みで、鍵の trash が実際に使っています。まだ無いのは journal 付きの**ディレクトリ**作成・削除・改名と、Config Explorer 上の任意ファイル操作で、後続の `sshc-file-operations` 計画が担当します。グループ改名はディレクトリの rename ではなくファイル単位の move の集合なので、空になった元ディレクトリは残ります。」 |
| 69 | 「グループは `groups.sshc.conf` に通常の `Host` ブロックとして生成し、子グループを親より先に配置します。`Include` は具体的な Host ブロックの後、最初の catch-all ブロックの前に挿入します。」 | 「グループは `~/.ssh/connections/<group>/` ディレクトリです。`~/.ssh/config` には生成マーカーで囲まれた領域を作り、宣言されたグループごとに `Include connections/<group>/*.conf` を 1 行ずつ、深い子グループから先に並べ、最後に `Include groups.sshc.conf` を置きます。この領域は具体的な Host ブロックの後、最初の catch-all ブロックの前に挿入します。catch-all が先頭にあるなど挿入位置で優先順位が変わる場合は、自動で挿入せず候補位置と実効値の差分を提示して利用者に選ばせます。グループの共通設定は従来どおり `groups.sshc.conf` に通常の `Host` ブロックとして生成し、子グループを親より先に置きます。マーカー間の行は次回保存時に置き換えられます。」 |
| 新規（69 の後） | — | 「鍵は `~/.ssh/keys/<group>/` に置けます。鍵を移動すると、Include グラフが到達する範囲の `IdentityFile` と `CertificateFile` の行を同一トランザクションで書き換えます。`~/.ssh` 外の設定ファイルから参照されている場合は、半端に適用せず移動そのものを拒否します。macOS Keychain の項目は絶対パス（`SSH: <path>`）で識別されるため移動で壊れますが、このアプリケーションは Keychain を読み書きしないので、警告するだけで確認も修復もできません。」 |
| 76（鍵管理の境界） | 「`~/.ssh` 配下のファイルは内容と権限で分類します。」 | 同文に一文追加：「`keys/<group>/` 配下も同様に走査します。走査の深さ上限は `~/.ssh` から 8 段（`keys.maxScanDepth`）なので、グループを 7 段より深く入れ子にした鍵は `depth_exceeded` として一覧から落ちます。」 |

### `docs/superpowers/specs/2026-08-04-sshc-design.md`

| Section | Current | Replacement |
|---|---|---|
| §2.3 | 「アプリ独自形式を SSH 設定の正本にすること」 | 変更しない。ただし §13 に「ディレクトリ規約は独自形式か」の項を追加し、本計画 2 節の三段落を収める。 |
| §4.2 | 「metadata にはスキーマバージョン、グループ、タグ、色、メモ、お気に入り、表示順を保存する。」 | 「metadata にはスキーマバージョン、グループの表示情報、タグ、色、メモ、お気に入り、表示順を保存する。グループ所属は保存しない。」 さらに一文追加：「グループの正本は二つに分かれる。どのグループが存在し、どの順で読まれるかは `~/.ssh/config` の生成領域にある `Include` 行が正本であり、ある Host がどのグループに属するかは `~/.ssh/connections/` 配下のどのディレクトリにあるかが正本である。どちらも通常の OpenSSH 設定とディレクトリであり、metadata ではない。」 |
| §5.4 | 「各 Host は設定を継承するプライマリグループを一つだけ持つ。グループは親子階層を持ち…」 | 冒頭を「各 Host は設定を継承するプライマリグループを一つだけ持つ。ファイルは一つのディレクトリにしか置けないため、この制約はファイルシステムが保証する。グループ名は `connections/` からの相対ディレクトリパスであり、親子階層はパスそのものが表す。」に置換。末尾に段落追加：「グループごとに `Include` を 1 行ずつ生成する。単一のワイルドカードにしないのは、`*` が `/` を跨がないため入れ子グループに届かず、また読み込み順が glob の辞書順に決まってしまい優先順位が偶然になるためである。」 |
| §6.2 | 「`~/.ssh` 内のファイル・フォルダ作成、移動、改名」 | 「`~/.ssh` 内のファイル作成とグループディレクトリ間の移動、グループの改名。ディレクトリの作成は行うが、journal の外で行うため中断すると空ディレクトリが残る。ディレクトリの削除と改名は journal 付きプリミティブが無く、まだ行わない。」 |
| §12 条件4 | 「Include 階層、単一プライマリグループ、親子継承が機能する」 | 文言は変えない。`internal/acceptance/conditions_test.go` の proof 一覧に本計画の新規テストを追加し、`Gap` に「順序規則を実際の OpenSSH で確かめる差分試験は `ssh` がある機械でのみ成立する」を記録する。 |

### `web/src/explorer/ConfigExplorer.tsx` (or `web/src/i18n/messages.ts`)

On `main`, line 187-191 ends with "Moving, renaming and deleting files needs journalled delete and rename primitives this version does not have yet." In the current working tree that sentence has already been removed by an uncommitted i18n refactor and the note lives as `explorer.newFileNote`. Either way the note must end with: "Moving a connection between groups is done from the Connections screen. Renaming and deleting arbitrary files and folders is not offered here yet: it needs journalled directory create, remove and rename, which do not exist." Japanese: 「グループ間の移動は Connections 画面で行います。任意のファイルとフォルダの改名・削除はまだ提供していません。journal 付きのディレクトリ作成・削除・改名が必要です。」

### `docs/superpowers/plans/2026-08-04-sshc-roadmap.md`

Add a status line for this plan, and add two entries to "Known open defects in merged code", both closed by this plan: `PlanGroupInclude` counting a conditional Include as present, and `overlayLoader` modelling neither a move nor a removal. Add one entry that this plan does *not* close: journalled directory create, remove and rename remain with `sshc-file-operations`, whose scope is now exactly those three plus the Config Explorer interface.

### `docs/manual-acceptance.md`

Add M6 as described in Task 12 Step 4, and add its row to the 記録 table as 未実施.

---

## Decisions settled after review

Two of the three risks were reviewed and answered. They are recorded here rather than left in "Open questions", which is amended below.

### Decision 5: every key reference this application writes is absolute, and an unresolvable one blocks a move until it is normalised

Open question 2 asked what to do about a directive `keys.expandKeyPath` refuses to resolve. The answer has two halves, and only together do they close it.

**Half one — what this application writes.** Every `IdentityFile` and `CertificateFile` that sshc creates or rewrites is written as an absolute path. A reference written this way always resolves, so it is always indexed, so a later move can always find and rewrite it. This costs nothing and removes the whole class for anything sshc touched.

It does not, and cannot, fix what is already there. `internal/keys/references.go` lines 143-147 explain why, and the reasoning is sound: OpenSSH resolves a relative `IdentityFile` against the working directory of the `ssh` process, which is not knowable when the configuration is edited. `IdentityFile id_work` may or may not name the key being moved, and no amount of care at write time makes an existing line resolvable. The circularity is exact — the move cannot rewrite the reference to an absolute path, because rewriting it would require already knowing it names this key.

**Half two — what the move does about the rest.** The refusal rule changes from candidate (b) to candidate (a): a key move is refused when the graph contains **any** unresolved `IdentityFile` or `CertificateFile`, not only one whose base name matches. The base-name test in Task 7 Step 4 is dropped.

(a) was rejected in the original open question because it "blocks the feature for anyone with a single `%u` in an unrelated file". Half one removes that objection, because the same change adds a way out: a separate, explicit **normalise key paths** operation that rewrites resolvable-by-the-user references to absolute form, with the same line-by-line preview every other write has. The user runs it once, the unresolved set empties, and moves are available. A rule that is strict but has a documented way through is better than a rule that is loose and occasionally silent.

The remaining hole is stated rather than closed: a reference inside a file reached by an `Include` with an unsupported expansion is not in the graph at all, so it is neither resolved nor unresolved — it is invisible. A move must therefore also refuse while any `include_unsupported_expansion` diagnostic exists, which is a graph-level check the engine already produces. What no design can see at all — `ssh -i`, `ssh -F`, git's `core.sshCommand`, a LaunchAgent, `/etc/ssh/ssh_config` — stays a warning, because nothing in a configuration editor can enumerate the readers of a file.

Tasks affected: Task 7 Step 4's assertion becomes `TestKeyMoveRefusesWhileAnyKeyReferenceIsUnresolved`; a new task covers the normalisation operation and the `include_unsupported_expansion` refusal.

### Decision 6: the overlay models moves and removals — done

Risk 2 is fixed on `main` ahead of this plan, because it is a correctness gap in committed code regardless of whether directory groups are built. `overlayLoader` now carries a `gone` set alongside `pending`, `Service.validate` builds both from the whole `storage.Request` through `overlayFor`, and a pending write beats a removal so a move onto an existing path still reads its new contents. `TestOverlayLoaderHidesAMovedSourceFromReadsAndGlobs` fails without it. Tasks that assumed they had to fix this first can consume it.

### Decision 7: sshc is assumed to be the only writer of the managed layout, and the check that catches it being wrong stays

The layout this plan creates — `connections/<group>/`, `keys/<group>/`, the generated `Include` lines — is assumed to be written only by this application. That assumption is what lets the design stop accommodating arbitrary hand-written shapes inside those directories: paths there are absolute because sshc wrote them, the `Include` order is the one sshc emitted, and a group directory contains what sshc put in it.

It also repairs the awkward part of Decision 5. The strict refusal — no key move while any reference is unresolved — reads as harsh only if it is permanent. It is not: **migration is what makes the assumption true.** Migration normalises key references to absolute paths and generates the layout, and from that point every write keeps them absolute. The refusal therefore bites once, before adoption, which is exactly when the configuration is least understood and strictness is most warranted.

What does not change is the precondition and conflict machinery. `~/.ssh` has other writers whether or not the user ever opens an editor: `ssh` appends to `known_hosts`, `ssh-keygen` writes key files, `ssh-copy-id` and dotfile managers drop things in, and a second copy of sshc is a second writer. The SHA-256 precondition and the three-way conflict view are already built and cost one hash per save, so keeping them is not extra work — it is the thing that notices when the assumption is wrong. The assumption is held in the design and verified at runtime, which is the only form of it that stays true.

### Decision 8: a per-host comment is written into the configuration, and it replaces the metadata note

The same argument that motivates directory groups applies to notes: today a note lives only in `~/.ssh/sshc/metadata.json`, so it disappears for anyone who reads the configuration without sshc. A comment line above the `Host` block is plain OpenSSH and survives.

**What is attachable.** `internal/config/line.go` defines `LineComment` as "a line whose first non-whitespace character is `#`", which is the correct reading — `ssh_config` has no trailing-comment syntax, and `Host foo # bar` parses `#` and `bar` as additional patterns. The UI therefore offers whole-line comments only, and must never offer to append a comment to a directive line.

**The attachment rule.** `Block.Header` is the index of the `Host` line and `Block.Start` is `Header+1`, so comments above a block are not part of it today. The comment belonging to a Host block is defined as the run of contiguous `LineComment` lines immediately above its `Host` line, stopping at a blank line, a directive or the start of the file. A blank line separates deliberately: without that rule a file's own header comment would be adopted by whichever Host block happens to be first, and editing the block would rewrite the file's banner.

**Editing.** Saving a comment rewrites exactly those lines — inserting, replacing or deleting them — and nothing else. The existing round-trip proof (`parsed.Render()` must equal the written bytes) already enforces that everything outside the rewritten run is untouched.

**Moving.** The comment travels with its block on a move or a rename. A connection whose comment stayed behind in the old file would be worse than one with no comment, because the stale text would then describe whatever block ends up in that position.

**The note is retired.** Keeping both a comment and a `note` would mean two places for one thing, the user having to remember which they wrote in, and no way for this application to resolve them when both are set and disagree. `metadata.json` keeps only what has no representation in the configuration: colour, tags, favourite and display order. Migration writes each existing note out as a comment above its block and drops the field.

This is independent of the rest of this plan — it needs no directory layout and no file moves — and can ship on its own.

## Open questions for the author

Four things the settled decisions do not cover. Each is written as a question rather than answered, because each is a judgment call rather than a technical gap.

1. **Do group *settings* also leave `metadata.json`?** Decision 4 says metadata keeps "colour, tags, note, favourite and display order", which would exclude `GroupMetadata.Settings`. This plan keeps settings in metadata and states the reason: the natural on-disk home would be a per-group settings file inside the group directory, and that file would be picked up by the group's own `Include connections/<group>/*.conf` and read in lexical order among the host files — so the group's shared settings would beat its own hosts' values unless the file were named to sort last, which is a naming trick rather than a design. Keeping the settings in metadata and compiling them into `groups.sshc.conf` after every connections Include preserves the precedence rule exactly. If you meant settings to leave metadata too, the alternative worth considering is a second generated file per group included *after* the region — but that multiplies generated files by the number of groups.

2. ~~**What is the right rule for an unresolvable key reference?**~~ Settled — see Decision 5. Original question: Decision 1 settles the case of a reference in a file outside `~/.ssh` — refuse. It does not settle the case where `keys.expandKeyPath` refuses to resolve a directive at all (`ReasonRelativePath`, `ReasonUnsupportedToken`), because the engine then cannot prove the directive does *not* name the key being moved. Three candidate rules, in decreasing strictness: (a) refuse whenever any unresolved `IdentityFile`/`CertificateFile` exists anywhere in the graph — safe, and blocks the feature for anyone with a single `%u` in an unrelated file; (b) refuse only when an unresolved reference's final path segment equals the moved file's base name — what this plan proposes, catches the common spelling, misses `IdentityFile ../keys/work/id_work` written from an unusual working directory; (c) warn, list them, and let the user confirm. I chose (b) and the plan can be changed to (a) or (c) with one predicate.

3. **Should a journalled directory rename be built now?** This plan renames a group as N file moves, following the precedent `keys.Restore` set, and leaves the empty source directory behind with a `group_directory_leftover` notice. A single `rename(2)` on the directory would be atomic, would leave nothing behind, and would not widen the conflict window with the size of the group. It needs a new journal action, a precondition semantics for a thing that has no digest, and a rollback story — a storage-layer design decision. Building it first would delay this plan; building it later means every rename until then leaves debris.

4. **Are `connections` and `keys` the right names, and should they be configurable?** `metadata.GroupsFile` is configurable and defaults to `groups.sshc.conf`; these two are proposed as fixed. A user who already has `~/.ssh/keys/` holding ungrouped keys is not harmed — a directory is only a group when the region declares it — but they will find the application proposing to put group keys into a directory they already use for something else. Making the two names configurable is a small change to `Metadata` (two more presentation fields) and a large change to how many code paths have to ask what the names are.
