# SSH UI Delivery Roadmap

The approved design spans six independently reviewable subsystems. Each subsystem receives its own implementation plan before its code is changed, and each leaves the repository in a runnable, testable state.

1. **Foundation** — secure localhost process, OpenAPI contract, embedded React shell, macOS browser launch.
2. **Lossless config engine** — byte-preserving parser, Include graph, safe filesystem transactions, journals and history.
3. **Connections UI and groups** — form/Raw synchronization, Include explorer, group inheritance, metadata and diffs.
4. **Key vault** — inventory, generation, passphrase handling, reveal, agent/Keychain integration, trash and restore.
5. **SSH integrations** — effective config, ProxyJump diagnostics, Terminal launch, Known Hosts and remote public-key registration.
6. **Hardening and release** — fuzzing, race tests, E2E, CSP and injection suite, single-binary packaging and acceptance checks.

Plans are executed in this order. A later plan may consume only interfaces committed by earlier plans. No plan may run against the user's real `~/.ssh` in automated tests.

## Status

- Subsystem 1 (Foundation): delivered on `main`; acceptance gate verified 2026-08-04.
- Subsystem 2 (Lossless config engine): delivered on `feature/config-engine`; plan `2026-08-05-ssh-ui-config-engine-implementation-plan.md`; acceptance gate verified 2026-08-05, including a clean 60-second parser fuzz run and no new module dependency.
- Subsystem 3 (Connections UI and groups): delivered on `main`; plan `2026-08-05-ssh-ui-connections-ui-implementation-plan.md`, 10 tasks. Includes moving a host block between files, which the plan originally deferred.
- Subsystem 4 (Key vault): delivered on `main`; plan `2026-08-05-ssh-ui-key-vault-implementation-plan.md`, 9 tasks. Introduced `golang.org/x/crypto v0.54.0`.
- Subsystem 5 (SSH integrations): delivered on `feature/ssh-integrations`; plan `2026-08-05-ssh-ui-ssh-integrations-implementation-plan.md`, 9 tasks; acceptance gate verified 2026-08-05, including a clean fuzz run, an unchanged `go.mod`/`go.sum` and a `make generate` that leaves no diff. The `ssh -G` differential test subsystem 2 deferred is now implemented in `internal/effective/differential_test.go`; it compares the engine's projection against the installed OpenSSH on fixtures containing no executable directive, inside `t.TempDir()`, and skips rather than fails when `ssh` is absent.
- Subsystem 6 (Hardening and release): planned, not started. `2026-08-05-ssh-ui-hardening-release-implementation-plan.md`, 8 tasks.
- Follow-up `ssh-ui-file-operations`: not planned. Owns `~/.ssh` file and folder move, rename and delete, which subsystem 3 defers.

## Known open defects in merged code

Found while planning subsystem 6, confirmed against the tree, and owned by that plan. They are recorded here so they cannot be lost between plans.

- **Fetch Metadata is checked only on state-changing requests.** `internal/httpserver/security.go` verifies `Origin` and `Sec-Fetch-Site` only when the method is not GET or HEAD, so an authenticated API GET skips both. Design §8.1 requires `Host`, `Origin` and Fetch Metadata to be verified without qualification. The `SameSite=Strict` session cookie is what actually stops a cross-site read today, which means one mechanism is carrying a guarantee the design assigns to three. Subsystem 6 Task 1 closes it and repairs the existing tests that will start returning 403.
- **No request body ceiling.** Nothing bounds a request body before a handler decodes it, though design §8.1 requires limits on both request bodies and command output. Command output is already bounded by `platform.MaxCapturedOutput`. Subsystem 6 Task 2 adds the middleware ceiling.
- **`make fuzz` runs one target.** `go test -fuzz` accepts a single target per invocation, so the current recipe silently covers only the parser round trip no matter how many fuzz functions exist. Subsystem 6 Task 5 replaces it with a loop and a test that fails when a `Fuzz` function is not in it.
- ~~**`keys.ValidateFileName` permits reserved names.**~~ Fixed on `main`: reserved names are refused case-insensitively, because a macOS filesystem treats `Config` and `config` as one file. Original report: Generating a key named `config` into an empty `~/.ssh` would create the entry configuration file and fill it with a private key. An existing file is protected by the transaction precondition, so this only bites on a fresh workspace, but the name policy should refuse the names the application itself depends on. Found and reported rather than silently patched by the key vault subsystem, since filename policy is not its to decide.
- **No test reads the log stream.** Several plans state that secrets must never be logged, and none assert it. Subsystem 6 Task 3 adds the sweep.
- ~~**Two delivered APIs have no interface.**~~ Closed on `main`; both confirmations are now user-facing. Original report: Subsystem 5 reported both rather than inventing a design. `POST /api/v1/known-hosts/add` is covered at the service and endpoint level, but the Known Hosts panel scans and lists unverified candidates without an add affordance, so adding a scanned key is API-only — and design §6.4 requires the confirmation step to be a user-facing one. `POST /api/v1/remote-keys/plan` and `/register` have no panel at all, though design §6.6 describes a user-facing confirmation showing the alias, effective user, fingerprint and intended change.

## Interface limits accepted while closing those gaps

Reported by the agent that built the panels rather than papered over. None is a defect in what was built; each is a consequence of the API shape underneath.

- **An unsupported remote is discovered by connecting to it.** `RemoteKeyPlan.supported` is always true from the server; the probe that learns otherwise lives inside `register`, which answers `422 unsupported_remote`. Design §6.6 reads as though the manual-instructions path could be chosen before any connection, but nothing can know a remote lacks a POSIX shell without asking it. So a user on an unsupported remote opens one connection before being told to proceed by hand. Both paths are implemented and tested; the ordering is inherent, not an oversight.
- **A public key cannot be picked from the inventory.** No endpoint returns a public key's text — `KeyItem` carries `relativePath` and `fingerprint` only — while `RemoteKeyPlanRequest` needs `publicKey`. The user pastes the key line and types the file path instead of selecting from the Keys screen. A read endpoint for a public key's contents would turn that into a selector; a public key is not a secret, so this is a convenience gap rather than a security one.
- **`RemoteKeyPlan.valuesFrom` is a free-form string.** The panel renders the values it knows and falls back to printing the raw string, so an unfamiliar value degrades to jargon rather than to a confident but wrong sentence.

## Integration notes for plans 3, 4 and 5

Plans 3, 4 and 5 were written concurrently against the tree as it stood after subsystem 2. They do not conflict in design, but each was authored without seeing the others' edits, so whoever executes them must expect drift in the shared wiring and reconcile it rather than pasting a plan's wiring step verbatim.

- Execution order stays 3, then 4, then 5. A later plan may consume interfaces the earlier one committed.
- All three add routes to `api/openapi.yaml`, handlers under `internal/httpserver`, and construction code in `internal/app/run.go` and `cmd/ssh-ui/main.go`. Each plan's wiring step describes the shape it expects; adapt it to what is actually in the tree at that point.
- Home directory resolution: plans 3 and 5 agree that `os.UserHomeDir` may be called only from `cmd/ssh-ui`, and plan 5 makes `app.Run` fail with `ErrMissingHome` instead of degrading silently. This supersedes the subsystem 2 acceptance-gate grep, which assumed no package needed a home directory yet.
- Storage primitives: plan 4 Task 4 adds `Move`, `Removal` and `Note` to `storage.Manager`, plus `PendingEntry.Action`/`Target` and `Pending.CanRollback`. Plan 3 is cross-referenced to them and the `ssh-ui-file-operations` follow-up must build on them.
- Dependencies: plan 4 introduces `golang.org/x/crypto v0.54.0` and `golang.org/x/sys v0.47.0`, verified against those exact versions. Plans 3 and 5 add nothing. Read plan 5's "no new dependency" gate as "nothing beyond what plan 4 already committed", not as an unchanged `go.mod` since subsystem 2.
- **Process seam ownership, decided at execution time.** Plans 4 and 5 independently specify `internal/platform/command.go` and `internal/platform/macos/command.go` with incompatible shapes: plan 4 Task 3 defines `Command{Name, Args, Input}`, `CommandResult`, `CommandExecutor`, `macos.NewExecutor`; plan 5 Task 1 defines `Command{Path, Arguments, Stdin, Timeout, StopAfter}`, `Output`, `OutputRunner`, `macos.NewOutputRunner`, `macos.Toolchain` and the alias, hostname and port validators. Plan 5's shape is the superset, so **plan 5 Task 1 is executed first as a shared foundation**, extended so `Toolchain` also resolves `ssh-keygen` and `ssh-add` for the key vault. Plan 4 Tasks 3, 6 and 8 then *consume* `platform.Command`, `platform.Output` and `platform.OutputRunner` instead of creating them, and must not create either command file. This is a deliberate deviation from both documents, recorded here rather than resolved silently at merge time.
- **Action token ownership, decided at execution time.** Plans 4 and 5 both add one-time action tokens to `internal/session/manager.go` with incompatible shapes: plan 4 Task 7 defines `Action{Purpose, Subject}`, `ActionLifetime`, `NewManagerWithClock` and `ErrActionUnknown`/`ErrActionExpired`/`ErrActionMismatch`; plan 5 Task 5 defines `ActionRequest{Kind, Target, Evidence}`, `ActionTokenTTL`, `MaxActionTokensPerSession`, a `Manager.Now` clock field, kind constants and `ErrInvalidAction`/`ErrActionExpired`/`ErrUnknownSession`/`ErrTooManyActions`. Plan 5's is the superset — it binds a token to a digest of the exact evidence shown to the user and caps outstanding tokens — so **the session half of plan 5 Task 5 is executed first as a shared foundation**, with plan 4's two kinds added to the same constant set. Plan 4 Task 7 then keeps only its OpenAPI work and consumes the committed token API; it must not touch `internal/session`.
- **Everything that touches `api/openapi.yaml`, `internal/httpserver`, `internal/session`, `internal/app` or `cmd/ssh-ui` runs serially, one subsystem at a time.** Three plans modify all five. Parallel execution there produces guaranteed conflicts and, worse, silently divergent route tables and generated models.
- Execution tracks after that shared task: plan 3 touches `internal/application`, `internal/httpserver`, `api` and `web`; plan 4 touches `internal/keys`, `internal/storage`, `internal/platform/macos/keyagent*`; plan 5 touches `internal/effective`, `internal/platform` and its own handlers. Only the HTTP, `app.Run` and `main.go` surfaces are shared, so the API and wiring tasks of the three plans run serially at the end, never concurrently.
- Confirmation gates: plan 5 splits design §8.3 into evaluation confirmation (`Match exec` only, since that is the sole directive OpenSSH runs while parsing) and connection confirmation (any executable directive). Plan 3's Host detail `Effective` and `Diagnostics` placeholders must hand over to those gates rather than inventing a third one.

## Toolchain decision

The local machine uses the Go 1.26.5 toolchain through Go's official toolchain switching, alongside Node 22.19.0, npm 11.7.0 and OpenSSH 10.2p1. The foundation therefore targets Echo v5.3.1 directly. Go, npm and project dependency installation were explicitly approved on 2026-08-04.

Frontend versions selected for the foundation are React 19.2.8, Vite 8.1.5, Tailwind CSS 4.3.3, TypeScript 5.9.3 and Vitest 4.1.1. TypeScript stays on the latest 5.x release because openapi-typescript 7.13.0 declares a `^5.x` peer dependency. Package-lock and go.sum are committed so all transitive versions remain reproducible.
