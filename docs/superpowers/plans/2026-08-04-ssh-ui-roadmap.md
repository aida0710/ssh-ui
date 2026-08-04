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
- Subsystem 3 (Connections UI and groups): planned, not started. `2026-08-05-ssh-ui-connections-ui-implementation-plan.md`, 10 tasks.
- Subsystem 4 (Key vault): planned, not started. `2026-08-05-ssh-ui-key-vault-implementation-plan.md`, 9 tasks.
- Subsystem 5 (SSH integrations): planned, not started. `2026-08-05-ssh-ui-ssh-integrations-implementation-plan.md`, 9 tasks.
- Subsystem 6 (Hardening and release): not planned.
- Follow-up `ssh-ui-file-operations`: not planned. Owns `~/.ssh` file and folder move, rename and delete, which subsystem 3 defers.

## Integration notes for plans 3, 4 and 5

Plans 3, 4 and 5 were written concurrently against the tree as it stood after subsystem 2. They do not conflict in design, but each was authored without seeing the others' edits, so whoever executes them must expect drift in the shared wiring and reconcile it rather than pasting a plan's wiring step verbatim.

- Execution order stays 3, then 4, then 5. A later plan may consume interfaces the earlier one committed.
- All three add routes to `api/openapi.yaml`, handlers under `internal/httpserver`, and construction code in `internal/app/run.go` and `cmd/ssh-ui/main.go`. Each plan's wiring step describes the shape it expects; adapt it to what is actually in the tree at that point.
- Home directory resolution: plans 3 and 5 agree that `os.UserHomeDir` may be called only from `cmd/ssh-ui`, and plan 5 makes `app.Run` fail with `ErrMissingHome` instead of degrading silently. This supersedes the subsystem 2 acceptance-gate grep, which assumed no package needed a home directory yet.
- Storage primitives: plan 4 Task 4 adds `Move`, `Removal` and `Note` to `storage.Manager`, plus `PendingEntry.Action`/`Target` and `Pending.CanRollback`. Plan 3 is cross-referenced to them and the `ssh-ui-file-operations` follow-up must build on them.
- Dependencies: plan 4 introduces `golang.org/x/crypto v0.54.0` and `golang.org/x/sys v0.47.0`, verified against those exact versions. Plans 3 and 5 add nothing. Read plan 5's "no new dependency" gate as "nothing beyond what plan 4 already committed", not as an unchanged `go.mod` since subsystem 2.
- **Process seam ownership, decided at execution time.** Plans 4 and 5 independently specify `internal/platform/command.go` and `internal/platform/macos/command.go` with incompatible shapes: plan 4 Task 3 defines `Command{Name, Args, Input}`, `CommandResult`, `CommandExecutor`, `macos.NewExecutor`; plan 5 Task 1 defines `Command{Path, Arguments, Stdin, Timeout, StopAfter}`, `Output`, `OutputRunner`, `macos.NewOutputRunner`, `macos.Toolchain` and the alias, hostname and port validators. Plan 5's shape is the superset, so **plan 5 Task 1 is executed first as a shared foundation**, extended so `Toolchain` also resolves `ssh-keygen` and `ssh-add` for the key vault. Plan 4 Tasks 3, 6 and 8 then *consume* `platform.Command`, `platform.Output` and `platform.OutputRunner` instead of creating them, and must not create either command file. This is a deliberate deviation from both documents, recorded here rather than resolved silently at merge time.
- Execution tracks after that shared task: plan 3 touches `internal/application`, `internal/httpserver`, `api` and `web`; plan 4 touches `internal/keys`, `internal/storage`, `internal/platform/macos/keyagent*`; plan 5 touches `internal/effective`, `internal/platform` and its own handlers. Only the HTTP, `app.Run` and `main.go` surfaces are shared, so the API and wiring tasks of the three plans run serially at the end, never concurrently.
- Confirmation gates: plan 5 splits design §8.3 into evaluation confirmation (`Match exec` only, since that is the sole directive OpenSSH runs while parsing) and connection confirmation (any executable directive). Plan 3's Host detail `Effective` and `Diagnostics` placeholders must hand over to those gates rather than inventing a third one.

## Toolchain decision

The local machine uses the Go 1.26.5 toolchain through Go's official toolchain switching, alongside Node 22.19.0, npm 11.7.0 and OpenSSH 10.2p1. The foundation therefore targets Echo v5.3.1 directly. Go, npm and project dependency installation were explicitly approved on 2026-08-04.

Frontend versions selected for the foundation are React 19.2.8, Vite 8.1.5, Tailwind CSS 4.3.3, TypeScript 5.9.3 and Vitest 4.1.1. TypeScript stays on the latest 5.x release because openapi-typescript 7.13.0 declares a `^5.x` peer dependency. Package-lock and go.sum are committed so all transitive versions remain reproducible.
