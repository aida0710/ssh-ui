# SSH UI Delivery Roadmap

The approved design spans six independently reviewable subsystems. Each subsystem receives its own implementation plan before its code is changed, and each leaves the repository in a runnable, testable state.

1. **Foundation** — secure localhost process, OpenAPI contract, embedded React shell, macOS browser launch.
2. **Lossless config engine** — byte-preserving parser, Include graph, safe filesystem transactions, journals and history.
3. **Connections UI and groups** — form/Raw synchronization, Include explorer, group inheritance, metadata and diffs.
4. **Key vault** — inventory, generation, passphrase handling, reveal, agent/Keychain integration, trash and restore.
5. **SSH integrations** — effective config, ProxyJump diagnostics, Terminal launch, Known Hosts and remote public-key registration.
6. **Hardening and release** — fuzzing, race tests, E2E, CSP and injection suite, single-binary packaging and acceptance checks.

Plans are executed in this order. A later plan may consume only interfaces committed by earlier plans. No plan may run against the user's real `~/.ssh` in automated tests.

## Toolchain decision

The local machine currently has Go 1.24.11, Node 22.19.0, npm 11.7.0 and OpenSSH 10.2p1. Echo v5 requires Go 1.25 or newer, so the foundation uses the maintained Echo v4.15.4 line instead of installing a new Go toolchain. The project can migrate to Echo v5 after Go is upgraded intentionally.

Frontend versions selected for the foundation are React 19.2.8, Vite 8.1.5, Tailwind CSS 4.3.3, TypeScript 7.0.2 and Vitest 4.1.1. Package-lock and go.sum are committed so all transitive versions remain reproducible.
