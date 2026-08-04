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

The local machine uses the Go 1.26.5 toolchain through Go's official toolchain switching, alongside Node 22.19.0, npm 11.7.0 and OpenSSH 10.2p1. The foundation therefore targets Echo v5.3.1 directly. Go, npm and project dependency installation were explicitly approved on 2026-08-04.

Frontend versions selected for the foundation are React 19.2.8, Vite 8.1.5, Tailwind CSS 4.3.3, TypeScript 5.9.3 and Vitest 4.1.1. TypeScript stays on the latest 5.x release because openapi-typescript 7.13.0 declares a `^5.x` peer dependency. Package-lock and go.sum are committed so all transitive versions remain reproducible.
