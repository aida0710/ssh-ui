# SSH UI Password Authentication Implementation Plan

**Status:** design, not yet implemented.

**Goal:** For a host that only accepts password authentication, let the user store the password once and have `ssh` receive it without typing. No `sshpass`, no `expect`, no pty puppetry: OpenSSH already has a supported mechanism for handing a secret to the client from a program, and this plan uses it. The password lives in the macOS login Keychain, never in `~/.ssh` and never in `metadata.json`, and the feature is opt-in per host.

**Architecture:** One new package, `internal/secret`, owning "store, fetch and forget one named secret in the login Keychain" through the existing `platform.OutputRunner`. `cmd/ssh-ui` gains one argv branch, `ssh-ui askpass`, which is the program `ssh` executes to obtain the password; it is the same binary so there is nothing extra to install, sign or keep in step. `internal/platform/macos/terminal.go` learns a second AppleScript that passes environment assignments as `argv`, exactly as the existing one passes the alias. `internal/diagnostics` decides whether a host is eligible and composes the command. Nothing about the configuration files changes: this feature writes no `ssh_config` byte.

**Tech Stack:** Go 1.26.5 (standard library only for this plan — no new module, and nothing new linked into the binary), Echo v5.3.1, oapi-codegen v2.7.0, React 19.2.8, TypeScript 5.9.3, Vitest 4.1.1, Playwright 1.62.1, `/usr/bin/security` and `/usr/bin/osascript` from the base macOS install, OpenSSH ≥ 8.4 (macOS ships 9.x/10.x).

## The mechanism, demonstrated rather than recalled

OpenSSH reads a passphrase or password through `read_passphrase()`. Since 8.4 that function consults two variables:

- `SSH_ASKPASS` — the program to run. Its single argument is the prompt text. Whatever it writes to standard output is the secret.
- `SSH_ASKPASS_REQUIRE` — `never`, `prefer` or `force`. `force` uses the askpass program whether or not a tty and whether or not `DISPLAY` is set.

Verified against OpenSSH 9.6p1 with no tty and no X display:

```console
$ printf '#!/bin/sh\necho hunter2\n' > ap.sh && chmod +x ap.sh
$ ssh-keygen -q -t ed25519 -N hunter2 -f enc_key

$ SSH_ASKPASS=./ap.sh SSH_ASKPASS_REQUIRE=force ssh-keygen -y -f enc_key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwctLWQ... probe

$ ssh-keygen -y -f enc_key < /dev/null
Enter passphrase: Load key "enc_key": incorrect passphrase supplied to decrypt private key
```

`strings /usr/bin/ssh` contains `SSH_ASKPASS_REQUIRE` and `force`. The remote password prompt goes through the same `read_passphrase()`, so the same route carries it.

This is worth stating plainly because the folklore answer is `sshpass`, which is not in a base macOS install, is a pty trick rather than a supported interface, and would be a new dependency this project does not take.

## 1. What the helper must refuse, and why that is the interesting part

`SSH_ASKPASS_REQUIRE=force` routes **every** interactive question to the helper, not only the password. At least three arrive on that channel:

| Prompt | What answering it automatically would mean |
| --- | --- |
| `ops@203.0.113.10's password: ` | the intended case |
| `Enter passphrase for key '/Users/x/.ssh/id_ed25519': ` | a different secret; answering with the account password is wrong |
| `Are you sure you want to continue connecting (yes/no/[fingerprint])? ` | **defeating host key verification** |

The third is the one that matters. A helper that answers everything turns a first-contact man-in-the-middle warning into a silent `yes`. This plan's helper therefore classifies on the prompt text and answers exactly one shape:

```go
// AnswerablePrompt reports whether this prompt is the remote account's
// password and nothing else.
//
// The default is refusal. A prompt this function does not recognise gets no
// answer, ssh fails, and the user sees why — which is the correct outcome for
// a question nobody has decided how to answer. In particular the host key
// question is never answerable here: a helper that says yes to it has removed
// the only check that a first connection performs.
func AnswerablePrompt(prompt string) bool
```

The rule: the prompt must end in `password: ` (OpenSSH's `askpass` prompt for `SSH_AUTH_PASSWORD`, formatted as `%.30s@%.128s's password: `), and must not contain `passphrase` or `continue connecting` or `fingerprint`. Table-tested against the literal prompt strings OpenSSH emits.

**The consequence, stated rather than hidden.** Because the host key question cannot be answered, the very first connection to an unknown host fails when the password helper is armed. That is not a defect to be worked around; it is the reason the feature is safe. The interface enforces it in advance: **the "connect with the saved password" action is offered only when the host's key is already in `known_hosts`.** This application owns the Known Hosts screen and can check that before offering the button, so the user is told to verify and add the key first rather than discovering a broken connection.

## 2. Where the password lives

The macOS login Keychain, through `/usr/bin/security`, which is the same shape of platform integration the project already uses for `osascript` and `ssh-add --apple-use-keychain`.

```
security add-generic-password -U -s ssh-ui-password -a <alias> -T <helper path> -w <password>
security find-generic-password    -s ssh-ui-password -a <alias> -w
security delete-generic-password  -s ssh-ui-password -a <alias>
```

`-s ssh-ui-password` namespaces every item this feature creates, so `delete` can never reach an item some other tool made. `-T <helper path>` puts the helper on the item's access-control list, so `ssh` invoking it does not raise a Keychain dialog on every connection.

**Three honest statements about this.**

1. `add-generic-password` has no way to read the secret from standard input, so the password is in the process's `argv` for the duration of that one call and visible to `ps`. There is no stdlib route to the Security framework without cgo, and this project is cgo-free. The window is short and any process that can read your `argv` can also execute the helper — see (2) — so this does not change the reachable outcome, but it should not be discovered later by reading the code.

2. The `-T` ACL restricts which *binaries* may read the item without a prompt. The helper is one of them, and the helper prints the secret to standard output. Anything that can execute the helper as you can therefore obtain the password by naming the alias. This is a confused deputy and it has no fix inside this design. It is the reason the feature is opt-in per host and the reason the UI says, in one sentence and not in a footnote, that this is weaker than a key.

3. The password is the *remote account's* credential, not a local one. Losing it is a different order of event from losing a key passphrase, because the same password is often reused. The UI does not offer to store a password for a host whose configuration also names an `IdentityFile`; it offers to use the key.

## 3. What the Terminal receives

The existing `TerminalScript` is a constant, and the alias is delivered through `on run argv` so that no alias is ever concatenated into AppleScript. That property is not negotiable and the new script keeps it, extending the same technique to the environment assignments:

```applescript
on run argv
	set targetAlias to item 1 of argv
	set helperPath to item 2 of argv
	set sshCommand to "SSH_ASKPASS=" & quoted form of helperPath & ¬
		" SSH_ASKPASS_REQUIRE=force" & ¬
		" SSH_UI_ASKPASS_ALIAS=" & quoted form of targetAlias & ¬
		" ssh -o NumberOfPasswordPrompts=1 -- " & quoted form of targetAlias
	tell application "Terminal"
		activate
		do script sshCommand
	end tell
end run
```

- **The alias is passed twice**, once as the ssh operand and once in `SSH_UI_ASKPASS_ALIAS`. The helper identifies the host from the variable, never by parsing it out of the prompt text — prompt parsing would tie the feature to OpenSSH's format string, and the prompt carries the *resolved* user and hostname rather than the alias the Keychain item is filed under.
- **`NumberOfPasswordPrompts=1`** so a wrong stored password fails once instead of three times, which on some servers counts toward a lockout.
- Both `quoted form of` and `platform.ValidateAlias` still stand between an alias and either interpreter, unchanged.
- The environment assignments are visible in the Terminal window's scrollback. That discloses the helper's path and the alias. It does not disclose the password.

## 4. Eligibility

`GET /api/v1/hosts/{alias}/password` answers a small record and never the secret:

```go
type PasswordStatus struct {
    Stored          bool   // an item exists for this alias
    Eligible        bool   // offering to store one is sensible
    Blocker         string // why not, when Eligible is false
}
```

`Eligible` is false, with a `Blocker`, when any of these hold. Each is a fact the application already computes:

| Blocker | Source |
| --- | --- |
| `identity_file_configured` | the projection resolves an `IdentityFile` for this alias |
| `host_key_unknown` | no `known_hosts` entry matches the resolved hostname and port |
| `password_auth_disabled` | the projection resolves `PasswordAuthentication no` |
| `alias_not_simple` | `Projection.Simple()` is false — a wildcard or `Match` decides this host, so which host the password would go to is not knowable here |

The last one matters more than it looks. A password sent to the wrong machine is a credential disclosure to that machine. When the engine will not commit to a single destination, this feature declines.

## Out of Scope

- Password authentication for anything other than opening a Terminal session. `ssh -G`, the reachability probe and the authentication test keep `BatchMode`-shaped behaviour and never receive a stored password.
- Keyboard-interactive with more than one prompt, and any two-factor flow. The helper answers one password prompt.
- Storing a password for a host whose key is not yet known. The Known Hosts screen already scans and adds; that is the prerequisite, not part of this.
- Any non-macOS Keychain. `internal/secret` is one interface with one implementation; a second platform would add a second implementation and nothing else.
- Rotating or expiring stored passwords.

## File Structure

```
cmd/ssh-ui/main.go                       # + one argv branch before flag.Parse
cmd/ssh-ui/askpass.go                    # new: the helper's whole behaviour
cmd/ssh-ui/askpass_test.go               # new
internal/secret/secret.go                # new: Store, Fetch, Forget, over platform.OutputRunner
internal/secret/secret_test.go           # new: argv assertions against a recording runner
internal/platform/macos/terminal.go      # + TerminalPasswordScript, LaunchWithPassword
internal/platform/macos/terminal_test.go # + argv and script assertions
internal/diagnostics/password.go         # new: eligibility, command composition
internal/diagnostics/password_test.go    # new
internal/httpserver/password.go          # new: three routes, one action token
internal/httpserver/password_test.go     # new
api/openapi.yaml                         # + PasswordStatus, three operations
web/src/diagnostics/PasswordPanel.tsx    # new
web/src/i18n/messages.ts                 # + en and ja
web/e2e/password.spec.ts                 # new
```

## Task 1: One named secret in the Keychain

**Files:** create `internal/secret/secret.go`, `internal/secret/secret_test.go`.

**Interfaces:**

```go
package secret

// Store is where a named secret lives. One implementation, the macOS login
// Keychain, reached through /usr/bin/security so that no test can touch a real
// keychain without a real runner.
type Store interface {
    Store(ctx context.Context, name, secret string) error
    Fetch(ctx context.Context, name string) (string, error)
    Forget(ctx context.Context, name string) error
    Has(ctx context.Context, name string) (bool, error)
}

var ErrNotFound = errors.New("no secret is stored under that name")

type Keychain struct {
    Runner  platform.OutputRunner
    Program string        // "/usr/bin/security"
    Service string        // "ssh-ui-password"
    Allow   []string      // -T entries; the helper's absolute path
    Timeout time.Duration
}
```

**What it must not change:** nothing. New package, no existing import.

**Tests.** A recording `platform.OutputRunner`, never the real program.
- `TestStorePassesTheServiceAccountAndACL` — argv is exactly `[-U -s ssh-ui-password -a bastion -T /Applications/… -w hunter2]`, in that order.
- `TestFetchReturnsTheTrimmedSecret` — `security` prints a trailing newline; the returned secret has it removed and nothing else.
- `TestFetchMapsExitCode44ToErrNotFound` — `security` exits 44 for "The specified item could not be found in the keychain"; that is `ErrNotFound`, not a generic failure.
- `TestForgetIsIdempotent` — a missing item is not an error.
- `TestNameIsRefusedWhenItIsNotASafeAlias` — `platform.ValidateAlias` guards the account name, so no argument can begin with `-`.
- `TestNoMethodEverLogsTheSecret` — the package has no logger; asserted by grepping the compiled package for a `log` import in a `go/parser` test, in the same spirit as the existing "must not log" assertions.

**Verification:** `go test ./internal/secret -v`; `go vet ./internal/secret`.

## Task 2: The askpass helper

**Files:** create `cmd/ssh-ui/askpass.go`, `cmd/ssh-ui/askpass_test.go`; modify `cmd/ssh-ui/main.go`.

**Interfaces:**

```go
// AnswerablePrompt reports whether this prompt asks for the remote account's
// password. Everything else — a key passphrase, the host key question, an
// unrecognised prompt — is refused.
func AnswerablePrompt(prompt string) bool

// runAskpass is the whole of `ssh-ui askpass <prompt>`. It writes the secret
// and nothing else on standard output, and returns a non-zero status without
// writing anything when it will not answer.
func runAskpass(ctx context.Context, args []string, env func(string) string,
    store secret.Store, out io.Writer, errOut io.Writer) int
```

`main` branches before `flag.Parse()`, because `flag` would otherwise consume the prompt:

```go
if len(os.Args) > 1 && os.Args[1] == "askpass" {
    os.Exit(runAskpass(context.Background(), os.Args[2:], os.Getenv, keychain, os.Stdout, os.Stderr))
}
```

**What it must not change:** the existing `-open` flag, the URL printing, the signal handling. `ssh-ui` with no arguments behaves exactly as it does today.

**Tests.**
- `TestAnswerablePromptAcceptsOnlyThePasswordPrompt` — a table carrying OpenSSH's literal prompts: `ops@203.0.113.10's password: ` accepted; `Enter passphrase for key '/x/id_ed25519': `, `Are you sure you want to continue connecting (yes/no/[fingerprint])? `, `Please type 'yes', 'no' or the fingerprint: `, `Verification code: `, the empty string, all refused.
- `TestAskpassRefusesWithoutAnAlias` — `SSH_UI_ASKPASS_ALIAS` unset means exit 1 and an empty stdout, even for a well-formed password prompt.
- `TestAskpassWritesOnlyTheSecret` — stdout is exactly the secret, no newline beyond the one OpenSSH tolerates, no banner, no log line.
- `TestAskpassWritesNothingOnRefusal` — the refusal path's stdout is zero bytes. A helper that prints a diagnostic to stdout would hand OpenSSH that diagnostic as the password.
- `TestAskpassReportsAMissingItemDistinctly` — `ErrNotFound` exits 2 with a message on stderr; any other failure exits 1.

**Verification:** `go test ./cmd/ssh-ui -v`. Then, by hand and once: arm the helper against a throwaway account on a host you control and confirm the connection succeeds; then delete the Keychain item and confirm it fails cleanly rather than hanging.

## Task 3: Terminal launch with the helper armed

**Files:** modify `internal/platform/macos/terminal.go`, `internal/platform/macos/terminal_test.go`.

**Interfaces:**

```go
const TerminalPasswordScript = `…`   // the script in section 3, verbatim

// LaunchWithPassword opens ssh in Terminal with the askpass helper armed.
// helperPath must be absolute; a relative path is refused before osascript is
// reached, so nothing resolves the helper through PATH.
func (t Terminal) LaunchWithPassword(ctx context.Context, alias, helperPath string) error
```

**What it must not change:** `TerminalScript` and `Launch`. A host without a stored password takes exactly the path it takes today, byte for byte.

**Tests.**
- `TestLaunchWithPasswordPassesTheAliasAndHelperAsArguments` — the runner sees `argv = ["-", alias, helperPath]` and the stdin is `TerminalPasswordScript` unmodified.
- `TestTerminalPasswordScriptNeverInterpolates` — the constant contains neither `%s` nor any alias; asserted by searching the constant for `item 1 of argv` and `item 2 of argv` and for the absence of string concatenation with anything but those.
- `TestLaunchWithPasswordRefusesARelativeHelper`.
- `TestLaunchWithPasswordRefusesAnUnsafeAlias` — the existing `platform.ValidateAlias` guard still fires first.

**Verification:** `go test ./internal/platform/macos -v`.

## Task 4: Eligibility and the routes

**Files:** create `internal/diagnostics/password.go`, `internal/httpserver/password.go` and their tests; modify `api/openapi.yaml`; modify `internal/session/action.go`.

**Interfaces:**

```go
// In internal/session, one new action kind. Storing a password is a
// confirmation-bearing operation like revealing a private key.
ActionStorePassword = "password.store"
```

```
GET    /api/v1/hosts/{alias}/password   → PasswordStatus     (never the secret)
PUT    /api/v1/hosts/{alias}/password   → 204                (requires the action token)
DELETE /api/v1/hosts/{alias}/password   → 204
```

**What it must not change:** `terminalCommand` keeps returning the plain `ssh -- alias` for a host with no stored password. For a host with one it returns the full armed command, because the copyable command must be the command that runs — a copy that silently differs from the launch is worse than no copy.

**Tests.**
- `TestPasswordStatusRefusesAHostWithAnIdentityFile`, `…AnUnknownHostKey`, `…PasswordAuthenticationNo`, `…ANonSimpleAlias` — one per blocker, each asserting the `Blocker` string.
- `TestStorePasswordRequiresAConfirmation` — without the action header, 403 and nothing reaches the store.
- `TestStoredPasswordIsNeverReturnedByAnyRoute` — a full route-table sweep asserting that no response body of any operation contains the stored value. This is the assertion that must not be allowed to rot.
- `TestDeleteRemovesTheItemAndIsIdempotent`.
- In `internal/acceptance`: `TestPasswordNeverReachesTheLogOrTheConfiguration` — store a password, then assert the captured log and every file under the fixture `~/.ssh` contain none of its bytes.

**Verification:** `go test ./internal/diagnostics ./internal/httpserver ./internal/session ./internal/acceptance -v`; `make verify-generated` after the OpenAPI edit.

## Task 5: The interface

**Files:** create `web/src/diagnostics/PasswordPanel.tsx` and its test; modify `web/src/i18n/messages.ts`; create `web/e2e/password.spec.ts`.

The panel sits inside the Host editor's Diagnostics tab and has three states:

1. **Not eligible** — the blocker, in a sentence, with what to do instead. For `host_key_unknown` that sentence links to the Known Hosts screen, because the fix is there.
2. **Eligible, nothing stored** — a password field, and above the button the plain statement: *"Anything running as you can read this password by running ssh-ui's helper. A key is stronger. Store one only for a server that will not take a key."* Not a tooltip, not a disclosure triangle.
3. **Stored** — no field, the fact that one is stored, a delete button, and the armed command shown exactly as it will run.

**Tests.**
- `renders the blocker instead of the field when a key is configured`
- `never puts the stored password in the DOM` — after a store, the document text contains no occurrence of the typed value.
- `asks for a confirmation before storing`
- e2e `password.spec.ts`: the fixture host has no known key, so the panel shows the `host_key_unknown` blocker; after adding a key through the Known Hosts screen the field appears. Nothing in the e2e suite stores a real password or launches a real Terminal — `terminalLaunch` is already the one route the suite never calls.

**Verification:** `npm test --prefix web`; `npm run typecheck --prefix web`; `make e2e`.

## Acceptance Gate

```sh
gofmt -l .            # prints nothing
go vet ./...
make verify-generated # no diff
make test
make e2e
```

Plus four statements that must be true and are each covered by a named test above:

1. The helper answers the password prompt and nothing else — in particular never the host key question.
2. No route, no log line, no file under `~/.ssh` ever contains a stored password.
3. A host with no stored password takes today's code path unchanged.
4. The copyable command and the launched command are the same command.

## Known Limitations

- **The confused deputy has no fix here.** Any process that can execute the helper as you can read any stored password. The Keychain ACL protects against other binaries, not against ours being used as the tool. The feature is opt-in per host and says so on screen, which is mitigation by informed consent, not by mechanism.
- **The password is briefly in `argv` when it is stored,** because `security` cannot read it from standard input and this project does not use cgo.
- **The first connection to an unknown host fails when the helper is armed.** This is by design, and the interface refuses to arm it until the host key is known — but a key that *changes* later produces a failed connection rather than the usual warning, and the user has to go and look at the Known Hosts screen to see why.
- **One prompt only.** A server that asks for a password and then a second factor will fail at the second prompt.
