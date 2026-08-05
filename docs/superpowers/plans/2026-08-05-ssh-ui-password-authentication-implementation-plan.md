# SSH UI Password Authentication Implementation Plan

**Status:** design, not yet implemented.

**Goal:** For a host that only accepts password authentication, let the user store the password once and have `ssh` receive it without typing. No `sshpass`, no `expect`, no pty puppetry: OpenSSH already has a supported mechanism for handing a secret to the client from a program, and this plan uses it. The passwords live in one encrypted file inside the workspace, so they travel with everything else the remote-sync plan carries.

**Architecture:** One new package, `internal/secret`, owning an encrypted vault at `~/.ssh/ssh-ui/secrets`: AES-256-GCM with an Argon2id-derived key, opened by a passphrase this application never stores. `cmd/ssh-ui` gains one argv branch, `ssh-ui askpass`, which is the program `ssh` executes to obtain the password; it holds no key and decrypts nothing, and instead asks the running, unlocked ssh-ui over the loopback interface with a one-time token that process minted. `internal/platform/macos/terminal.go` learns a second AppleScript that passes environment assignments as `argv`, exactly as the existing one passes the alias. `internal/diagnostics` decides whether a host is eligible and composes the command. Nothing about the configuration files changes: this feature writes no `ssh_config` byte.

**Tech Stack:** Go 1.26.5 (standard library plus `golang.org/x/crypto/argon2`, from the module already committed — `go.mod` and `go.sum` are unchanged), Echo v5.3.1, oapi-codegen v2.7.0, React 19.2.8, TypeScript 5.9.3, Vitest 4.1.1, Playwright 1.62.1, `/usr/bin/osascript` from the base macOS install, OpenSSH ≥ 8.4 (macOS ships 9.x/10.x).

## Why not the Keychain

The first draft of this plan put the password in the macOS login Keychain, and it was wrong for one reason: **a Keychain item belongs to a machine, and these have to travel.** The point of the remote-sync plan is that a second machine gets the same `~/.ssh`, and a password that stays behind is a feature that works on one laptop and silently does not on the other.

So the store is a file in the workspace, which is what syncs. That has a consequence that must be paid rather than argued away: the file sits on disk where any process running as the user can read it. It is therefore encrypted before it is written, with a key derived from a passphrase this application does not store anywhere — and the whole design follows from having to keep working without that passphrase on disk.

The exchange is a good one. The Keychain design had a confused deputy with no fix: anything that could execute the helper could ask it for any password, at any time, forever. This one cannot be attacked that way, because the helper cannot decrypt anything and the process that can must be running and unlocked and must have just been asked by the user to open that connection.

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

`~/.ssh/ssh-ui/secrets`, one file, encrypted. Implemented in `internal/secret/vault.go`.

```
magic 15 | envelope 1 | kdf 1 | time 4 | memory 4 | threads 1 | saltLen 1 | salt | nonce 12 | AES-256-GCM(…)
└──────────────────────── authenticated as additional data ────────────────────────┘
```

The plaintext is a JSON document mapping alias to password. The **header is the AEAD's additional data**, so the KDF cost cannot be rewritten down and replayed: change one byte of it and the open fails rather than deriving a cheaper key.

**The decisions inside that, and why.**

- **Argon2id, not PBKDF2.** This file leaves the machine — that is the whole point — so the threat is an offline attack by someone who obtained a copy. `golang.org/x/crypto/argon2` costs no new module (`x/crypto` is already a direct dependency and `x/sys` already indirect; `go.mod` and `go.sum` are unchanged), and it links `x/sys` into the shipped binary for the first time, which the release check should be told.
- **A cost ceiling on read.** The header states how much work opening costs, and this file *arrives* — from another machine, a bucket, a restore. `readHeader` refuses time > 16, memory > 1 GiB, threads > 16 before deriving anything. This is not theoretical: the first run of this package's own tamper test flipped one bit in the cost field, turned time from 3 into 65539, and asked for about ninety minutes of one core. The test hung for five minutes before anyone looked. Refusing high parameters is not a weakening, because the header is authenticated and a real attacker cannot lower the true cost undetected; it only stops work being started that will never be worth finishing.
- **A 12-rune minimum passphrase and no character-class rule.** Class rules push people towards short strings they cannot remember, and length is what makes an offline attack expensive.
- **A fresh nonce per seal**, so two saves of the same content are different bytes and neither reveals that they are the same.
- **Neither the passwords nor the aliases appear in the sealed bytes.** The set of hosts that have a stored password is not something an observer of the file should learn.

**What is still true and must be said on screen.** The password is the *remote account's* credential, and the same password is often reused elsewhere. The UI does not offer to store one for a host whose configuration already names an `IdentityFile`; it offers to use the key.

## 2a. How the helper gets the password without holding the key

The helper is spawned by `ssh`, not by this application, and it cannot be given the passphrase — putting it in the environment would put it in the process table and defeat the encryption entirely.

So it does not decrypt. It asks:

This diagram was wrong about the invocation, and the error shipped. `SSH_ASKPASS`
names a *program*: OpenSSH execs it with the prompt as its only argument, with no
shell in between, so no subcommand word can reach it. The binary decides it is
the helper from the environment — the one-time token and the endpoint, which only
this application ever sets — and `ssh-ui askpass "<prompt>"` remains the way to
run it by hand. Until that was fixed, `ssh` started a second copy of the whole
application, browser and all, and got no password. The integration suite against
a real sshd is what found it; nothing hermetic could have.

```
ssh  ──execs──▶  ssh-ui "<prompt>"   (SSH_UI_ASKPASS_TOKEN et al. in the environment)
                        │  POST http://127.0.0.1:<port>/askpass
                        │  X-SSH-UI-Askpass: <one-time token>
                        │  {"alias":"bastion","prompt":"ops@…'s password: "}
                        ▼
                  the running ssh-ui, vault unlocked in memory
```

- **The token is minted when the user clicks connect**, is bound to that alias, is single-use and expires in two minutes. Running the helper by hand obtains nothing: there is no token, and a token is spent by the connection it was made for.
- **The prompt rule is applied server-side as well**, so it cannot be skipped by invoking the helper differently. The helper checks it too, only so that an unanswerable prompt costs no round trip and spends no token.
- **The helper refuses any endpoint that is not `127.0.0.1`.** The URL arrives in an environment variable, so it is input; an exported `SSH_UI_ASKPASS_URL` pointing elsewhere would otherwise turn the helper into an exfiltration tool for the password it is about to fetch.
- **The endpoint is not under `/api/`.** It authenticates by token alone — no session cookie, no CSRF — and requires `Content-Type: application/json` and a custom header, both of which force a CORS preflight this server does not answer, so no web page can reach it however much it knows.
- **The vault must be unlocked**, which means the application must be running and the user must have entered the passphrase this session. That is a real cost in convenience and it is what replaces the Keychain's confused deputy with something bounded.

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

- **The alias is passed twice**, once as the ssh operand and once in `SSH_UI_ASKPASS_ALIAS`, alongside `SSH_UI_ASKPASS_URL` and `SSH_UI_ASKPASS_TOKEN`. The helper identifies the host from the variable, never by parsing it out of the prompt text — prompt parsing would tie the feature to OpenSSH's format string, and the prompt carries the *resolved* user and hostname rather than the alias the Keychain item is filed under.
- **`NumberOfPasswordPrompts=1`** so a wrong stored password fails once instead of three times, which on some servers counts toward a lockout.
- Both `quoted form of` and `platform.ValidateAlias` still stand between an alias and either interpreter, unchanged.
- The environment assignments are visible in the Terminal window's scrollback and in the process table. That discloses the helper's path, the alias, the loopback port and a token that is single-use, bound to that alias and dead in two minutes. It does not disclose the password.

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
internal/secret/vault.go                 # new: the encrypted vault, its envelope and its cost ceiling
internal/secret/vault_test.go            # new
internal/secret/service.go               # new: the unlocked vault, its writes, its one-time tokens
internal/secret/service_test.go          # new
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

## Task 1: The encrypted vault  ✅ implemented

**Files:** `internal/secret/vault.go`, `internal/secret/vault_test.go`.

**Interfaces:**

```go
func Create(passphrase string) (*Vault, error)          // ErrWeakPassphrase below 12 runes
func Open(sealed []byte, passphrase string) (*Vault, error)
func (v *Vault) Seal() ([]byte, error)                  // fresh nonce every call
func (v *Vault) Password(alias string) (string, bool)
func (v *Vault) Has(alias string) bool
func (v *Vault) Aliases() []string
func (v *Vault) Set(alias, password string) error
func (v *Vault) Remove(alias string)
func (v *Vault) Rename(from, to string) error
```

`Vault` holds the derived key, not the passphrase, so a change can be re-sealed without asking again.

**What it must not change:** nothing. New package, no existing import.

**Tests, all written and passing.**
- `TestSealThenOpenRoundTrips` — including a password ending in a space, which nothing may trim.
- `TestSealedBytesContainNoPasswordAndNoAlias` — the file syncs; an observer must not learn which hosts have one.
- `TestOpenRefusesTheWrongPassphrase`, and the error carries no plaintext.
- `TestOpenRefusesATamperedFileIncludingItsHeader`.
- `TestOpenRefusesAHeaderDemandingAbsurdWork` — the cost ceiling of section 2, with the three fields tested separately.
- `TestSealUsesAFreshNonceEveryTime` — fifty seals, fifty distinct outputs.
- `TestOpenRefusesSomethingThatIsNotAVault` — empty, short, wrong magic, zero cost, truncated, header only, random.
- `TestOpenSaysUpgradeRatherThanCorruptForAFutureFile` — "this build is too old" and "your data is gone" are different messages.
- `TestCreateRefusesAShortPassphrase`, `TestSetRefusesAnUnsafeAliasAndAnEmptyPassword`.
- `TestRenameCarriesThePasswordAndLeavesNothingBehind` — a host rename that orphaned the password would make it silently stop working.
- `TestPackageImportsNoLogger` — structural, because a comment asking people not to log a password is not a guard.

**Verification:** `go test ./internal/secret -v` (1.5 s); `go vet ./internal/secret`; `git diff --exit-code go.mod go.sum`.

## Task 2: The askpass helper  ✅ implemented

**Files:** `cmd/ssh-ui/askpass.go`, `cmd/ssh-ui/askpass_test.go`; `cmd/ssh-ui/main.go`.

**Interfaces:**

```go
func AnswerablePrompt(prompt string) bool
func runAskpass(ctx context.Context, arguments []string, lookup func(string) string,
    client *http.Client, out, errOut io.Writer) int
```

`main` branches before `flag.Parse()`, because `flag` would otherwise consume the prompt.

**What it must not change:** the `-open` flag, the URL printing, the signal handling. `ssh-ui` with no arguments behaves exactly as it does today.

**Tests, all written and passing.**
- `TestAnswerablePromptAcceptsOnlyThePasswordPrompt` — a table of the literal prompts OpenSSH emits: four accepted, thirteen refused, including the host key question, both passphrase forms, keyboard-interactive, the FIDO PIN and presence prompts, and a prompt that contains both a passphrase request and a password suffix.
- `TestAskpassWritesOnlyThePasswordOnStandardOutput` — one trailing newline, the token in the header, the alias in the body.
- `TestAskpassWritesNothingOnStandardOutputWhenItRefuses` — seven refusal paths, each asserting zero bytes on stdout and a reason on stderr. A diagnostic on stdout would be handed to OpenSSH as the password.
- `TestAskpassRefusesAnEndpointThatIsNotLoopback` — five non-loopback URLs including `localhost` and `::1`, and an assertion that no request reached the server at all.
- `TestAskpassDistinguishesNothingStoredFromRefused`.
- `TestAskpassRefusesAnEmptyPasswordFromTheServer` — an empty answer would spend a password attempt for nothing.

**Verification:** `go test ./cmd/ssh-ui -v`.

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
2. No route, no log line, and no file under `~/.ssh` in clear ever contains a stored password — the sealed vault contains neither the passwords nor the aliases.
3. A host with no stored password takes today's code path unchanged.
4. The copyable command and the launched command are the same command.

## Known Limitations

- **The vault must be unlocked, every session.** A saved password does nothing until the passphrase has been entered once since the application started, and nothing at all if the application is not running. That is the price of not keeping a key on disk, and it should be stated in the interface rather than discovered.
- **Lose the passphrase and the passwords are gone.** There is no recovery path and there must not be one.
- **A password is readable by anything that can drive the unlocked application.** The token narrows the window to one connection the user asked for, but a process that can reach the loopback API with a session cookie is inside the trust boundary already — the same is true of every other route.
- **The first connection to an unknown host fails when the helper is armed.** This is by design, and the interface refuses to arm it until the host key is known — but a key that *changes* later produces a failed connection rather than the usual warning, and the user has to go and look at the Known Hosts screen to see why.
- **One prompt only.** A server that asks for a password and then a second factor will fail at the second prompt.
