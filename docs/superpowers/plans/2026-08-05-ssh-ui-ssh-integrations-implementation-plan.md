# sshc SSH Integrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the installed OpenSSH client usable from the UI without ever running a command behind the user's back: effective configuration through `ssh -G`, value provenance and multi-hop `ProxyJump` visualisation, separately triggered diagnostics, macOS Terminal launch, `known_hosts` maintenance, and remote public-key registration.

**Architecture:** Every external process goes through one seam. `internal/platform` gains a bounded `OutputRunner` (direct argv, fixed stdin, capped output, timeout, cancellation) plus OpenSSH discovery, a Terminal launcher and the alias/hostname character rules; `internal/platform/macos` implements them with `os/exec` and a constant AppleScript that receives the alias as `argv`, never as concatenated text. `internal/effective` is a pure package over the committed `internal/config` graph: it finds the directives that can execute a program, runs `ssh -G` only when the caller passes an explicit confirmation, parses its output, and projects value provenance and jump routes without inventing a source. `internal/diagnostics` adds two independent operations — a direct TCP dial that ignores `ProxyJump` and says so, and a bounded, cancellable authentication test that disables forwarding and `LocalCommand` through command-line precedence. `internal/knownhosts` and `internal/remotekey` own `known_hosts` maintenance and `authorized_keys` registration; every `known_hosts` write goes through the committed `storage.Manager` so it is journalled and backed up. `internal/session` gains one-time action tokens bound to session, operation kind, target and the exact executable directives that were displayed, and `internal/httpserver` exposes the whole surface behind the existing CSRF and session middleware.

**Tech Stack:** Go 1.26.5, Echo v5.3.1, standard library only for the new Go packages, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1.

## Global Constraints

- macOS only. Bind only to `127.0.0.1`; no CORS; no LaunchAgent; the server exists only while `sshc` runs.
- Pinned versions from the foundation: Go 1.26.5, Echo v5.3.1, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1. Echo v5 handlers take `*echo.Context`.
- Prefer zero new dependencies. This plan adds none; any addition must be justified in the task that adds it and pinned exactly in `go.mod` or `web/package.json`.
- No shell interpretation anywhere. Build argv directly. Never call `sh -c`, never build a shell string, never build AppleScript by concatenation. Treat every alias, hostname, user and key value as untrusted data, including values OpenSSH itself would accept.
- Never evaluate a configuration automatically when evaluating it can run a command. `Match exec`, `ProxyCommand`, `KnownHostsCommand`, `LocalCommand` and `RemoteCommand` are detected from the parsed syntax tree, displayed with their exact command text, and require a separate explicit confirmation before any evaluation or connection.
- Warn, in the UI and in the README, that OpenSSH does not shell-escape the tokens it expands, so a hostname or user value can reach the shell of an executable directive unchanged.
- Every state-changing or externally visible operation — `ssh -G` on a configuration that can execute a command, reachability check, authentication test, Terminal launch, `known_hosts` change, remote registration — requires the `X-SSHC-CSRF` header plus a one-time, short-lived action token bound to the session, the operation kind, the target, and the executable directives that were displayed.
- Every `known_hosts` write goes through `storage.Manager.Commit` so it is journalled, backed up and recoverable like any other managed file. Never write `known_hosts` directly.
- Automated tests must never contact a real remote host, run a real `ssh` or `ssh-keyscan` against the network, or touch the real `~/.ssh`, Keychain or Terminal. Use `t.TempDir()`, fake `OutputRunner`s and fake dialers.
- Two narrow real-binary carve-outs, and no others: (1) the differential test may run the installed `ssh -G -F` against safe fixtures — fixtures containing no executable directive — inside `t.TempDir()`, and must `t.Skip` when `ssh` is unavailable; (2) the process adapter's own tests may run `/bin/echo`, `/bin/cat`, `/bin/sleep`, `/usr/bin/false` and `/usr/bin/yes` with fixed argv. Neither touches the network or the real home directory.
- Real remote connections, real `authorized_keys` changes, real Terminal launch and real Keychain use are manual acceptance tests listed at the end of this plan, never automated.
- Never log command output, hostnames or paths beyond the minimum, and never log tokens, cookies or request bodies. The new packages import neither `log` nor `log/slog`; a verification step checks this.
- OpenAPI first: add endpoints to `api/openapi.yaml`, then run `make generate`. Do not hand-edit `internal/api/models.gen.go` or `web/src/api/schema.d.ts`.
- Home directory resolution stays in `cmd/sshc/main.go`. Nothing under `internal/` may call `os.UserHomeDir` or read `$HOME`, so every test can inject a temporary home.

### Out of scope

Stated here so no task drifts into a neighbouring subsystem:

- Key generation, passphrase handling, private-key reveal, ssh-agent and Keychain registration, trash and restore belong to roadmap subsystem 4 (Key vault). This plan only *consumes* a public key the caller supplies.
- Connections tree, Host forms, groups, metadata, tags and Raw editing belong to roadmap subsystem 3 (Connections UI). This plan adds self-contained Diagnostics and Known Hosts panels that plug into the existing App shell navigation and depends on no type from subsystem 3 or 4.
- Fuzzing beyond what exists, Playwright E2E, packaging and release hardening belong to roadmap subsystem 6.

---

## File Structure

```text
api/openapi.yaml                              # extended contract (Tasks 5, 6, 7, 8)
cmd/sshc/main.go                            # resolves the home directory, builds the macOS adapters
internal/
├── platform/
│   ├── browser.go                            # unchanged
│   ├── command.go                            # Command, Output, OutputRunner, Toolchain seams
│   ├── alias.go                              # alias, hostname and port character rules
│   ├── terminal.go                           # TerminalLauncher seam
│   ├── command_test.go
│   ├── alias_test.go
│   └── macos/
│       ├── browser.go                        # unchanged
│       ├── command.go                        # os/exec adapter: argv only, caps, timeout, stop marker
│       ├── toolchain.go                      # ssh and ssh-keyscan discovery at fixed paths
│       ├── terminal.go                       # constant AppleScript, alias delivered as argv
│       ├── command_test.go
│       ├── toolchain_test.go
│       └── terminal_test.go
├── effective/                                # pure: explains and evaluates one alias
│   ├── danger.go                             # executable directive scan and confirmation evidence
│   ├── evaluate.go                           # confirmed `ssh -G` execution and output parsing
│   ├── provenance.go                         # value provenance projection and pattern matching
│   ├── jump.go                               # ProxyJump chain parsing and route expansion
│   ├── danger_test.go
│   ├── evaluate_test.go
│   ├── provenance_test.go
│   ├── jump_test.go
│   └── differential_test.go                  # `ssh -G -F` differential test, skips without ssh
├── diagnostics/
│   ├── reachability.go                       # direct TCP dial that ignores ProxyJump
│   ├── authentication.go                     # bounded, cancellable authentication test
│   ├── service.go                            # composes resolver, scan, evaluator, checks
│   ├── reachability_test.go
│   ├── authentication_test.go
│   └── service_test.go
├── knownhosts/
│   ├── file.go                               # lossless known_hosts model and fingerprints
│   ├── scan.go                               # ssh-keyscan candidates, always unverified
│   ├── service.go                            # search, delete and add through storage.Manager
│   ├── file_test.go
│   ├── scan_test.go
│   └── service_test.go
├── remotekey/
│   ├── register.go                           # POSIX-shell probe, fixed routine, stdin payload
│   └── register_test.go
├── session/
│   ├── manager.go                            # modified: sessions carry action tokens
│   ├── action.go                             # one-time action tokens bound to kind and target
│   └── action_test.go
├── httpserver/
│   ├── server.go                             # modified: optional integration routes
│   ├── requests.go                           # bounded JSON decoding and shared problem codes
│   ├── actions.go                            # action token endpoint and evidence rules
│   ├── diagnostics.go                        # config, effective, reachability, authentication, terminal
│   ├── knownhosts.go                         # known_hosts endpoints
│   ├── remotekey.go                          # remote registration endpoints
│   ├── actions_test.go
│   ├── diagnostics_test.go
│   ├── knownhosts_test.go
│   └── remotekey_test.go
└── app/run.go                                # modified: builds the integration services
web/src/
├── api/client.ts                             # modified: problem codes surface as ApiError
├── api/integrations.ts                       # typed wrappers for the new endpoints
├── diagnostics/DiagnosticsPanel.tsx
├── diagnostics/DiagnosticsPanel.test.tsx
├── knownhosts/KnownHostsPanel.tsx
├── knownhosts/KnownHostsPanel.test.tsx
├── App.tsx                                   # modified: Diagnostics and Known Hosts become reachable
└── App.test.tsx                              # modified
README.md                                     # modified: SSH 実行の境界
```

## Task 1: Bounded external process execution, OpenSSH discovery and alias safety

**Files:**
- Create: `internal/platform/command.go`
- Create: `internal/platform/alias.go`
- Create: `internal/platform/alias_test.go`
- Create: `internal/platform/macos/command.go`
- Create: `internal/platform/macos/command_test.go`
- Create: `internal/platform/macos/toolchain.go`
- Create: `internal/platform/macos/toolchain_test.go`

**Interfaces:**
- Consumes: the committed `platform.CommandRunner` seam only as precedent; nothing else.
- Produces: `platform.MaxCapturedOutput = 64 << 10`.
- Produces: `platform.Command{Path string, Arguments []string, Stdin []byte, Timeout time.Duration, StopAfter []byte}`.
- Produces: `platform.Output{Stdout, Stderr []byte, ExitCode int, Truncated, Stopped bool, Elapsed time.Duration}`.
- Produces: `platform.OutputRunner` interface with `RunOutput(ctx context.Context, command Command) (Output, error)`.
- Produces: `platform.Toolchain` interface with `SSH() (string, error)` and `KeyScan() (string, error)`.
- Produces: `platform.ErrTimedOut`, `platform.ErrProgramPathNotAbsolute`.
- Produces: `platform.ValidateAlias(alias string) error`, `platform.ValidateHostname(host string) error`, `platform.ValidatePort(port int) error`, `platform.ErrUnsafeAlias`, `platform.ErrUnsafeHostname`, `platform.ErrUnsafePort`, `platform.MaxAliasLength = 64`, `platform.MaxHostnameLength = 255`.
- Produces: `macos.OutputRunner`, `macos.NewOutputRunner() platform.OutputRunner`.
- Produces: `macos.Toolchain{Directories []string, Stat func(string) (fs.FileInfo, error)}`, `macos.NewToolchain() Toolchain`, `macos.ErrProgramNotFound`.

- [ ] **Step 1: Write the failing alias, hostname and port rules test**

```go
// internal/platform/alias_test.go
package platform_test

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/platform"
)

func TestValidateAliasAcceptsOnlyTheSafeCharacterSet(t *testing.T) {
	accepted := []string{"bastion", "web-01", "db.internal", "a", "A1_b", strings.Repeat("h", 64)}
	for _, alias := range accepted {
		if err := platform.ValidateAlias(alias); err != nil {
			t.Errorf("ValidateAlias(%q) = %v, want nil", alias, err)
		}
	}

	rejected := []string{
		"",
		strings.Repeat("h", 65),
		"-oProxyCommand=touch /tmp/pwned",
		"--",
		"host name",
		"host;touch /tmp/pwned",
		`host"quote`,
		"host'quote",
		"host$(id)",
		"host`id`",
		"host\\escape",
		"host\nnewline",
		"host\ttab",
		"*",
		"!negated",
		"user@host",
		"%d",
		"../escape",
		"ホスト",
		".leading",
	}
	for _, alias := range rejected {
		if err := platform.ValidateAlias(alias); !errors.Is(err, platform.ErrUnsafeAlias) {
			t.Errorf("ValidateAlias(%q) = %v, want ErrUnsafeAlias", alias, err)
		}
	}
}

func TestValidateHostnameAcceptsNamesAndAddressesOnly(t *testing.T) {
	accepted := []string{"example.com", "bastion-1.internal", "203.0.113.10", "2001:db8::1", "host_name"}
	for _, host := range accepted {
		if err := platform.ValidateHostname(host); err != nil {
			t.Errorf("ValidateHostname(%q) = %v, want nil", host, err)
		}
	}

	rejected := []string{"", "-p2222", "host name", "host;id", "[2001:db8::1]", "host/path", strings.Repeat("h", 256)}
	for _, host := range rejected {
		if err := platform.ValidateHostname(host); !errors.Is(err, platform.ErrUnsafeHostname) {
			t.Errorf("ValidateHostname(%q) = %v, want ErrUnsafeHostname", host, err)
		}
	}
}

func TestValidatePortRejectsValuesOutsideTheTCPRange(t *testing.T) {
	for _, port := range []int{1, 22, 65535} {
		if err := platform.ValidatePort(port); err != nil {
			t.Errorf("ValidatePort(%d) = %v, want nil", port, err)
		}
	}
	for _, port := range []int{0, -1, 65536, 100000} {
		if err := platform.ValidatePort(port); !errors.Is(err, platform.ErrUnsafePort) {
			t.Errorf("ValidatePort(%d) = %v, want ErrUnsafePort", port, err)
		}
	}
}
```

- [ ] **Step 2: Run the test and verify the rules are absent**

Run: `go test ./internal/platform`

Expected: FAIL to compile with `undefined: platform.ValidateAlias`.

- [ ] **Step 3: Implement the character rules**

```go
// internal/platform/alias.go
package platform

import (
	"errors"
	"regexp"
)

const (
	// MaxAliasLength bounds a Host alias this application is willing to place
	// on a command line.
	MaxAliasLength = 64
	// MaxHostnameLength is the DNS limit; ssh-keyscan targets may not exceed it.
	MaxHostnameLength = 255
)

var (
	ErrUnsafeAlias    = errors.New("alias contains characters this application refuses to pass to an external program")
	ErrUnsafeHostname = errors.New("hostname contains characters this application refuses to pass to an external program")
	ErrUnsafePort     = errors.New("port is outside the TCP range")
)

// safeAliasPattern is deliberately narrower than what OpenSSH accepts.
//
// OpenSSH will happily read a Host alias containing spaces, quotes, '%'
// tokens or a leading '-'. Such an alias could become an option ("-oProxy
// Command=..."), could change the meaning of a copied command line, or could
// escape a string in a terminal automation payload. An alias outside this set
// is never launched or evaluated; the UI offers the command as copyable text
// instead.
var safeAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// safeHostnamePattern allows DNS names, IPv4 literals and bare IPv6 literals.
// Brackets are excluded because this application adds them itself when it
// formats a known_hosts entry for a non-default port.
var safeHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$`)

// ValidateAlias reports whether alias may be handed to an external program.
func ValidateAlias(alias string) error {
	if len(alias) == 0 || len(alias) > MaxAliasLength || !safeAliasPattern.MatchString(alias) {
		return ErrUnsafeAlias
	}
	return nil
}

// ValidateHostname reports whether host may be handed to an external program.
func ValidateHostname(host string) error {
	if len(host) == 0 || len(host) > MaxHostnameLength || !safeHostnamePattern.MatchString(host) {
		return ErrUnsafeHostname
	}
	return nil
}

// ValidatePort reports whether port is a usable TCP port.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return ErrUnsafePort
	}
	return nil
}
```

- [ ] **Step 4: Run the rules test**

Run: `go test ./internal/platform -run 'TestValidate' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing process adapter test**

```go
// internal/platform/macos/command_test.go
package macos_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"sshc/internal/platform"
	"sshc/internal/platform/macos"
)

// These tests run only local, non-networked system programs with a fixed argv:
// /bin/echo, /bin/cat, /bin/sleep, /usr/bin/false and /usr/bin/yes. They never
// start ssh, never touch the network and never read the real home directory.

func TestRunOutputCapturesStdoutAndExitStatus(t *testing.T) {
	runner := macos.NewOutputRunner()

	output, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/bin/echo",
		Arguments: []string{"one", "two three"},
	})
	if err != nil {
		t.Fatalf("RunOutput = %v", err)
	}
	if got := string(output.Stdout); got != "one two three\n" {
		t.Errorf("stdout = %q", got)
	}
	if output.ExitCode != 0 || output.Truncated || output.Stopped {
		t.Errorf("output = %#v", output)
	}

	failure, err := runner.RunOutput(context.Background(), platform.Command{Path: "/usr/bin/false"})
	if err != nil {
		t.Fatalf("RunOutput(/usr/bin/false) = %v, want a captured exit status", err)
	}
	if failure.ExitCode != 1 {
		t.Errorf("exit code = %d, want 1", failure.ExitCode)
	}
}

func TestRunOutputFeedsFixedStandardInput(t *testing.T) {
	output, err := macos.NewOutputRunner().RunOutput(context.Background(), platform.Command{
		Path:  "/bin/cat",
		Stdin: []byte("payload without a shell\n"),
	})
	if err != nil {
		t.Fatalf("RunOutput = %v", err)
	}
	if got := string(output.Stdout); got != "payload without a shell\n" {
		t.Errorf("stdout = %q", got)
	}
}

func TestRunOutputStopsAtTheTimeoutAndTruncatesOutput(t *testing.T) {
	runner := macos.NewOutputRunner()

	if _, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/bin/sleep",
		Arguments: []string{"30"},
		Timeout:   150 * time.Millisecond,
	}); !errors.Is(err, platform.ErrTimedOut) {
		t.Fatalf("RunOutput(sleep) = %v, want ErrTimedOut", err)
	}

	flood, err := runner.RunOutput(context.Background(), platform.Command{
		Path:      "/usr/bin/yes",
		Arguments: []string{"flood"},
		Timeout:   400 * time.Millisecond,
	})
	if !errors.Is(err, platform.ErrTimedOut) {
		t.Fatalf("RunOutput(yes) = %v, want ErrTimedOut", err)
	}
	if !flood.Truncated {
		t.Error("unbounded output was not reported as truncated")
	}
	if len(flood.Stdout) > platform.MaxCapturedOutput {
		t.Errorf("captured %d bytes, want at most %d", len(flood.Stdout), platform.MaxCapturedOutput)
	}
}

func TestRunOutputStopsAsSoonAsTheMarkerAppears(t *testing.T) {
	started := time.Now()
	output, err := macos.NewOutputRunner().RunOutput(context.Background(), platform.Command{
		Path:      "/usr/bin/yes",
		Arguments: []string{"authenticated-marker"},
		Timeout:   10 * time.Second,
		StopAfter: []byte("authenticated-marker"),
	})
	if err != nil {
		t.Fatalf("RunOutput = %v", err)
	}
	if !output.Stopped {
		t.Fatalf("output = %#v, want Stopped", output)
	}
	if !bytes.Contains(output.Stdout, []byte("authenticated-marker")) {
		t.Error("captured output does not contain the marker")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("marker did not stop the process early: %s", elapsed)
	}
}

func TestRunOutputRefusesRelativeProgramsAndHonoursCancellation(t *testing.T) {
	runner := macos.NewOutputRunner()

	if _, err := runner.RunOutput(context.Background(), platform.Command{Path: "echo"}); !errors.Is(err, platform.ErrProgramPathNotAbsolute) {
		t.Fatalf("relative program = %v, want ErrProgramPathNotAbsolute", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	if _, err := runner.RunOutput(ctx, platform.Command{Path: "/bin/sleep", Arguments: []string{"30"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run = %v, want context.Canceled", err)
	}
}
```

- [ ] **Step 6: Run the test and verify the adapter is absent**

Run: `go test ./internal/platform/macos -run TestRunOutput`

Expected: FAIL to compile with `undefined: macos.NewOutputRunner` and `undefined: platform.Command`.

- [ ] **Step 7: Implement the process seam**

```go
// internal/platform/command.go
package platform

import (
	"context"
	"errors"
	"time"
)

// MaxCapturedOutput bounds how many bytes of one stream this application keeps
// in memory for a single external command.
const MaxCapturedOutput = 64 << 10

var (
	// ErrTimedOut reports that a command did not finish within its timeout and
	// was killed.
	ErrTimedOut = errors.New("command did not finish before its timeout")
	// ErrProgramPathNotAbsolute rejects a program that would otherwise be
	// looked up through PATH.
	ErrProgramPathNotAbsolute = errors.New("program path must be absolute")
)

// Command is one external process.
//
// Path is an absolute program path and Arguments is its argv tail. There is no
// field for a command line, because this application never builds one: nothing
// here is ever interpreted by a shell.
type Command struct {
	Path      string
	Arguments []string
	// Stdin is the complete standard input. It is always supplied, so a child
	// never inherits the terminal and never blocks on a prompt.
	Stdin []byte
	// Timeout kills the process when it is exceeded. Zero means the caller's
	// context is the only bound.
	Timeout time.Duration
	// StopAfter stops the process as soon as this byte sequence appears in
	// stdout or stderr. It lets a long-lived command report a decisive result
	// without waiting for its own timeout.
	StopAfter []byte
}

// Output is the bounded result of one external command. A non-zero exit status
// is data, not an error: it is reported in ExitCode with err == nil.
type Output struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
	Stopped   bool
	Elapsed   time.Duration
}

// OutputRunner runs one external program and returns its bounded output.
type OutputRunner interface {
	RunOutput(ctx context.Context, command Command) (Output, error)
}

// Toolchain locates the OpenSSH programs installed on this machine.
type Toolchain interface {
	SSH() (string, error)
	KeyScan() (string, error)
}
```

- [ ] **Step 8: Implement the macOS process adapter**

```go
// internal/platform/macos/command.go
package macos

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"sshc/internal/platform"
)

// OutputRunner runs external programs with a direct argv.
//
// It never invokes a shell, always supplies a fixed standard input so a child
// cannot read the terminal, and never keeps more than
// platform.MaxCapturedOutput bytes of either stream.
type OutputRunner struct{}

// NewOutputRunner returns the macOS process adapter.
func NewOutputRunner() platform.OutputRunner { return OutputRunner{} }

func (OutputRunner) RunOutput(ctx context.Context, command platform.Command) (platform.Output, error) {
	if !filepath.IsAbs(command.Path) {
		return platform.Output{}, platform.ErrProgramPathNotAbsolute
	}

	runContext, stop := context.WithCancel(ctx)
	defer stop()
	if command.Timeout > 0 {
		timedContext, cancelTimeout := context.WithTimeout(runContext, command.Timeout)
		defer cancelTimeout()
		runContext = timedContext
	}

	process := exec.CommandContext(runContext, command.Path, command.Arguments...)
	process.Stdin = bytes.NewReader(command.Stdin)
	// WaitDelay bounds how long Wait blocks on inherited pipes after the
	// process is killed, so a stuck child cannot hold a request open.
	process.WaitDelay = 2 * time.Second

	stdout := &boundedBuffer{limit: platform.MaxCapturedOutput, marker: command.StopAfter, stop: stop}
	stderr := &boundedBuffer{limit: platform.MaxCapturedOutput, marker: command.StopAfter, stop: stop}
	process.Stdout = stdout
	process.Stderr = stderr

	started := time.Now()
	runErr := process.Run()
	output := platform.Output{
		Stdout:    stdout.contents(),
		Stderr:    stderr.contents(),
		Truncated: stdout.overflowed() || stderr.overflowed(),
		Stopped:   stdout.sawMarker() || stderr.sawMarker(),
		Elapsed:   time.Since(started),
	}

	var exitError *exec.ExitError
	switch {
	case runErr == nil:
		return output, nil
	case output.Stopped:
		// The caller asked to stop at the marker, so the non-zero status only
		// reflects this application's own cancellation.
		output.ExitCode = -1
		return output, nil
	case errors.Is(ctx.Err(), context.Canceled):
		output.ExitCode = -1
		return output, ctx.Err()
	case errors.Is(runContext.Err(), context.DeadlineExceeded):
		output.ExitCode = -1
		return output, platform.ErrTimedOut
	case errors.As(runErr, &exitError):
		output.ExitCode = exitError.ExitCode()
		return output, nil
	default:
		return output, runErr
	}
}

// boundedBuffer collects at most limit bytes and can stop the process as soon
// as marker appears. os/exec writes to it from its copying goroutine, so every
// field is guarded.
type boundedBuffer struct {
	mutex     sync.Mutex
	buffer    bytes.Buffer
	tail      []byte
	limit     int
	marker    []byte
	stop      context.CancelFunc
	truncated bool
	found     bool
}

func (b *boundedBuffer) Write(chunk []byte) (int, error) {
	b.mutex.Lock()
	switch remaining := b.limit - b.buffer.Len(); {
	case remaining <= 0:
		b.truncated = true
	case len(chunk) > remaining:
		b.buffer.Write(chunk[:remaining])
		b.truncated = true
	default:
		b.buffer.Write(chunk)
	}

	if len(b.marker) > 0 && !b.found {
		// Search across chunk boundaries by keeping the last marker-1 bytes.
		window := append(append([]byte(nil), b.tail...), chunk...)
		if bytes.Contains(window, b.marker) {
			b.found = true
		}
		if len(window) >= len(b.marker) {
			b.tail = append([]byte(nil), window[len(window)-len(b.marker)+1:]...)
		} else {
			b.tail = window
		}
	}
	found := b.found
	b.mutex.Unlock()

	if found && b.stop != nil {
		b.stop()
	}
	return len(chunk), nil
}

func (b *boundedBuffer) contents() []byte {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

func (b *boundedBuffer) overflowed() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.truncated
}

func (b *boundedBuffer) sawMarker() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.found
}
```

- [ ] **Step 9: Run the adapter tests with the race detector**

Run:

```bash
go test ./internal/platform/... -run TestRunOutput -v
go test -race ./internal/platform/...
```

Expected: PASS. The marker test finishes in well under a second even though `/usr/bin/yes` never ends on its own.

- [ ] **Step 10: Write the failing OpenSSH discovery test**

```go
// internal/platform/macos/toolchain_test.go
package macos_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sshc/internal/platform/macos"
)

func writeProgram(t *testing.T, directory, name string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/usr/bin/true\n"), mode); err != nil {
		t.Fatal(err)
	}
}

func TestToolchainPrefersTheFirstDirectoryThatHoldsAnExecutable(t *testing.T) {
	preferred := t.TempDir()
	fallback := t.TempDir()
	writeProgram(t, fallback, "ssh", 0o755)
	writeProgram(t, preferred, "ssh", 0o755)
	writeProgram(t, fallback, "ssh-keyscan", 0o755)

	toolchain := macos.Toolchain{Directories: []string{preferred, fallback}}

	sshPath, err := toolchain.SSH()
	if err != nil {
		t.Fatalf("SSH() = %v", err)
	}
	if want := filepath.Join(preferred, "ssh"); sshPath != want {
		t.Errorf("SSH() = %q, want %q", sshPath, want)
	}

	keyscanPath, err := toolchain.KeyScan()
	if err != nil {
		t.Fatalf("KeyScan() = %v", err)
	}
	if want := filepath.Join(fallback, "ssh-keyscan"); keyscanPath != want {
		t.Errorf("KeyScan() = %q, want %q", keyscanPath, want)
	}
}

func TestToolchainIgnoresMissingAndNonExecutableFiles(t *testing.T) {
	directory := t.TempDir()
	writeProgram(t, directory, "ssh", 0o644)
	if err := os.Mkdir(filepath.Join(directory, "ssh-keyscan"), 0o755); err != nil {
		t.Fatal(err)
	}

	toolchain := macos.Toolchain{Directories: []string{directory}}
	if _, err := toolchain.SSH(); !errors.Is(err, macos.ErrProgramNotFound) {
		t.Errorf("SSH() = %v, want ErrProgramNotFound", err)
	}
	if _, err := toolchain.KeyScan(); !errors.Is(err, macos.ErrProgramNotFound) {
		t.Errorf("KeyScan() = %v, want ErrProgramNotFound", err)
	}
}

func TestNewToolchainLooksAtTheSystemOpenSSHFirst(t *testing.T) {
	directories := macos.NewToolchain().Directories
	if len(directories) == 0 || directories[0] != "/usr/bin" {
		t.Fatalf("directories = %#v, want /usr/bin first", directories)
	}
}
```

- [ ] **Step 11: Run the test and verify discovery is absent**

Run: `go test ./internal/platform/macos -run TestToolchain`

Expected: FAIL to compile with `undefined: macos.Toolchain`.

- [ ] **Step 12: Implement OpenSSH discovery**

```go
// internal/platform/macos/toolchain.go
package macos

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrProgramNotFound reports that an OpenSSH program is not installed in any
// directory this application is willing to run programs from.
var ErrProgramNotFound = errors.New("OpenSSH program not found")

// Toolchain finds OpenSSH programs at fixed absolute paths.
//
// PATH is deliberately not consulted: the program this application runs must
// not depend on the environment it inherited. /usr/bin comes first because the
// design targets the OpenSSH that ships with macOS; the Homebrew prefixes are
// fallbacks for a machine where Apple's copy was removed.
type Toolchain struct {
	Directories []string
	Stat        func(string) (fs.FileInfo, error)
}

// NewToolchain returns the default macOS search order.
func NewToolchain() Toolchain {
	return Toolchain{Directories: []string{"/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"}}
}

// SSH returns the absolute path of the ssh client.
func (t Toolchain) SSH() (string, error) { return t.find("ssh") }

// KeyScan returns the absolute path of ssh-keyscan.
func (t Toolchain) KeyScan() (string, error) { return t.find("ssh-keyscan") }

func (t Toolchain) find(program string) (string, error) {
	stat := t.Stat
	if stat == nil {
		stat = os.Stat
	}
	for _, directory := range t.Directories {
		candidate := filepath.Join(directory, program)
		info, err := stat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%w: %s", ErrProgramNotFound, program)
}
```

- [ ] **Step 13: Run the platform tests**

Run:

```bash
go test ./internal/platform/...
go test -race ./internal/platform/...
```

Expected: PASS.

- [ ] **Step 14: Commit the process seam**

```bash
git add internal/platform
git commit -m "feat: add a bounded shell-free process seam for OpenSSH"
```

## Task 2: Detect executable directives and evaluate `ssh -G` only when confirmed

**Files:**
- Create: `internal/effective/danger.go`
- Create: `internal/effective/danger_test.go`
- Create: `internal/effective/evaluate.go`
- Create: `internal/effective/evaluate_test.go`

**Interfaces:**
- Consumes: `config.Graph`, `config.Node`, `config.File`, `config.Block`, `config.BlockMatch`, `config.Criterion`, `config.LineDirective`, `config.Line`, `(*File).Blocks`, `(*File).Condition`; Task 1 `platform.Command`, `platform.Output`, `platform.OutputRunner`, `platform.Toolchain`, `platform.ValidateAlias`.
- Produces: `effective.Executable{Keyword, Command, Path string, Line int, Condition string, OnEvaluate, OnConnect, Overridable bool}`.
- Produces: `effective.Report{Directives []Executable}` with `Scan(graph *config.Graph) Report`, `(Report).EvaluationNeedsConfirmation() bool`, `(Report).ConnectionNeedsConfirmation() bool`, `(Report).Unavoidable() []Executable`, `(Report).Evidence() string`.
- Produces: `effective.TokenEscapeWarning`.
- Produces: `effective.Values{Keywords []string, Entries map[string][]string}` with `First(keyword string) string`, `All(keyword string) []string`, and `effective.ParseValues(stdout []byte) Values`.
- Produces: `effective.Evaluator{Runner platform.OutputRunner, Toolchain platform.Toolchain, ConfigPath string, Timeout time.Duration}` with `Evaluate(ctx context.Context, report Report, alias string, confirmed bool) (Values, error)`.
- Produces: `effective.OpenSSHError{ExitCode int, Stderr string, Truncated bool}`, `effective.ErrEvaluationNotConfirmed`, `effective.ErrOutputTruncated`, `effective.DefaultEvaluationTimeout`.

- [ ] **Step 1: Write the failing executable-directive scan test**

```go
// internal/effective/danger_test.go
package effective_test

import (
	"io/fs"
	"path"
	"sort"
	"testing"

	"sshc/internal/config"
	"sshc/internal/effective"
)

// fakeLoader serves configuration files from a map so no test reads a disk.
type fakeLoader struct{ files map[string]string }

func (l fakeLoader) ReadFile(name string) ([]byte, error) {
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
	sort.Strings(matches)
	return matches, nil
}

const testHome = "/Users/tester"
const testRoot = "/Users/tester/.ssh"
const testConfig = "/Users/tester/.ssh/config"

func graphFor(t *testing.T, files map[string]string) *config.Graph {
	t.Helper()
	resolver := config.Resolver{
		Loader: fakeLoader{files: files},
		Home:   testHome,
		Root:   testRoot,
		Tokens: map[byte]string{'d': testHome},
	}
	graph, err := resolver.Resolve(testConfig)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func TestScanFindsEveryExecutableDirectiveWithItsExactText(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Include conf.d/*.conf\n" +
			"Host jump\n" +
			"\tProxyCommand   /usr/bin/nc  -X 5 -x proxy:1080 %h %p\n" +
			"\tLocalCommand /usr/bin/say connected\n" +
			"\tPermitLocalCommand yes\n" +
			"Match exec \"test -f /tmp/at-work\"\n" +
			"\tUser office\n",
		"/Users/tester/.ssh/conf.d/10-extra.conf": "Host shell\n" +
			"\tRemoteCommand tmux attach\n" +
			"\tKnownHostsCommand /usr/local/bin/hosts %H\n",
	})

	report := effective.Scan(graph)
	if len(report.Directives) != 5 {
		t.Fatalf("directives = %#v", report.Directives)
	}

	byKeyword := make(map[string]effective.Executable, len(report.Directives))
	for _, directive := range report.Directives {
		byKeyword[directive.Keyword] = directive
	}

	proxy := byKeyword["ProxyCommand"]
	if proxy.Command != "/usr/bin/nc  -X 5 -x proxy:1080 %h %p" {
		t.Errorf("ProxyCommand text = %q, want the exact argument text", proxy.Command)
	}
	if proxy.Path != testConfig || proxy.Line != 3 || proxy.Condition != "Host jump" {
		t.Errorf("ProxyCommand location = %#v", proxy)
	}
	if !proxy.OnConnect || proxy.OnEvaluate || proxy.Overridable {
		t.Errorf("ProxyCommand flags = %#v", proxy)
	}

	matchExec := byKeyword["Match exec"]
	if matchExec.Command != "test -f /tmp/at-work" || !matchExec.OnEvaluate {
		t.Errorf("Match exec = %#v", matchExec)
	}
	if matchExec.Line != 6 {
		t.Errorf("Match exec line = %d, want 6", matchExec.Line)
	}

	if local := byKeyword["LocalCommand"]; !local.Overridable || !local.OnConnect {
		t.Errorf("LocalCommand = %#v", local)
	}
	if remote := byKeyword["RemoteCommand"]; !remote.Overridable || remote.Path != "/Users/tester/.ssh/conf.d/10-extra.conf" {
		t.Errorf("RemoteCommand = %#v", remote)
	}
	if known := byKeyword["KnownHostsCommand"]; known.Overridable || !known.OnConnect {
		t.Errorf("KnownHostsCommand = %#v", known)
	}
}

func TestReportGatesEvaluationAndConnectionSeparately(t *testing.T) {
	safe := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host plain\n\tHostName 203.0.113.10\n\tUser ops\n",
	}))
	if safe.EvaluationNeedsConfirmation() || safe.ConnectionNeedsConfirmation() {
		t.Fatalf("a configuration without executable directives needs no confirmation: %#v", safe)
	}
	if len(safe.Unavoidable()) != 0 {
		t.Errorf("unavoidable = %#v", safe.Unavoidable())
	}

	connectOnly := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tLocalCommand /usr/bin/say hi\n",
	}))
	if connectOnly.EvaluationNeedsConfirmation() {
		t.Error("LocalCommand does not run while OpenSSH evaluates a configuration")
	}
	if !connectOnly.ConnectionNeedsConfirmation() {
		t.Error("LocalCommand runs while OpenSSH connects")
	}
	if len(connectOnly.Unavoidable()) != 0 {
		t.Errorf("LocalCommand can be disabled on the command line: %#v", connectOnly.Unavoidable())
	}

	evaluation := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Match exec \"id -u\"\n\tUser root\n",
	}))
	if !evaluation.EvaluationNeedsConfirmation() || !evaluation.ConnectionNeedsConfirmation() {
		t.Errorf("Match exec gates both operations: %#v", evaluation)
	}
	if len(evaluation.Unavoidable()) != 1 {
		t.Errorf("Match exec cannot be disabled: %#v", evaluation.Unavoidable())
	}
}

func TestEvidenceChangesWhenTheDisplayedCommandChanges(t *testing.T) {
	first := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tProxyCommand /usr/bin/nc %h %p\n",
	}))
	same := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tProxyCommand /usr/bin/nc %h %p\n",
	}))
	changed := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tProxyCommand /usr/bin/nc -X 5 %h %p\n",
	}))

	if first.Evidence() != same.Evidence() {
		t.Error("identical configurations produced different evidence")
	}
	if first.Evidence() == changed.Evidence() {
		t.Error("an edited command produced the same evidence")
	}
	if effective.Report{}.Evidence() == "" {
		t.Error("an empty report must still produce a stable evidence value")
	}
}
```

- [ ] **Step 2: Run the test and verify the scan is absent**

Run: `go test ./internal/effective`

Expected: FAIL — the package does not exist, so the build reports `no Go files` or `undefined: effective.Scan`.

- [ ] **Step 3: Implement the executable-directive scan**

```go
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

	"sshc/internal/config"
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
```

- [ ] **Step 4: Run the scan tests**

Run: `go test ./internal/effective -run 'TestScan|TestReport|TestEvidence' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing evaluation test**

```go
// internal/effective/evaluate_test.go
package effective_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/platform/macos"
)

// recordingRunner captures the command it was asked to run and replays a
// canned result. No test in this package starts a real process through it.
type recordingRunner struct {
	commands []platform.Command
	output   platform.Output
	err      error
}

func (runner *recordingRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, runner.err
}

type fixedToolchain struct {
	ssh     string
	keyscan string
	err     error
}

func (t fixedToolchain) SSH() (string, error)     { return t.ssh, t.err }
func (t fixedToolchain) KeyScan() (string, error) { return t.keyscan, t.err }

const sampleOutput = "host bastion\n" +
	"user ops\n" +
	"hostname 203.0.113.10\n" +
	"port 2222\n" +
	"identityfile ~/.ssh/id_ed25519\n" +
	"identityfile ~/.ssh/id_rsa\n" +
	"proxyjump ops@edge:2201,inner\n"

func TestEvaluateBuildsArgvWithoutAShellAndParsesOutput(t *testing.T) {
	runner := &recordingRunner{output: platform.Output{Stdout: []byte(sampleOutput)}}
	evaluator := effective.Evaluator{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: testConfig,
	}

	values, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", false)
	if err != nil {
		t.Fatalf("Evaluate = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v", runner.commands)
	}
	command := runner.commands[0]
	if command.Path != "/usr/bin/ssh" {
		t.Errorf("path = %q", command.Path)
	}
	want := []string{"-G", "-F", testConfig, "--", "bastion"}
	if !slices.Equal(command.Arguments, want) {
		t.Fatalf("arguments = %#v, want %#v", command.Arguments, want)
	}
	if command.Timeout != effective.DefaultEvaluationTimeout {
		t.Errorf("timeout = %s", command.Timeout)
	}

	if got := values.First("hostname"); got != "203.0.113.10" {
		t.Errorf("hostname = %q", got)
	}
	if got := values.All("identityfile"); len(got) != 2 || got[1] != "~/.ssh/id_rsa" {
		t.Errorf("identityfile = %#v", got)
	}
	if got := values.First("proxyjump"); got != "ops@edge:2201,inner" {
		t.Errorf("proxyjump = %q", got)
	}
	if got := values.First("absent"); got != "" {
		t.Errorf("absent keyword = %q", got)
	}
	if len(values.Keywords) != 6 || values.Keywords[0] != "host" {
		t.Errorf("keywords = %#v", values.Keywords)
	}
}

func TestEvaluateRefusesToRunWhenEvaluationCanExecuteACommand(t *testing.T) {
	runner := &recordingRunner{output: platform.Output{Stdout: []byte(sampleOutput)}}
	evaluator := effective.Evaluator{Runner: runner, Toolchain: fixedToolchain{ssh: "/usr/bin/ssh"}, ConfigPath: testConfig}
	report := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Match exec \"id -u\"\n\tUser root\n",
	}))

	if _, err := evaluator.Evaluate(context.Background(), report, "bastion", false); !errors.Is(err, effective.ErrEvaluationNotConfirmed) {
		t.Fatalf("Evaluate = %v, want ErrEvaluationNotConfirmed", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("a refused evaluation started a process: %#v", runner.commands)
	}

	if _, err := evaluator.Evaluate(context.Background(), report, "bastion", true); err != nil {
		t.Fatalf("confirmed Evaluate = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("confirmed evaluation did not run: %#v", runner.commands)
	}
}

func TestEvaluateRejectsUnsafeAliasesAndReportsOpenSSHFailures(t *testing.T) {
	runner := &recordingRunner{}
	evaluator := effective.Evaluator{Runner: runner, Toolchain: fixedToolchain{ssh: "/usr/bin/ssh"}, ConfigPath: testConfig}

	if _, err := evaluator.Evaluate(context.Background(), effective.Report{}, "-oProxyCommand=id", false); !errors.Is(err, platform.ErrUnsafeAlias) {
		t.Fatalf("unsafe alias = %v, want ErrUnsafeAlias", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("an unsafe alias started a process: %#v", runner.commands)
	}

	failing := &recordingRunner{output: platform.Output{
		ExitCode: 255,
		Stderr:   []byte("config: line 2: Bad configuration option: notadirective\n"),
	}}
	evaluator.Runner = failing
	_, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", false)
	var opensshError *effective.OpenSSHError
	if !errors.As(err, &opensshError) {
		t.Fatalf("Evaluate = %v, want *OpenSSHError", err)
	}
	if opensshError.ExitCode != 255 || !strings.Contains(opensshError.Stderr, "Bad configuration option") {
		t.Errorf("openssh error = %#v", opensshError)
	}
	if strings.Contains(opensshError.Error(), "Bad configuration option") {
		t.Error("the error message must not repeat captured output")
	}

	truncated := &recordingRunner{output: platform.Output{Stdout: []byte("host bastion\n"), Truncated: true}}
	evaluator.Runner = truncated
	if _, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", false); !errors.Is(err, effective.ErrOutputTruncated) {
		t.Fatalf("truncated output = %v, want ErrOutputTruncated", err)
	}
}

// TestEvaluateParsesInstalledOpenSSHOutput is the first half of the `ssh -G`
// differential coverage the config-engine plan deferred to this subsystem. It
// uses the real ssh with a fixture that contains no executable directive, in a
// temporary directory, and skips when OpenSSH is not installed.
func TestEvaluateParsesInstalledOpenSSHOutput(t *testing.T) {
	toolchain := macos.NewToolchain()
	if _, err := toolchain.SSH(); err != nil {
		t.Skip("OpenSSH ssh is not installed; skipping the real-binary check")
	}

	directory := t.TempDir()
	configPath := directory + "/config"
	if err := os.WriteFile(configPath, []byte("Host fixture\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	evaluator := effective.Evaluator{
		Runner:     macos.NewOutputRunner(),
		Toolchain:  toolchain,
		ConfigPath: configPath,
	}
	values, err := evaluator.Evaluate(context.Background(), effective.Report{}, "fixture", false)
	if err != nil {
		t.Fatalf("Evaluate = %v", err)
	}
	for keyword, want := range map[string]string{
		"hostname": "203.0.113.10",
		"user":     "ops",
		"port":     "2222",
	} {
		if got := values.First(keyword); got != want {
			t.Errorf("%s = %q, want %q", keyword, got, want)
		}
	}
}
```

Add `"os"` to this file's import block; the last test writes its fixture with `os.WriteFile`.

- [ ] **Step 6: Run the test and verify the evaluator is absent**

Run: `go test ./internal/effective -run TestEvaluate`

Expected: FAIL to compile with `undefined: effective.Evaluator`.

- [ ] **Step 7: Implement the evaluator**

```go
// internal/effective/evaluate.go
package effective

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"sshc/internal/platform"
)

// DefaultEvaluationTimeout bounds one `ssh -G` run. Evaluation never touches
// the network, so a slow run means something is wrong locally.
const DefaultEvaluationTimeout = 10 * time.Second

var (
	// ErrEvaluationNotConfirmed reports that evaluating this configuration can
	// run a command and the caller did not present a confirmation.
	ErrEvaluationNotConfirmed = errors.New("evaluating this configuration can run a command and needs explicit confirmation")
	// ErrOutputTruncated reports that ssh printed more than the capture limit,
	// so the parsed values would be incomplete and are not returned.
	ErrOutputTruncated = errors.New("ssh -G produced more output than the capture limit")
)

// Values is the effective configuration OpenSSH reported for one alias.
// Keywords keeps the output order; Entries keeps every value of a keyword that
// may appear more than once, such as identityfile.
type Values struct {
	Keywords []string
	Entries  map[string][]string
}

// First returns the first value of keyword, or an empty string.
func (v Values) First(keyword string) string {
	values := v.Entries[strings.ToLower(keyword)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// All returns every value of keyword in output order.
func (v Values) All(keyword string) []string { return v.Entries[strings.ToLower(keyword)] }

// ParseValues parses `ssh -G` output. Each line is a lowercase keyword, a
// single space and the rest of the line, which may itself contain spaces.
func ParseValues(stdout []byte) Values {
	values := Values{Entries: make(map[string][]string)}
	for _, raw := range strings.Split(string(stdout), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		keyword, argument, _ := strings.Cut(line, " ")
		keyword = strings.ToLower(keyword)
		if _, seen := values.Entries[keyword]; !seen {
			values.Keywords = append(values.Keywords, keyword)
		}
		values.Entries[keyword] = append(values.Entries[keyword], argument)
	}
	return values
}

// OpenSSHError reports that the installed ssh rejected the request. Stderr is
// already bounded by the process seam and is meant for display, not for logs.
type OpenSSHError struct {
	ExitCode  int
	Stderr    string
	Truncated bool
}

func (e *OpenSSHError) Error() string {
	return fmt.Sprintf("ssh exited with status %d", e.ExitCode)
}

// Evaluator runs `ssh -G` for one alias against a specific configuration file.
type Evaluator struct {
	Runner     platform.OutputRunner
	Toolchain  platform.Toolchain
	ConfigPath string
	Timeout    time.Duration
}

// Evaluate asks the installed OpenSSH for the effective configuration of alias.
//
// confirmed must come from a consumed action token. When the configuration can
// execute a command during evaluation, Evaluate refuses without it and starts
// no process at all.
func (e Evaluator) Evaluate(ctx context.Context, report Report, alias string, confirmed bool) (Values, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Values{}, err
	}
	if report.EvaluationNeedsConfirmation() && !confirmed {
		return Values{}, ErrEvaluationNotConfirmed
	}
	program, err := e.Toolchain.SSH()
	if err != nil {
		return Values{}, err
	}

	timeout := e.Timeout
	if timeout <= 0 {
		timeout = DefaultEvaluationTimeout
	}
	output, err := e.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-G", "-F", e.ConfigPath, "--", alias},
		Timeout:   timeout,
	})
	if err != nil {
		return Values{}, err
	}
	if output.Truncated {
		return Values{}, ErrOutputTruncated
	}
	if output.ExitCode != 0 {
		return Values{}, &OpenSSHError{
			ExitCode:  output.ExitCode,
			Stderr:    string(output.Stderr),
			Truncated: output.Truncated,
		}
	}
	return ParseValues(output.Stdout), nil
}
```

- [ ] **Step 8: Run the effective tests with the race detector**

Run:

```bash
go test ./internal/effective -v
go test -race ./internal/effective
```

Expected: PASS. `TestEvaluateParsesInstalledOpenSSHOutput` runs on a machine with OpenSSH and skips elsewhere.

- [ ] **Step 9: Commit the scan and evaluator**

```bash
git add internal/effective
git commit -m "feat: evaluate ssh -G only after an explicit confirmation"
```

## Task 3: Project value provenance and the multi-hop jump route, and prove it against real OpenSSH

**Files:**
- Create: `internal/effective/provenance.go`
- Create: `internal/effective/provenance_test.go`
- Create: `internal/effective/jump.go`
- Create: `internal/effective/jump_test.go`
- Create: `internal/effective/differential_test.go`

**Interfaces:**
- Consumes: Task 2 `argumentText`; `config.Graph`, `config.Block`, `config.BlockGlobal`, `config.BlockHost`, `config.BlockMatch`, `config.Pattern`, `config.Diagnostic`, `config.SeverityInfo`, `(*File).Blocks`, `(*File).Condition`, `config.EqualKeyword`.
- Produces: `effective.Source{Keyword, Value, Path string, Line int, Condition, Kind string, Winner bool}` and the `SourceExact`, `SourceWildcard`, `SourceGlobal` constants.
- Produces: `effective.Complexity{Code, Path string, Line int, Condition, Detail string}` and the `ComplexityWildcardPattern`, `ComplexityNegatedPattern`, `ComplexityMatchBlock`, `ComplexityDuplicateAlias`, `ComplexityUnresolvedInclude`, `ComplexityJumpInvalid`, `ComplexityJumpCycle`, `ComplexityJumpDepth` constants.
- Produces: `effective.Projection{Alias string, Sources []Source, Complexities []Complexity}` with `Simple() bool` and `Value(keyword string) (Source, bool)`.
- Produces: `effective.Project(graph *config.Graph, alias string) Projection` and `effective.MatchPattern(pattern, value string) bool`.
- Produces: `effective.Hop{Raw, User, Host, Port string, UserExplicit, PortExplicit bool}`, `effective.Chain{Raw string, Disabled bool, Hops []Hop}`, `effective.ParseChain(raw string) (Chain, error)`, `effective.ErrInvalidJump`, `effective.DefaultJumpPort`, `effective.MaxJumpDepth`.
- Produces: `effective.Stage{Order, Depth int, Parent string, Hop Hop, Hostname, User, Port string, Sources []Source, Complex bool}` and `effective.ExpandRoute(graph *config.Graph, alias string) ([]Stage, []Complexity)`.

- [ ] **Step 1: Write the failing provenance test**

```go
// internal/effective/provenance_test.go
package effective_test

import (
	"testing"

	"sshc/internal/effective"
)

func codesOf(complexities []effective.Complexity) map[string]effective.Complexity {
	byCode := make(map[string]effective.Complexity, len(complexities))
	for _, complexity := range complexities {
		byCode[complexity.Code] = complexity
	}
	return byCode
}

func TestProjectAttributesTheFirstValueOfEachKeyword(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Include conf.d/*.conf\n" +
			"Host bastion\n" +
			"\tHostName 203.0.113.10\n" +
			"\tPort 2222\n",
		"/Users/tester/.ssh/conf.d/10-defaults.conf": "Host bastion\n" +
			"\tPort 9999\n" +
			"\tUser ops\n",
	})

	projection := effective.Project(graph, "bastion")

	hostName, ok := projection.Value("hostname")
	if !ok || hostName.Value != "203.0.113.10" || hostName.Path != testConfig || hostName.Line != 3 {
		t.Fatalf("hostname source = %#v, ok = %v", hostName, ok)
	}
	if hostName.Condition != "Host bastion" || hostName.Kind != effective.SourceExact || !hostName.Winner {
		t.Errorf("hostname source = %#v", hostName)
	}

	port, _ := projection.Value("port")
	if port.Value != "2222" || port.Line != 4 {
		t.Errorf("OpenSSH keeps the first value it read: %#v", port)
	}
	user, ok := projection.Value("user")
	if !ok || user.Value != "ops" || user.Path != "/Users/tester/.ssh/conf.d/10-defaults.conf" {
		t.Errorf("user source = %#v", user)
	}

	losers := 0
	for _, source := range projection.Sources {
		if !source.Winner {
			losers++
		}
	}
	if losers != 1 {
		t.Errorf("the overridden Port must still be listed once: %#v", projection.Sources)
	}
	if projection.Simple() {
		t.Error("two Host blocks claiming the same alias is not a simple projection")
	}
	if _, ok := codesOf(projection.Complexities)[effective.ComplexityDuplicateAlias]; !ok {
		t.Errorf("complexities = %#v", projection.Complexities)
	}
}

func TestProjectFlagsWildcardNegationAndMatchAsComplexExternalRules(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Host !legacy *.internal\n" +
			"\tUser ops\n" +
			"Match host db user ops\n" +
			"\tIdentityAgent none\n" +
			"Host *\n" +
			"\tServerAliveInterval 30\n",
	})

	projection := effective.Project(graph, "db.internal")
	codes := codesOf(projection.Complexities)
	for _, code := range []string{
		effective.ComplexityWildcardPattern,
		effective.ComplexityNegatedPattern,
		effective.ComplexityMatchBlock,
	} {
		if _, ok := codes[code]; !ok {
			t.Errorf("missing complexity %q in %#v", code, projection.Complexities)
		}
	}
	if user, ok := projection.Value("user"); !ok || user.Kind != effective.SourceWildcard {
		t.Errorf("user source = %#v, ok = %v", user, ok)
	}
	if _, ok := projection.Value("identityagent"); ok {
		t.Error("a Match block must not contribute a projected value")
	}
	if interval, ok := projection.Value("serveraliveinterval"); !ok || interval.Value != "30" {
		t.Errorf("Host * still contributes a value: %#v", interval)
	}

	excluded := effective.Project(graph, "legacy")
	if _, ok := excluded.Value("user"); ok {
		t.Error("a negated pattern must exclude the block")
	}
}

func TestProjectReportsUnresolvedIncludesInsteadOfInventingValues(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Include %h/from-hostname.conf\nHost bastion\n\tUser ops\n",
	})

	projection := effective.Project(graph, "bastion")
	if _, ok := codesOf(projection.Complexities)[effective.ComplexityUnresolvedInclude]; !ok {
		t.Fatalf("complexities = %#v", projection.Complexities)
	}
	if projection.Simple() {
		t.Error("an unresolved Include is not a simple projection")
	}
}

func TestMatchPatternFollowsOpenSSHSemantics(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"bastion", "bastion", true},
		{"BASTION", "bastion", true},
		{"*", "anything", true},
		{"*.internal", "db.internal", true},
		{"*.internal", "internal", false},
		{"web-?", "web-1", true},
		{"web-?", "web-12", false},
		{"a*c*e", "abcde", true},
		{"a*c*e", "abcd", false},
		{"host*", "host", true},
		{"[abc]", "a", false},
	}
	for _, test := range tests {
		if got := effective.MatchPattern(test.pattern, test.value); got != test.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", test.pattern, test.value, got, test.want)
		}
	}
}
```

- [ ] **Step 2: Run the test and verify the projection is absent**

Run: `go test ./internal/effective -run 'TestProject|TestMatchPattern'`

Expected: FAIL to compile with `undefined: effective.Project`.

- [ ] **Step 3: Implement the provenance projection**

```go
// internal/effective/provenance.go
package effective

import (
	"strings"

	"sshc/internal/config"
)

// How confidently a source can be explained.
const (
	SourceExact    = "exact"
	SourceWildcard = "wildcard"
	SourceGlobal   = "global"
)

// Why a projection cannot be shown as one tidy inheritance chain.
const (
	ComplexityWildcardPattern   = "wildcard_pattern"
	ComplexityNegatedPattern    = "negated_pattern"
	ComplexityMatchBlock        = "match_block"
	ComplexityDuplicateAlias    = "duplicate_alias"
	ComplexityUnresolvedInclude = "unresolved_include"
	ComplexityJumpInvalid       = "jump_invalid"
	ComplexityJumpCycle         = "jump_cycle"
	ComplexityJumpDepth         = "jump_depth_exceeded"
)

// Source is one place a value came from. Winner marks the value OpenSSH keeps,
// because the first value read wins; the others are listed so a reader can see
// what is being shadowed.
type Source struct {
	Keyword   string
	Value     string
	Path      string
	Line      int
	Condition string
	Kind      string
	Winner    bool
}

// Complexity records a reason the engine refuses to present its projection as
// the whole truth. The UI shows these as complex external rules and defers to
// `ssh -G` for the authoritative value.
type Complexity struct {
	Code      string
	Path      string
	Line      int
	Condition string
	Detail    string
}

// Projection is the engine's own reading of the configuration for one alias.
type Projection struct {
	Alias        string
	Sources      []Source
	Complexities []Complexity
}

// Simple reports whether every value could be attributed without a caveat.
func (p Projection) Simple() bool { return len(p.Complexities) == 0 }

// Value returns the winning source for keyword.
func (p Projection) Value(keyword string) (Source, bool) {
	wanted := strings.ToLower(keyword)
	for _, source := range p.Sources {
		if source.Winner && strings.ToLower(source.Keyword) == wanted {
			return source, true
		}
	}
	return Source{}, false
}

// Project walks the Include graph in load order and attributes each keyword to
// the first block that set it, which is what OpenSSH does.
//
// Match blocks never contribute a value: their criteria depend on state that
// only exists while connecting. A Match block anywhere in the graph is instead
// recorded as a complexity, because it can also shadow a value this projection
// attributes to a later Host block.
func Project(graph *config.Graph, alias string) Projection {
	projection := Projection{Alias: alias}
	if graph == nil {
		return projection
	}
	claimed := make(map[string]bool)
	matchedHostBlocks := 0

	for _, filePath := range graph.Order {
		node := graph.Nodes[filePath]
		if node == nil || node.File == nil {
			continue
		}
		for _, block := range node.File.Blocks() {
			condition := node.File.Condition(block)
			if block.Kind == config.BlockMatch {
				projection.Complexities = append(projection.Complexities, Complexity{
					Code:      ComplexityMatchBlock,
					Path:      filePath,
					Line:      block.Header + 1,
					Condition: condition,
					Detail:    "Match criteria are evaluated while connecting, so this block may override values shown here",
				})
				continue
			}

			kind, applies := blockApplies(block, alias)
			if !applies {
				continue
			}
			if block.Kind == config.BlockHost {
				matchedHostBlocks++
				if matchedHostBlocks > 1 {
					projection.Complexities = append(projection.Complexities, Complexity{
						Code:      ComplexityDuplicateAlias,
						Path:      filePath,
						Line:      block.Header + 1,
						Condition: condition,
						Detail:    "more than one Host block claims this alias",
					})
				}
				if kind == SourceWildcard {
					projection.Complexities = append(projection.Complexities, Complexity{
						Code:      ComplexityWildcardPattern,
						Path:      filePath,
						Line:      block.Header + 1,
						Condition: condition,
						Detail:    "this block matched through a wildcard pattern",
					})
				}
				for _, pattern := range block.Patterns {
					if !pattern.Negated {
						continue
					}
					projection.Complexities = append(projection.Complexities, Complexity{
						Code:      ComplexityNegatedPattern,
						Path:      filePath,
						Line:      block.Header + 1,
						Condition: condition,
						Detail:    "this block excludes hosts through " + pattern.Raw,
					})
					break
				}
			}

			for index := block.Start; index < block.End; index++ {
				line := node.File.Lines[index]
				if line.Kind != config.LineDirective || config.EqualKeyword(line.Keyword, "Include") {
					continue
				}
				keyword := strings.ToLower(line.Keyword)
				projection.Sources = append(projection.Sources, Source{
					Keyword:   line.Keyword,
					Value:     argumentText(line),
					Path:      filePath,
					Line:      index + 1,
					Condition: condition,
					Kind:      kind,
					Winner:    !claimed[keyword],
				})
				claimed[keyword] = true
			}
		}
	}

	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Severity == config.SeverityInfo {
			continue
		}
		projection.Complexities = append(projection.Complexities, Complexity{
			Code:   ComplexityUnresolvedInclude,
			Path:   diagnostic.Path,
			Line:   diagnostic.Line,
			Detail: diagnostic.Code,
		})
	}
	return projection
}

// blockApplies reports whether a block governs alias and how it matched.
func blockApplies(block config.Block, alias string) (kind string, applies bool) {
	switch block.Kind {
	case config.BlockGlobal:
		return SourceGlobal, true
	case config.BlockMatch:
		return "", false
	}
	for _, pattern := range block.Patterns {
		if pattern.Negated && MatchPattern(pattern.Value, alias) {
			return "", false
		}
	}
	for _, pattern := range block.Patterns {
		if pattern.Negated || !MatchPattern(pattern.Value, alias) {
			continue
		}
		if pattern.Wildcard {
			return SourceWildcard, true
		}
		return SourceExact, true
	}
	return "", false
}

// MatchPattern implements OpenSSH's match_pattern: '*' matches any sequence,
// '?' matches exactly one character, comparison is case-insensitive, and no
// other metacharacter is special.
func MatchPattern(pattern, value string) bool {
	loweredPattern := strings.ToLower(pattern)
	loweredValue := strings.ToLower(value)

	patternIndex, valueIndex := 0, 0
	starIndex, resumeIndex := -1, 0
	for valueIndex < len(loweredValue) {
		switch {
		case patternIndex < len(loweredPattern) &&
			(loweredPattern[patternIndex] == '?' || loweredPattern[patternIndex] == loweredValue[valueIndex]):
			patternIndex++
			valueIndex++
		case patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*':
			starIndex = patternIndex
			resumeIndex = valueIndex
			patternIndex++
		case starIndex >= 0:
			patternIndex = starIndex + 1
			resumeIndex++
			valueIndex = resumeIndex
		default:
			return false
		}
	}
	for patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(loweredPattern)
}
```

- [ ] **Step 4: Run the provenance tests**

Run: `go test ./internal/effective -run 'TestProject|TestMatchPattern' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing jump route test**

```go
// internal/effective/jump_test.go
package effective_test

import (
	"errors"
	"testing"

	"sshc/internal/effective"
)

func TestParseChainReadsEveryDestinationForm(t *testing.T) {
	chain, err := effective.ParseChain("ops@edge:2201, inner ,[2001:db8::1]:2202,[2001:db8::2]")
	if err != nil {
		t.Fatalf("ParseChain = %v", err)
	}
	if len(chain.Hops) != 4 {
		t.Fatalf("hops = %#v", chain.Hops)
	}
	first := chain.Hops[0]
	if first.User != "ops" || first.Host != "edge" || first.Port != "2201" || !first.UserExplicit || !first.PortExplicit {
		t.Errorf("hop 0 = %#v", first)
	}
	second := chain.Hops[1]
	if second.Host != "inner" || second.Port != effective.DefaultJumpPort || second.PortExplicit {
		t.Errorf("hop 1 = %#v", second)
	}
	if third := chain.Hops[2]; third.Host != "2001:db8::1" || third.Port != "2202" {
		t.Errorf("hop 2 = %#v", third)
	}
	if fourth := chain.Hops[3]; fourth.Host != "2001:db8::2" || fourth.Port != effective.DefaultJumpPort {
		t.Errorf("hop 3 = %#v", fourth)
	}

	disabled, err := effective.ParseChain("none")
	if err != nil || !disabled.Disabled || len(disabled.Hops) != 0 {
		t.Errorf("ParseChain(none) = %#v, %v", disabled, err)
	}

	for _, invalid := range []string{"edge,,inner", "@edge", "ops@", "[2001:db8::1", "edge:"} {
		if _, err := effective.ParseChain(invalid); !errors.Is(err, effective.ErrInvalidJump) {
			t.Errorf("ParseChain(%q) = %v, want ErrInvalidJump", invalid, err)
		}
	}
}

func TestExpandRouteFollowsCommaSeparatedAndNestedJumps(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Host target\n" +
			"\tProxyJump ops@edge:2201,inner\n" +
			"Host edge\n" +
			"\tHostName 192.0.2.7\n" +
			"\tPort 22\n" +
			"Host inner\n" +
			"\tHostName 10.1.1.5\n" +
			"\tUser deploy\n" +
			"\tProxyJump edge\n",
	})

	stages, complexities := effective.ExpandRoute(graph, "target")
	if len(complexities) != 0 {
		t.Fatalf("complexities = %#v", complexities)
	}
	if len(stages) != 3 {
		t.Fatalf("stages = %#v", stages)
	}

	first := stages[0]
	if first.Order != 1 || first.Depth != 0 || first.Parent != "target" {
		t.Errorf("stage 0 position = %#v", first)
	}
	if first.Hostname != "192.0.2.7" || first.User != "ops" || first.Port != "2201" {
		t.Errorf("stage 0 destination = %#v", first)
	}

	second := stages[1]
	if second.Depth != 0 || second.Hostname != "10.1.1.5" || second.User != "deploy" || second.Port != "22" {
		t.Errorf("stage 1 = %#v", second)
	}

	nested := stages[2]
	if nested.Depth != 1 || nested.Parent != "inner" || nested.Hostname != "192.0.2.7" {
		t.Errorf("nested stage = %#v", nested)
	}
}

func TestExpandRouteStopsAtACycleAndReportsInvalidValues(t *testing.T) {
	cyclic := graphFor(t, map[string]string{
		testConfig: "Host alpha\n\tProxyJump bravo\nHost bravo\n\tProxyJump alpha\n",
	})
	stages, complexities := effective.ExpandRoute(cyclic, "alpha")
	if len(stages) == 0 {
		t.Fatal("a cycle must still show the hops it walked")
	}
	if _, ok := codesOf(complexities)[effective.ComplexityJumpCycle]; !ok {
		t.Fatalf("complexities = %#v", complexities)
	}

	broken := graphFor(t, map[string]string{
		testConfig: "Host alpha\n\tProxyJump ops@\n",
	})
	if _, complexities := effective.ExpandRoute(broken, "alpha"); len(complexities) != 1 ||
		complexities[0].Code != effective.ComplexityJumpInvalid {
		t.Fatalf("complexities = %#v", complexities)
	}

	none := graphFor(t, map[string]string{
		testConfig: "Host alpha\n\tProxyJump none\n",
	})
	if stages, complexities := effective.ExpandRoute(none, "alpha"); len(stages) != 0 || len(complexities) != 0 {
		t.Fatalf("ProxyJump none = %#v, %#v", stages, complexities)
	}
}
```

- [ ] **Step 6: Run the test and verify the route expansion is absent**

Run: `go test ./internal/effective -run 'TestParseChain|TestExpandRoute'`

Expected: FAIL to compile with `undefined: effective.ParseChain`.

- [ ] **Step 7: Implement chain parsing and route expansion**

```go
// internal/effective/jump.go
package effective

import (
	"errors"
	"strings"

	"sshc/internal/config"
)

const (
	// DefaultJumpPort is the port OpenSSH uses for a hop without one.
	DefaultJumpPort = "22"
	// MaxJumpDepth bounds how far nested ProxyJump values are followed.
	MaxJumpDepth = 8
	// jumpDisabled is the literal that switches ProxyJump off.
	jumpDisabled = "none"
)

// ErrInvalidJump reports a ProxyJump value this engine refuses to interpret.
var ErrInvalidJump = errors.New("ProxyJump value is not a valid destination list")

// Hop is one destination of a ProxyJump list. UserExplicit and PortExplicit
// record whether the value came from the list itself, because a value written
// in the list wins over the hop's own configuration.
type Hop struct {
	Raw          string
	User         string
	Host         string
	Port         string
	UserExplicit bool
	PortExplicit bool
}

// Chain is a parsed ProxyJump value.
type Chain struct {
	Raw      string
	Disabled bool
	Hops     []Hop
}

// ParseChain reads a single or comma-separated ProxyJump value.
func ParseChain(raw string) (Chain, error) {
	chain := Chain{Raw: raw}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return chain, nil
	}
	if strings.EqualFold(trimmed, jumpDisabled) {
		chain.Disabled = true
		return chain, nil
	}

	for _, element := range strings.Split(trimmed, ",") {
		element = strings.TrimSpace(element)
		if element == "" {
			return Chain{}, ErrInvalidJump
		}
		hop := Hop{Raw: element, Port: DefaultJumpPort}
		destination := element
		if at := strings.LastIndex(destination, "@"); at >= 0 {
			hop.User = destination[:at]
			hop.UserExplicit = true
			destination = destination[at+1:]
			if hop.User == "" || destination == "" {
				return Chain{}, ErrInvalidJump
			}
		}
		switch {
		case strings.HasPrefix(destination, "["):
			closing := strings.Index(destination, "]")
			if closing < 0 {
				return Chain{}, ErrInvalidJump
			}
			hop.Host = destination[1:closing]
			if remainder := destination[closing+1:]; remainder != "" {
				if !strings.HasPrefix(remainder, ":") {
					return Chain{}, ErrInvalidJump
				}
				hop.Port = remainder[1:]
				hop.PortExplicit = true
			}
		default:
			if colon := strings.LastIndex(destination, ":"); colon >= 0 && !strings.Contains(destination[:colon], ":") {
				hop.Host = destination[:colon]
				hop.Port = destination[colon+1:]
				hop.PortExplicit = true
			} else {
				hop.Host = destination
			}
		}
		if hop.Host == "" || hop.Port == "" {
			return Chain{}, ErrInvalidJump
		}
		chain.Hops = append(chain.Hops, hop)
	}
	return chain, nil
}

// Stage is one hop of the route, flattened so the API and the UI do not need a
// recursive type. Depth is 0 for the target's own ProxyJump list; a jump host
// that carries its own ProxyJump contributes stages at the next depth.
type Stage struct {
	Order    int
	Depth    int
	Parent   string
	Hop      Hop
	Hostname string
	User     string
	Port     string
	Sources  []Source
	Complex  bool
}

// ExpandRoute expands the ProxyJump chain of alias and of every jump host in
// it, so the whole route can be shown rather than only its first hop.
func ExpandRoute(graph *config.Graph, alias string) ([]Stage, []Complexity) {
	visited := map[string]bool{strings.ToLower(alias): true}
	order := 0
	return expandRoute(graph, alias, visited, 0, &order)
}

func expandRoute(graph *config.Graph, alias string, visited map[string]bool, depth int, order *int) ([]Stage, []Complexity) {
	projection := Project(graph, alias)
	source, ok := projection.Value("proxyjump")
	if !ok {
		return nil, nil
	}
	chain, err := ParseChain(source.Value)
	if err != nil {
		return nil, []Complexity{{
			Code:   ComplexityJumpInvalid,
			Path:   source.Path,
			Line:   source.Line,
			Detail: source.Value,
		}}
	}
	if chain.Disabled {
		return nil, nil
	}
	if depth >= MaxJumpDepth {
		return nil, []Complexity{{
			Code:   ComplexityJumpDepth,
			Path:   source.Path,
			Line:   source.Line,
			Detail: "the jump route is deeper than this engine follows",
		}}
	}

	var stages []Stage
	var complexities []Complexity
	for _, hop := range chain.Hops {
		hopProjection := Project(graph, hop.Host)
		*order++
		stage := Stage{
			Order:    *order,
			Depth:    depth,
			Parent:   alias,
			Hop:      hop,
			Hostname: hop.Host,
			User:     hop.User,
			Port:     hop.Port,
			Complex:  !hopProjection.Simple(),
		}
		if hostName, found := hopProjection.Value("hostname"); found {
			stage.Hostname = hostName.Value
			stage.Sources = append(stage.Sources, hostName)
		}
		if !hop.UserExplicit {
			if user, found := hopProjection.Value("user"); found {
				stage.User = user.Value
				stage.Sources = append(stage.Sources, user)
			}
		}
		if !hop.PortExplicit {
			if port, found := hopProjection.Value("port"); found {
				stage.Port = port.Value
				stage.Sources = append(stage.Sources, port)
			}
		}
		stages = append(stages, stage)

		lowered := strings.ToLower(hop.Host)
		if visited[lowered] {
			complexities = append(complexities, Complexity{
				Code:   ComplexityJumpCycle,
				Detail: hop.Host + " already appears earlier in this route",
			})
			continue
		}
		visited[lowered] = true
		nestedStages, nestedComplexities := expandRoute(graph, hop.Host, visited, depth+1, order)
		stages = append(stages, nestedStages...)
		complexities = append(complexities, nestedComplexities...)
	}
	return stages, complexities
}
```

- [ ] **Step 8: Run the jump tests**

Run: `go test ./internal/effective -run 'TestParseChain|TestExpandRoute' -v`

Expected: PASS.

- [ ] **Step 9: Write the deferred `ssh -G -F` differential test**

```go
// internal/effective/differential_test.go
package effective_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"sshc/internal/config"
	"sshc/internal/effective"
	"sshc/internal/platform/macos"
	"sshc/internal/storage"
)

// TestProjectionMatchesInstalledOpenSSH is the differential test the
// config-engine plan deferred to this subsystem.
//
// Every fixture is safe by construction: none contains ProxyCommand,
// LocalCommand, RemoteCommand, KnownHostsCommand or Match exec, so evaluating
// it cannot run a program. Each fixture lives in its own t.TempDir() and the
// real ~/.ssh is never read. The comparison is limited to keywords the fixture
// sets, because `ssh -G -F file` still reads /etc/ssh/ssh_config for
// everything else.
func TestProjectionMatchesInstalledOpenSSH(t *testing.T) {
	toolchain := macos.NewToolchain()
	if _, err := toolchain.SSH(); err != nil {
		t.Skip("OpenSSH ssh is not installed; skipping the differential test")
	}

	tests := []struct {
		name       string
		contents   string
		alias      string
		keywords   []string
		wantSimple bool
	}{
		{
			name:       "explicit host",
			contents:   "Host bastion\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 2222\n",
			alias:      "bastion",
			keywords:   []string{"hostname", "user", "port"},
			wantSimple: true,
		},
		{
			name:     "wildcard defaults",
			contents: "Host web-01\n\tHostName 198.51.100.20\n\nHost *\n\tUser deploy\n\tPort 2022\n",
			alias:    "web-01",
			keywords: []string{"hostname", "user", "port"},
		},
		{
			name:     "first value wins across duplicate blocks",
			contents: "Host db\n\tPort 2200\n\nHost db\n\tPort 9999\n\tUser dba\n",
			alias:    "db",
			keywords: []string{"port", "user"},
		},
		{
			name:     "negated pattern",
			contents: "Host !legacy *.internal\n\tUser ops\n\tPort 2202\n",
			alias:    "app.internal",
			keywords: []string{"user", "port"},
		},
		{
			name:       "multi hop jump",
			contents:   "Host edge\n\tHostName 192.0.2.7\n\nHost inner\n\tHostName 10.1.1.5\n\tProxyJump ops@edge:2222\n",
			alias:      "inner",
			keywords:   []string{"hostname", "proxyjump"},
			wantSimple: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".ssh")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(root, "config")
			if err := os.WriteFile(configPath, []byte(test.contents), 0o600); err != nil {
				t.Fatal(err)
			}

			workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := storage.NewResolver(workspace).Resolve(configPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, diagnostic := range graph.Diagnostics {
				if diagnostic.Severity == config.SeverityError {
					t.Fatalf("fixture produced an error diagnostic: %#v", diagnostic)
				}
			}

			report := effective.Scan(graph)
			if len(report.Directives) != 0 {
				t.Fatalf("fixture is not safe for automatic evaluation: %#v", report.Directives)
			}

			evaluator := effective.Evaluator{
				Runner:     macos.NewOutputRunner(),
				Toolchain:  toolchain,
				ConfigPath: configPath,
			}
			values, err := evaluator.Evaluate(context.Background(), report, test.alias, false)
			if err != nil {
				t.Fatalf("Evaluate = %v", err)
			}

			projection := effective.Project(graph, test.alias)
			for _, keyword := range test.keywords {
				source, ok := projection.Value(keyword)
				if !ok {
					t.Fatalf("engine did not project %q", keyword)
				}
				if want := values.First(keyword); source.Value != want {
					t.Errorf("%s: engine = %q, ssh -G = %q", keyword, source.Value, want)
				}
			}
			if projection.Simple() != test.wantSimple {
				t.Errorf("Simple() = %v, want %v (complexities %#v)", projection.Simple(), test.wantSimple, projection.Complexities)
			}
		})
	}
}
```

- [ ] **Step 10: Run the differential test and the whole package**

Run:

```bash
go test ./internal/effective -run TestProjectionMatchesInstalledOpenSSH -v
go test ./internal/effective
go test -race ./internal/effective
```

Expected: PASS. On this machine the differential subtests run against OpenSSH 10.2p1; on a machine without `ssh` the test reports `SKIP` and the suite stays green.

- [ ] **Step 11: Commit provenance and the jump route**

```bash
git add internal/effective
git commit -m "feat: explain ssh value provenance and jump routes"
```

## Task 4: Direct reachability and the bounded, cancellable authentication test

**Files:**
- Create: `internal/diagnostics/reachability.go`
- Create: `internal/diagnostics/reachability_test.go`
- Create: `internal/diagnostics/authentication.go`
- Create: `internal/diagnostics/authentication_test.go`

**Interfaces:**
- Consumes: Task 1 `platform.Command`, `platform.Output`, `platform.OutputRunner`, `platform.Toolchain`, `platform.ValidateAlias`, `platform.ErrTimedOut`; Task 2 `effective.Report`, `effective.Executable`.
- Produces: `diagnostics.Dialer` interface with `DialContext(ctx context.Context, network, address string) (net.Conn, error)`.
- Produces: `diagnostics.Reachability{Dialer Dialer, Timeout time.Duration}` with `Check(ctx context.Context, hostname, port string) ReachabilityResult`.
- Produces: `diagnostics.ReachabilityResult{Address, Outcome string, Elapsed time.Duration, Detail, Notice string}` and the outcome constants `ReachabilityReached`, `ReachabilityRefused`, `ReachabilityTimeout`, `ReachabilityDNSFailure`, `ReachabilityFailed`, plus `diagnostics.ProxyJumpNotice` and `diagnostics.DefaultReachabilityTimeout`.
- Produces: `diagnostics.Authentication{Runner platform.OutputRunner, Toolchain platform.Toolchain, ConfigPath string, Timeout, ConnectTimeout time.Duration}` with `Test(ctx context.Context, report effective.Report, alias string, acknowledged bool) (AuthenticationResult, error)`.
- Produces: `diagnostics.HardeningOptions(connectTimeout time.Duration) []string`, `diagnostics.AuthenticatedMarker`, `diagnostics.MaxReportedOutput`.
- Produces: `diagnostics.AuthenticationResult{Outcome string, Authenticated bool, ExitCode int, Stderr string, Truncated bool, Elapsed time.Duration}` and the outcome constants `OutcomeAuthenticated`, `OutcomeDenied`, `OutcomeHostKeyUnknown`, `OutcomeHostKeyChanged`, `OutcomeDNSFailure`, `OutcomeRefused`, `OutcomeTimeout`, `OutcomeFailed`.
- Produces: `diagnostics.ExecutableDirectiveError{Directives []effective.Executable}`, `diagnostics.DefaultAuthenticationTimeout`, `diagnostics.DefaultConnectTimeout`.

- [ ] **Step 1: Write the failing reachability test**

```go
// internal/diagnostics/reachability_test.go
package diagnostics_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"sshc/internal/diagnostics"
)

// dialerFunc turns a function into a Dialer so a test can decide the outcome
// without opening a socket.
type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (dial dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dial(ctx, network, address)
}

func TestCheckReportsALoopbackListenerAsReached(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)

	result := diagnostics.Reachability{Dialer: &net.Dialer{}}.Check(
		context.Background(), "127.0.0.1", strconv.Itoa(address.Port))

	if result.Outcome != diagnostics.ReachabilityReached {
		t.Fatalf("outcome = %q, detail = %q", result.Outcome, result.Detail)
	}
	if result.Address != "127.0.0.1:"+strconv.Itoa(address.Port) {
		t.Errorf("address = %q", result.Address)
	}
	if !strings.Contains(result.Notice, "ProxyJump") {
		t.Errorf("notice = %q, want an explicit statement that ProxyJump was ignored", result.Notice)
	}
}

func TestCheckClassifiesFailuresWithoutGuessing(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		want  string
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "missing.invalid", IsNotFound: true}, diagnostics.ReachabilityDNSFailure},
		{"refused", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, diagnostics.ReachabilityTimeout},
		{"other", errors.New("network is unreachable"), diagnostics.ReachabilityFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reachability := diagnostics.Reachability{
				Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, test.err }),
			}
			result := reachability.Check(context.Background(), "example.internal", "22")
			if result.Outcome != test.want {
				t.Fatalf("outcome = %q, want %q (detail %q)", result.Outcome, test.want, result.Detail)
			}
		})
	}

	refused := diagnostics.Reachability{Dialer: &net.Dialer{}}
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(closed.Addr().(*net.TCPAddr).Port)
	closed.Close()
	if result := refused.Check(context.Background(), "127.0.0.1", port); result.Outcome != diagnostics.ReachabilityRefused {
		t.Fatalf("outcome = %q, want %q", result.Outcome, diagnostics.ReachabilityRefused)
	}
}

func TestCheckAppliesItsOwnTimeout(t *testing.T) {
	reachability := diagnostics.Reachability{
		Timeout: 50 * time.Millisecond,
		Dialer: dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	}
	started := time.Now()
	result := reachability.Check(context.Background(), "slow.internal", "22")
	if result.Outcome != diagnostics.ReachabilityTimeout {
		t.Fatalf("outcome = %q", result.Outcome)
	}
	if time.Since(started) > time.Second {
		t.Error("the check did not apply its own timeout")
	}
}
```

- [ ] **Step 2: Run the test and verify the package is absent**

Run: `go test ./internal/diagnostics`

Expected: FAIL — the package does not exist, so the build reports `no Go files` or `undefined: diagnostics.Reachability`.

- [ ] **Step 3: Implement the direct reachability check**

```go
// Package diagnostics runs the separately triggered checks of the design:
// a configuration check, a direct TCP reachability check, and an SSH
// authentication test. Each is an independent operation the user starts on
// purpose; nothing here runs as a side effect of opening a screen.
package diagnostics

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// ProxyJumpNotice accompanies every reachability result. The check dials the
// destination itself, so a host that is only reachable through a jump host is
// expected to fail here, and the UI must say so rather than imply the host is
// down.
const ProxyJumpNotice = "This check dialled the destination directly. ProxyJump, ProxyCommand and any jump-host firewall were not used."

// DefaultReachabilityTimeout bounds one TCP dial.
const DefaultReachabilityTimeout = 5 * time.Second

// Reachability outcomes.
const (
	ReachabilityReached    = "reached"
	ReachabilityRefused    = "refused"
	ReachabilityTimeout    = "timeout"
	ReachabilityDNSFailure = "dns_failure"
	ReachabilityFailed     = "failed"
)

// Dialer opens a TCP connection. *net.Dialer satisfies it; tests substitute a
// function so no automated test opens a remote socket.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ReachabilityResult is one completed dial attempt.
type ReachabilityResult struct {
	Address string
	Outcome string
	Elapsed time.Duration
	Detail  string
	Notice  string
}

// Reachability dials a destination directly, ignoring ProxyJump on purpose.
type Reachability struct {
	Dialer  Dialer
	Timeout time.Duration
}

// Check dials hostname:port once and classifies the outcome.
func (r Reachability) Check(ctx context.Context, hostname, port string) ReachabilityResult {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultReachabilityTimeout
	}
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(hostname, port)
	result := ReachabilityResult{Address: address, Notice: ProxyJumpNotice}

	started := time.Now()
	connection, err := r.Dialer.DialContext(dialContext, "tcp", address)
	result.Elapsed = time.Since(started)
	if err == nil {
		connection.Close()
		result.Outcome = ReachabilityReached
		return result
	}

	result.Detail = err.Error()
	var dnsError *net.DNSError
	switch {
	case errors.As(err, &dnsError):
		result.Outcome = ReachabilityDNSFailure
	case errors.Is(err, syscall.ECONNREFUSED):
		result.Outcome = ReachabilityRefused
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		result.Outcome = ReachabilityTimeout
	default:
		result.Outcome = ReachabilityFailed
	}
	return result
}
```

- [ ] **Step 4: Run the reachability tests**

Run: `go test ./internal/diagnostics -run TestCheck -v`

Expected: PASS.

- [ ] **Step 5: Write the failing authentication test**

```go
// internal/diagnostics/authentication_test.go
package diagnostics_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"sshc/internal/config"
	"sshc/internal/diagnostics"
	"sshc/internal/effective"
	"sshc/internal/platform"
)

type scriptedRunner struct {
	commands []platform.Command
	output   platform.Output
	err      error
}

func (runner *scriptedRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, runner.err
}

type fixedToolchain struct{ ssh, keyscan string }

func (t fixedToolchain) SSH() (string, error)     { return t.ssh, nil }
func (t fixedToolchain) KeyScan() (string, error) { return t.keyscan, nil }

func reportFrom(t *testing.T, contents string) effective.Report {
	t.Helper()
	graph := &config.Graph{
		Root:  "/Users/tester/.ssh/config",
		Order: []string{"/Users/tester/.ssh/config"},
		Nodes: map[string]*config.Node{
			"/Users/tester/.ssh/config": {Path: "/Users/tester/.ssh/config", Editable: true, File: config.Parse([]byte(contents))},
		},
	}
	return effective.Scan(graph)
}

func TestHardeningOptionsDisableForwardingAndLocalCommand(t *testing.T) {
	options := diagnostics.HardeningOptions(7 * time.Second)
	joined := strings.Join(options, " ")
	for _, want := range []string{
		"BatchMode=yes",
		"PermitLocalCommand=no",
		"ClearAllForwardings=yes",
		"ForwardAgent=no",
		"ForwardX11=no",
		"ForwardX11Trusted=no",
		"ControlMaster=no",
		"ControlPath=none",
		"RemoteCommand=none",
		"RequestTTY=no",
		"SessionType=none",
		"StrictHostKeyChecking=yes",
		"NumberOfPasswordPrompts=0",
		"ConnectTimeout=7",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("hardening options are missing %q: %v", want, options)
		}
	}
	for index := 0; index < len(options); index += 2 {
		if options[index] != "-o" {
			t.Fatalf("option %d = %q, want -o", index, options[index])
		}
	}
}

func TestAuthenticationTestBuildsASafeCommandAndReadsTheMarker(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{
		Stderr:  []byte("debug1: Authenticated to bastion ([203.0.113.10]:22) using \"publickey\".\n"),
		Stopped: true,
	}}
	authentication := diagnostics.Authentication{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: "/Users/tester/.ssh/config",
	}

	result, err := authentication.Test(context.Background(), effective.Report{}, "bastion", false)
	if err != nil {
		t.Fatalf("Test = %v", err)
	}
	if !result.Authenticated || result.Outcome != diagnostics.OutcomeAuthenticated {
		t.Fatalf("result = %#v", result)
	}

	command := runner.commands[0]
	if command.Path != "/usr/bin/ssh" {
		t.Errorf("path = %q", command.Path)
	}
	if string(command.StopAfter) != diagnostics.AuthenticatedMarker {
		t.Errorf("stop marker = %q", command.StopAfter)
	}
	if command.Timeout != diagnostics.DefaultAuthenticationTimeout {
		t.Errorf("timeout = %s", command.Timeout)
	}
	if last := command.Arguments[len(command.Arguments)-2:]; !slices.Equal(last, []string{"--", "bastion"}) {
		t.Errorf("argv tail = %#v, want -- bastion", last)
	}
	if !slices.Contains(command.Arguments, "-v") || !slices.Contains(command.Arguments, "-F") {
		t.Errorf("argv = %#v", command.Arguments)
	}
}

func TestAuthenticationTestRefusesUntilUnavoidableCommandsAreAcknowledged(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{Stopped: true, Stderr: []byte(diagnostics.AuthenticatedMarker + "host\n")}}
	authentication := diagnostics.Authentication{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: "/Users/tester/.ssh/config",
	}
	report := reportFrom(t, "Host jump\n\tProxyCommand /usr/bin/nc %h %p\n")

	_, err := authentication.Test(context.Background(), report, "jump", false)
	var directiveError *diagnostics.ExecutableDirectiveError
	if !errors.As(err, &directiveError) {
		t.Fatalf("Test = %v, want *ExecutableDirectiveError", err)
	}
	if len(directiveError.Directives) != 1 || directiveError.Directives[0].Keyword != "ProxyCommand" {
		t.Fatalf("directives = %#v", directiveError.Directives)
	}
	if len(runner.commands) != 0 {
		t.Fatal("a refused authentication test started a process")
	}

	if _, err := authentication.Test(context.Background(), report, "jump", true); err != nil {
		t.Fatalf("acknowledged Test = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("acknowledged test did not run: %#v", runner.commands)
	}

	overridable := reportFrom(t, "Host jump\n\tLocalCommand /usr/bin/say hi\n")
	if _, err := authentication.Test(context.Background(), overridable, "jump", false); err != nil {
		t.Fatalf("a directive the command line disables must not block the test: %v", err)
	}
}

func TestAuthenticationTestClassifiesFailures(t *testing.T) {
	tests := []struct {
		name    string
		output  platform.Output
		runErr  error
		want    string
	}{
		{"denied", platform.Output{ExitCode: 255, Stderr: []byte("ops@203.0.113.10: Permission denied (publickey).\n")}, nil, diagnostics.OutcomeDenied},
		{"unknown host key", platform.Output{ExitCode: 255, Stderr: []byte("Host key verification failed.\n")}, nil, diagnostics.OutcomeHostKeyUnknown},
		{"changed host key", platform.Output{ExitCode: 255, Stderr: []byte("@@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@@\nHost key verification failed.\n")}, nil, diagnostics.OutcomeHostKeyChanged},
		{"dns", platform.Output{ExitCode: 255, Stderr: []byte("ssh: Could not resolve hostname missing.invalid: nodename nor servname provided\n")}, nil, diagnostics.OutcomeDNSFailure},
		{"refused", platform.Output{ExitCode: 255, Stderr: []byte("ssh: connect to host 203.0.113.10 port 22: Connection refused\n")}, nil, diagnostics.OutcomeRefused},
		{"timeout", platform.Output{}, platform.ErrTimedOut, diagnostics.OutcomeTimeout},
		{"other", platform.Output{ExitCode: 1, Stderr: []byte("something else\n")}, nil, diagnostics.OutcomeFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authentication := diagnostics.Authentication{
				Runner:     &scriptedRunner{output: test.output, err: test.runErr},
				Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
				ConfigPath: "/Users/tester/.ssh/config",
			}
			result, err := authentication.Test(context.Background(), effective.Report{}, "bastion", false)
			if err != nil {
				t.Fatalf("Test = %v", err)
			}
			if result.Outcome != test.want || result.Authenticated {
				t.Fatalf("result = %#v, want outcome %q", result, test.want)
			}
		})
	}
}

func TestAuthenticationTestRejectsUnsafeAliasesAndCapsReportedOutput(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{
		ExitCode:  255,
		Stderr:    []byte(strings.Repeat("x", diagnostics.MaxReportedOutput+4096)),
		Truncated: true,
	}}
	authentication := diagnostics.Authentication{
		Runner:     runner,
		Toolchain:  fixedToolchain{ssh: "/usr/bin/ssh"},
		ConfigPath: "/Users/tester/.ssh/config",
	}

	if _, err := authentication.Test(context.Background(), effective.Report{}, "bad alias", false); !errors.Is(err, platform.ErrUnsafeAlias) {
		t.Fatalf("unsafe alias = %v, want ErrUnsafeAlias", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("an unsafe alias started a process")
	}

	result, err := authentication.Test(context.Background(), effective.Report{}, "bastion", false)
	if err != nil {
		t.Fatalf("Test = %v", err)
	}
	if len(result.Stderr) > diagnostics.MaxReportedOutput {
		t.Errorf("reported %d bytes, want at most %d", len(result.Stderr), diagnostics.MaxReportedOutput)
	}
	if !result.Truncated {
		t.Error("truncation was not reported")
	}
}
```

- [ ] **Step 6: Run the test and verify the authentication test is absent**

Run: `go test ./internal/diagnostics -run 'TestHardening|TestAuthentication'`

Expected: FAIL to compile with `undefined: diagnostics.Authentication`.

- [ ] **Step 7: Implement the authentication test**

```go
// internal/diagnostics/authentication.go
package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sshc/internal/effective"
	"sshc/internal/platform"
)

const (
	// AuthenticatedMarker is the phrase OpenSSH prints once a session is
	// authenticated. Watching for it lets the test finish as soon as the
	// question is answered instead of waiting for its own timeout.
	AuthenticatedMarker = "Authenticated to "
	// MaxReportedOutput bounds the captured stderr handed back for display.
	MaxReportedOutput = 8 << 10
	// DefaultAuthenticationTimeout bounds one authentication test.
	DefaultAuthenticationTimeout = 20 * time.Second
	// DefaultConnectTimeout is passed to OpenSSH so a stalled TCP connection
	// fails before this application's own timeout fires.
	DefaultConnectTimeout = 8 * time.Second
)

// Authentication test outcomes.
const (
	OutcomeAuthenticated  = "authenticated"
	OutcomeDenied         = "authentication_denied"
	OutcomeHostKeyUnknown = "host_key_unknown"
	OutcomeHostKeyChanged = "host_key_changed"
	OutcomeDNSFailure     = "dns_failure"
	OutcomeRefused        = "connection_refused"
	OutcomeTimeout        = "timeout"
	OutcomeFailed         = "failed"
)

// ExecutableDirectiveError reports that connecting would run a command that no
// command-line option can disable, and that the user has not confirmed it.
type ExecutableDirectiveError struct {
	Directives []effective.Executable
}

func (e *ExecutableDirectiveError) Error() string {
	return fmt.Sprintf("connecting would run %d configured command(s) that cannot be disabled", len(e.Directives))
}

// AuthenticationResult is one completed authentication test.
type AuthenticationResult struct {
	Outcome       string
	Authenticated bool
	ExitCode      int
	Stderr        string
	Truncated     bool
	Elapsed       time.Duration
}

// Authentication runs one real SSH authentication attempt.
type Authentication struct {
	Runner         platform.OutputRunner
	Toolchain      platform.Toolchain
	ConfigPath     string
	Timeout        time.Duration
	ConnectTimeout time.Duration
}

// HardeningOptions returns the command-line options that neutralise everything
// this test does not need. Command-line options take precedence over every
// configuration file, which is why the test can rely on them: SessionType=none
// asks for no shell and no remote command, ClearAllForwardings drops local,
// remote and dynamic forwards, PermitLocalCommand=no blocks LocalCommand, and
// StrictHostKeyChecking=yes refuses to trust an unknown host key silently.
func HardeningOptions(connectTimeout time.Duration) []string {
	seconds := int(connectTimeout.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	settings := []string{
		"BatchMode=yes",
		"PermitLocalCommand=no",
		"ClearAllForwardings=yes",
		"ForwardAgent=no",
		"ForwardX11=no",
		"ForwardX11Trusted=no",
		"ControlMaster=no",
		"ControlPath=none",
		"RemoteCommand=none",
		"RequestTTY=no",
		"SessionType=none",
		"StrictHostKeyChecking=yes",
		"NumberOfPasswordPrompts=0",
		"ConnectTimeout=" + strconv.Itoa(seconds),
	}
	options := make([]string, 0, len(settings)*2)
	for _, setting := range settings {
		options = append(options, "-o", setting)
	}
	return options
}

// Test authenticates against alias and stops as soon as the answer is known.
//
// acknowledged must come from a consumed action token that displayed the exact
// commands in report.Unavoidable(); without it, a configuration that would run
// such a command does not start.
func (a Authentication) Test(ctx context.Context, report effective.Report, alias string, acknowledged bool) (AuthenticationResult, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return AuthenticationResult{}, err
	}
	if blocking := report.Unavoidable(); len(blocking) > 0 && !acknowledged {
		return AuthenticationResult{}, &ExecutableDirectiveError{Directives: blocking}
	}
	program, err := a.Toolchain.SSH()
	if err != nil {
		return AuthenticationResult{}, err
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = DefaultAuthenticationTimeout
	}
	connectTimeout := a.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = DefaultConnectTimeout
	}

	arguments := []string{"-v", "-F", a.ConfigPath}
	arguments = append(arguments, HardeningOptions(connectTimeout)...)
	arguments = append(arguments, "--", alias)

	output, runErr := a.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: arguments,
		Timeout:   timeout,
		StopAfter: []byte(AuthenticatedMarker),
	})
	if runErr != nil && !errors.Is(runErr, platform.ErrTimedOut) {
		return AuthenticationResult{}, runErr
	}

	result := AuthenticationResult{
		ExitCode:  output.ExitCode,
		Stderr:    trimOutput(string(output.Stderr)),
		Truncated: output.Truncated,
		Elapsed:   output.Elapsed,
	}
	result.Truncated = result.Truncated || len(output.Stderr) > MaxReportedOutput
	result.Outcome, result.Authenticated = classify(output, runErr)
	return result, nil
}

func classify(output platform.Output, runErr error) (string, bool) {
	stderr := string(output.Stderr)
	if strings.Contains(stderr, AuthenticatedMarker) || strings.Contains(string(output.Stdout), AuthenticatedMarker) {
		return OutcomeAuthenticated, true
	}
	if errors.Is(runErr, platform.ErrTimedOut) {
		return OutcomeTimeout, false
	}
	switch {
	case strings.Contains(stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return OutcomeHostKeyChanged, false
	case strings.Contains(stderr, "Host key verification failed"):
		return OutcomeHostKeyUnknown, false
	case strings.Contains(stderr, "Permission denied"):
		return OutcomeDenied, false
	case strings.Contains(stderr, "Could not resolve hostname"):
		return OutcomeDNSFailure, false
	case strings.Contains(stderr, "Connection refused"):
		return OutcomeRefused, false
	case strings.Contains(stderr, "Connection timed out"), strings.Contains(stderr, "Operation timed out"):
		return OutcomeTimeout, false
	default:
		return OutcomeFailed, false
	}
}

func trimOutput(text string) string {
	if len(text) <= MaxReportedOutput {
		return text
	}
	return text[:MaxReportedOutput]
}
```

- [ ] **Step 8: Run the diagnostics tests with the race detector**

Run:

```bash
go test ./internal/diagnostics -v
go test -race ./internal/diagnostics
```

Expected: PASS.

- [ ] **Step 9: Commit the two connection checks**

```bash
git add internal/diagnostics
git commit -m "feat: add direct reachability and a bounded ssh authentication test"
```

## Task 5: One-time action tokens, the diagnostics service and its HTTP surface

**Files:**
- Create: `internal/session/action.go`
- Create: `internal/session/action_test.go`
- Modify: `internal/session/manager.go`
- Create: `internal/diagnostics/service.go`
- Create: `internal/diagnostics/service_test.go`
- Modify: `api/openapi.yaml`
- Create: `internal/httpserver/requests.go`
- Create: `internal/httpserver/actions.go`
- Create: `internal/httpserver/diagnostics.go`
- Create: `internal/httpserver/diagnostics_test.go`
- Modify: `internal/httpserver/server.go`
- Modify: `internal/app/run.go`
- Modify: `internal/app/run_test.go`
- Modify: `cmd/sshc/main.go`

**Interfaces:**
- Consumes: Tasks 1–4; committed `storage.NewWorkspace`, `storage.OSFileSystem`, `storage.NewResolver`, `config.Resolver`, `config.Graph`, `config.Diagnostic`; committed `httpserver.Security`, `SessionCookie`, `CSRFHeader`, `SessionContextKey`, `problem`.
- Produces: `session.ActionRequest{Kind, Target, Evidence string}`, `(*session.Manager).IssueAction(sessionID string, request ActionRequest) (string, error)`, `(*session.Manager).ConsumeAction(sessionID, presented string, request ActionRequest) error`.
- Produces: `session.ActionTokenTTL`, `session.MaxActionTokensPerSession`, `session.ErrInvalidAction`, `session.ErrActionExpired`, `session.ErrUnknownSession`, `session.ErrTooManyActions`, the action kind constants `session.ActionEvaluate`, `ActionReachability`, `ActionAuthentication`, `ActionTerminalLaunch`, `ActionKnownHostsDelete`, `ActionKnownHostsScan`, `ActionKnownHostsAdd`, `ActionRemoteKeyRegister`, and `session.KnownActionKind(kind string) bool`.
- Produces: `(*session.Manager).Now` clock field for tests.
- Produces: `diagnostics.Service` with `NewService(workspace *storage.Workspace, runner platform.OutputRunner, toolchain platform.Toolchain, terminal platform.TerminalLauncher) *Service`, `ConfigPath() string`, `Safety() (effective.Report, error)`, `ConfigCheck() (ConfigReport, error)`, `Inspect(ctx context.Context, alias string, confirmed bool) (Inspection, error)`, `Destination(alias string) (string, string, error)`, `Reach(ctx context.Context, alias string) (ReachabilityResult, error)`, `Authenticate(ctx context.Context, alias string, acknowledged bool) (AuthenticationResult, error)`.
- Produces: `diagnostics.ConfigReport{Root string, Files []ConfigFile, Diagnostics []config.Diagnostic}`, `diagnostics.ConfigFile{Path string, Editable, Missing bool, Loads, Includes int}`, `diagnostics.Inspection{Alias string, Report effective.Report, RequiresConfirmation, Evaluated bool, Values effective.Values, Projection effective.Projection, Route []effective.Stage, RouteComplexities []effective.Complexity, Failure *effective.OpenSSHError}`.
- Produces: `httpserver.MaxRequestBody`, `httpserver.DiagnosticsHandlers`, `httpserver.ActionHandlers`, and the `Options.Diagnostics` field.
- Produces: `app.Dependencies.Home`, `app.Dependencies.Runner`, `app.Dependencies.Toolchain`, `app.ErrMissingHome`.

- [ ] **Step 1: Write the failing action token test**

```go
// internal/session/action_test.go
package session

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func newTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	manager, bootstrap, err := NewManager(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	return manager, credentials.SessionID
}

func TestActionTokenIsSingleUseAndBoundToKindTargetAndEvidence(t *testing.T) {
	manager, sessionID := newTestManager(t)
	request := ActionRequest{Kind: ActionAuthentication, Target: "bastion", Evidence: "digest-a"}

	issued, err := manager.IssueAction(sessionID, request)
	if err != nil {
		t.Fatalf("IssueAction = %v", err)
	}
	if len(issued) != 43 {
		t.Fatalf("token length = %d, want 43", len(issued))
	}
	if err := manager.ConsumeAction(sessionID, issued, request); err != nil {
		t.Fatalf("ConsumeAction = %v", err)
	}
	if err := manager.ConsumeAction(sessionID, issued, request); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("replay = %v, want ErrInvalidAction", err)
	}

	mismatches := []ActionRequest{
		{Kind: ActionTerminalLaunch, Target: "bastion", Evidence: "digest-a"},
		{Kind: ActionAuthentication, Target: "other", Evidence: "digest-a"},
		{Kind: ActionAuthentication, Target: "bastion", Evidence: "digest-b"},
	}
	for _, mismatch := range mismatches {
		token, err := manager.IssueAction(sessionID, request)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.ConsumeAction(sessionID, token, mismatch); !errors.Is(err, ErrInvalidAction) {
			t.Errorf("ConsumeAction(%#v) = %v, want ErrInvalidAction", mismatch, err)
		}
		// A rejected presentation still burns the token.
		if err := manager.ConsumeAction(sessionID, token, request); !errors.Is(err, ErrInvalidAction) {
			t.Errorf("a rejected token stayed usable: %v", err)
		}
	}
}

func TestActionTokenExpiresAndIsScopedToOneSession(t *testing.T) {
	manager, sessionID := newTestManager(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	manager.Now = func() time.Time { return now }
	request := ActionRequest{Kind: ActionEvaluate, Target: "bastion", Evidence: "digest"}

	token, err := manager.IssueAction(sessionID, request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(ActionTokenTTL + time.Second)
	if err := manager.ConsumeAction(sessionID, token, request); !errors.Is(err, ErrActionExpired) {
		t.Fatalf("expired token = %v, want ErrActionExpired", err)
	}

	if _, err := manager.IssueAction("not-a-session", request); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("unknown session = %v, want ErrUnknownSession", err)
	}
	if err := manager.ConsumeAction("not-a-session", token, request); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("unknown session = %v, want ErrUnknownSession", err)
	}
}

func TestIssueActionRejectsUnknownKindsAndBoundsStoredTokens(t *testing.T) {
	manager, sessionID := newTestManager(t)

	if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: "shell.exec", Target: "bastion"}); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("unknown kind = %v, want ErrInvalidAction", err)
	}
	if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: ActionEvaluate}); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("empty target = %v, want ErrInvalidAction", err)
	}

	for index := 0; index < MaxActionTokensPerSession; index++ {
		if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: ActionEvaluate, Target: "bastion"}); err != nil {
			t.Fatalf("IssueAction %d = %v", index, err)
		}
	}
	if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: ActionEvaluate, Target: "bastion"}); !errors.Is(err, ErrTooManyActions) {
		t.Fatalf("exceeded limit = %v, want ErrTooManyActions", err)
	}
}

func TestKnownActionKindListsEveryConfirmedOperation(t *testing.T) {
	for _, kind := range []string{
		ActionEvaluate, ActionReachability, ActionAuthentication, ActionTerminalLaunch,
		ActionKnownHostsDelete, ActionKnownHostsScan, ActionKnownHostsAdd, ActionRemoteKeyRegister,
	} {
		if !KnownActionKind(kind) {
			t.Errorf("KnownActionKind(%q) = false", kind)
		}
	}
	if KnownActionKind("") || KnownActionKind("anything") {
		t.Error("KnownActionKind accepted an unknown kind")
	}
}
```

- [ ] **Step 2: Run the test and verify action tokens are absent**

Run: `go test ./internal/session -run TestAction`

Expected: FAIL to compile with `undefined: ActionRequest`.

- [ ] **Step 3: Implement action tokens**

Add the action store to the existing session, keeping the committed hashing shape:

```go
// internal/session/manager.go — modify the Session type and Bootstrap
type Session struct {
	csrfHash [sha256.Size]byte
	actions  map[[sha256.Size]byte]actionRecord
}
```

In `Bootstrap`, replace the stored session literal with one that carries an
initialised map, so `IssueAction` never writes to a nil map:

```go
	m.sessions[sha256.Sum256([]byte(sessionID))] = Session{
		csrfHash: sha256.Sum256([]byte(csrf)),
		actions:  make(map[[sha256.Size]byte]actionRecord),
	}
```

Add the `Now` clock field to `Manager` (leave every other field unchanged):

```go
type Manager struct {
	mu            sync.RWMutex
	random        io.Reader
	bootstrapHash [sha256.Size]byte
	bootstrapUsed bool
	sessions      map[[sha256.Size]byte]Session

	// Now is the clock used for action token expiry. It is nil in production,
	// where time.Now is used; tests set it once before the manager is shared.
	Now func() time.Time
}
```

`manager.go` needs `"time"` in its import block.

```go
// internal/session/action.go
package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"
)

const (
	// ActionTokenTTL is how long one confirmation stays usable. It is short
	// because a confirmation is answered by a person who is looking at the
	// dialog right now.
	ActionTokenTTL = 2 * time.Minute
	// MaxActionTokensPerSession bounds the memory one session can pin.
	MaxActionTokensPerSession = 32
)

// Action kinds. A token issued for one kind is useless for any other.
const (
	ActionEvaluate          = "diagnostics.evaluate"
	ActionReachability      = "diagnostics.reachability"
	ActionAuthentication    = "diagnostics.authentication"
	ActionTerminalLaunch    = "terminal.launch"
	ActionKnownHostsDelete  = "known_hosts.delete"
	ActionKnownHostsScan    = "known_hosts.scan"
	ActionKnownHostsAdd     = "known_hosts.add"
	ActionRemoteKeyRegister = "remote_key.register"
)

var (
	ErrInvalidAction  = errors.New("action token is not valid for this operation")
	ErrActionExpired  = errors.New("action token has expired")
	ErrUnknownSession = errors.New("session does not exist")
	ErrTooManyActions = errors.New("too many pending confirmations for this session")
)

var knownActionKinds = map[string]bool{
	ActionEvaluate:          true,
	ActionReachability:      true,
	ActionAuthentication:    true,
	ActionTerminalLaunch:    true,
	ActionKnownHostsDelete:  true,
	ActionKnownHostsScan:    true,
	ActionKnownHostsAdd:     true,
	ActionRemoteKeyRegister: true,
}

// KnownActionKind reports whether kind is an operation this application will
// ever confirm.
func KnownActionKind(kind string) bool { return knownActionKinds[kind] }

// ActionRequest identifies exactly one confirmed operation.
//
// Evidence is a digest of what the confirmation dialog displayed — usually the
// executable directives, or the current contents of the file being edited — so
// a change between the confirmation and the execution invalidates the token
// instead of silently applying to something else.
type ActionRequest struct {
	Kind     string
	Target   string
	Evidence string
}

type actionRecord struct {
	kind      string
	target    string
	evidence  string
	expiresAt time.Time
}

func (m *Manager) clock() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// IssueAction stores one confirmation and returns its token. The token is
// returned once and only its hash is kept, exactly like the session secrets.
func (m *Manager) IssueAction(sessionID string, request ActionRequest) (string, error) {
	if !KnownActionKind(request.Kind) || request.Target == "" {
		return "", ErrInvalidAction
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sessionValue, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	if !ok {
		return "", ErrUnknownSession
	}
	now := m.clock()
	expireLocked(sessionValue, now)
	if len(sessionValue.actions) >= MaxActionTokensPerSession {
		return "", ErrTooManyActions
	}

	value, err := token(m.random)
	if err != nil {
		return "", err
	}
	sessionValue.actions[sha256.Sum256([]byte(value))] = actionRecord{
		kind:      request.Kind,
		target:    request.Target,
		evidence:  request.Evidence,
		expiresAt: now.Add(ActionTokenTTL),
	}
	return value, nil
}

// ConsumeAction verifies and burns one confirmation.
//
// The token is removed before it is checked, so a presentation that does not
// match cannot be retried against a different operation.
func (m *Manager) ConsumeAction(sessionID, presented string, request ActionRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionValue, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	if !ok {
		return ErrUnknownSession
	}
	now := m.clock()
	expireLocked(sessionValue, now)

	presentedHash := sha256.Sum256([]byte(presented))
	record, found := sessionValue.actions[presentedHash]
	if !found {
		return ErrInvalidAction
	}
	delete(sessionValue.actions, presentedHash)

	if now.After(record.expiresAt) {
		return ErrActionExpired
	}
	matched := subtle.ConstantTimeCompare([]byte(record.kind), []byte(request.Kind)) &
		subtle.ConstantTimeCompare([]byte(record.target), []byte(request.Target)) &
		subtle.ConstantTimeCompare([]byte(record.evidence), []byte(request.Evidence))
	if matched != 1 {
		return ErrInvalidAction
	}
	return nil
}

func expireLocked(sessionValue Session, now time.Time) {
	for hash, record := range sessionValue.actions {
		if now.After(record.expiresAt) {
			delete(sessionValue.actions, hash)
		}
	}
}
```

- [ ] **Step 4: Run the session tests with the race detector**

Run:

```bash
go test ./internal/session -v
go test -race ./internal/session
```

Expected: PASS, including the committed bootstrap and CSRF tests.

- [ ] **Step 5: Write the failing diagnostics service test**

```go
// internal/diagnostics/service_test.go
package diagnostics_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"sshc/internal/diagnostics"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/storage"
)

const serviceConfig = `Host bastion
	HostName 203.0.113.10
	User ops
	Port 2222

Host risky
	ProxyCommand /usr/bin/nc %h %p
`

func newServiceWorkspace(t *testing.T, contents string) *storage.Workspace {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}

func newTestService(t *testing.T, runner platform.OutputRunner) *diagnostics.Service {
	t.Helper()
	service := diagnostics.NewService(
		newServiceWorkspace(t, serviceConfig),
		runner,
		fixedToolchain{ssh: "/usr/bin/ssh", keyscan: "/usr/bin/ssh-keyscan"},
		nil,
	)
	service.Reachability = diagnostics.Reachability{
		Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: errRefusedForTest}
		}),
	}
	return service
}

var errRefusedForTest = net.UnknownNetworkError("refused in test")

func TestServiceInspectEvaluatesSafeConfigurationsAutomatically(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{Stdout: []byte("hostname 203.0.113.10\nuser ops\nport 2222\n")}}
	service := newTestService(t, runner)

	inspection, err := service.Inspect(context.Background(), "bastion", false)
	if err != nil {
		t.Fatalf("Inspect = %v", err)
	}
	if !inspection.Evaluated || inspection.RequiresConfirmation {
		t.Fatalf("inspection = %#v", inspection)
	}
	if got := inspection.Values.First("hostname"); got != "203.0.113.10" {
		t.Errorf("hostname = %q", got)
	}
	if source, ok := inspection.Projection.Value("hostname"); !ok || source.Line != 2 {
		t.Errorf("projection = %#v", inspection.Projection)
	}
	if len(inspection.Report.Directives) != 1 || inspection.Report.Directives[0].Keyword != "ProxyCommand" {
		t.Errorf("report = %#v", inspection.Report)
	}
}

func TestServiceInspectReportsAnOpenSSHFailureAsData(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{ExitCode: 255, Stderr: []byte("Bad configuration option\n")}}
	inspection, err := newTestService(t, runner).Inspect(context.Background(), "bastion", false)
	if err != nil {
		t.Fatalf("Inspect = %v", err)
	}
	if inspection.Evaluated || inspection.Failure == nil || inspection.Failure.ExitCode != 255 {
		t.Fatalf("inspection = %#v", inspection)
	}
}

func TestServiceDestinationUsesTheEngineSoABlockedEvaluationStillWorks(t *testing.T) {
	runner := &scriptedRunner{}
	service := newTestService(t, runner)

	hostname, port, err := service.Destination("bastion")
	if err != nil {
		t.Fatalf("Destination = %v", err)
	}
	if hostname != "203.0.113.10" || port != "2222" {
		t.Fatalf("destination = %s:%s", hostname, port)
	}

	unknownHostname, unknownPort, err := service.Destination("unlisted")
	if err != nil {
		t.Fatalf("Destination = %v", err)
	}
	if unknownHostname != "unlisted" || unknownPort != "22" {
		t.Errorf("defaults = %s:%s, want unlisted:22", unknownHostname, unknownPort)
	}

	result, err := service.Reach(context.Background(), "bastion")
	if err != nil {
		t.Fatalf("Reach = %v", err)
	}
	if result.Address != "203.0.113.10:2222" || result.Notice == "" {
		t.Errorf("result = %#v", result)
	}
	if len(runner.commands) != 0 {
		t.Fatal("reachability must not start ssh")
	}
}

func TestServiceConfigCheckSummarisesTheIncludeGraph(t *testing.T) {
	report, err := newTestService(t, &scriptedRunner{}).ConfigCheck()
	if err != nil {
		t.Fatalf("ConfigCheck = %v", err)
	}
	if len(report.Files) != 1 || !report.Files[0].Editable || report.Files[0].Missing {
		t.Fatalf("files = %#v", report.Files)
	}
	for _, diagnostic := range report.Diagnostics {
		if diagnostic.Severity > 0 {
			t.Errorf("unexpected diagnostic: %#v", diagnostic)
		}
	}
}

func TestServiceSafetyReportsTheSameEvidenceAsAFreshScan(t *testing.T) {
	service := newTestService(t, &scriptedRunner{})
	report, err := service.Safety()
	if err != nil {
		t.Fatalf("Safety = %v", err)
	}
	if report.Evidence() == (effective.Report{}).Evidence() {
		t.Error("a configuration with a ProxyCommand must not produce empty evidence")
	}
}
```

- [ ] **Step 6: Run the test and verify the service is absent**

Run: `go test ./internal/diagnostics -run TestService`

Expected: FAIL to compile with `undefined: diagnostics.NewService`.

- [ ] **Step 7: Implement the diagnostics service**

```go
// internal/diagnostics/service.go
package diagnostics

import (
	"context"
	"errors"
	"net"
	"path/filepath"

	"sshc/internal/config"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/storage"
)

// ConfigFile is one file of the Include graph, summarised for display.
type ConfigFile struct {
	Path     string
	Editable bool
	Missing  bool
	Loads    int
	Includes int
}

// ConfigReport is the syntax and Include check. It starts no process.
type ConfigReport struct {
	Root        string
	Files       []ConfigFile
	Diagnostics []config.Diagnostic
}

// Inspection is everything the effective-configuration screen needs.
type Inspection struct {
	Alias                string
	Report               effective.Report
	RequiresConfirmation bool
	Evaluated            bool
	Values               effective.Values
	Projection           effective.Projection
	Route                []effective.Stage
	RouteComplexities    []effective.Complexity
	Failure              *effective.OpenSSHError
}

// Service composes the configuration engine with the checks in this package.
// It re-reads the configuration for every request, because the files are the
// source of truth and may change between two requests.
type Service struct {
	Workspace      *storage.Workspace
	Resolver       config.Resolver
	Evaluator      effective.Evaluator
	Reachability   Reachability
	Authentication Authentication
	Terminal       platform.TerminalLauncher
}

// NewService wires the production dependencies together.
func NewService(workspace *storage.Workspace, runner platform.OutputRunner, toolchain platform.Toolchain, terminal platform.TerminalLauncher) *Service {
	configPath := filepath.Join(workspace.Root(), "config")
	return &Service{
		Workspace:      workspace,
		Resolver:       storage.NewResolver(workspace),
		Evaluator:      effective.Evaluator{Runner: runner, Toolchain: toolchain, ConfigPath: configPath},
		Reachability:   Reachability{Dialer: &net.Dialer{}},
		Authentication: Authentication{Runner: runner, Toolchain: toolchain, ConfigPath: configPath},
		Terminal:       terminal,
	}
}

// ConfigPath is the user configuration this service evaluates.
func (s *Service) ConfigPath() string { return filepath.Join(s.Workspace.Root(), "config") }

func (s *Service) graph() (*config.Graph, error) { return s.Resolver.Resolve(s.ConfigPath()) }

// Safety scans the current configuration for executable directives.
func (s *Service) Safety() (effective.Report, error) {
	graph, err := s.graph()
	if err != nil {
		return effective.Report{}, err
	}
	return effective.Scan(graph), nil
}

// ConfigCheck reports the Include graph and its diagnostics.
func (s *Service) ConfigCheck() (ConfigReport, error) {
	graph, err := s.graph()
	if err != nil {
		return ConfigReport{}, err
	}
	report := ConfigReport{Root: graph.Root, Diagnostics: graph.Diagnostics}
	for _, path := range graph.Order {
		node := graph.Nodes[path]
		if node == nil {
			continue
		}
		report.Files = append(report.Files, ConfigFile{
			Path:     node.Path,
			Editable: node.Editable,
			Missing:  node.Missing,
			Loads:    node.Loads,
			Includes: len(node.Includes),
		})
	}
	return report, nil
}

// Inspect explains one alias and, when that is allowed, evaluates it.
//
// A refused evaluation and a failing ssh are both returned as data: the screen
// still shows the engine's own projection and the exact commands that must be
// confirmed first.
func (s *Service) Inspect(ctx context.Context, alias string, confirmed bool) (Inspection, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Inspection{}, err
	}
	graph, err := s.graph()
	if err != nil {
		return Inspection{}, err
	}

	inspection := Inspection{Alias: alias, Report: effective.Scan(graph)}
	inspection.Projection = effective.Project(graph, alias)
	inspection.Route, inspection.RouteComplexities = effective.ExpandRoute(graph, alias)
	inspection.RequiresConfirmation = inspection.Report.EvaluationNeedsConfirmation()

	values, err := s.Evaluator.Evaluate(ctx, inspection.Report, alias, confirmed)
	var opensshError *effective.OpenSSHError
	switch {
	case err == nil:
		inspection.Values = values
		inspection.Evaluated = true
	case errors.Is(err, effective.ErrEvaluationNotConfirmed):
		// Expected: the caller has not confirmed yet.
	case errors.As(err, &opensshError):
		inspection.Failure = opensshError
	default:
		return Inspection{}, err
	}
	return inspection, nil
}

// Destination returns the hostname and port the engine projects for alias.
//
// It never runs ssh, so a reachability check still works while evaluation is
// blocked by an executable directive.
func (s *Service) Destination(alias string) (string, string, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return "", "", err
	}
	graph, err := s.graph()
	if err != nil {
		return "", "", err
	}
	projection := effective.Project(graph, alias)
	hostname := alias
	if source, ok := projection.Value("hostname"); ok {
		hostname = source.Value
	}
	port := "22"
	if source, ok := projection.Value("port"); ok {
		port = source.Value
	}
	return hostname, port, nil
}

// Reach dials the destination directly, ignoring ProxyJump.
func (s *Service) Reach(ctx context.Context, alias string) (ReachabilityResult, error) {
	hostname, port, err := s.Destination(alias)
	if err != nil {
		return ReachabilityResult{}, err
	}
	if err := platform.ValidateHostname(hostname); err != nil {
		return ReachabilityResult{}, err
	}
	return s.Reachability.Check(ctx, hostname, port), nil
}

// Authenticate runs the authentication test for alias.
func (s *Service) Authenticate(ctx context.Context, alias string, acknowledged bool) (AuthenticationResult, error) {
	report, err := s.Safety()
	if err != nil {
		return AuthenticationResult{}, err
	}
	return s.Authentication.Test(ctx, report, alias, acknowledged)
}
```

- [ ] **Step 8: Run the diagnostics package tests**

Run:

```bash
go test ./internal/diagnostics -v
go test -race ./internal/diagnostics
```

Expected: PASS.

- [ ] **Step 9: Extend the OpenAPI contract**

Add these five paths to `api/openapi.yaml` under the existing `paths:` mapping, after `/api/v1/health`:

```yaml
  /api/v1/actions/token:
    post:
      operationId: issueActionToken
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/ActionTokenRequest" }
      responses:
        "200":
          description: One-time confirmation issued
          content:
            application/json:
              schema: { $ref: "#/components/schemas/ActionTokenResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/diagnostics/config:
    post:
      operationId: checkConfiguration
      responses:
        "200":
          description: Syntax and Include graph check
          content:
            application/json:
              schema: { $ref: "#/components/schemas/ConfigCheckResponse" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/diagnostics/effective:
    post:
      operationId: inspectEffectiveConfiguration
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/EffectiveRequest" }
      responses:
        "200":
          description: Effective configuration, provenance and jump route
          content:
            application/json:
              schema: { $ref: "#/components/schemas/EffectiveResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/diagnostics/reachability:
    post:
      operationId: checkReachability
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/TargetRequest" }
      responses:
        "200":
          description: Direct TCP reachability, ignoring ProxyJump
          content:
            application/json:
              schema: { $ref: "#/components/schemas/ReachabilityResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/diagnostics/authentication:
    post:
      operationId: testAuthentication
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/AuthenticationRequest" }
      responses:
        "200":
          description: Completed authentication test
          content:
            application/json:
              schema: { $ref: "#/components/schemas/AuthenticationResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
```

Add these schemas under `components.schemas`, after `HealthResponse`. Every
request field is required so the generated Go models use plain values rather
than pointers; a field that does not apply is sent as an empty string or
`false`.

```yaml
    ActionTokenRequest:
      type: object
      additionalProperties: false
      required: [kind, target]
      properties:
        kind: { type: string, minLength: 1, maxLength: 64 }
        target: { type: string, minLength: 1, maxLength: 255 }
    ActionTokenResponse:
      type: object
      additionalProperties: false
      required: [token, expiresInSeconds, executableDirectives, tokenWarning]
      properties:
        token: { type: string, minLength: 43, maxLength: 43 }
        expiresInSeconds: { type: integer }
        tokenWarning: { type: string }
        executableDirectives:
          type: array
          items: { $ref: "#/components/schemas/ExecutableDirective" }
    ExecutableDirective:
      type: object
      additionalProperties: false
      required: [keyword, command, path, line, condition, onEvaluate, onConnect, overridable]
      properties:
        keyword: { type: string }
        command: { type: string }
        path: { type: string }
        line: { type: integer }
        condition: { type: string }
        onEvaluate: { type: boolean }
        onConnect: { type: boolean }
        overridable: { type: boolean }
    ConfigCheckResponse:
      type: object
      additionalProperties: false
      required: [root, files, diagnostics]
      properties:
        root: { type: string }
        files:
          type: array
          items: { $ref: "#/components/schemas/ConfigFileSummary" }
        diagnostics:
          type: array
          items: { $ref: "#/components/schemas/ConfigDiagnostic" }
    ConfigFileSummary:
      type: object
      additionalProperties: false
      required: [path, editable, missing, loads, includes]
      properties:
        path: { type: string }
        editable: { type: boolean }
        missing: { type: boolean }
        loads: { type: integer }
        includes: { type: integer }
    ConfigDiagnostic:
      type: object
      additionalProperties: false
      required: [severity, code, path, line, detail]
      properties:
        severity: { type: string }
        code: { type: string }
        path: { type: string }
        line: { type: integer }
        detail: { type: string }
    EffectiveRequest:
      type: object
      additionalProperties: false
      required: [alias, actionToken]
      properties:
        alias: { type: string, minLength: 1, maxLength: 64 }
        actionToken: { type: string, maxLength: 43 }
    EffectiveResponse:
      type: object
      additionalProperties: false
      required: [alias, evaluated, requiresConfirmation, tokenWarning, executableDirectives, values, sources, complexities, route, failure]
      properties:
        alias: { type: string }
        evaluated: { type: boolean }
        requiresConfirmation: { type: boolean }
        tokenWarning: { type: string }
        executableDirectives:
          type: array
          items: { $ref: "#/components/schemas/ExecutableDirective" }
        values:
          type: array
          items: { $ref: "#/components/schemas/EffectiveValue" }
        sources:
          type: array
          items: { $ref: "#/components/schemas/ValueSource" }
        complexities:
          type: array
          items: { $ref: "#/components/schemas/ComplexityNote" }
        route:
          type: array
          items: { $ref: "#/components/schemas/JumpStage" }
        failure: { $ref: "#/components/schemas/OpenSSHFailure" }
    EffectiveValue:
      type: object
      additionalProperties: false
      required: [keyword, values]
      properties:
        keyword: { type: string }
        values:
          type: array
          items: { type: string }
    ValueSource:
      type: object
      additionalProperties: false
      required: [keyword, value, path, line, condition, kind, winner]
      properties:
        keyword: { type: string }
        value: { type: string }
        path: { type: string }
        line: { type: integer }
        condition: { type: string }
        kind: { type: string }
        winner: { type: boolean }
    ComplexityNote:
      type: object
      additionalProperties: false
      required: [code, path, line, condition, detail]
      properties:
        code: { type: string }
        path: { type: string }
        line: { type: integer }
        condition: { type: string }
        detail: { type: string }
    JumpStage:
      type: object
      additionalProperties: false
      required: [order, depth, parent, hop, hostname, user, port, complex]
      properties:
        order: { type: integer }
        depth: { type: integer }
        parent: { type: string }
        hop: { type: string }
        hostname: { type: string }
        user: { type: string }
        port: { type: string }
        complex: { type: boolean }
    OpenSSHFailure:
      type: object
      additionalProperties: false
      required: [failed, exitCode, stderr, truncated]
      properties:
        failed: { type: boolean }
        exitCode: { type: integer }
        stderr: { type: string }
        truncated: { type: boolean }
    TargetRequest:
      type: object
      additionalProperties: false
      required: [alias, actionToken]
      properties:
        alias: { type: string, minLength: 1, maxLength: 64 }
        actionToken: { type: string, minLength: 43, maxLength: 43 }
    ReachabilityResponse:
      type: object
      additionalProperties: false
      required: [address, outcome, elapsedMs, detail, notice]
      properties:
        address: { type: string }
        outcome: { type: string }
        elapsedMs: { type: integer }
        detail: { type: string }
        notice: { type: string }
    AuthenticationRequest:
      type: object
      additionalProperties: false
      required: [alias, actionToken, acknowledgeExecutable]
      properties:
        alias: { type: string, minLength: 1, maxLength: 64 }
        actionToken: { type: string, minLength: 43, maxLength: 43 }
        acknowledgeExecutable: { type: boolean }
    AuthenticationResponse:
      type: object
      additionalProperties: false
      required: [outcome, authenticated, exitCode, stderr, truncated, elapsedMs]
      properties:
        outcome: { type: string }
        authenticated: { type: boolean }
        exitCode: { type: integer }
        stderr: { type: string }
        truncated: { type: boolean }
        elapsedMs: { type: integer }
```

Run: `make generate`

Expected: `internal/api/models.gen.go` and `web/src/api/schema.d.ts` gain the new types; `go test ./internal/api` still passes.

- [ ] **Step 10: Write the failing HTTP surface test**

```go
// internal/httpserver/diagnostics_test.go
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/api"
	"sshc/internal/diagnostics"
	"sshc/internal/platform"
	"sshc/internal/session"
	"sshc/internal/storage"
)

type stubRunner struct {
	commands []platform.Command
	output   platform.Output
}

func (runner *stubRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, nil
}

type stubToolchain struct{}

func (stubToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (stubToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }

const handlerConfig = "Host bastion\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 2222\n\nHost risky\n\tProxyCommand /usr/bin/nc %h %p\n"

type testServer struct {
	server  *Server
	client  *http.Client
	origin  string
	host    string
	cookie  *http.Cookie
	csrf    string
	runner  *stubRunner
	service *diagnostics.Service
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config"), []byte(handlerConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}

	runner := &stubRunner{output: platform.Output{Stdout: []byte("hostname 203.0.113.10\nport 2222\n")}}
	service := diagnostics.NewService(workspace, runner, stubToolchain{}, nil)
	service.Reachability = diagnostics.Reachability{
		Dialer: dialerStub(func(context.Context, string, string) (net.Conn, error) {
			return nil, net.UnknownNetworkError("unreachable in test")
		}),
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x3c}, 8192)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{
		Listener:    listener,
		Sessions:    manager,
		UI:          emptyUI{},
		Version:     "test",
		Diagnostics: service,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	harness := &testServer{
		server:  server,
		client:  &http.Client{},
		origin:  server.URL(),
		host:    strings.TrimPrefix(server.URL(), "http://"),
		runner:  runner,
		service: service,
	}

	request, err := http.NewRequest(http.MethodPost, server.URL()+"/api/v1/session/bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = harness.host
	request.Header.Set("Origin", harness.origin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("X-SSHC-Bootstrap", bootstrap)
	response, err := harness.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var payload api.BootstrapResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	harness.cookie = response.Cookies()[0]
	harness.csrf = payload.CsrfToken
	return harness
}

func (s *testServer) post(t *testing.T, path string, body any, withCSRF bool) *http.Response {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, s.origin+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = s.host
	request.Header.Set("Origin", s.origin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	if withCSRF {
		request.Header.Set(CSRFHeader, s.csrf)
	}
	request.AddCookie(s.cookie)
	response, err := s.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (s *testServer) actionToken(t *testing.T, kind, target string) string {
	t.Helper()
	response := s.post(t, "/api/v1/actions/token", api.ActionTokenRequest{Kind: kind, Target: target}, true)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("actions/token = %d", response.StatusCode)
	}
	var payload api.ActionTokenResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Token
}

// dialerStub and emptyUI keep this test self-contained.
type dialerStub func(ctx context.Context, network, address string) (net.Conn, error)

func (dial dialerStub) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dial(ctx, network, address)
}

type emptyUI struct{}

func (emptyUI) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }

func TestEffectiveEndpointRefusesWithoutAConfirmationAndThenEvaluates(t *testing.T) {
	server := newTestServer(t)

	response := server.post(t, "/api/v1/diagnostics/effective", api.EffectiveRequest{Alias: "bastion"}, true)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("effective = %d", response.StatusCode)
	}
	var payload api.EffectiveResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Evaluated {
		t.Fatalf("a configuration without Match exec evaluates automatically: %#v", payload)
	}
	if len(payload.ExecutableDirectives) != 1 || payload.ExecutableDirectives[0].Command != "/usr/bin/nc %h %p" {
		t.Errorf("executable directives = %#v", payload.ExecutableDirectives)
	}
	if payload.TokenWarning == "" {
		t.Error("the response must carry the token-escaping warning")
	}
	if len(payload.Sources) == 0 || payload.Sources[0].Path == "" {
		t.Errorf("sources = %#v", payload.Sources)
	}
}

func TestStateChangingDiagnosticsRequireCSRFAndAOneTimeActionToken(t *testing.T) {
	server := newTestServer(t)

	noCSRF := server.post(t, "/api/v1/diagnostics/reachability", api.TargetRequest{Alias: "bastion", ActionToken: strings.Repeat("a", 43)}, false)
	noCSRF.Body.Close()
	if noCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF = %d, want 403", noCSRF.StatusCode)
	}

	wrongToken := server.post(t, "/api/v1/diagnostics/reachability", api.TargetRequest{Alias: "bastion", ActionToken: strings.Repeat("a", 43)}, true)
	wrongToken.Body.Close()
	if wrongToken.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid action token = %d, want 403", wrongToken.StatusCode)
	}

	token := server.actionToken(t, session.ActionReachability, "bastion")
	accepted := server.post(t, "/api/v1/diagnostics/reachability", api.TargetRequest{Alias: "bastion", ActionToken: token}, true)
	defer accepted.Body.Close()
	if accepted.StatusCode != http.StatusOK {
		t.Fatalf("reachability = %d", accepted.StatusCode)
	}
	var payload api.ReachabilityResponse
	if err := json.NewDecoder(accepted.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Address != "203.0.113.10:2222" || payload.Notice == "" {
		t.Errorf("payload = %#v", payload)
	}

	replay := server.post(t, "/api/v1/diagnostics/reachability", api.TargetRequest{Alias: "bastion", ActionToken: token}, true)
	replay.Body.Close()
	if replay.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed token = %d, want 403", replay.StatusCode)
	}
}

func TestActionTokenIsUselessForAnotherOperationOrTarget(t *testing.T) {
	server := newTestServer(t)

	token := server.actionToken(t, session.ActionReachability, "bastion")
	wrongKind := server.post(t, "/api/v1/diagnostics/authentication",
		api.AuthenticationRequest{Alias: "bastion", ActionToken: token}, true)
	wrongKind.Body.Close()
	if wrongKind.StatusCode != http.StatusForbidden {
		t.Fatalf("token used for another kind = %d, want 403", wrongKind.StatusCode)
	}

	other := server.actionToken(t, session.ActionReachability, "risky")
	wrongTarget := server.post(t, "/api/v1/diagnostics/reachability",
		api.TargetRequest{Alias: "bastion", ActionToken: other}, true)
	wrongTarget.Body.Close()
	if wrongTarget.StatusCode != http.StatusForbidden {
		t.Fatalf("token used for another target = %d, want 403", wrongTarget.StatusCode)
	}
}

func TestDiagnosticsRejectUnsafeAliasesAndOversizedBodies(t *testing.T) {
	server := newTestServer(t)

	unsafe := server.post(t, "/api/v1/diagnostics/effective", api.EffectiveRequest{Alias: "-oProxyCommand=id"}, true)
	unsafe.Body.Close()
	if unsafe.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsafe alias = %d, want 400", unsafe.StatusCode)
	}
	if len(server.runner.commands) != 0 {
		t.Fatal("an unsafe alias started a process")
	}

	oversized := server.post(t, "/api/v1/diagnostics/effective",
		api.EffectiveRequest{Alias: strings.Repeat("a", MaxRequestBody)}, true)
	oversized.Body.Close()
	if oversized.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body = %d, want 400", oversized.StatusCode)
	}
}

func TestConfigCheckNeedsNoActionTokenAndStartsNoProcess(t *testing.T) {
	server := newTestServer(t)

	response := server.post(t, "/api/v1/diagnostics/config", struct{}{}, true)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("config check = %d", response.StatusCode)
	}
	var payload api.ConfigCheckResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Files) != 1 {
		t.Fatalf("files = %#v", payload.Files)
	}
	if len(server.runner.commands) != 0 {
		t.Fatal("the configuration check started a process")
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

```

Add `"io/fs"` to this file's import block for `emptyUI`.

- [ ] **Step 11: Run the test and verify the endpoints are absent**

Run: `go test ./internal/httpserver -run 'TestEffectiveEndpoint|TestStateChangingDiagnostics'`

Expected: FAIL to compile with `unknown field Diagnostics in Options`.

- [ ] **Step 12: Implement request decoding and the action token endpoint**

```go
// internal/httpserver/requests.go
package httpserver

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v5"
)

// MaxRequestBody bounds every JSON body this application accepts.
const MaxRequestBody = 64 << 10

// decodeJSON reads a bounded JSON body and rejects unknown fields, so a
// request cannot smuggle a field a future version might honour.
func decodeJSON(c *echo.Context, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, MaxRequestBody))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// currentSession returns the session identifier the security middleware stored.
func currentSession(c *echo.Context) string {
	value, _ := c.Get(SessionContextKey).(string)
	return value
}
```

```go
// internal/httpserver/actions.go
package httpserver

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/diagnostics"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/session"
)

// ActionHandlers issues the one-time confirmations every externally visible
// operation requires.
type ActionHandlers struct {
	Sessions    *session.Manager
	Diagnostics *diagnostics.Service
}

// IssueToken returns a token bound to the session, the operation kind, the
// target and the evidence the caller must have displayed.
func (h ActionHandlers) IssueToken(c *echo.Context) error {
	var request api.ActionTokenRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if !session.KnownActionKind(request.Kind) {
		return problem(c, http.StatusBadRequest, "unknown_action_kind")
	}

	evidence, directives, err := h.evidence(request.Kind, request.Target)
	if err != nil {
		return problem(c, http.StatusBadRequest, err.Error())
	}

	token, err := h.Sessions.IssueAction(currentSession(c), session.ActionRequest{
		Kind:     request.Kind,
		Target:   request.Target,
		Evidence: evidence,
	})
	if err != nil {
		return problem(c, http.StatusForbidden, "action_token_refused")
	}
	return c.JSON(http.StatusOK, api.ActionTokenResponse{
		Token:                token,
		ExpiresInSeconds:     int(session.ActionTokenTTL.Seconds()),
		TokenWarning:         effective.TokenEscapeWarning,
		ExecutableDirectives: describeDirectives(directives),
	})
}

// evidence binds a confirmation to the state the user was shown.
//
// SSH operations are bound to the executable directives of the current
// configuration; the known_hosts and remote-key kinds are added by their own
// tasks. An edit between the confirmation and the execution therefore
// invalidates the token instead of silently applying to something else.
func (h ActionHandlers) evidence(kind, target string) (string, []effective.Executable, error) {
	switch kind {
	case session.ActionEvaluate, session.ActionReachability, session.ActionAuthentication,
		session.ActionTerminalLaunch, session.ActionRemoteKeyRegister:
		if err := platform.ValidateAlias(target); err != nil {
			return "", nil, errInvalidTarget
		}
		if h.Diagnostics == nil {
			return "", nil, errUnavailable
		}
		report, err := h.Diagnostics.Safety()
		if err != nil {
			return "", nil, errUnavailable
		}
		return report.Evidence(), report.Directives, nil
	default:
		return "", nil, errUnsupportedKind
	}
}

// The problem codes these sentinel errors carry are returned verbatim.
var (
	errInvalidTarget   = actionError("invalid_target")
	errUnavailable     = actionError("integration_unavailable")
	errUnsupportedKind = actionError("unknown_action_kind")
)

type actionError string

func (e actionError) Error() string { return string(e) }

func describeDirectives(directives []effective.Executable) []api.ExecutableDirective {
	described := make([]api.ExecutableDirective, 0, len(directives))
	for _, directive := range directives {
		described = append(described, api.ExecutableDirective{
			Keyword:     directive.Keyword,
			Command:     directive.Command,
			Path:        directive.Path,
			Line:        directive.Line,
			Condition:   directive.Condition,
			OnEvaluate:  directive.OnEvaluate,
			OnConnect:   directive.OnConnect,
			Overridable: directive.Overridable,
		})
	}
	return described
}
```

- [ ] **Step 13: Implement the diagnostics handlers**

```go
// internal/httpserver/diagnostics.go
package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/config"
	"sshc/internal/diagnostics"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/session"
)

// DiagnosticsHandlers exposes the separately triggered checks.
type DiagnosticsHandlers struct {
	Sessions *session.Manager
	Service  *diagnostics.Service
}

// CheckConfig runs the syntax and Include check. It starts no process, so it
// needs no action token, only a session and the CSRF header.
func (h DiagnosticsHandlers) CheckConfig(c *echo.Context) error {
	report, err := h.Service.ConfigCheck()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}

	response := api.ConfigCheckResponse{
		Root:        report.Root,
		Files:       make([]api.ConfigFileSummary, 0, len(report.Files)),
		Diagnostics: make([]api.ConfigDiagnostic, 0, len(report.Diagnostics)),
	}
	for _, file := range report.Files {
		response.Files = append(response.Files, api.ConfigFileSummary{
			Path: file.Path, Editable: file.Editable, Missing: file.Missing,
			Loads: file.Loads, Includes: file.Includes,
		})
	}
	for _, diagnostic := range report.Diagnostics {
		response.Diagnostics = append(response.Diagnostics, api.ConfigDiagnostic{
			Severity: severityName(diagnostic.Severity),
			Code:     diagnostic.Code,
			Path:     diagnostic.Path,
			Line:     diagnostic.Line,
			Detail:   diagnostic.Detail,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Effective explains one alias and evaluates it when that is allowed.
func (h DiagnosticsHandlers) Effective(c *echo.Context) error {
	var request api.EffectiveRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}

	confirmed := false
	if request.ActionToken != "" {
		if err := h.consume(c, session.ActionEvaluate, request.Alias, request.ActionToken); err != nil {
			return err
		}
		confirmed = true
	}

	inspection, err := h.Service.Inspect(c.Request().Context(), request.Alias, confirmed)
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inspection_failed")
	}

	response := api.EffectiveResponse{
		Alias:                inspection.Alias,
		Evaluated:            inspection.Evaluated,
		RequiresConfirmation: inspection.RequiresConfirmation,
		TokenWarning:         effective.TokenEscapeWarning,
		ExecutableDirectives: describeDirectives(inspection.Report.Directives),
		Values:               make([]api.EffectiveValue, 0, len(inspection.Values.Keywords)),
		Sources:              make([]api.ValueSource, 0, len(inspection.Projection.Sources)),
		Complexities:         make([]api.ComplexityNote, 0, len(inspection.Projection.Complexities)),
		Route:                make([]api.JumpStage, 0, len(inspection.Route)),
		Failure:              api.OpenSSHFailure{},
	}
	for _, keyword := range inspection.Values.Keywords {
		response.Values = append(response.Values, api.EffectiveValue{
			Keyword: keyword,
			Values:  inspection.Values.All(keyword),
		})
	}
	for _, source := range inspection.Projection.Sources {
		response.Sources = append(response.Sources, api.ValueSource{
			Keyword: source.Keyword, Value: source.Value, Path: source.Path,
			Line: source.Line, Condition: source.Condition, Kind: source.Kind, Winner: source.Winner,
		})
	}
	for _, complexity := range append(inspection.Projection.Complexities, inspection.RouteComplexities...) {
		response.Complexities = append(response.Complexities, api.ComplexityNote{
			Code: complexity.Code, Path: complexity.Path, Line: complexity.Line,
			Condition: complexity.Condition, Detail: complexity.Detail,
		})
	}
	for _, stage := range inspection.Route {
		response.Route = append(response.Route, api.JumpStage{
			Order: stage.Order, Depth: stage.Depth, Parent: stage.Parent, Hop: stage.Hop.Raw,
			Hostname: stage.Hostname, User: stage.User, Port: stage.Port, Complex: stage.Complex,
		})
	}
	if inspection.Failure != nil {
		response.Failure = api.OpenSSHFailure{
			Failed:    true,
			ExitCode:  inspection.Failure.ExitCode,
			Stderr:    inspection.Failure.Stderr,
			Truncated: inspection.Failure.Truncated,
		}
	}
	return c.JSON(http.StatusOK, response)
}

// Reachability dials the destination directly.
func (h DiagnosticsHandlers) Reachability(c *echo.Context) error {
	var request api.TargetRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	if err := h.consume(c, session.ActionReachability, request.Alias, request.ActionToken); err != nil {
		return err
	}

	result, err := h.Service.Reach(c.Request().Context(), request.Alias)
	if err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_destination")
	}
	return c.JSON(http.StatusOK, api.ReachabilityResponse{
		Address:   result.Address,
		Outcome:   result.Outcome,
		ElapsedMs: int(result.Elapsed.Milliseconds()),
		Detail:    result.Detail,
		Notice:    result.Notice,
	})
}

// Authentication runs the bounded authentication test.
func (h DiagnosticsHandlers) Authentication(c *echo.Context) error {
	var request api.AuthenticationRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	if err := h.consume(c, session.ActionAuthentication, request.Alias, request.ActionToken); err != nil {
		return err
	}

	result, err := h.Service.Authenticate(c.Request().Context(), request.Alias, request.AcknowledgeExecutable)
	var directiveError *diagnostics.ExecutableDirectiveError
	switch {
	case errors.As(err, &directiveError):
		return problem(c, http.StatusConflict, "executable_directive_not_acknowledged")
	case err != nil:
		return problem(c, http.StatusInternalServerError, "authentication_test_failed")
	}
	return c.JSON(http.StatusOK, api.AuthenticationResponse{
		Outcome:       result.Outcome,
		Authenticated: result.Authenticated,
		ExitCode:      result.ExitCode,
		Stderr:        result.Stderr,
		Truncated:     result.Truncated,
		ElapsedMs:     int(result.Elapsed.Milliseconds()),
	})
}

// consume verifies a one-time action token against the operation being asked
// for. The evidence is recomputed from the configuration on disk, so a file
// edited after the confirmation invalidates the token.
func (h DiagnosticsHandlers) consume(c *echo.Context, kind, target, token string) error {
	report, err := h.Service.Safety()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}
	if err := h.Sessions.ConsumeAction(currentSession(c), token, session.ActionRequest{
		Kind:     kind,
		Target:   target,
		Evidence: report.Evidence(),
	}); err != nil {
		return problem(c, http.StatusForbidden, "invalid_action_token")
	}
	return nil
}

func severityName(severity config.Severity) string {
	switch severity {
	case config.SeverityError:
		return "error"
	case config.SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}
```

- [ ] **Step 14: Register the routes**

In `internal/httpserver/server.go`, add the service to `Options` and register
the routes only when it is present, so the foundation tests keep working:

```go
type Options struct {
	Listener    net.Listener
	Sessions    *session.Manager
	UI          fs.FS
	Version     string
	Logger      *slog.Logger
	Diagnostics *diagnostics.Service
}
```

Insert the registration after the existing `e.GET("/api/v1/health", ...)` line
and before the static routes, because `e.GET("/*", static)` must stay last:

```go
	if options.Diagnostics != nil {
		actions := ActionHandlers{Sessions: options.Sessions, Diagnostics: options.Diagnostics}
		checks := DiagnosticsHandlers{Sessions: options.Sessions, Service: options.Diagnostics}
		e.POST("/api/v1/actions/token", actions.IssueToken)
		e.POST("/api/v1/diagnostics/config", checks.CheckConfig)
		e.POST("/api/v1/diagnostics/effective", checks.Effective)
		e.POST("/api/v1/diagnostics/reachability", checks.Reachability)
		e.POST("/api/v1/diagnostics/authentication", checks.Authentication)
	}
```

Add `"sshc/internal/diagnostics"` to the file's import block.

- [ ] **Step 15: Wire the services into the process**

In `internal/app/run.go`, extend `Dependencies` and build the service:

```go
type Dependencies struct {
	Random    io.Reader
	Browser   platform.BrowserLauncher
	Listen    ListenFunc
	UI        fs.FS
	Logger    *slog.Logger
	Home      string
	Runner    platform.OutputRunner
	Toolchain platform.Toolchain
}

// ErrMissingHome reports that no home directory was supplied. Resolving it is
// the entry point's job so nothing under internal/ reads the environment.
var ErrMissingHome = errors.New("home directory is required")
```

At the top of `Run`, before the listener is created:

```go
	if dependencies.Home == "" {
		return ErrMissingHome
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, dependencies.Home)
	if err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	diagnosticsService := diagnostics.NewService(workspace, dependencies.Runner, dependencies.Toolchain, nil)
```

and pass `Diagnostics: diagnosticsService` in the `httpserver.New(httpserver.Options{...})` literal. Add `"errors"`, `"sshc/internal/diagnostics"` and `"sshc/internal/storage"` to the imports.

In `internal/app/run_test.go`, add `Home: t.TempDir()`, `Runner: macos.NewOutputRunner()` and `Toolchain: macos.NewToolchain()` to each of the three `Dependencies` literals, and add one test:

```go
func TestRunRequiresAHomeDirectory(t *testing.T) {
	err := Run(context.Background(), Dependencies{
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x11}, 96)),
		Browser: browserFunc(func(context.Context, string) error { return nil }),
		Listen:  net.Listen,
		UI:      fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, "test")
	if !errors.Is(err, ErrMissingHome) {
		t.Fatalf("Run = %v, want ErrMissingHome", err)
	}
}
```

In `cmd/sshc/main.go`, resolve the home directory and pass the adapters:

```go
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("resolve home directory", "error", err)
		os.Exit(1)
	}
	dependencies := app.Dependencies{
		Random:    rand.Reader,
		Browser:   macos.NewBrowser(macos.NewExecRunner()),
		Listen:    net.Listen,
		UI:        assets,
		Logger:    logger,
		Home:      home,
		Runner:    macos.NewOutputRunner(),
		Toolchain: macos.NewToolchain(),
	}
```

- [ ] **Step 16: Run the full suite**

Run:

```bash
make generate
go test ./...
go test -race ./...
npm run typecheck --prefix web
git status --short
```

Expected: every package passes; `make generate` leaves no diff after the first
committed generation; the new endpoints appear in `web/src/api/schema.d.ts`.

- [ ] **Step 17: Commit the confirmed diagnostics surface**

```bash
git add internal/session internal/diagnostics internal/httpserver internal/app cmd api internal/api web/src/api/schema.d.ts
git commit -m "feat: expose confirmed ssh diagnostics over the local API"
```

## Task 6: Launch Terminal for safe aliases only, and offer a copyable command otherwise

**Files:**
- Create: `internal/platform/terminal.go`
- Create: `internal/platform/macos/terminal.go`
- Create: `internal/platform/macos/terminal_test.go`
- Modify: `api/openapi.yaml`
- Modify: `internal/httpserver/diagnostics.go`
- Modify: `internal/httpserver/server.go`
- Modify: `internal/httpserver/diagnostics_test.go`
- Modify: `internal/diagnostics/service.go`
- Modify: `internal/diagnostics/service_test.go`
- Modify: `internal/app/run.go`
- Modify: `cmd/sshc/main.go`

**Interfaces:**
- Consumes: Tasks 1 and 5.
- Produces: `platform.TerminalLauncher` interface with `Launch(ctx context.Context, alias string) error`.
- Produces: `macos.Terminal{Runner platform.OutputRunner, Program string, Timeout time.Duration}`, `macos.NewTerminal(runner platform.OutputRunner) Terminal`, `macos.TerminalScript`, `macos.LaunchError{ExitCode int, Stderr string}`, `macos.ErrTerminalUnavailable`.
- Produces: `(*diagnostics.Service).LaunchTerminal(ctx context.Context, alias string) error` and `(*diagnostics.Service).TerminalCommand(alias string) (command string, launchable bool, warning string)`.
- Produces: `POST /api/v1/terminal/command` and `POST /api/v1/terminal/launch`.

- [ ] **Step 1: Write the failing Terminal launcher test**

```go
// internal/platform/macos/terminal_test.go
package macos_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"sshc/internal/platform"
	"sshc/internal/platform/macos"
)

type captureRunner struct {
	commands []platform.Command
	output   platform.Output
}

func (runner *captureRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, nil
}

func TestTerminalDeliversTheAliasAsAnArgumentNotAsScriptText(t *testing.T) {
	runner := &captureRunner{}
	terminal := macos.NewTerminal(runner)

	if err := terminal.Launch(context.Background(), "bastion"); err != nil {
		t.Fatalf("Launch = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v", runner.commands)
	}

	command := runner.commands[0]
	if command.Path != "/usr/bin/osascript" {
		t.Errorf("path = %q", command.Path)
	}
	if !slices.Equal(command.Arguments, []string{"-", "bastion"}) {
		t.Fatalf("arguments = %#v, want [- bastion]", command.Arguments)
	}
	if string(command.Stdin) != macos.TerminalScript {
		t.Error("the AppleScript sent on stdin is not the package constant")
	}
	if strings.Contains(macos.TerminalScript, "bastion") {
		t.Error("the alias must never be part of the script text")
	}
	if !strings.Contains(macos.TerminalScript, "quoted form of") {
		t.Error("the script must quote the argument before handing it to a shell")
	}
}

func TestTerminalRefusesAnAliasThatCouldEscapeItsQuoting(t *testing.T) {
	runner := &captureRunner{}
	terminal := macos.NewTerminal(runner)

	for _, alias := range []string{"a b", "a\"b", "a'b", "-oProxyCommand=id", "a;id", "a\nb"} {
		if err := terminal.Launch(context.Background(), alias); !errors.Is(err, platform.ErrUnsafeAlias) {
			t.Errorf("Launch(%q) = %v, want ErrUnsafeAlias", alias, err)
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("an unsafe alias reached osascript: %#v", runner.commands)
	}
}

func TestTerminalReportsAFailedLaunch(t *testing.T) {
	runner := &captureRunner{output: platform.Output{ExitCode: 1, Stderr: []byte("execution error\n")}}

	err := macos.NewTerminal(runner).Launch(context.Background(), "bastion")
	var launchError *macos.LaunchError
	if !errors.As(err, &launchError) || launchError.ExitCode != 1 {
		t.Fatalf("Launch = %v, want *LaunchError", err)
	}
}
```

- [ ] **Step 2: Run the test and verify the launcher is absent**

Run: `go test ./internal/platform/macos -run TestTerminal`

Expected: FAIL to compile with `undefined: macos.NewTerminal`.

- [ ] **Step 3: Implement the Terminal seam and adapter**

```go
// internal/platform/terminal.go
package platform

import "context"

// TerminalLauncher opens an interactive SSH session in the user's terminal.
// Only an alias that passes ValidateAlias is ever handed to it.
type TerminalLauncher interface {
	Launch(ctx context.Context, alias string) error
}
```

```go
// internal/platform/macos/terminal.go
package macos

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sshc/internal/platform"
)

// ErrTerminalUnavailable reports that the automation program is missing.
var ErrTerminalUnavailable = errors.New("osascript is not available")

// TerminalScript is the complete automation payload and a constant.
//
// The alias is delivered as an argument to `on run argv` and is never
// concatenated into this text, so there is no AppleScript string for an alias
// to escape from. `quoted form of` then produces a POSIX-quoted token for the
// shell Terminal runs, and the caller has already restricted the alias to a
// character set with no shell metacharacters at all.
const TerminalScript = `on run argv
	set targetAlias to item 1 of argv
	set sshCommand to "ssh -- " & quoted form of targetAlias
	tell application "Terminal"
		activate
		do script sshCommand
	end tell
end run
`

// LaunchError reports that the automation program refused the request.
type LaunchError struct {
	ExitCode int
	Stderr   string
}

func (e *LaunchError) Error() string {
	return fmt.Sprintf("terminal launch failed with status %d", e.ExitCode)
}

// Terminal opens Terminal.app through osascript.
type Terminal struct {
	Runner  platform.OutputRunner
	Program string
	Timeout time.Duration
}

// NewTerminal returns the macOS Terminal launcher.
func NewTerminal(runner platform.OutputRunner) Terminal {
	return Terminal{Runner: runner, Program: "/usr/bin/osascript", Timeout: 10 * time.Second}
}

// Launch opens `ssh -- <alias>` in a new Terminal window.
func (t Terminal) Launch(ctx context.Context, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	program := t.Program
	if program == "" {
		program = "/usr/bin/osascript"
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	output, err := t.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-", alias},
		Stdin:     []byte(TerminalScript),
		Timeout:   timeout,
	})
	if err != nil {
		return err
	}
	if output.ExitCode != 0 {
		return &LaunchError{ExitCode: output.ExitCode, Stderr: string(output.Stderr)}
	}
	return nil
}
```

- [ ] **Step 4: Run the launcher tests**

Run: `go test ./internal/platform/macos -run TestTerminal -v`

Expected: PASS.

- [ ] **Step 5: Add the service methods and their test**

Append to `internal/diagnostics/service.go`:

```go
// ErrTerminalNotConfigured reports that no terminal launcher was wired in.
var ErrTerminalNotConfigured = errors.New("terminal launcher is not configured")

// UnsafeAliasWarning explains why an alias is copy-only.
const UnsafeAliasWarning = "This alias contains characters that could change the meaning of a command line. Copy the command and check it before running it yourself."

// LaunchTerminal opens an interactive session for alias.
func (s *Service) LaunchTerminal(ctx context.Context, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	if s.Terminal == nil {
		return ErrTerminalNotConfigured
	}
	return s.Terminal.Launch(ctx, alias)
}

// TerminalCommand returns the command a user would run by hand.
//
// An alias outside the safe character set is never launched; the command is
// still returned as text so the user can inspect and quote it themselves.
func (s *Service) TerminalCommand(alias string) (string, bool, string) {
	command := "ssh -- " + alias
	if err := platform.ValidateAlias(alias); err != nil {
		return command, false, UnsafeAliasWarning
	}
	return command, true, ""
}
```

Append to `internal/diagnostics/service_test.go`:

```go
type recordingTerminal struct{ aliases []string }

func (terminal *recordingTerminal) Launch(_ context.Context, alias string) error {
	terminal.aliases = append(terminal.aliases, alias)
	return nil
}

func TestServiceLaunchesOnlySafeAliases(t *testing.T) {
	terminal := &recordingTerminal{}
	service := newTestService(t, &scriptedRunner{})
	service.Terminal = terminal

	if err := service.LaunchTerminal(context.Background(), "bastion"); err != nil {
		t.Fatalf("LaunchTerminal = %v", err)
	}
	if len(terminal.aliases) != 1 || terminal.aliases[0] != "bastion" {
		t.Fatalf("aliases = %#v", terminal.aliases)
	}

	if err := service.LaunchTerminal(context.Background(), "a b"); err == nil {
		t.Fatal("LaunchTerminal accepted an unsafe alias")
	}
	if len(terminal.aliases) != 1 {
		t.Fatal("an unsafe alias reached the launcher")
	}

	command, launchable, warning := service.TerminalCommand("a b")
	if launchable || warning == "" || command != "ssh -- a b" {
		t.Fatalf("TerminalCommand = %q, %v, %q", command, launchable, warning)
	}
	if command, launchable, warning := service.TerminalCommand("bastion"); !launchable || warning != "" || command != "ssh -- bastion" {
		t.Fatalf("TerminalCommand = %q, %v, %q", command, launchable, warning)
	}
}
```

- [ ] **Step 6: Extend the contract with the two terminal endpoints**

Add to `paths:`:

```yaml
  /api/v1/terminal/command:
    post:
      operationId: getTerminalCommand
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/AliasRequest" }
      responses:
        "200":
          description: Command text and whether it may be launched
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TerminalCommandResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
  /api/v1/terminal/launch:
    post:
      operationId: launchTerminal
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/TargetRequest" }
      responses:
        "200":
          description: Terminal opened
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TerminalLaunchResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
```

Add to `components.schemas`:

```yaml
    AliasRequest:
      type: object
      additionalProperties: false
      required: [alias]
      properties:
        alias: { type: string, minLength: 1, maxLength: 255 }
    TerminalCommandResponse:
      type: object
      additionalProperties: false
      required: [command, launchable, warning]
      properties:
        command: { type: string }
        launchable: { type: boolean }
        warning: { type: string }
    TerminalLaunchResponse:
      type: object
      additionalProperties: false
      required: [launched]
      properties:
        launched: { type: boolean }
```

`AliasRequest` deliberately accepts up to 255 characters: the command endpoint
must be able to describe an alias it refuses to launch.

Run: `make generate`

- [ ] **Step 7: Write the failing endpoint test**

Append to `internal/httpserver/diagnostics_test.go`:

```go
func TestTerminalEndpointsSeparateCopyableCommandsFromLaunches(t *testing.T) {
	server := newTestServer(t)
	terminal := &recordingLauncher{}
	server.service.Terminal = terminal

	unsafe := server.post(t, "/api/v1/terminal/command", api.AliasRequest{Alias: `weird "alias"`}, true)
	defer unsafe.Body.Close()
	if unsafe.StatusCode != http.StatusOK {
		t.Fatalf("terminal command = %d", unsafe.StatusCode)
	}
	var described api.TerminalCommandResponse
	if err := json.NewDecoder(unsafe.Body).Decode(&described); err != nil {
		t.Fatal(err)
	}
	if described.Launchable || described.Warning == "" {
		t.Fatalf("response = %#v", described)
	}

	refused := server.post(t, "/api/v1/terminal/launch",
		api.TargetRequest{Alias: `weird "alias"`, ActionToken: strings.Repeat("a", 43)}, true)
	refused.Body.Close()
	if refused.StatusCode != http.StatusBadRequest {
		t.Fatalf("launching an unsafe alias = %d, want 400", refused.StatusCode)
	}
	if len(terminal.aliases) != 0 {
		t.Fatal("an unsafe alias reached the launcher")
	}

	token := server.actionToken(t, session.ActionTerminalLaunch, "bastion")
	launched := server.post(t, "/api/v1/terminal/launch", api.TargetRequest{Alias: "bastion", ActionToken: token}, true)
	launched.Body.Close()
	if launched.StatusCode != http.StatusOK {
		t.Fatalf("launch = %d", launched.StatusCode)
	}
	if len(terminal.aliases) != 1 || terminal.aliases[0] != "bastion" {
		t.Fatalf("aliases = %#v", terminal.aliases)
	}
}

type recordingLauncher struct{ aliases []string }

func (launcher *recordingLauncher) Launch(_ context.Context, alias string) error {
	launcher.aliases = append(launcher.aliases, alias)
	return nil
}
```

- [ ] **Step 8: Implement the terminal handlers and routes**

Append to `internal/httpserver/diagnostics.go`:

```go
// TerminalCommand returns the command text for an alias and whether this
// application is willing to launch it.
func (h DiagnosticsHandlers) TerminalCommand(c *echo.Context) error {
	var request api.AliasRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	command, launchable, warning := h.Service.TerminalCommand(request.Alias)
	return c.JSON(http.StatusOK, api.TerminalCommandResponse{
		Command:    command,
		Launchable: launchable,
		Warning:    warning,
	})
}

// TerminalLaunch opens Terminal for a confirmed, safe alias.
func (h DiagnosticsHandlers) TerminalLaunch(c *echo.Context) error {
	var request api.TargetRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "alias_not_launchable")
	}
	if err := h.consume(c, session.ActionTerminalLaunch, request.Alias, request.ActionToken); err != nil {
		return err
	}
	if err := h.Service.LaunchTerminal(c.Request().Context(), request.Alias); err != nil {
		return problem(c, http.StatusInternalServerError, "terminal_launch_failed")
	}
	return c.JSON(http.StatusOK, api.TerminalLaunchResponse{Launched: true})
}
```

Register both routes inside the existing `if options.Diagnostics != nil` block
in `server.go`:

```go
		e.POST("/api/v1/terminal/command", checks.TerminalCommand)
		e.POST("/api/v1/terminal/launch", checks.TerminalLaunch)
```

In `internal/app/run.go`, build the launcher and pass it to the service:

```go
	diagnosticsService := diagnostics.NewService(workspace, dependencies.Runner, dependencies.Toolchain, dependencies.Terminal)
```

with a new `Terminal platform.TerminalLauncher` field on `Dependencies`, and in
`cmd/sshc/main.go` add `Terminal: macos.NewTerminal(macos.NewOutputRunner())`
to the dependency literal. A nil launcher stays valid: `LaunchTerminal` then
returns `ErrTerminalNotConfigured` instead of panicking, which is what the
existing `app` tests rely on.

- [ ] **Step 9: Run the suite**

Run:

```bash
go test ./...
go test -race ./...
```

Expected: PASS. No automated test opens a real Terminal window.

- [ ] **Step 10: Commit Terminal launch**

```bash
git add internal/platform internal/diagnostics internal/httpserver internal/app cmd api internal/api web/src/api/schema.d.ts
git commit -m "feat: launch Terminal without a shell or AppleScript injection"
```

## Task 7: Known Hosts search, journalled deletion and unverified scan candidates

**Files:**
- Create: `internal/knownhosts/file.go`
- Create: `internal/knownhosts/file_test.go`
- Create: `internal/knownhosts/scan.go`
- Create: `internal/knownhosts/scan_test.go`
- Create: `internal/knownhosts/service.go`
- Create: `internal/knownhosts/service_test.go`
- Modify: `api/openapi.yaml`
- Create: `internal/httpserver/knownhosts.go`
- Create: `internal/httpserver/knownhosts_test.go`
- Modify: `internal/httpserver/actions.go`
- Modify: `internal/httpserver/server.go`
- Modify: `internal/app/run.go`

**Interfaces:**
- Consumes: Tasks 1 and 5; committed `storage.Workspace`, `storage.NewManager`, `storage.Manager.Commit`, `storage.Request`, `storage.Change`, `storage.Precondition`, `storage.Digest`, `storage.ConflictError`, `storage.Result`.
- Produces: `knownhosts.Entry{Marker string, Hosts []string, Hashed bool, KeyType, Key, Fingerprint, Comment string}`.
- Produces: `knownhosts.Line{Number int, Raw, Ending string, Entry *Entry, Problem string}` and `knownhosts.File{Lines []Line}` with `ParseFile(contents []byte) *File`, `(*File).Render() []byte`, `(*File).Entries() []Line`.
- Produces: `knownhosts.Fingerprint(encodedKey string) (string, error)`, `knownhosts.ErrInvalidKey`.
- Produces: `(Entry).MatchesHost(host string) bool` and `knownhosts.Search(file *File, query string) []Line`.
- Produces: `knownhosts.Candidate{Host string, Port int, KeyType, Key, Fingerprint string, Verified bool}`, `knownhosts.Scanner{Runner, Toolchain, Timeout}` with `Scan(ctx, host string, port int) ([]Candidate, error)`, `knownhosts.UnverifiedNotice`, `knownhosts.DefaultScanTimeout`.
- Produces: `knownhosts.Service{Workspace, Manager, Scanner}` with `NewService(...)`, `Path() string`, `Listing(query string) (Listing, error)`, `Evidence() (string, error)`, `Delete(targets []Target) (storage.Result, error)`, `Add(candidate Candidate, expectedFingerprint string, acknowledged bool) (storage.Result, error)`.
- Produces: `knownhosts.Target{Line int, Digest string}`, `knownhosts.Listing{Path string, Lines []Line}`, `knownhosts.ErrUnverifiedCandidate`, `knownhosts.ErrEntryChanged`, `knownhosts.ErrNoSuchEntry`, `knownhosts.ErrUnsupportedKeyType`.

- [ ] **Step 1: Write the failing known_hosts model test**

The fixtures below are real OpenSSH output: the key, its `SHA256` fingerprint
and the hashed host field were produced with `ssh-keygen` and `ssh-keygen -H`.

```go
// internal/knownhosts/file_test.go
package knownhosts_test

import (
	"bytes"
	"testing"

	"sshc/internal/knownhosts"
)

const (
	fixtureKeyType     = "ssh-ed25519"
	fixtureKey         = "AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS"
	fixtureFingerprint = "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs"
	fixtureHashedHost  = "|1|u94nmAngiqvuJf3A9CcExCUb2oE=|tDiE1i4vIaZJu8QmzSCwb54jMP4="
)

const fixtureFile = "# generated by hand\n" +
	"bastion.example.com,203.0.113.10 " + fixtureKeyType + " " + fixtureKey + " admin@example\n" +
	"\n" +
	"[db.example.com]:2222 " + fixtureKeyType + " " + fixtureKey + "\n" +
	"@cert-authority *.example.com " + fixtureKeyType + " " + fixtureKey + "\n" +
	fixtureHashedHost + " " + fixtureKeyType + " " + fixtureKey + "\n" +
	"this line is not a known_hosts entry\n"

func TestParseFileRoundTripsAndClassifiesEveryLine(t *testing.T) {
	file := knownhosts.ParseFile([]byte(fixtureFile))
	if rendered := file.Render(); !bytes.Equal(rendered, []byte(fixtureFile)) {
		t.Fatalf("render changed bytes:\n%q\n%q", rendered, fixtureFile)
	}
	if len(file.Lines) != 7 {
		t.Fatalf("lines = %d", len(file.Lines))
	}

	plain := file.Lines[1]
	if plain.Entry == nil {
		t.Fatal("line 2 was not parsed as an entry")
	}
	if len(plain.Entry.Hosts) != 2 || plain.Entry.Hosts[1] != "203.0.113.10" {
		t.Errorf("hosts = %#v", plain.Entry.Hosts)
	}
	if plain.Entry.KeyType != fixtureKeyType || plain.Entry.Fingerprint != fixtureFingerprint {
		t.Errorf("entry = %#v", plain.Entry)
	}
	if plain.Entry.Comment != "admin@example" || plain.Number != 2 {
		t.Errorf("entry = %#v, number = %d", plain.Entry, plain.Number)
	}

	if bracketed := file.Lines[3].Entry; bracketed == nil || bracketed.Hosts[0] != "[db.example.com]:2222" {
		t.Errorf("bracketed entry = %#v", bracketed)
	}
	if authority := file.Lines[4].Entry; authority == nil || authority.Marker != "@cert-authority" {
		t.Errorf("marker entry = %#v", authority)
	}
	if hashed := file.Lines[5].Entry; hashed == nil || !hashed.Hashed {
		t.Errorf("hashed entry = %#v", hashed)
	}
	if unparsable := file.Lines[6]; unparsable.Entry != nil || unparsable.Problem == "" {
		t.Errorf("unparsable line = %#v", unparsable)
	}
}

func TestFingerprintMatchesOpenSSHAndRejectsGarbage(t *testing.T) {
	fingerprint, err := knownhosts.Fingerprint(fixtureKey)
	if err != nil {
		t.Fatalf("Fingerprint = %v", err)
	}
	if fingerprint != fixtureFingerprint {
		t.Fatalf("Fingerprint = %q, want %q", fingerprint, fixtureFingerprint)
	}
	if _, err := knownhosts.Fingerprint("not base64!"); err == nil {
		t.Error("Fingerprint accepted a value that is not base64")
	}
}

func TestMatchesHostCoversPlainPatternsAndHashedEntries(t *testing.T) {
	file := knownhosts.ParseFile([]byte(fixtureFile))

	plain := file.Lines[1].Entry
	if !plain.MatchesHost("bastion.example.com") || !plain.MatchesHost("203.0.113.10") {
		t.Error("plain entry did not match its own hosts")
	}
	if plain.MatchesHost("other.example.com") {
		t.Error("plain entry matched an unrelated host")
	}
	if wildcard := file.Lines[4].Entry; !wildcard.MatchesHost("api.example.com") {
		t.Error("wildcard pattern did not match")
	}

	hashed := file.Lines[5].Entry
	if !hashed.MatchesHost("bastion.example.com") {
		t.Error("hashed entry did not match the host it was generated from")
	}
	if hashed.MatchesHost("other.example.com") {
		t.Error("hashed entry matched an unrelated host")
	}
}

func TestSearchFindsHostsKeyTypesAndFingerprints(t *testing.T) {
	file := knownhosts.ParseFile([]byte(fixtureFile))

	if found := knownhosts.Search(file, "bastion"); len(found) != 1 || found[0].Number != 2 {
		t.Errorf("host search = %#v", found)
	}
	if found := knownhosts.Search(file, "bytFrSjx"); len(found) != 4 {
		t.Errorf("fingerprint search = %d entries, want every entry", len(found))
	}
	if found := knownhosts.Search(file, ""); len(found) != 4 {
		t.Errorf("empty query = %d entries, want every entry", len(found))
	}
	if found := knownhosts.Search(file, "ED25519"); len(found) != 4 {
		t.Errorf("key type search is case-insensitive: %#v", found)
	}
}
```

- [ ] **Step 2: Run the test and verify the package is absent**

Run: `go test ./internal/knownhosts`

Expected: FAIL — the package does not exist.

- [ ] **Step 3: Implement the known_hosts model**

```go
// Package knownhosts reads and edits the user's known_hosts file.
//
// Parsing is lossless: an unmodified file renders back byte for byte, so a
// deletion removes exactly the lines it was asked to remove and touches
// nothing else. Every write goes through the storage transaction manager.
package knownhosts

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrInvalidKey reports a key blob that is not valid base64.
var ErrInvalidKey = errors.New("public key is not valid base64")

// Entry is one parsed known_hosts record.
type Entry struct {
	Marker      string
	Hosts       []string
	Hashed      bool
	KeyType     string
	Key         string
	Fingerprint string
	Comment     string
}

// Line is one physical line. Entry is nil for a blank line, a comment, or a
// line this package could not parse; such a line is preserved verbatim.
type Line struct {
	Number  int
	Raw     string
	Ending  string
	Entry   *Entry
	Problem string
}

// File is a parsed known_hosts file.
type File struct {
	Lines []Line
}

// ParseFile splits contents into lines and parses the entries.
func ParseFile(contents []byte) *File {
	file := &File{}
	remaining := string(contents)
	number := 0
	for len(remaining) > 0 {
		text, ending, rest := splitLine(remaining)
		number++
		line := Line{Number: number, Raw: text, Ending: ending}
		trimmed := strings.TrimSpace(text)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			entry, err := parseEntry(trimmed)
			if err != nil {
				line.Problem = err.Error()
			} else {
				line.Entry = entry
			}
		}
		file.Lines = append(file.Lines, line)
		remaining = rest
	}
	return file
}

// Render returns the file exactly as it was read.
func (f *File) Render() []byte {
	var builder strings.Builder
	for _, line := range f.Lines {
		builder.WriteString(line.Raw)
		builder.WriteString(line.Ending)
	}
	return []byte(builder.String())
}

// Entries returns only the lines that hold a parsed record.
func (f *File) Entries() []Line {
	var entries []Line
	for _, line := range f.Lines {
		if line.Entry != nil {
			entries = append(entries, line)
		}
	}
	return entries
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

func parseEntry(text string) (*Entry, error) {
	fields := strings.Fields(text)
	entry := &Entry{}
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		entry.Marker = fields[0]
		fields = fields[1:]
	}
	if len(fields) < 3 {
		return nil, errors.New("line does not have a host, key type and key")
	}

	entry.Hosts = strings.Split(fields[0], ",")
	entry.Hashed = strings.HasPrefix(fields[0], "|1|")
	entry.KeyType = fields[1]
	entry.Key = fields[2]
	entry.Comment = strings.Join(fields[3:], " ")

	fingerprint, err := Fingerprint(entry.Key)
	if err != nil {
		return nil, err
	}
	entry.Fingerprint = fingerprint
	return entry, nil
}

// Fingerprint returns the SHA256 fingerprint OpenSSH prints for a public key.
func Fingerprint(encodedKey string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(blob) == 0 {
		return "", ErrInvalidKey
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// MatchesHost reports whether this entry covers host.
//
// A hashed entry cannot be read back, but it can be tested: OpenSSH stores
// |1|base64(salt)|base64(HMAC-SHA1(salt, host)), so the same computation
// answers the question without revealing anything.
func (e *Entry) MatchesHost(host string) bool {
	for _, pattern := range e.Hosts {
		if e.Hashed {
			if hashedMatch(pattern, host) {
				return true
			}
			continue
		}
		if matchHostPattern(pattern, host) {
			return true
		}
	}
	return false
}

func hashedMatch(field, host string) bool {
	parts := strings.Split(field, "|")
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}
	salt, saltErr := base64.StdEncoding.DecodeString(parts[2])
	expected, hashErr := base64.StdEncoding.DecodeString(parts[3])
	if saltErr != nil || hashErr != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(host))
	return hmac.Equal(mac.Sum(nil), expected)
}

// matchHostPattern implements the '*' and '?' matching OpenSSH uses for
// known_hosts patterns, case-insensitively.
func matchHostPattern(pattern, host string) bool {
	loweredPattern := strings.ToLower(pattern)
	loweredHost := strings.ToLower(host)

	patternIndex, hostIndex := 0, 0
	starIndex, resumeIndex := -1, 0
	for hostIndex < len(loweredHost) {
		switch {
		case patternIndex < len(loweredPattern) &&
			(loweredPattern[patternIndex] == '?' || loweredPattern[patternIndex] == loweredHost[hostIndex]):
			patternIndex++
			hostIndex++
		case patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*':
			starIndex = patternIndex
			resumeIndex = hostIndex
			patternIndex++
		case starIndex >= 0:
			patternIndex = starIndex + 1
			resumeIndex++
			hostIndex = resumeIndex
		default:
			return false
		}
	}
	for patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(loweredPattern)
}

// Search returns the entries whose host, key type, fingerprint or comment
// contains query. An empty query returns every entry.
func Search(file *File, query string) []Line {
	wanted := strings.ToLower(strings.TrimSpace(query))
	var found []Line
	for _, line := range file.Entries() {
		if wanted == "" {
			found = append(found, line)
			continue
		}
		haystack := strings.ToLower(strings.Join(line.Entry.Hosts, ",") + " " +
			line.Entry.KeyType + " " + line.Entry.Fingerprint + " " + line.Entry.Comment)
		if strings.Contains(haystack, wanted) {
			found = append(found, line)
		}
	}
	return found
}
```

- [ ] **Step 4: Run the model tests**

Run: `go test ./internal/knownhosts -v`

Expected: PASS, including the fingerprint check against the real OpenSSH value.

- [ ] **Step 5: Write the failing scanner and service tests**

```go
// internal/knownhosts/scan_test.go
package knownhosts_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"sshc/internal/knownhosts"
	"sshc/internal/platform"
)

type stubRunner struct {
	commands []platform.Command
	output   platform.Output
}

func (runner *stubRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, nil
}

type stubToolchain struct{}

func (stubToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (stubToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }

func TestScanReturnsUnverifiedCandidates(t *testing.T) {
	runner := &stubRunner{output: platform.Output{Stdout: []byte(
		"# bastion.example.com:2222 SSH-2.0-OpenSSH_9.6\n" +
			"bastion.example.com " + fixtureKeyType + " " + fixtureKey + "\n")}}

	candidates, err := knownhosts.Scanner{Runner: runner, Toolchain: stubToolchain{}}.
		Scan(context.Background(), "bastion.example.com", 2222)
	if err != nil {
		t.Fatalf("Scan = %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	candidate := candidates[0]
	if candidate.Verified {
		t.Error("a scanned key is never verified")
	}
	if candidate.Fingerprint != fixtureFingerprint || candidate.Port != 2222 {
		t.Errorf("candidate = %#v", candidate)
	}

	command := runner.commands[0]
	if command.Path != "/usr/bin/ssh-keyscan" {
		t.Errorf("path = %q", command.Path)
	}
	if !slices.Equal(command.Arguments, []string{"-T", "5", "-p", "2222", "bastion.example.com"}) {
		t.Fatalf("arguments = %#v", command.Arguments)
	}
}

func TestScanRejectsUnsafeTargetsBeforeStartingAProcess(t *testing.T) {
	runner := &stubRunner{}
	scanner := knownhosts.Scanner{Runner: runner, Toolchain: stubToolchain{}}

	if _, err := scanner.Scan(context.Background(), "-p2222", 22); !errors.Is(err, platform.ErrUnsafeHostname) {
		t.Fatalf("unsafe host = %v, want ErrUnsafeHostname", err)
	}
	if _, err := scanner.Scan(context.Background(), "example.com", 0); !errors.Is(err, platform.ErrUnsafePort) {
		t.Fatalf("invalid port = %v, want ErrUnsafePort", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("an unsafe target started a process")
	}
}
```

```go
// internal/knownhosts/service_test.go
package knownhosts_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshc/internal/knownhosts"
	"sshc/internal/storage"
)

func newTestService(t *testing.T, contents string, runner *stubRunner) *knownhosts.Service {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if contents != "" {
		if err := os.WriteFile(filepath.Join(root, "known_hosts"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	manager := storage.NewManager(workspace, time.Now, bytes.NewReader(bytes.Repeat([]byte{0x2f}, 4096)))
	return knownhosts.NewService(workspace, manager, knownhosts.Scanner{Runner: runner, Toolchain: stubToolchain{}})
}

func TestDeleteRemovesOnlyTheRequestedLinesThroughTheTransactionManager(t *testing.T) {
	service := newTestService(t, fixtureFile, &stubRunner{})

	listing, err := service.Listing("")
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Lines) != 4 {
		t.Fatalf("entries = %#v", listing.Lines)
	}

	target := knownhosts.Target{Line: listing.Lines[0].Number, Digest: storage.Digest([]byte(listing.Lines[0].Raw))}
	result, err := service.Delete([]knownhosts.Target{target})
	if err != nil {
		t.Fatalf("Delete = %v", err)
	}
	if result.BackupDir == "" || len(result.Written) != 1 {
		t.Fatalf("result = %#v", result)
	}

	after, err := os.ReadFile(service.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "bastion.example.com,203.0.113.10") {
		t.Error("the requested entry was not removed")
	}
	if !strings.Contains(string(after), "# generated by hand") ||
		!strings.Contains(string(after), "this line is not a known_hosts entry") {
		t.Error("unrelated lines were not preserved")
	}

	backup, err := os.ReadFile(filepath.Join(result.BackupDir, "known_hosts"))
	if err != nil || !bytes.Equal(backup, []byte(fixtureFile)) {
		t.Fatalf("backup = %q, %v", backup, err)
	}
}

func TestDeleteRefusesWhenTheLineOnDiskChanged(t *testing.T) {
	service := newTestService(t, fixtureFile, &stubRunner{})

	stale := knownhosts.Target{Line: 2, Digest: storage.Digest([]byte("a line that is not there"))}
	if _, err := service.Delete([]knownhosts.Target{stale}); !errors.Is(err, knownhosts.ErrEntryChanged) {
		t.Fatalf("Delete = %v, want ErrEntryChanged", err)
	}
	missing := knownhosts.Target{Line: 999, Digest: storage.Digest([]byte("x"))}
	if _, err := service.Delete([]knownhosts.Target{missing}); !errors.Is(err, knownhosts.ErrNoSuchEntry) {
		t.Fatalf("Delete = %v, want ErrNoSuchEntry", err)
	}
}

func TestAddRequiresAFingerprintOrAnExplicitAcknowledgement(t *testing.T) {
	service := newTestService(t, "", &stubRunner{})
	candidate := knownhosts.Candidate{
		Host: "bastion.example.com", Port: 22, KeyType: fixtureKeyType, Key: fixtureKey,
	}

	if _, err := service.Add(candidate, "", false); !errors.Is(err, knownhosts.ErrUnverifiedCandidate) {
		t.Fatalf("Add = %v, want ErrUnverifiedCandidate", err)
	}
	if _, err := service.Add(candidate, "SHA256:someoneelse", false); !errors.Is(err, knownhosts.ErrUnverifiedCandidate) {
		t.Fatalf("Add with a wrong fingerprint = %v, want ErrUnverifiedCandidate", err)
	}

	if _, err := service.Add(candidate, fixtureFingerprint, false); err != nil {
		t.Fatalf("Add with the out-of-band fingerprint = %v", err)
	}
	contents, err := os.ReadFile(service.Path())
	if err != nil {
		t.Fatal(err)
	}
	want := "bastion.example.com " + fixtureKeyType + " " + fixtureKey + "\n"
	if string(contents) != want {
		t.Fatalf("known_hosts = %q, want %q", contents, want)
	}

	// A repeated add is a no-op rather than a duplicate line.
	if _, err := service.Add(candidate, fixtureFingerprint, false); err != nil {
		t.Fatalf("repeated Add = %v", err)
	}
	repeated, err := os.ReadFile(service.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(repeated) != want {
		t.Fatalf("repeated Add changed the file: %q", repeated)
	}

	nonDefaultPort := knownhosts.Candidate{Host: "db.example.com", Port: 2222, KeyType: fixtureKeyType, Key: fixtureKey}
	if _, err := service.Add(nonDefaultPort, "", true); err != nil {
		t.Fatalf("acknowledged Add = %v", err)
	}
	withPort, err := os.ReadFile(service.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(withPort), "[db.example.com]:2222 ") {
		t.Errorf("known_hosts = %q, want a bracketed host for a non-default port", withPort)
	}
}

func TestAddRejectsAKeyTypeOrBlobItDoesNotUnderstand(t *testing.T) {
	service := newTestService(t, "", &stubRunner{})

	invalidType := knownhosts.Candidate{Host: "a.example.com", Port: 22, KeyType: "rm -rf /", Key: fixtureKey}
	if _, err := service.Add(invalidType, "", true); !errors.Is(err, knownhosts.ErrUnsupportedKeyType) {
		t.Fatalf("Add = %v, want ErrUnsupportedKeyType", err)
	}
	invalidKey := knownhosts.Candidate{Host: "a.example.com", Port: 22, KeyType: fixtureKeyType, Key: "not base64!"}
	if _, err := service.Add(invalidKey, "", true); !errors.Is(err, knownhosts.ErrInvalidKey) {
		t.Fatalf("Add = %v, want ErrInvalidKey", err)
	}
	if _, err := os.Stat(service.Path()); !os.IsNotExist(err) {
		t.Fatal("a rejected candidate created the file")
	}
}
```

- [ ] **Step 6: Run the tests and verify the scanner and service are absent**

Run: `go test ./internal/knownhosts -run 'TestScan|TestDelete|TestAdd'`

Expected: FAIL to compile with `undefined: knownhosts.Scanner`.

- [ ] **Step 7: Implement the scanner**

```go
// internal/knownhosts/scan.go
package knownhosts

import (
	"context"
	"strconv"
	"strings"
	"time"

	"sshc/internal/platform"
)

// UnverifiedNotice accompanies every scan result.
const UnverifiedNotice = "ssh-keyscan proves only that something answered at this address. It does not prove the host's identity. Compare the fingerprint with one you obtained another way before trusting it."

// DefaultScanTimeout bounds one ssh-keyscan run.
const DefaultScanTimeout = 15 * time.Second

// Candidate is one key ssh-keyscan reported. Verified is always false here;
// only the user can decide that a key is genuine.
type Candidate struct {
	Host        string
	Port        int
	KeyType     string
	Key         string
	Fingerprint string
	Verified    bool
}

// Scanner fetches host key candidates.
type Scanner struct {
	Runner    platform.OutputRunner
	Toolchain platform.Toolchain
	Timeout   time.Duration
}

// Scan asks ssh-keyscan for the keys of one host.
func (s Scanner) Scan(ctx context.Context, host string, port int) ([]Candidate, error) {
	if err := platform.ValidateHostname(host); err != nil {
		return nil, err
	}
	if err := platform.ValidatePort(port); err != nil {
		return nil, err
	}
	program, err := s.Toolchain.KeyScan()
	if err != nil {
		return nil, err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultScanTimeout
	}
	output, err := s.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-T", "5", "-p", strconv.Itoa(port), host},
		Timeout:   timeout,
	})
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	for _, line := range strings.Split(string(output.Stdout), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		fingerprint, fingerprintErr := Fingerprint(fields[2])
		if fingerprintErr != nil {
			continue
		}
		candidates = append(candidates, Candidate{
			Host:        host,
			Port:        port,
			KeyType:     fields[1],
			Key:         fields[2],
			Fingerprint: fingerprint,
		})
	}
	return candidates, nil
}
```

- [ ] **Step 8: Implement the service**

```go
// internal/knownhosts/service.go
package knownhosts

import (
	"crypto/subtle"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"sshc/internal/storage"
)

var (
	ErrUnverifiedCandidate = errors.New("a scanned key needs a matching fingerprint or an explicit acknowledgement")
	ErrEntryChanged        = errors.New("the entry on disk is not the entry that was displayed")
	ErrNoSuchEntry         = errors.New("no such known_hosts entry")
	ErrUnsupportedKeyType  = errors.New("unsupported host key type")
)

// supportedKeyTypes is the set this application will write into known_hosts.
// Anything else is refused rather than copied through unchecked.
var supportedKeyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"rsa-sha2-256":                       true,
	"rsa-sha2-512":                       true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,3}$`)

// Target identifies one entry to remove. Digest is the hash of the exact line
// the user saw, so a file edited in the meantime cannot lose the wrong line.
type Target struct {
	Line   int
	Digest string
}

// Listing is the searchable view of the file.
type Listing struct {
	Path  string
	Lines []Line
}

// Service reads and edits known_hosts through the transaction manager.
type Service struct {
	Workspace *storage.Workspace
	Manager   *storage.Manager
	Scanner   Scanner
}

// NewService wires the production dependencies together.
func NewService(workspace *storage.Workspace, manager *storage.Manager, scanner Scanner) *Service {
	return &Service{Workspace: workspace, Manager: manager, Scanner: scanner}
}

// Path is the known_hosts file this service manages.
func (s *Service) Path() string { return filepath.Join(s.Workspace.Root(), "known_hosts") }

func (s *Service) read() ([]byte, error) {
	contents, err := s.Workspace.FileSystem().ReadFile(s.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return contents, err
}

// Listing returns the entries matching query.
func (s *Service) Listing(query string) (Listing, error) {
	contents, err := s.read()
	if err != nil {
		return Listing{}, err
	}
	return Listing{Path: s.Path(), Lines: Search(ParseFile(contents), query)}, nil
}

// Evidence is a digest of the current file. An action token for a known_hosts
// change is bound to it, so an external edit invalidates the confirmation.
func (s *Service) Evidence() (string, error) {
	contents, err := s.read()
	if err != nil {
		return "", err
	}
	return storage.Digest(contents), nil
}

// Delete removes the requested lines and leaves every other byte untouched.
func (s *Service) Delete(targets []Target) (storage.Result, error) {
	contents, err := s.read()
	if err != nil {
		return storage.Result{}, err
	}
	file := ParseFile(contents)

	removing := make(map[int]bool, len(targets))
	for _, target := range targets {
		found := false
		for _, line := range file.Lines {
			if line.Number != target.Line {
				continue
			}
			found = true
			if storage.Digest([]byte(line.Raw)) != target.Digest {
				return storage.Result{}, ErrEntryChanged
			}
			removing[line.Number] = true
		}
		if !found {
			return storage.Result{}, ErrNoSuchEntry
		}
	}

	remaining := &File{}
	for _, line := range file.Lines {
		if removing[line.Number] {
			continue
		}
		remaining.Lines = append(remaining.Lines, line)
	}
	return s.commit("known_hosts.delete", contents, remaining.Render())
}

// Add appends one scanned key after the user proved it is the key they meant.
//
// Either expectedFingerprint matches the key's real fingerprint, or the user
// acknowledged explicitly that the key is unverified. The line is rebuilt from
// validated parts rather than trusting the text a client sent.
func (s *Service) Add(candidate Candidate, expectedFingerprint string, acknowledged bool) (storage.Result, error) {
	if !supportedKeyTypes[candidate.KeyType] {
		return storage.Result{}, ErrUnsupportedKeyType
	}
	if !base64Pattern.MatchString(candidate.Key) {
		return storage.Result{}, ErrInvalidKey
	}
	fingerprint, err := Fingerprint(candidate.Key)
	if err != nil {
		return storage.Result{}, err
	}
	switch {
	case expectedFingerprint != "":
		if subtle.ConstantTimeCompare([]byte(expectedFingerprint), []byte(fingerprint)) != 1 {
			return storage.Result{}, ErrUnverifiedCandidate
		}
	case !acknowledged:
		return storage.Result{}, ErrUnverifiedCandidate
	}

	hostField := candidate.Host
	if candidate.Port != 22 {
		hostField = "[" + candidate.Host + "]:" + strconv.Itoa(candidate.Port)
	}
	newLine := hostField + " " + candidate.KeyType + " " + candidate.Key

	contents, err := s.read()
	if err != nil {
		return storage.Result{}, err
	}
	file := ParseFile(contents)
	for _, line := range file.Lines {
		if strings.TrimSpace(line.Raw) == newLine {
			// Exact duplicate: nothing to write.
			return storage.Result{}, nil
		}
	}

	updated := string(contents)
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += newLine + "\n"
	return s.commit("known_hosts.add", contents, []byte(updated))
}

func (s *Service) commit(operation string, previous, updated []byte) (storage.Result, error) {
	return s.Manager.Commit(storage.Request{
		Operation: operation,
		Changes: []storage.Change{{
			Path:         s.Path(),
			Contents:     updated,
			Precondition: storage.Precondition{Exists: previous != nil, Digest: storage.Digest(previous)},
		}},
	})
}
```

`Precondition.Exists` is false only when the file was absent, in which case
`Digest(nil)` is never compared, matching the committed manager's contract.

- [ ] **Step 9: Run the known_hosts tests**

Run:

```bash
go test ./internal/knownhosts -v
go test -race ./internal/knownhosts
```

Expected: PASS.

- [ ] **Step 10: Extend the contract with the known_hosts endpoints**

Add to `paths:`:

```yaml
  /api/v1/known-hosts:
    get:
      operationId: listKnownHosts
      parameters:
        - name: query
          in: query
          required: false
          schema: { type: string, maxLength: 255 }
      responses:
        "200":
          description: Matching known_hosts entries
          content:
            application/json:
              schema: { $ref: "#/components/schemas/KnownHostsResponse" }
        "401": { $ref: "#/components/responses/Problem" }
  /api/v1/known-hosts/delete:
    post:
      operationId: deleteKnownHosts
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/KnownHostsDeleteRequest" }
      responses:
        "200":
          description: Entries removed
          content:
            application/json:
              schema: { $ref: "#/components/schemas/KnownHostsChangeResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
  /api/v1/known-hosts/scan:
    post:
      operationId: scanKnownHosts
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/KnownHostsScanRequest" }
      responses:
        "200":
          description: Unverified candidates
          content:
            application/json:
              schema: { $ref: "#/components/schemas/KnownHostsScanResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/known-hosts/add:
    post:
      operationId: addKnownHost
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/KnownHostsAddRequest" }
      responses:
        "200":
          description: Entry added
          content:
            application/json:
              schema: { $ref: "#/components/schemas/KnownHostsChangeResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
```

Add to `components.schemas`:

```yaml
    KnownHostsResponse:
      type: object
      additionalProperties: false
      required: [path, entries]
      properties:
        path: { type: string }
        entries:
          type: array
          items: { $ref: "#/components/schemas/KnownHostEntry" }
    KnownHostEntry:
      type: object
      additionalProperties: false
      required: [line, digest, marker, hosts, hashed, keyType, fingerprint, comment]
      properties:
        line: { type: integer }
        digest: { type: string }
        marker: { type: string }
        hosts:
          type: array
          items: { type: string }
        hashed: { type: boolean }
        keyType: { type: string }
        fingerprint: { type: string }
        comment: { type: string }
    KnownHostTarget:
      type: object
      additionalProperties: false
      required: [line, digest]
      properties:
        line: { type: integer }
        digest: { type: string, minLength: 64, maxLength: 64 }
    KnownHostsDeleteRequest:
      type: object
      additionalProperties: false
      required: [entries, actionToken]
      properties:
        entries:
          type: array
          items: { $ref: "#/components/schemas/KnownHostTarget" }
        actionToken: { type: string, minLength: 43, maxLength: 43 }
    KnownHostsChangeResponse:
      type: object
      additionalProperties: false
      required: [changed, transactionId]
      properties:
        changed: { type: boolean }
        transactionId: { type: string }
    KnownHostsScanRequest:
      type: object
      additionalProperties: false
      required: [host, port, actionToken]
      properties:
        host: { type: string, minLength: 1, maxLength: 255 }
        port: { type: integer }
        actionToken: { type: string, minLength: 43, maxLength: 43 }
    KnownHostsScanResponse:
      type: object
      additionalProperties: false
      required: [notice, candidates]
      properties:
        notice: { type: string }
        candidates:
          type: array
          items: { $ref: "#/components/schemas/KnownHostCandidate" }
    KnownHostCandidate:
      type: object
      additionalProperties: false
      required: [host, port, keyType, key, fingerprint, verified]
      properties:
        host: { type: string }
        port: { type: integer }
        keyType: { type: string }
        key: { type: string }
        fingerprint: { type: string }
        verified: { type: boolean }
    KnownHostsAddRequest:
      type: object
      additionalProperties: false
      required: [host, port, keyType, key, expectedFingerprint, acknowledged, actionToken]
      properties:
        host: { type: string, minLength: 1, maxLength: 255 }
        port: { type: integer }
        keyType: { type: string, minLength: 1, maxLength: 64 }
        key: { type: string, minLength: 1, maxLength: 4096 }
        expectedFingerprint: { type: string, maxLength: 128 }
        acknowledged: { type: boolean }
        actionToken: { type: string, minLength: 43, maxLength: 43 }
```

Run: `make generate`

- [ ] **Step 11: Write the failing known_hosts endpoint test**

```go
// internal/httpserver/knownhosts_test.go
package httpserver

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"sshc/internal/api"
	"sshc/internal/session"
	"sshc/internal/storage"
)

func TestKnownHostsListSearchAndDeleteAreJournalled(t *testing.T) {
	server := newTestServer(t)
	server.writeKnownHosts(t, knownHostsFixture)

	response, err := server.get(t, "/api/v1/known-hosts?query=bastion")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var listing api.KnownHostsResponse
	if err := json.NewDecoder(response.Body).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Entries) != 1 || listing.Entries[0].Fingerprint == "" {
		t.Fatalf("entries = %#v", listing.Entries)
	}

	token := server.actionToken(t, session.ActionKnownHostsDelete, "known_hosts")
	deleted := server.post(t, "/api/v1/known-hosts/delete", api.KnownHostsDeleteRequest{
		Entries:     []api.KnownHostTarget{{Line: listing.Entries[0].Line, Digest: listing.Entries[0].Digest}},
		ActionToken: token,
	}, true)
	defer deleted.Body.Close()
	if deleted.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d", deleted.StatusCode)
	}

	contents, err := os.ReadFile(server.knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "bastion.example.com") {
		t.Error("the entry was not removed")
	}
	if _, err := os.Stat(server.workspace.StateDir()); err != nil {
		t.Errorf("the change was not journalled: %v", err)
	}
}

func TestKnownHostsAddRefusesAnUnverifiedCandidate(t *testing.T) {
	server := newTestServer(t)

	token := server.actionToken(t, session.ActionKnownHostsAdd, "bastion.example.com:22")
	refused := server.post(t, "/api/v1/known-hosts/add", api.KnownHostsAddRequest{
		Host: "bastion.example.com", Port: 22, KeyType: knownHostKeyType, Key: knownHostKey,
		ActionToken: token,
	}, true)
	refused.Body.Close()
	if refused.StatusCode != http.StatusConflict {
		t.Fatalf("unverified add = %d, want 409", refused.StatusCode)
	}

	accepted := server.post(t, "/api/v1/known-hosts/add", api.KnownHostsAddRequest{
		Host: "bastion.example.com", Port: 22, KeyType: knownHostKeyType, Key: knownHostKey,
		ExpectedFingerprint: knownHostFingerprint,
		ActionToken:         server.actionToken(t, session.ActionKnownHostsAdd, "bastion.example.com:22"),
	}, true)
	accepted.Body.Close()
	if accepted.StatusCode != http.StatusOK {
		t.Fatalf("verified add = %d", accepted.StatusCode)
	}
}

func TestKnownHostsScanMarksEveryCandidateUnverified(t *testing.T) {
	server := newTestServer(t)
	server.runner.output.Stdout = []byte("bastion.example.com " + knownHostKeyType + " " + knownHostKey + "\n")

	token := server.actionToken(t, session.ActionKnownHostsScan, "bastion.example.com:22")
	response := server.post(t, "/api/v1/known-hosts/scan", api.KnownHostsScanRequest{
		Host: "bastion.example.com", Port: 22, ActionToken: token,
	}, true)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("scan = %d", response.StatusCode)
	}
	var payload api.KnownHostsScanResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Notice == "" {
		t.Error("the scan response must state that the result is unverified")
	}
	for _, candidate := range payload.Candidates {
		if candidate.Verified {
			t.Errorf("candidate marked verified: %#v", candidate)
		}
	}
}

func TestKnownHostsTokenIsInvalidAfterTheFileChanges(t *testing.T) {
	server := newTestServer(t)
	server.writeKnownHosts(t, knownHostsFixture)

	token := server.actionToken(t, session.ActionKnownHostsDelete, "known_hosts")
	server.writeKnownHosts(t, knownHostsFixture+"extra.example.com "+knownHostKeyType+" "+knownHostKey+"\n")

	response := server.post(t, "/api/v1/known-hosts/delete", api.KnownHostsDeleteRequest{
		Entries:     []api.KnownHostTarget{{Line: 1, Digest: storage.Digest([]byte("whatever"))}},
		ActionToken: token,
	}, true)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("token after an external edit = %d, want 403", response.StatusCode)
	}
}
```

Extend `newTestServer` in `diagnostics_test.go` so the shared harness also
builds the known_hosts service: keep the workspace and the storage manager on
the `testServer` struct, add `knownHostsPath` and `workspace` fields, add a
`get` helper mirroring `post` for the read-only endpoint, add a
`writeKnownHosts` helper that writes the file with `0600`, and pass
`KnownHosts: knownhosts.NewService(workspace, storage.NewManager(workspace, time.Now, rand), knownhosts.Scanner{Runner: runner, Toolchain: stubToolchain{}})`
to `Options`. Declare the shared fixtures once:

```go
const (
	knownHostKeyType     = "ssh-ed25519"
	knownHostKey         = "AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS"
	knownHostFingerprint = "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs"
	knownHostsFixture    = "bastion.example.com " + knownHostKeyType + " " + knownHostKey + "\n"
)
```

- [ ] **Step 12: Run the test and verify the endpoints are absent**

Run: `go test ./internal/httpserver -run TestKnownHosts`

Expected: FAIL to compile with `unknown field KnownHosts in Options`.

- [ ] **Step 13: Implement the known_hosts handlers**

```go
// internal/httpserver/knownhosts.go
package httpserver

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/knownhosts"
	"sshc/internal/platform"
	"sshc/internal/session"
	"sshc/internal/storage"
)

// KnownHostsHandlers expose known_hosts search and maintenance.
type KnownHostsHandlers struct {
	Sessions *session.Manager
	Service  *knownhosts.Service
}

// List returns the entries matching the query parameter.
func (h KnownHostsHandlers) List(c *echo.Context) error {
	listing, err := h.Service.Listing(c.QueryParam("query"))
	if err != nil {
		return problem(c, http.StatusInternalServerError, "known_hosts_unreadable")
	}
	response := api.KnownHostsResponse{Path: listing.Path, Entries: make([]api.KnownHostEntry, 0, len(listing.Lines))}
	for _, line := range listing.Lines {
		response.Entries = append(response.Entries, api.KnownHostEntry{
			Line:        line.Number,
			Digest:      storage.Digest([]byte(line.Raw)),
			Marker:      line.Entry.Marker,
			Hosts:       line.Entry.Hosts,
			Hashed:      line.Entry.Hashed,
			KeyType:     line.Entry.KeyType,
			Fingerprint: line.Entry.Fingerprint,
			Comment:     line.Entry.Comment,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Delete removes the confirmed entries through the transaction manager.
func (h KnownHostsHandlers) Delete(c *echo.Context) error {
	var request api.KnownHostsDeleteRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if len(request.Entries) == 0 {
		return problem(c, http.StatusBadRequest, "no_entries_selected")
	}
	if err := h.consume(c, session.ActionKnownHostsDelete, "known_hosts", request.ActionToken); err != nil {
		return err
	}

	targets := make([]knownhosts.Target, 0, len(request.Entries))
	for _, entry := range request.Entries {
		targets = append(targets, knownhosts.Target{Line: entry.Line, Digest: entry.Digest})
	}
	result, err := h.Service.Delete(targets)
	switch {
	case errors.Is(err, knownhosts.ErrEntryChanged), errors.Is(err, knownhosts.ErrNoSuchEntry):
		return problem(c, http.StatusConflict, "known_hosts_changed")
	case err != nil:
		var conflict *storage.ConflictError
		if errors.As(err, &conflict) {
			return problem(c, http.StatusConflict, "known_hosts_changed")
		}
		return problem(c, http.StatusInternalServerError, "known_hosts_write_failed")
	}
	return c.JSON(http.StatusOK, api.KnownHostsChangeResponse{Changed: true, TransactionId: result.ID})
}

// Scan fetches unverified candidates for one host.
func (h KnownHostsHandlers) Scan(c *echo.Context) error {
	var request api.KnownHostsScanRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateHostname(request.Host); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_hostname")
	}
	if err := platform.ValidatePort(request.Port); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_port")
	}
	target := request.Host + ":" + strconv.Itoa(request.Port)
	if err := h.consume(c, session.ActionKnownHostsScan, target, request.ActionToken); err != nil {
		return err
	}

	candidates, err := h.Service.Scanner.Scan(c.Request().Context(), request.Host, request.Port)
	if err != nil {
		return problem(c, http.StatusInternalServerError, "keyscan_failed")
	}
	response := api.KnownHostsScanResponse{
		Notice:     knownhosts.UnverifiedNotice,
		Candidates: make([]api.KnownHostCandidate, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		response.Candidates = append(response.Candidates, api.KnownHostCandidate{
			Host: candidate.Host, Port: candidate.Port, KeyType: candidate.KeyType,
			Key: candidate.Key, Fingerprint: candidate.Fingerprint, Verified: false,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Add appends one key the user verified or explicitly accepted.
func (h KnownHostsHandlers) Add(c *echo.Context) error {
	var request api.KnownHostsAddRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateHostname(request.Host); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_hostname")
	}
	if err := platform.ValidatePort(request.Port); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_port")
	}
	target := request.Host + ":" + strconv.Itoa(request.Port)
	if err := h.consume(c, session.ActionKnownHostsAdd, target, request.ActionToken); err != nil {
		return err
	}

	result, err := h.Service.Add(knownhosts.Candidate{
		Host: request.Host, Port: request.Port, KeyType: request.KeyType, Key: request.Key,
	}, request.ExpectedFingerprint, request.Acknowledged)
	switch {
	case errors.Is(err, knownhosts.ErrUnverifiedCandidate):
		return problem(c, http.StatusConflict, "candidate_not_verified")
	case errors.Is(err, knownhosts.ErrUnsupportedKeyType), errors.Is(err, knownhosts.ErrInvalidKey):
		return problem(c, http.StatusBadRequest, "unsupported_host_key")
	case err != nil:
		return problem(c, http.StatusInternalServerError, "known_hosts_write_failed")
	}
	return c.JSON(http.StatusOK, api.KnownHostsChangeResponse{Changed: true, TransactionId: result.ID})
}

// consume verifies a one-time token bound to the current file contents.
func (h KnownHostsHandlers) consume(c *echo.Context, kind, target, token string) error {
	evidence, err := h.Service.Evidence()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "known_hosts_unreadable")
	}
	if err := h.Sessions.ConsumeAction(currentSession(c), token, session.ActionRequest{
		Kind: kind, Target: target, Evidence: evidence,
	}); err != nil {
		return problem(c, http.StatusForbidden, "invalid_action_token")
	}
	return nil
}
```

- [ ] **Step 14: Teach the token endpoint about the known_hosts kinds**

In `internal/httpserver/actions.go`, add the service and the extra cases:

```go
type ActionHandlers struct {
	Sessions    *session.Manager
	Diagnostics *diagnostics.Service
	KnownHosts  *knownhosts.Service
}
```

```go
	case session.ActionKnownHostsDelete, session.ActionKnownHostsScan, session.ActionKnownHostsAdd:
		if h.KnownHosts == nil {
			return "", nil, errUnavailable
		}
		evidence, err := h.KnownHosts.Evidence()
		if err != nil {
			return "", nil, errUnavailable
		}
		return evidence, nil, nil
```

Register the routes in `server.go` inside a new guard, and pass the service in
`app.Run` by building `storage.NewManager(workspace, time.Now, dependencies.Random)`
once and handing it to `knownhosts.NewService`:

```go
	if options.KnownHosts != nil {
		hosts := KnownHostsHandlers{Sessions: options.Sessions, Service: options.KnownHosts}
		e.GET("/api/v1/known-hosts", hosts.List)
		e.POST("/api/v1/known-hosts/delete", hosts.Delete)
		e.POST("/api/v1/known-hosts/scan", hosts.Scan)
		e.POST("/api/v1/known-hosts/add", hosts.Add)
	}
```

The `Options` struct gains `KnownHosts *knownhosts.Service`, and the
`ActionHandlers` literal in `server.go` gains `KnownHosts: options.KnownHosts`.

- [ ] **Step 15: Run the full suite**

Run:

```bash
go test ./...
go test -race ./...
```

Expected: PASS.

- [ ] **Step 16: Commit Known Hosts**

```bash
git add internal/knownhosts internal/httpserver internal/app api internal/api web/src/api/schema.d.ts
git commit -m "feat: manage known_hosts through journalled transactions"
```

## Task 8: Register a public key on a POSIX remote host, or explain how to do it by hand

**Files:**
- Create: `internal/remotekey/register.go`
- Create: `internal/remotekey/register_test.go`
- Modify: `api/openapi.yaml`
- Create: `internal/httpserver/remotekey.go`
- Create: `internal/httpserver/remotekey_test.go`
- Modify: `internal/httpserver/server.go`
- Modify: `internal/app/run.go`

**Interfaces:**
- Consumes: Tasks 1–5 and `knownhosts.Fingerprint`.
- Produces: `remotekey.PublicKey{Path, Line string}` and `remotekey.ParsePublicKey(line string) (PublicKey, string, error)` returning the key and its fingerprint.
- Produces: `remotekey.Plan{Alias, User, Hostname, Port, ValuesFrom, Fingerprint, KeyPath, KeyLine, RemotePath, Routine string, Supported bool, Manual []string}`.
- Produces: `remotekey.Service{Runner platform.OutputRunner, Toolchain platform.Toolchain, ConfigPath string, Timeout time.Duration}` with `NewService(runner platform.OutputRunner, toolchain platform.Toolchain, configPath string) *Service`, `Plan(alias string, key PublicKey, fingerprint, user, hostname, port, valuesFrom string) Plan`, `Register(ctx context.Context, report effective.Report, alias string, key PublicKey, acknowledged bool) (Result, error)`.
- Produces: `remotekey.Result{Outcome string, ExitCode int, Stderr string, Truncated bool}`, `remotekey.RegistrationAdded`, `remotekey.RegistrationExisting`.
- Produces: `remotekey.Routine`, `remotekey.ProbeCommand`, `remotekey.ProbeMarker`, `remotekey.ManualSteps`, `remotekey.ErrInvalidPublicKey`, `remotekey.ErrUnsupportedRemote`, `remotekey.ErrNotAcknowledged`.
- Produces: `POST /api/v1/remote-keys/plan` and `POST /api/v1/remote-keys/register`.

- [ ] **Step 1: Write the failing registration test**

```go
// internal/remotekey/register_test.go
package remotekey_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/remotekey"
)

const (
	keyLine     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS fixture@example"
	fingerprint = "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs"
)

type scriptedRunner struct {
	commands []platform.Command
	outputs  []platform.Output
}

func (runner *scriptedRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	if len(runner.outputs) == 0 {
		return platform.Output{}, nil
	}
	next := runner.outputs[0]
	runner.outputs = runner.outputs[1:]
	return next, nil
}

type stubToolchain struct{}

func (stubToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (stubToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }

func newService(runner platform.OutputRunner) remotekey.Service {
	return remotekey.Service{Runner: runner, Toolchain: stubToolchain{}, ConfigPath: "/Users/tester/.ssh/config"}
}

func TestParsePublicKeyAcceptsOnlyOneValidLine(t *testing.T) {
	key, computed, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatalf("ParsePublicKey = %v", err)
	}
	if key.Line != keyLine || computed != fingerprint {
		t.Fatalf("key = %#v, fingerprint = %q", key, computed)
	}

	rejected := []string{
		"",
		"ssh-ed25519",
		"ssh-ed25519 not-base64!",
		keyLine + "\nssh-ed25519 AAAA more",
		"rm -rf / AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS comment\rwith-cr",
	}
	for _, line := range rejected {
		if _, _, err := remotekey.ParsePublicKey(line); !errors.Is(err, remotekey.ErrInvalidPublicKey) {
			t.Errorf("ParsePublicKey(%q) = %v, want ErrInvalidPublicKey", line, err)
		}
	}
}

func TestRegisterProbesThenSendsTheKeyOnStandardInput(t *testing.T) {
	runner := &scriptedRunner{outputs: []platform.Output{
		{Stdout: []byte(remotekey.ProbeMarker + "\n")},
		{Stdout: []byte("sshc: added\n")},
	}}
	key, _, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}

	result, err := newService(runner).Register(context.Background(), effective.Report{}, "bastion", key, false)
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if result.Outcome != remotekey.RegistrationAdded {
		t.Fatalf("result = %#v", result)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v", runner.commands)
	}

	probe := runner.commands[0]
	if probe.Arguments[len(probe.Arguments)-1] != remotekey.ProbeCommand {
		t.Errorf("probe argv = %#v", probe.Arguments)
	}
	register := runner.commands[1]
	if register.Arguments[len(register.Arguments)-1] != remotekey.Routine {
		t.Errorf("registration argv = %#v", register.Arguments)
	}
	if string(register.Stdin) != keyLine+"\n" {
		t.Errorf("stdin = %q, want the key line", register.Stdin)
	}
	if strings.Contains(remotekey.Routine, "fixture@example") {
		t.Error("the remote routine must never contain caller input")
	}
	if !slices.Contains(register.Arguments, "-T") {
		t.Errorf("registration argv = %#v, want -T", register.Arguments)
	}
	for _, argument := range register.Arguments {
		if strings.Contains(argument, "sh -c") {
			t.Fatalf("argv smuggled a shell invocation: %q", argument)
		}
	}
}

func TestRegisterReportsAnExistingKeyAndAnUnsupportedRemote(t *testing.T) {
	key, _, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}

	existing := &scriptedRunner{outputs: []platform.Output{
		{Stdout: []byte(remotekey.ProbeMarker + "\n")},
		{Stdout: []byte("sshc: already-present\n")},
	}}
	result, err := newService(existing).Register(context.Background(), effective.Report{}, "bastion", key, false)
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if result.Outcome != remotekey.RegistrationExisting {
		t.Fatalf("result = %#v", result)
	}

	unsupported := &scriptedRunner{outputs: []platform.Output{
		{Stdout: []byte("Windows PowerShell\n"), ExitCode: 0},
	}}
	if _, err := newService(unsupported).Register(context.Background(), effective.Report{}, "bastion", key, false); !errors.Is(err, remotekey.ErrUnsupportedRemote) {
		t.Fatalf("Register = %v, want ErrUnsupportedRemote", err)
	}
	if len(unsupported.commands) != 1 {
		t.Fatal("an unsupported remote still received the registration routine")
	}
}

func TestRegisterRefusesUntilExecutableDirectivesAreAcknowledged(t *testing.T) {
	runner := &scriptedRunner{}
	key, _, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}
	report := effective.Report{Directives: []effective.Executable{
		{Keyword: "ProxyCommand", Command: "/usr/bin/nc %h %p", OnConnect: true},
	}}

	if _, err := newService(runner).Register(context.Background(), report, "bastion", key, false); !errors.Is(err, remotekey.ErrNotAcknowledged) {
		t.Fatalf("Register = %v, want ErrNotAcknowledged", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("a refused registration started a process")
	}

	if _, err := newService(runner).Register(context.Background(), effective.Report{}, "bad alias", key, false); !errors.Is(err, platform.ErrUnsafeAlias) {
		t.Fatalf("Register = %v, want ErrUnsafeAlias", err)
	}
}

func TestPlanDescribesExactlyWhatWillHappen(t *testing.T) {
	key, computed, err := remotekey.ParsePublicKey(keyLine)
	if err != nil {
		t.Fatal(err)
	}
	plan := newService(&scriptedRunner{}).Plan("bastion", key, computed, "ops", "203.0.113.10", "2222", "openssh")

	if !plan.Supported || plan.RemotePath != "~/.ssh/authorized_keys" {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.Routine != remotekey.Routine || plan.KeyLine != keyLine || plan.Fingerprint != fingerprint {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.User != "ops" || plan.Hostname != "203.0.113.10" || plan.Port != "2222" || plan.ValuesFrom != "openssh" {
		t.Fatalf("plan = %#v", plan)
	}
	if len(plan.Manual) == 0 || !strings.Contains(strings.Join(plan.Manual, "\n"), "authorized_keys") {
		t.Errorf("manual steps = %#v", plan.Manual)
	}
}
```

- [ ] **Step 2: Run the test and verify the package is absent**

Run: `go test ./internal/remotekey`

Expected: FAIL — the package does not exist.

- [ ] **Step 3: Implement remote registration**

```go
// Package remotekey installs a public key in a remote account's
// authorized_keys file.
//
// The remote command is a package constant. The key travels on standard
// input, where the fixed routine reads it into a shell variable, so no caller
// input is ever spliced into a command line, a shell string or a here-document.
package remotekey

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"sshc/internal/effective"
	"sshc/internal/knownhosts"
	"sshc/internal/platform"
)

const (
	// ProbeMarker is what a POSIX shell must echo back.
	ProbeMarker = "sshc-posix-shell"
	// ProbeCommand is the fixed command used to decide whether the remote
	// account has a POSIX shell. It prints one known word and nothing else.
	ProbeCommand = `printf '%s\n' sshc-posix-shell`
	// RemotePath is the file this package appends to.
	RemotePath = "~/.ssh/authorized_keys"

	// Registration outcomes.
	RegistrationAdded    = "added"
	RegistrationExisting = "already_present"

	// DefaultTimeout bounds one remote operation.
	DefaultTimeout = 30 * time.Second
)

// Routine is the complete remote program. It contains no caller input.
//
// The key arrives on standard input and is read into "$key"; grep -x -F
// compares whole lines literally, so a key that is already present is never
// duplicated; the permissions are tightened before anything is written.
const Routine = `set -e
umask 077
key=$(cat)
case "$key" in
  ssh-*|ecdsa-*|sk-*) ;;
  *) echo "sshc: unsupported key" >&2; exit 3 ;;
esac
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
if grep -qxF "$key" "$HOME/.ssh/authorized_keys"; then
  echo "sshc: already-present"
  exit 0
fi
printf '%s\n' "$key" >> "$HOME/.ssh/authorized_keys"
echo "sshc: added"
`

var (
	ErrInvalidPublicKey  = errors.New("public key must be exactly one valid OpenSSH public key line")
	ErrUnsupportedRemote = errors.New("this remote environment does not provide the POSIX shell this operation needs")
	ErrNotAcknowledged   = errors.New("connecting would run a configured command that has not been acknowledged")
)

// publicKeyPattern accepts one line: a known algorithm name, a base64 blob and
// an optional comment without any control character.
var publicKeyPattern = regexp.MustCompile(
	`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) ([A-Za-z0-9+/]+={0,3})( [^\x00-\x1f\x7f]*)?$`)

// PublicKey is the key the caller selected. The key vault subsystem chooses
// it; this package needs only the file it came from and its exact line.
type PublicKey struct {
	Path string
	Line string
}

// ParsePublicKey validates one public key line and returns its fingerprint.
func ParsePublicKey(line string) (PublicKey, string, error) {
	trimmed := strings.TrimRight(line, "\n")
	if strings.ContainsAny(trimmed, "\n\r") || !publicKeyPattern.MatchString(trimmed) {
		return PublicKey{}, "", ErrInvalidPublicKey
	}
	fields := strings.Fields(trimmed)
	fingerprint, err := knownhosts.Fingerprint(fields[1])
	if err != nil {
		return PublicKey{}, "", ErrInvalidPublicKey
	}
	return PublicKey{Line: trimmed}, fingerprint, nil
}

// ManualSteps are the instructions shown for a remote this package will not
// automate. They describe what to do, they never run anything.
var ManualSteps = []string{
	"Open a session to the host yourself and check which shell the account uses.",
	"Create ~/.ssh with mode 700 and ~/.ssh/authorized_keys with mode 600 if they do not exist.",
	"Append the public key line shown above to ~/.ssh/authorized_keys as a single line.",
	"Confirm the file still contains one key per line and that no key was split or duplicated.",
}

// Plan is what the user confirms before anything runs on the remote host.
type Plan struct {
	Alias       string
	User        string
	Hostname    string
	Port        string
	ValuesFrom  string
	Fingerprint string
	KeyPath     string
	KeyLine     string
	RemotePath  string
	Routine     string
	Supported   bool
	Manual      []string
}

// Result is one completed registration.
type Result struct {
	Outcome   string
	ExitCode  int
	Stderr    string
	Truncated bool
}

// Service performs remote registration through the process seam.
type Service struct {
	Runner     platform.OutputRunner
	Toolchain  platform.Toolchain
	ConfigPath string
	Timeout    time.Duration
}

// NewService wires the production dependencies together.
func NewService(runner platform.OutputRunner, toolchain platform.Toolchain, configPath string) *Service {
	return &Service{Runner: runner, Toolchain: toolchain, ConfigPath: configPath}
}

// Plan describes the change without contacting anything.
//
// valuesFrom records whether the account details came from `ssh -G` or from
// this application's own reading of the configuration, so the confirmation
// dialog can say which.
func (s Service) Plan(alias string, key PublicKey, fingerprint, user, hostname, port, valuesFrom string) Plan {
	return Plan{
		Alias:       alias,
		User:        user,
		Hostname:    hostname,
		Port:        port,
		ValuesFrom:  valuesFrom,
		Fingerprint: fingerprint,
		KeyPath:     key.Path,
		KeyLine:     key.Line,
		RemotePath:  RemotePath,
		Routine:     Routine,
		Supported:   true,
		Manual:      ManualSteps,
	}
}

// Register probes the remote shell and then installs the key.
func (s Service) Register(ctx context.Context, report effective.Report, alias string, key PublicKey, acknowledged bool) (Result, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Result{}, err
	}
	if _, _, err := ParsePublicKey(key.Line); err != nil {
		return Result{}, err
	}
	if len(report.Unavoidable()) > 0 && !acknowledged {
		return Result{}, ErrNotAcknowledged
	}
	program, err := s.Toolchain.SSH()
	if err != nil {
		return Result{}, err
	}

	probe, err := s.run(ctx, program, alias, ProbeCommand, nil)
	if err != nil {
		return Result{}, err
	}
	if probe.ExitCode != 0 || strings.TrimSpace(string(probe.Stdout)) != ProbeMarker {
		return Result{}, ErrUnsupportedRemote
	}

	output, err := s.run(ctx, program, alias, Routine, []byte(key.Line+"\n"))
	if err != nil {
		return Result{}, err
	}
	result := Result{
		ExitCode:  output.ExitCode,
		Stderr:    string(output.Stderr),
		Truncated: output.Truncated,
	}
	switch {
	case strings.Contains(string(output.Stdout), "sshc: already-present"):
		result.Outcome = RegistrationExisting
	case strings.Contains(string(output.Stdout), "sshc: added"):
		result.Outcome = RegistrationAdded
	default:
		return result, ErrUnsupportedRemote
	}
	return result, nil
}

func (s Service) run(ctx context.Context, program, alias, remoteCommand string, stdin []byte) (platform.Output, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	arguments := []string{"-T", "-F", s.ConfigPath,
		"-o", "BatchMode=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ForwardAgent=no",
		"-o", "RequestTTY=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "NumberOfPasswordPrompts=0",
		"--", alias, remoteCommand,
	}
	return s.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: arguments,
		Stdin:     stdin,
		Timeout:   timeout,
	})
}
```

The remote command is the last argv element and is a package constant, so
OpenSSH's own joining of the remote argv can never concatenate caller data.

- [ ] **Step 4: Run the remote registration tests**

Run:

```bash
go test ./internal/remotekey -v
go test -race ./internal/remotekey
```

Expected: PASS. No test connects anywhere: both runs are served by the
scripted fake.

- [ ] **Step 5: Extend the contract with the registration endpoints**

Add to `paths:`:

```yaml
  /api/v1/remote-keys/plan:
    post:
      operationId: planRemoteKeyRegistration
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RemoteKeyPlanRequest" }
      responses:
        "200":
          description: What the registration would do
          content:
            application/json:
              schema: { $ref: "#/components/schemas/RemoteKeyPlan" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
  /api/v1/remote-keys/register:
    post:
      operationId: registerRemoteKey
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RemoteKeyRegisterRequest" }
      responses:
        "200":
          description: Completed registration
          content:
            application/json:
              schema: { $ref: "#/components/schemas/RemoteKeyRegisterResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
        "422": { $ref: "#/components/responses/Problem" }
```

Add to `components.schemas`:

```yaml
    RemoteKeyPlanRequest:
      type: object
      additionalProperties: false
      required: [alias, keyPath, publicKey]
      properties:
        alias: { type: string, minLength: 1, maxLength: 64 }
        keyPath: { type: string, maxLength: 4096 }
        publicKey: { type: string, minLength: 1, maxLength: 4096 }
    RemoteKeyPlan:
      type: object
      additionalProperties: false
      required: [alias, user, hostname, port, valuesFrom, fingerprint, keyPath, keyLine, remotePath, routine, supported, manual, executableDirectives]
      properties:
        alias: { type: string }
        user: { type: string }
        hostname: { type: string }
        port: { type: string }
        valuesFrom: { type: string }
        fingerprint: { type: string }
        keyPath: { type: string }
        keyLine: { type: string }
        remotePath: { type: string }
        routine: { type: string }
        supported: { type: boolean }
        manual:
          type: array
          items: { type: string }
        executableDirectives:
          type: array
          items: { $ref: "#/components/schemas/ExecutableDirective" }
    RemoteKeyRegisterRequest:
      type: object
      additionalProperties: false
      required: [alias, keyPath, publicKey, actionToken, acknowledgeExecutable]
      properties:
        alias: { type: string, minLength: 1, maxLength: 64 }
        keyPath: { type: string, maxLength: 4096 }
        publicKey: { type: string, minLength: 1, maxLength: 4096 }
        actionToken: { type: string, minLength: 43, maxLength: 43 }
        acknowledgeExecutable: { type: boolean }
    RemoteKeyRegisterResponse:
      type: object
      additionalProperties: false
      required: [outcome, exitCode, stderr, truncated]
      properties:
        outcome: { type: string }
        exitCode: { type: integer }
        stderr: { type: string }
        truncated: { type: boolean }
```

Run: `make generate`

- [ ] **Step 6: Write the failing endpoint test**

```go
// internal/httpserver/remotekey_test.go
package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"sshc/internal/api"
	"sshc/internal/platform"
	"sshc/internal/remotekey"
	"sshc/internal/session"
)

const registrationKey = "ssh-ed25519 " + knownHostKey + " fixture@example"

func TestRemoteKeyPlanShowsTheExactChangeBeforeAnythingRuns(t *testing.T) {
	server := newTestServer(t)

	response := server.post(t, "/api/v1/remote-keys/plan", api.RemoteKeyPlanRequest{
		Alias: "bastion", KeyPath: "/Users/tester/.ssh/id_ed25519.pub", PublicKey: registrationKey,
	}, true)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("plan = %d", response.StatusCode)
	}
	var plan api.RemoteKeyPlan
	if err := json.NewDecoder(response.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	if plan.Fingerprint != knownHostFingerprint || plan.KeyLine != registrationKey {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.Routine != remotekey.Routine || plan.RemotePath != remotekey.RemotePath {
		t.Errorf("plan routine = %q", plan.Routine)
	}
	if plan.Hostname != "203.0.113.10" || plan.Port != "2222" {
		t.Errorf("plan destination = %s:%s", plan.Hostname, plan.Port)
	}
	if len(server.runner.commands) != 1 {
		t.Fatalf("the plan ran %d commands; only ssh -G is allowed", len(server.runner.commands))
	}
	if !strings.Contains(strings.Join(server.runner.commands[0].Arguments, " "), "-G") {
		t.Errorf("plan argv = %#v", server.runner.commands[0].Arguments)
	}
}

func TestRemoteKeyRegisterNeedsAConfirmationAndAValidKey(t *testing.T) {
	server := newTestServer(t)

	noToken := server.post(t, "/api/v1/remote-keys/register", api.RemoteKeyRegisterRequest{
		Alias: "bastion", PublicKey: registrationKey, ActionToken: strings.Repeat("a", 43),
	}, true)
	noToken.Body.Close()
	if noToken.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid token = %d, want 403", noToken.StatusCode)
	}

	badKey := server.post(t, "/api/v1/remote-keys/register", api.RemoteKeyRegisterRequest{
		Alias:       "bastion",
		PublicKey:   "ssh-ed25519 not-base64!",
		ActionToken: server.actionToken(t, session.ActionRemoteKeyRegister, "bastion"),
	}, true)
	badKey.Body.Close()
	if badKey.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid key = %d, want 400", badKey.StatusCode)
	}

	server.runner.outputs = []platform.Output{
		{Stdout: []byte(remotekey.ProbeMarker + "\n")},
		{Stdout: []byte("sshc: added\n")},
	}
	accepted := server.post(t, "/api/v1/remote-keys/register", api.RemoteKeyRegisterRequest{
		Alias:       "bastion",
		KeyPath:     "/Users/tester/.ssh/id_ed25519.pub",
		PublicKey:   registrationKey,
		ActionToken: server.actionToken(t, session.ActionRemoteKeyRegister, "bastion"),
	}, true)
	defer accepted.Body.Close()
	if accepted.StatusCode != http.StatusOK {
		t.Fatalf("register = %d", accepted.StatusCode)
	}
	var result api.RemoteKeyRegisterResponse
	if err := json.NewDecoder(accepted.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Outcome != remotekey.RegistrationAdded {
		t.Fatalf("result = %#v", result)
	}
}
```

This test needs two harness changes. First, give the shared `stubRunner` an
`outputs []platform.Output` field that is consumed in order and falls back to
the existing single `output` when the queue is empty, and update the earlier
tests that set `output` directly. Second, pass
`RemoteKeys: remotekey.NewService(runner, stubToolchain{}, filepath.Join(workspace.Root(), "config"))`
to `Options` in `newTestServer`, next to `Diagnostics` and `KnownHosts`, so the
routes exist for this test.

- [ ] **Step 7: Implement the registration handlers**

```go
// internal/httpserver/remotekey.go
package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/diagnostics"
	"sshc/internal/platform"
	"sshc/internal/remotekey"
	"sshc/internal/session"
)

// RemoteKeyHandlers register a public key on a remote host.
type RemoteKeyHandlers struct {
	Sessions    *session.Manager
	Diagnostics *diagnostics.Service
	Service     *remotekey.Service
}

// Plan describes the change without touching the remote host.
func (h RemoteKeyHandlers) Plan(c *echo.Context) error {
	var request api.RemoteKeyPlanRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	key, fingerprint, err := remotekey.ParsePublicKey(request.PublicKey)
	if err != nil {
		return problem(c, http.StatusBadRequest, "invalid_public_key")
	}
	key.Path = request.KeyPath

	inspection, err := h.Diagnostics.Inspect(c.Request().Context(), request.Alias, false)
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inspection_failed")
	}
	user, hostname, port, valuesFrom := accountFrom(inspection, request.Alias)

	plan := h.Service.Plan(request.Alias, key, fingerprint, user, hostname, port, valuesFrom)
	return c.JSON(http.StatusOK, api.RemoteKeyPlan{
		Alias: plan.Alias, User: plan.User, Hostname: plan.Hostname, Port: plan.Port,
		ValuesFrom: plan.ValuesFrom, Fingerprint: plan.Fingerprint, KeyPath: plan.KeyPath,
		KeyLine: plan.KeyLine, RemotePath: plan.RemotePath, Routine: plan.Routine,
		Supported: plan.Supported, Manual: plan.Manual,
		ExecutableDirectives: describeDirectives(inspection.Report.Directives),
	})
}

// Register installs the key after the user confirmed the plan.
func (h RemoteKeyHandlers) Register(c *echo.Context) error {
	var request api.RemoteKeyRegisterRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	key, _, err := remotekey.ParsePublicKey(request.PublicKey)
	if err != nil {
		return problem(c, http.StatusBadRequest, "invalid_public_key")
	}
	key.Path = request.KeyPath

	report, err := h.Diagnostics.Safety()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}
	if err := h.Sessions.ConsumeAction(currentSession(c), request.ActionToken, session.ActionRequest{
		Kind: session.ActionRemoteKeyRegister, Target: request.Alias, Evidence: report.Evidence(),
	}); err != nil {
		return problem(c, http.StatusForbidden, "invalid_action_token")
	}

	result, err := h.Service.Register(c.Request().Context(), report, request.Alias, key, request.AcknowledgeExecutable)
	switch {
	case errors.Is(err, remotekey.ErrNotAcknowledged):
		return problem(c, http.StatusConflict, "executable_directive_not_acknowledged")
	case errors.Is(err, remotekey.ErrUnsupportedRemote):
		return problem(c, http.StatusUnprocessableEntity, "remote_not_supported")
	case err != nil:
		return problem(c, http.StatusInternalServerError, "registration_failed")
	}
	return c.JSON(http.StatusOK, api.RemoteKeyRegisterResponse{
		Outcome:   result.Outcome,
		ExitCode:  result.ExitCode,
		Stderr:    result.Stderr,
		Truncated: result.Truncated,
	})
}

// accountFrom prefers the values OpenSSH reported and falls back to this
// application's own projection, saying which one was used.
func accountFrom(inspection diagnostics.Inspection, alias string) (user, hostname, port, valuesFrom string) {
	if inspection.Evaluated {
		return inspection.Values.First("user"), inspection.Values.First("hostname"), inspection.Values.First("port"), "openssh"
	}
	hostname = alias
	port = "22"
	if source, ok := inspection.Projection.Value("hostname"); ok {
		hostname = source.Value
	}
	if source, ok := inspection.Projection.Value("port"); ok {
		port = source.Value
	}
	if source, ok := inspection.Projection.Value("user"); ok {
		user = source.Value
	}
	return user, hostname, port, "engine"
}
```

Register the routes in `server.go` beside the others, guarded by
`options.RemoteKeys != nil` with a new `RemoteKeys *remotekey.Service` field on
`Options`, and build the service in `app.Run` with
`remotekey.NewService(dependencies.Runner, dependencies.Toolchain, filepath.Join(workspace.Root(), "config"))`.

- [ ] **Step 8: Run the full suite**

Run:

```bash
go test ./...
go test -race ./...
```

Expected: PASS.

- [ ] **Step 9: Commit remote registration**

```bash
git add internal/remotekey internal/httpserver internal/app api internal/api web/src/api/schema.d.ts
git commit -m "feat: register public keys on POSIX remotes without shell interpolation"
```

## Task 9: Diagnostics and Known Hosts panels, documentation and subsystem verification

**Files:**
- Modify: `web/src/api/client.ts`
- Create: `web/src/api/integrations.ts`
- Create: `web/src/diagnostics/DiagnosticsPanel.tsx`
- Create: `web/src/diagnostics/DiagnosticsPanel.test.tsx`
- Create: `web/src/knownhosts/KnownHostsPanel.tsx`
- Create: `web/src/knownhosts/KnownHostsPanel.test.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/App.test.tsx`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-04-sshc-roadmap.md`

**Interfaces:**
- Consumes: every endpoint added in Tasks 5–8, through the generated `components["schemas"]` types.
- Produces: `ApiError` with a `code` field from `web/src/api/client.ts`.
- Produces: `integrations` client with `checkConfig`, `inspect`, `issueToken`, `reach`, `authenticate`, `terminalCommand`, `launchTerminal`, `listKnownHosts`, `deleteKnownHosts`, `scanKnownHosts`, `addKnownHost`.
- Produces: `DiagnosticsPanel` and `KnownHostsPanel`, both taking their client functions as props so tests never touch `fetch`.

- [ ] **Step 1: Surface problem codes in the API client**

Modify `web/src/api/client.ts` so a rejected mutation carries the server's
problem code while keeping the existing message the foundation tests assert:

```ts
export class ApiError extends Error {
  readonly code: string;

  constructor(code: string) {
    super("api_mutation_failed");
    this.code = code;
  }
}
```

and replace the failure branch of `mutate`:

```ts
    if (!response.ok) {
      const problem: unknown = await response.json().catch(() => null);
      const code =
        typeof problem === "object" && problem !== null && typeof (problem as { code?: unknown }).code === "string"
          ? (problem as { code: string }).code
          : "api_mutation_failed";
      throw new ApiError(code);
    }
```

- [ ] **Step 2: Write the typed integration client**

```ts
// web/src/api/integrations.ts
import { apiClient } from "./client";
import type { components } from "./schema";

type Schemas = components["schemas"];

export type EffectiveResponse = Schemas["EffectiveResponse"];
export type ExecutableDirective = Schemas["ExecutableDirective"];
export type ActionTokenResponse = Schemas["ActionTokenResponse"];
export type ConfigCheckResponse = Schemas["ConfigCheckResponse"];
export type ReachabilityResponse = Schemas["ReachabilityResponse"];
export type AuthenticationResponse = Schemas["AuthenticationResponse"];
export type TerminalCommandResponse = Schemas["TerminalCommandResponse"];
export type KnownHostsResponse = Schemas["KnownHostsResponse"];
export type KnownHostEntry = Schemas["KnownHostEntry"];
export type KnownHostsScanResponse = Schemas["KnownHostsScanResponse"];
export type KnownHostCandidate = Schemas["KnownHostCandidate"];

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const integrations = {
  issueToken(kind: string, target: string): Promise<ActionTokenResponse> {
    return apiClient.mutate<ActionTokenResponse>("/api/v1/actions/token", json({ kind, target }));
  },
  checkConfig(): Promise<ConfigCheckResponse> {
    return apiClient.mutate<ConfigCheckResponse>("/api/v1/diagnostics/config", json({}));
  },
  inspect(alias: string, actionToken = ""): Promise<EffectiveResponse> {
    return apiClient.mutate<EffectiveResponse>("/api/v1/diagnostics/effective", json({ alias, actionToken }));
  },
  reach(alias: string, actionToken: string): Promise<ReachabilityResponse> {
    return apiClient.mutate<ReachabilityResponse>("/api/v1/diagnostics/reachability", json({ alias, actionToken }));
  },
  authenticate(alias: string, actionToken: string, acknowledgeExecutable: boolean): Promise<AuthenticationResponse> {
    return apiClient.mutate<AuthenticationResponse>(
      "/api/v1/diagnostics/authentication",
      json({ alias, actionToken, acknowledgeExecutable }),
    );
  },
  terminalCommand(alias: string): Promise<TerminalCommandResponse> {
    return apiClient.mutate<TerminalCommandResponse>("/api/v1/terminal/command", json({ alias }));
  },
  launchTerminal(alias: string, actionToken: string): Promise<{ launched: boolean }> {
    return apiClient.mutate<{ launched: boolean }>("/api/v1/terminal/launch", json({ alias, actionToken }));
  },
  async listKnownHosts(query: string): Promise<KnownHostsResponse> {
    const response = await fetch(`/api/v1/known-hosts?query=${encodeURIComponent(query)}`, {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error("known_hosts_failed");
    return (await response.json()) as KnownHostsResponse;
  },
  deleteKnownHosts(entries: { line: number; digest: string }[], actionToken: string): Promise<{ changed: boolean }> {
    return apiClient.mutate<{ changed: boolean }>("/api/v1/known-hosts/delete", json({ entries, actionToken }));
  },
  scanKnownHosts(host: string, port: number, actionToken: string): Promise<KnownHostsScanResponse> {
    return apiClient.mutate<KnownHostsScanResponse>("/api/v1/known-hosts/scan", json({ host, port, actionToken }));
  },
  addKnownHost(
    candidate: KnownHostCandidate,
    expectedFingerprint: string,
    acknowledged: boolean,
    actionToken: string,
  ): Promise<{ changed: boolean }> {
    return apiClient.mutate<{ changed: boolean }>(
      "/api/v1/known-hosts/add",
      json({
        host: candidate.host,
        port: candidate.port,
        keyType: candidate.keyType,
        key: candidate.key,
        expectedFingerprint,
        acknowledged,
        actionToken,
      }),
    );
  },
};
```

- [ ] **Step 3: Write the failing Diagnostics panel test**

```tsx
// web/src/diagnostics/DiagnosticsPanel.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DiagnosticsPanel } from "./DiagnosticsPanel";

const token = "t".repeat(43);

const dangerousDirective = {
  keyword: "Match exec",
  command: "test -f /tmp/at-work",
  path: "/Users/tester/.ssh/config",
  line: 6,
  condition: "Match exec \"test -f /tmp/at-work\"",
  onEvaluate: true,
  onConnect: true,
  overridable: false,
};

function baseClient(overrides = {}) {
  return {
    inspect: vi.fn().mockResolvedValue({
      alias: "bastion",
      evaluated: false,
      requiresConfirmation: true,
      tokenWarning: "OpenSSH does not shell-escape the tokens it expands.",
      executableDirectives: [dangerousDirective],
      values: [],
      sources: [],
      complexities: [],
      route: [],
      failure: { failed: false, exitCode: 0, stderr: "", truncated: false },
    }),
    issueToken: vi.fn().mockResolvedValue({
      token,
      expiresInSeconds: 120,
      tokenWarning: "OpenSSH does not shell-escape the tokens it expands.",
      executableDirectives: [dangerousDirective],
    }),
    reach: vi.fn(),
    authenticate: vi.fn(),
    terminalCommand: vi.fn().mockResolvedValue({ command: "ssh -- bastion", launchable: true, warning: "" }),
    launchTerminal: vi.fn().mockResolvedValue({ launched: true }),
    ...overrides,
  };
}

describe("DiagnosticsPanel", () => {
  it("shows the exact command and requires a confirmation before evaluating", async () => {
    const client = baseClient();
    const user = userEvent.setup();
    render(<DiagnosticsPanel client={client} />);

    await user.type(screen.getByLabelText("Host alias"), "bastion");
    await user.click(screen.getByRole("button", { name: "Explain configuration" }));

    expect(await screen.findByText("test -f /tmp/at-work")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("does not shell-escape");
    expect(client.issueToken).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Confirm and run ssh -G" }));

    await waitFor(() => expect(client.issueToken).toHaveBeenCalledWith("diagnostics.evaluate", "bastion"));
    expect(client.inspect).toHaveBeenLastCalledWith("bastion", token);
  });

  it("states that the reachability check ignored ProxyJump", async () => {
    const client = baseClient({
      reach: vi.fn().mockResolvedValue({
        address: "203.0.113.10:2222",
        outcome: "refused",
        elapsedMs: 12,
        detail: "connect: connection refused",
        notice: "This check dialled the destination directly.",
      }),
    });
    const user = userEvent.setup();
    render(<DiagnosticsPanel client={client} />);

    await user.type(screen.getByLabelText("Host alias"), "bastion");
    await user.click(screen.getByRole("button", { name: "Check TCP reachability" }));

    expect(await screen.findByText(/dialled the destination directly/)).toBeInTheDocument();
    expect(screen.getByText("203.0.113.10:2222")).toBeInTheDocument();
  });

  it("offers a copyable command instead of a launch for an unsafe alias", async () => {
    const client = baseClient({
      terminalCommand: vi.fn().mockResolvedValue({
        command: `ssh -- weird "alias"`,
        launchable: false,
        warning: "This alias contains characters that could change the meaning of a command line.",
      }),
    });
    const user = userEvent.setup();
    render(<DiagnosticsPanel client={client} />);

    await user.type(screen.getByLabelText("Host alias"), "weird");
    await user.click(screen.getByRole("button", { name: "Show terminal command" }));

    expect(await screen.findByText(/could change the meaning/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open in Terminal" })).toBeDisabled();
    expect(client.launchTerminal).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 4: Implement the Diagnostics panel**

```tsx
// web/src/diagnostics/DiagnosticsPanel.tsx
import { useState } from "react";
import type {
  AuthenticationResponse,
  EffectiveResponse,
  ExecutableDirective,
  ReachabilityResponse,
  TerminalCommandResponse,
} from "../api/integrations";

type DiagnosticsClient = {
  inspect: (alias: string, actionToken?: string) => Promise<EffectiveResponse>;
  issueToken: (kind: string, target: string) => Promise<{ token: string }>;
  reach: (alias: string, actionToken: string) => Promise<ReachabilityResponse>;
  authenticate: (alias: string, actionToken: string, acknowledgeExecutable: boolean) => Promise<AuthenticationResponse>;
  terminalCommand: (alias: string) => Promise<TerminalCommandResponse>;
  launchTerminal: (alias: string, actionToken: string) => Promise<{ launched: boolean }>;
};

function DirectiveList({ directives }: { directives: ExecutableDirective[] }) {
  if (directives.length === 0) return null;
  return (
    <ul className="mt-2 space-y-2">
      {directives.map((directive) => (
        <li key={`${directive.path}:${directive.line}:${directive.keyword}`} className="rounded border border-amber-700 p-3">
          <p className="font-medium">{directive.keyword}</p>
          <p className="font-mono text-sm break-all">{directive.command}</p>
          <p className="text-xs text-zinc-400">
            {directive.path}:{directive.line}
            {directive.condition ? ` · ${directive.condition}` : ""}
            {directive.overridable ? " · disabled for a test run" : " · cannot be disabled"}
          </p>
        </li>
      ))}
    </ul>
  );
}

export function DiagnosticsPanel({ client }: { client: DiagnosticsClient }) {
  const [alias, setAlias] = useState("");
  const [effective, setEffective] = useState<EffectiveResponse | null>(null);
  const [reachability, setReachability] = useState<ReachabilityResponse | null>(null);
  const [authentication, setAuthentication] = useState<AuthenticationResponse | null>(null);
  const [terminal, setTerminal] = useState<TerminalCommandResponse | null>(null);
  const [failure, setFailure] = useState("");

  const run = async (operation: () => Promise<void>) => {
    setFailure("");
    try {
      await operation();
    } catch (error) {
      setFailure(error instanceof Error ? error.message : "request_failed");
    }
  };

  const explain = () => run(async () => setEffective(await client.inspect(alias)));

  const confirmAndEvaluate = () =>
    run(async () => {
      const issued = await client.issueToken("diagnostics.evaluate", alias);
      setEffective(await client.inspect(alias, issued.token));
    });

  const checkReachability = () =>
    run(async () => {
      const issued = await client.issueToken("diagnostics.reachability", alias);
      setReachability(await client.reach(alias, issued.token));
    });

  const testAuthentication = () =>
    run(async () => {
      const issued = await client.issueToken("diagnostics.authentication", alias);
      const unavoidable = (effective?.executableDirectives ?? []).some(
        (directive) => directive.onConnect && !directive.overridable,
      );
      setAuthentication(await client.authenticate(alias, issued.token, unavoidable));
    });

  const showCommand = () => run(async () => setTerminal(await client.terminalCommand(alias)));

  const launch = () =>
    run(async () => {
      const issued = await client.issueToken("terminal.launch", alias);
      await client.launchTerminal(alias, issued.token);
    });

  return (
    <section aria-labelledby="diagnostics-heading" className="space-y-6">
      <h2 id="diagnostics-heading" className="text-lg font-medium">Diagnostics</h2>

      <div className="flex items-end gap-3">
        <label className="flex flex-col text-sm" htmlFor="diagnostics-alias">
          Host alias
          <input
            id="diagnostics-alias"
            className="mt-1 rounded border border-zinc-700 bg-zinc-900 px-3 py-2"
            value={alias}
            onChange={(event) => setAlias(event.target.value)}
          />
        </label>
        <button type="button" onClick={explain} className="rounded bg-zinc-800 px-3 py-2">Explain configuration</button>
        <button type="button" onClick={checkReachability} className="rounded bg-zinc-800 px-3 py-2">Check TCP reachability</button>
        <button type="button" onClick={testAuthentication} className="rounded bg-zinc-800 px-3 py-2">Test authentication</button>
        <button type="button" onClick={showCommand} className="rounded bg-zinc-800 px-3 py-2">Show terminal command</button>
      </div>

      {failure !== "" && <p role="alert">{failure}</p>}

      {effective && (
        <div className="space-y-3">
          {effective.executableDirectives.length > 0 && (
            <div>
              <p role="alert" className="text-amber-300">{effective.tokenWarning}</p>
              <DirectiveList directives={effective.executableDirectives} />
            </div>
          )}
          {!effective.evaluated && effective.requiresConfirmation && (
            <button type="button" onClick={confirmAndEvaluate} className="rounded bg-amber-700 px-3 py-2">
              Confirm and run ssh -G
            </button>
          )}
          {effective.failure.failed && (
            <p role="status">ssh exited with status {effective.failure.exitCode}</p>
          )}
          {effective.evaluated && (
            <table>
              <caption className="text-left text-sm text-zinc-400">Effective values reported by ssh -G</caption>
              <tbody>
                {effective.values.map((value) => (
                  <tr key={value.keyword}>
                    <th scope="row" className="pr-4 text-left font-normal">{value.keyword}</th>
                    <td className="font-mono">{value.values.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {effective.sources.length > 0 && (
            <ul className="text-sm">
              {effective.sources.filter((source) => source.winner).map((source) => (
                <li key={`${source.path}:${source.line}`}>
                  {source.keyword} = {source.value} · {source.path}:{source.line}
                  {source.condition ? ` · ${source.condition}` : ""}
                </li>
              ))}
            </ul>
          )}
          {effective.complexities.length > 0 && (
            <div>
              <p>Complex external rules apply; trust the ssh -G values above.</p>
              <ul className="text-sm text-zinc-400">
                {effective.complexities.map((complexity, index) => (
                  <li key={`${complexity.code}-${index}`}>{complexity.code}: {complexity.detail}</li>
                ))}
              </ul>
            </div>
          )}
          {effective.route.length > 0 && (
            <ol className="text-sm">
              {effective.route.map((stage) => (
                <li key={`${stage.order}`} style={{ marginLeft: `${stage.depth}rem` }}>
                  {stage.order}. {stage.hop} → {stage.user ? `${stage.user}@` : ""}{stage.hostname}:{stage.port}
                  {stage.complex ? " · complex external rule" : ""}
                </li>
              ))}
            </ol>
          )}
        </div>
      )}

      {reachability && (
        <div>
          <p>{reachability.address}</p>
          <p role="status">{reachability.outcome}</p>
          <p>{reachability.notice}</p>
        </div>
      )}

      {authentication && (
        <div>
          <p role="status">{authentication.outcome}</p>
          {authentication.stderr !== "" && <pre className="overflow-x-auto text-xs">{authentication.stderr}</pre>}
        </div>
      )}

      {terminal && (
        <div>
          <p className="font-mono break-all">{terminal.command}</p>
          {terminal.warning !== "" && <p role="alert">{terminal.warning}</p>}
          <button type="button" onClick={launch} disabled={!terminal.launchable} className="rounded bg-zinc-800 px-3 py-2">
            Open in Terminal
          </button>
        </div>
      )}
    </section>
  );
}
```

- [ ] **Step 5: Write the failing Known Hosts panel test**

```tsx
// web/src/knownhosts/KnownHostsPanel.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { KnownHostsPanel } from "./KnownHostsPanel";

const token = "t".repeat(43);
const fingerprint = "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs";

function baseClient(overrides = {}) {
  return {
    listKnownHosts: vi.fn().mockResolvedValue({
      path: "/Users/tester/.ssh/known_hosts",
      entries: [
        {
          line: 1,
          digest: "d".repeat(64),
          marker: "",
          hosts: ["bastion.example.com"],
          hashed: false,
          keyType: "ssh-ed25519",
          fingerprint,
          comment: "",
        },
      ],
    }),
    issueToken: vi.fn().mockResolvedValue({ token }),
    deleteKnownHosts: vi.fn().mockResolvedValue({ changed: true }),
    scanKnownHosts: vi.fn().mockResolvedValue({
      notice: "ssh-keyscan proves only that something answered at this address.",
      candidates: [
        { host: "bastion.example.com", port: 22, keyType: "ssh-ed25519", key: "AAAA", fingerprint, verified: false },
      ],
    }),
    addKnownHost: vi.fn().mockResolvedValue({ changed: true }),
    ...overrides,
  };
}

describe("KnownHostsPanel", () => {
  it("lists entries with their key type and fingerprint", async () => {
    render(<KnownHostsPanel client={baseClient()} />);

    expect(await screen.findByText("bastion.example.com")).toBeInTheDocument();
    expect(screen.getByText("ssh-ed25519")).toBeInTheDocument();
    expect(screen.getByText(fingerprint)).toBeInTheDocument();
  });

  it("deletes an entry only through a fresh confirmation", async () => {
    const client = baseClient();
    const user = userEvent.setup();
    render(<KnownHostsPanel client={client} />);

    await user.click(await screen.findByRole("button", { name: "Delete entry on line 1" }));

    await waitFor(() => expect(client.issueToken).toHaveBeenCalledWith("known_hosts.delete", "known_hosts"));
    expect(client.deleteKnownHosts).toHaveBeenCalledWith([{ line: 1, digest: "d".repeat(64) }], token);
  });

  it("marks scanned keys unverified and refuses to add one without proof", async () => {
    const client = baseClient();
    const user = userEvent.setup();
    render(<KnownHostsPanel client={client} />);

    await user.type(screen.getByLabelText("Host to scan"), "bastion.example.com");
    await user.click(screen.getByRole("button", { name: "Fetch candidates" }));

    expect(await screen.findByText(/proves only that something answered/)).toBeInTheDocument();
    expect(screen.getByText("unverified")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Add to known_hosts" }));
    expect(client.addKnownHost).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent("fingerprint");

    await user.type(screen.getByLabelText("Fingerprint you obtained another way"), fingerprint);
    await user.click(screen.getByRole("button", { name: "Add to known_hosts" }));

    await waitFor(() => expect(client.addKnownHost).toHaveBeenCalled());
    const [, expectedFingerprint, acknowledged] = client.addKnownHost.mock.calls[0];
    expect(expectedFingerprint).toBe(fingerprint);
    expect(acknowledged).toBe(false);
  });
});
```

- [ ] **Step 6: Implement the Known Hosts panel**

```tsx
// web/src/knownhosts/KnownHostsPanel.tsx
import { useEffect, useState } from "react";
import type { KnownHostCandidate, KnownHostEntry, KnownHostsResponse, KnownHostsScanResponse } from "../api/integrations";

type KnownHostsClient = {
  listKnownHosts: (query: string) => Promise<KnownHostsResponse>;
  issueToken: (kind: string, target: string) => Promise<{ token: string }>;
  deleteKnownHosts: (entries: { line: number; digest: string }[], actionToken: string) => Promise<{ changed: boolean }>;
  scanKnownHosts: (host: string, port: number, actionToken: string) => Promise<KnownHostsScanResponse>;
  addKnownHost: (
    candidate: KnownHostCandidate,
    expectedFingerprint: string,
    acknowledged: boolean,
    actionToken: string,
  ) => Promise<{ changed: boolean }>;
};

export function KnownHostsPanel({ client }: { client: KnownHostsClient }) {
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<KnownHostEntry[]>([]);
  const [scanHost, setScanHost] = useState("");
  const [scan, setScan] = useState<KnownHostsScanResponse | null>(null);
  const [expected, setExpected] = useState("");
  const [failure, setFailure] = useState("");

  const reload = async (search: string) => {
    const listing = await client.listKnownHosts(search);
    setEntries(listing.entries);
  };

  useEffect(() => {
    void reload("").catch(() => setFailure("known_hosts_unreadable"));
    // The panel loads once; searching is an explicit action.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const run = async (operation: () => Promise<void>) => {
    setFailure("");
    try {
      await operation();
    } catch (error) {
      setFailure(error instanceof Error ? error.message : "request_failed");
    }
  };

  const search = () => run(() => reload(query));

  const remove = (entry: KnownHostEntry) =>
    run(async () => {
      const issued = await client.issueToken("known_hosts.delete", "known_hosts");
      await client.deleteKnownHosts([{ line: entry.line, digest: entry.digest }], issued.token);
      await reload(query);
    });

  const fetchCandidates = () =>
    run(async () => {
      const issued = await client.issueToken("known_hosts.scan", `${scanHost}:22`);
      setScan(await client.scanKnownHosts(scanHost, 22, issued.token));
    });

  const add = (candidate: KnownHostCandidate) =>
    run(async () => {
      if (expected.trim() === "") {
        setFailure("Enter the fingerprint you obtained another way, or acknowledge that this key is unverified.");
        return;
      }
      const issued = await client.issueToken("known_hosts.add", `${candidate.host}:${candidate.port}`);
      await client.addKnownHost(candidate, expected.trim(), false, issued.token);
      setScan(null);
      setExpected("");
      await reload(query);
    });

  return (
    <section aria-labelledby="known-hosts-heading" className="space-y-6">
      <h2 id="known-hosts-heading" className="text-lg font-medium">Known Hosts</h2>

      <div className="flex items-end gap-3">
        <label className="flex flex-col text-sm" htmlFor="known-hosts-query">
          Search
          <input
            id="known-hosts-query"
            className="mt-1 rounded border border-zinc-700 bg-zinc-900 px-3 py-2"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <button type="button" onClick={search} className="rounded bg-zinc-800 px-3 py-2">Search</button>
      </div>

      {failure !== "" && <p role="alert">{failure}</p>}

      <table>
        <thead>
          <tr>
            <th scope="col" className="text-left">Hosts</th>
            <th scope="col" className="text-left">Key type</th>
            <th scope="col" className="text-left">Fingerprint</th>
            <th scope="col" className="text-left">Action</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.line}>
              <td>{entry.hashed ? `hashed entry (line ${entry.line})` : entry.hosts.join(", ")}</td>
              <td>{entry.keyType}</td>
              <td className="font-mono text-xs">{entry.fingerprint}</td>
              <td>
                <button type="button" onClick={() => remove(entry)} className="rounded bg-zinc-800 px-2 py-1">
                  Delete entry on line {entry.line}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="flex items-end gap-3">
        <label className="flex flex-col text-sm" htmlFor="known-hosts-scan">
          Host to scan
          <input
            id="known-hosts-scan"
            className="mt-1 rounded border border-zinc-700 bg-zinc-900 px-3 py-2"
            value={scanHost}
            onChange={(event) => setScanHost(event.target.value)}
          />
        </label>
        <button type="button" onClick={fetchCandidates} className="rounded bg-zinc-800 px-3 py-2">Fetch candidates</button>
      </div>

      {scan && (
        <div className="space-y-3">
          <p role="status">{scan.notice}</p>
          <label className="flex flex-col text-sm" htmlFor="known-hosts-expected">
            Fingerprint you obtained another way
            <input
              id="known-hosts-expected"
              className="mt-1 rounded border border-zinc-700 bg-zinc-900 px-3 py-2"
              value={expected}
              onChange={(event) => setExpected(event.target.value)}
            />
          </label>
          <ul className="space-y-2">
            {scan.candidates.map((candidate) => (
              <li key={`${candidate.host}:${candidate.port}:${candidate.fingerprint}`} className="rounded border border-zinc-700 p-3">
                <p>{candidate.host}:{candidate.port} · {candidate.keyType}</p>
                <p className="font-mono text-xs">{candidate.fingerprint}</p>
                <p className="text-amber-300">unverified</p>
                <button type="button" onClick={() => add(candidate)} className="mt-2 rounded bg-zinc-800 px-3 py-2">
                  Add to known_hosts
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
```

- [ ] **Step 7: Make both panels reachable from the shell**

In `web/src/App.tsx`, replace the disabled navigation with a selection that
enables only the two sections this subsystem owns:

```tsx
const sections = ["Connections", "Groups", "Config", "Keys", "Known Hosts", "Diagnostics", "History"] as const;
const available: readonly string[] = ["Known Hosts", "Diagnostics"];
```

Track `const [section, setSection] = useState<string>("Diagnostics");`, render
each navigation item as
`<button disabled={!available.includes(section)} onClick={() => setSection(section)}>`,
and render `<DiagnosticsPanel client={integrations} />` or
`<KnownHostsPanel client={integrations} />` in `<main>` beside the existing
status card. Keep the status card, the error screen and the bootstrap effect
exactly as they are.

Update `web/src/App.test.tsx`: the assertion that every navigation label is
disabled now applies only to `["Connections", "Groups", "Config", "Keys", "History"]`,
and add a case asserting that `Diagnostics` and `Known Hosts` are enabled. The
App test injects its own bootstrap and health functions, so no panel request is
made during that test.

- [ ] **Step 8: Run the frontend checks**

Run:

```bash
npm test --prefix web
npm run typecheck --prefix web
```

Expected: PASS.

- [ ] **Step 9: Document the boundary in README.md**

Append after the existing `## SSH config エンジンの境界` section, in the same
Japanese style:

```markdown
## SSH 実行の境界

- 外部プロセスは argv を直接組み立てて実行します。シェル、`sh -c`、文字列連結した AppleScript は使いません。alias、hostname、user は OpenSSH が受理する値であっても信頼しません。
- `Match exec`、`ProxyCommand`、`KnownHostsCommand`、`LocalCommand`、`RemoteCommand` を危険ディレクティブとして構文木から検出し、実際のコマンド文字列を表示します。`Match exec` がある場合、`ssh -G` は自動実行しません。
- OpenSSH は展開したトークンをシェル向けにエスケープしません。hostname や user の値がそのまま危険ディレクティブのシェルへ届きます。UI と API はこの警告を必ず添えます。
- 接続テスト、Terminal 起動、`known_hosts` 変更、公開鍵のリモート登録、危険な設定での `ssh -G` は、CSRF header に加えて、対象と操作種別と表示済みコマンドへ紐付いた一回限りの action token を必要とします。設定を編集すると token は無効になります。
- 到達性チェックは宛先を直接 dial します。`ProxyJump` と `ProxyCommand` は使いません。結果には必ずその旨を表示します。
- 認証テストはタイムアウトとキャンセルを持ち、出力を上限つきで取得し、forwarding と `LocalCommand` をコマンドライン優先設定で無効化します。無効化できない実行可能ディレクティブが残る場合は、その内容を確認するまで開始しません。
- Terminal 起動は安全な文字集合の alias に限ります。それ以外はコマンドのコピーだけを提供します。AppleScript は定数で、alias は `argv` として渡します。
- `ssh-keyscan` の結果は本人性を証明しません。常に「未検証」と表示し、別経路で取得した fingerprint の一致か、明示的な承認がある場合だけ追加します。
- `known_hosts` の変更は `storage.Manager` を通し、journal と世代バックアップを残します。
- 公開鍵のリモート登録は POSIX shell を持つ環境に限定し、固定のリモート処理へ公開鍵を標準入力で渡します。ユーザー入力をリモートシェル文字列へ補間しません。対応外環境では手順の表示だけを行います。
- 自動テストは実リモート、実 `~/.ssh`、実 Keychain、実 Terminal を使いません。唯一の例外は、一時ディレクトリ内の安全な fixture に対する `ssh -G -F` の差分試験です。`ssh` が無い環境では skip します。
```

- [ ] **Step 10: Record the subsystem in the roadmap**

In `docs/superpowers/plans/2026-08-04-sshc-roadmap.md`, update the Status
section: mark subsystem 5 delivered with this plan's filename and the date the
acceptance gate was verified, and note that the deferred `ssh -G` differential
test from subsystem 2 is now implemented in `internal/effective/differential_test.go`.

- [ ] **Step 11: Verify the whole subsystem**

Run:

```bash
make generate
go test ./...
go test -race ./...
make fuzz
npm test --prefix web
npm run typecheck --prefix web
go build -trimpath -o bin/sshc ./cmd/sshc
git diff --stat go.mod go.sum
git status --short
```

Expected: everything passes; `go.mod` and `go.sum` are unchanged, proving no
dependency was added; `make generate` leaves no diff.

- [ ] **Step 12: Verify the constraints mechanically**

Run:

```bash
grep -rn "log/slog\|\"log\"" internal/effective internal/diagnostics internal/knownhosts internal/remotekey || echo "no logging in the new packages"
grep -rn "sh -c\|/bin/sh\|exec.Command(" internal/effective internal/diagnostics internal/knownhosts internal/remotekey internal/platform || echo "no shell and no direct exec outside the adapter"
grep -rn "UserHomeDir\|os.Getenv(\"HOME\")" internal/ || echo "no home directory access under internal/"
grep -rln "t.TempDir()" internal/effective internal/knownhosts internal/httpserver
ls -la ~/.ssh/sshc 2>/dev/null || echo "no state directory in the real home"
go test ./internal/effective -run TestProjectionMatchesInstalledOpenSSH -v | grep -E "PASS|SKIP"
```

Expected: the first three commands print their "no ..." message; the fourth
lists the test files that isolate themselves in temporary directories; the real
`~/.ssh` gained no `sshc` directory; the differential test reports PASS on a
machine with OpenSSH or SKIP without it. `exec.Command(` must appear only in
`internal/platform/macos/command.go` and the committed `browser.go`, both of
which use `exec.CommandContext` with a direct argv.

- [ ] **Step 13: Commit the panels and documentation**

```bash
git add web README.md docs/superpowers/plans/2026-08-04-sshc-roadmap.md
git commit -m "feat: add diagnostics and known hosts panels"
```

## SSH Integrations Acceptance Gate

Before starting the hardening and release plan, verify all of the following:

- `go test ./...`, `go test -race ./...`, `make fuzz`, `npm test --prefix web` and `npm run typecheck --prefix web` all pass.
- `go build -trimpath -o bin/sshc ./cmd/sshc` succeeds and `go.mod`/`go.sum` are unchanged: this subsystem added no dependency.
- `make generate` produces no diff, so the committed models match `api/openapi.yaml`.
- The deferred `ssh -G -F` differential test exists in `internal/effective/differential_test.go`, compares the engine's projection against real OpenSSH on fixtures with no executable directive inside `t.TempDir()`, and reports SKIP rather than FAIL when `ssh` is absent.
- `Match exec`, `ProxyCommand`, `KnownHostsCommand`, `LocalCommand` and `RemoteCommand` are detected from the parsed syntax tree with their exact command text, file, line and enclosing condition.
- A configuration containing `Match exec` never reaches `ssh -G` without a consumed action token; the corresponding test asserts that no process was started.
- Every response that lists an executable directive also carries the warning that OpenSSH does not shell-escape its expanded tokens.
- Value provenance reports file, line and block for each winning value, lists shadowed values, and marks wildcard, negation, `Match` and duplicate-alias situations as complex external rules instead of inventing a source.
- Single and comma-separated multi-hop `ProxyJump` chains expand into a route, including a jump host's own `ProxyJump`, with cycle and depth limits reported rather than followed.
- The four diagnostics are independent operations with separate endpoints: configuration check, `ssh -G`, direct TCP reachability, and the authentication test.
- Every reachability result states that `ProxyJump` was ignored.
- The authentication test has a timeout, honours request cancellation, caps captured output, disables forwarding and `LocalCommand` through `-o` options, stops as soon as OpenSSH reports authentication, and refuses to start when a non-overridable executable directive has not been acknowledged.
- Terminal launch accepts only aliases matching `^[A-Za-z0-9][A-Za-z0-9._-]*$` up to 64 characters; anything else is copy-command-only, and the AppleScript is a constant with the alias delivered as `argv`.
- `known_hosts` search shows hostname, key type and fingerprint; hashed entries are matched, never invented; deletion goes through `storage.Manager` and leaves a backup and a history record; an entry whose line changed on disk is refused.
- `ssh-keyscan` candidates are always marked unverified, and adding one requires either a matching out-of-band fingerprint or an explicit acknowledgement.
- Remote registration shows the alias, effective user, destination, fingerprint and the exact remote routine before running; it probes for a POSIX shell first, sends the key on stdin, never interpolates input into a remote shell string, avoids duplicates by exact line match, tightens `~/.ssh` to `0700` and `authorized_keys` to `0600`, and shows manual steps for an unsupported remote.
- Every state-changing or externally visible endpoint rejects a missing CSRF header, a replayed action token, a token issued for another kind or target, and a token whose evidence no longer matches the files on disk.
- No automated test contacted a remote host, ran `ssh`/`ssh-keyscan` against the network, or touched the real `~/.ssh`, Keychain or Terminal; the only real binaries executed are the local `ssh -G -F` differential test and `/bin/echo`, `/bin/cat`, `/bin/sleep`, `/usr/bin/false`, `/usr/bin/yes` in the process adapter's own tests.
- `internal/effective`, `internal/diagnostics`, `internal/knownhosts` and `internal/remotekey` import no logging package, and no captured output, hostname, token or request body is logged anywhere.
- Nothing under `internal/` reads the home directory; `cmd/sshc/main.go` is the only place that resolves it.

## Manual Acceptance Checklist

These require a real host and are never automated. Run them once, on purpose,
against a machine you control, and record the result.

1. **Effective configuration on a real alias.** Pick an alias with no executable directive. Confirm the effective values match `ssh -G <alias>` run by hand, and that the provenance list points at the file and line you expect.
2. **Dangerous directive gate.** Temporarily add `Match exec "true"` to a scratch include. Confirm the UI shows the exact command, refuses to evaluate until you confirm, and that the confirmation stops working after you edit the file.
3. **Multi-hop jump.** Configure `ProxyJump a,b` with `b` carrying its own `ProxyJump`. Confirm the route shows all stages with the correct user, host and port.
4. **Reachability wording.** Run the check against a host reachable only through a jump host. Confirm it fails and that the result says `ProxyJump` was ignored.
5. **Authentication test.** Run it against a host where your key works; confirm it reports authenticated quickly and that no shell, forwarding or `LocalCommand` ran. Repeat against a host with an unknown key and confirm it reports the host key problem instead of trusting it.
6. **Cancellation.** Start the authentication test against an unresponsive address and cancel the request; confirm the `ssh` process is gone (`pgrep -f 'ssh -v'` prints nothing).
7. **Terminal launch.** Launch a safe alias and confirm a Terminal window opens with `ssh -- <alias>`. Then define an alias containing a space or a quote and confirm the UI offers only the copyable command.
8. **Known Hosts deletion.** Delete a stale entry, then confirm the backup under `~/.ssh/sshc/backups/<id>/known_hosts` holds the original bytes and the history record exists.
9. **Keyscan.** Scan a host you control, compare the fingerprint with `ssh-keygen -lf` output taken on the host itself, and confirm adding it requires that fingerprint or an explicit acknowledgement.
10. **Remote registration.** Register a public key on a POSIX host: confirm the plan showed the right user and destination, the key appears exactly once in `authorized_keys`, `~/.ssh` is `0700`, `authorized_keys` is `0600`, and a second registration reports `already_present` without duplicating the line.
11. **Unsupported remote.** Point the registration at a host without a POSIX shell and confirm only manual instructions appear and nothing was written.
