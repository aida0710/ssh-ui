# SSH UI Hardening and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the assembled `ssh-ui` system keeps the promises of design §8, §10.4 and §10.5 — with fuzz targets beyond the parser, a security suite that drives the real loopback server, an injection suite that inspects the exact argument vectors the application would execute, a Playwright run over an isolated `~/.ssh`, and a single reproducible binary — then state, condition by condition, which of design §12's completion conditions hold.

**Architecture:** One new test-only Go package, `internal/acceptance`, starts the *production* server through a new `app.Build` seam on a real `127.0.0.1:0` listener against a throwaway `$HOME`, and enumerates its route table from the Echo router instead of keeping a hand-written list, so a route added later is covered without anyone remembering to cover it. Recording process, terminal and agent doubles capture every `platform.Command` the application would run, which turns "no option injection" and "no AppleScript injection" into assertions about argv rather than about the absence of a crash. A `@playwright/test` project drives the built binary in real Chromium, where CSP enforcement, cookie flags, fragment removal and "no external origin was contacted" can be observed rather than assumed.

**Tech Stack:** Go 1.26.5, Echo v5.3.1, `golang.org/x/crypto` v0.54.0, `gopkg.in/yaml.v3` v3.0.1 (promoted from indirect to direct), React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, `@playwright/test` 1.62.1, Node 22.19.0, npm 11.7.0, OpenSSH 10.2p1 (never invoked by an automated test in this plan).

## Global Constraints

- macOS only. The server binds loopback `127.0.0.1` on an OS-assigned port and nothing else. No CORS. No LaunchAgent. The server exists only while the `ssh-ui` process runs.
- Pinned versions, unchanged from the earlier subsystems: Go 1.26.5, Echo v5.3.1, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, and `golang.org/x/crypto v0.54.0` which subsystem 4 introduced.
- This plan adds exactly two dependencies, both justified in the task that adds them and pinned exactly: `@playwright/test` **1.62.1** as a `devDependencies` entry in `web/package.json` (Task 6), and `gopkg.in/yaml.v3` **v3.0.1** promoted from an existing indirect requirement to a direct one in `go.mod` (Task 1). `go.sum` gains nothing, because v3.0.1 is already there. Any further dependency must be justified and pinned exactly.
- Automated tests must never contact a real remote host, change a real `authorized_keys`, or touch the real `~/.ssh`, the real Keychain, a real `ssh-agent` or Terminal. Every test in this plan runs against a `t.TempDir()` home and fake seams.
- The permitted real-binary carve-outs are the ones already in the tree, named rather than widened: (1) `internal/effective/differential_test.go` may run the installed `ssh -G -F` against fixtures containing no executable directive, inside `t.TempDir()`; (2) `internal/effective/evaluate_test.go`'s `TestEvaluateParsesInstalledOpenSSHOutput` may do the same for one fixture; (3) `internal/platform/macos/command_test.go` may run `/bin/echo`, `/bin/cat`, `/bin/sleep`, `/usr/bin/false` and `/usr/bin/yes` with fixed argv. This plan adds exactly one more, and no others: `internal/acceptance/binary_test.go` runs the local Go toolchain (`go build`) and then the binary it just produced, with `HOME` pointed at a temporary directory.
- A security test must assert on the property, not on today's implementation detail. Every suite in this plan ends with an explicit **mutation step**: weaken the defence, watch the test fail, restore the defence. A test that survives its mutation step is rewritten, not accepted.
- Every suite carries a **positive control** — one input that must reach the defended code path — so a suite can never pass merely because the route is broken or the fixture is empty.
- No test may be skipped to make a suite green. A skip must be a deliberate, documented capability check, like the differential test's "is `ssh` installed". The acceptance gate enumerates the only skips allowed to exist.
- Never log request bodies, cookies, bootstrap, session, CSRF or action tokens, key material, passphrases, file contents or clipboard contents. This plan adds the first test that actually scrapes the log stream for them.
- `os.UserHomeDir` and `$HOME` may be read only from `cmd/ssh-ui`. Nothing under `internal/` may read either, including this plan's test package, which receives its home as a value.
- `api/openapi.yaml` stays the contract. Endpoint changes go there first, then `make generate`. Never hand-edit `internal/api/models.gen.go` or `web/src/api/schema.d.ts`.
- Never write a raw control character into source or into this document. Use `"\x00"` in Go and `"\u0000"` in TypeScript.
- Playwright artefacts must never contain secrets: traces, videos and screenshots are disabled, because one end-to-end flow renders a private key on screen by design.

### Relationship to the four earlier plans

This plan owns the cross-cutting suite and the release. It does not re-run gates the earlier plans own.

- Subsystem 2 owns the parser round trip, the Include graph diagnostics, the workspace guard's unit tests and the transaction recovery tests. This plan adds fuzzing to the Include **pattern expander**, which subsystem 2 left unfuzzed, and exercises the workspace guard **through the HTTP surface**, which nothing else does.
- Subsystem 3 owns lossless edits, diffs, conflicts, group compilation and per-handler CSRF/no-store assertions on the config routes. This plan asserts those properties **over the whole route table**, including routes subsystem 3 never saw.
- Subsystem 4 owns reveal, passphrase, trash and its per-route action-token tests. This plan adds the **expiry** case, the **exhaustive** "no token-guarded route can be reached without one" property, and the log scrape, which subsystem 4's own gate names as an untested constraint.
- Subsystem 5 owns the differential test, the executable-directive gates and the per-handler token tests. This plan adds the fuzz targets subsystem 5's Out of Scope defers here by name, and the argv-level injection properties.
- CSP is claimed by no earlier plan. It is entirely this plan's.

---

## File Structure

```text
.
├── Makefile                                     # modified: fuzz loops over every target; e2e, verify-generated
├── README.md                                    # modified: 強化とリリースの境界
├── .gitignore                                   # modified: Playwright artefacts
├── go.mod                                       # modified: gopkg.in/yaml.v3 becomes a direct requirement
├── api/openapi.yaml                             # unchanged by this plan; read by the contract test
├── cmd/ssh-ui/main.go                           # modified: -open flag and the URL-printing launcher
├── docs/
│   └── manual-acceptance.md                     # created: the checklist automation must not run
├── internal/
│   ├── acceptance/                              # created: test-only package, no production code
│   │   ├── harness_test.go                      # isolated $HOME fixture, real server, recording seams
│   │   ├── transport_test.go                    # Host, Origin, Fetch Metadata, session, CSP, no-store, bind
│   │   ├── limits_test.go                       # request body ceiling, command output ceiling
│   │   ├── leak_test.go                         # action tokens and the canary sweep over responses and logs
│   │   ├── injection_test.go                    # option, AppleScript, shell, traversal, symlink, NUL alias
│   │   ├── fuzz_test.go                         # FuzzAPIRequestBodies and the make-fuzz coverage test
│   │   ├── binary_test.go                       # build, serve, SIGTERM
│   │   ├── conditions_test.go                   # design §12 audit, machine-checked
│   │   └── testdata/fuzz/FuzzAPIRequestBodies/  # committed corpus
│   ├── app/run.go                               # modified: Build extracted from Run; SessionNow seam
│   ├── config/fuzz_test.go                      # modified: FuzzExpandIncludePattern
│   ├── effective/
│   │   ├── fuzz_test.go                         # created: FuzzParseValues
│   │   └── testdata/ssh-g-output.txt            # created: a captured `ssh -G` transcript, used as seed
│   ├── knownhosts/
│   │   ├── fuzz_test.go                         # created: FuzzParseKnownHostsRoundTrip
│   │   └── testdata/known_hosts.sample          # created: a realistic known_hosts fixture, used as seed
│   └── httpserver/
│       ├── server.go                            # modified: Route, (*Server).Routes()
│       ├── security.go                          # modified: Fetch Metadata on every /api/ request; body ceiling
│       ├── security_test.go                     # modified: existing cases gain Sec-Fetch-Site
│       ├── handlers_test.go                     # modified: existing cases gain Sec-Fetch-Site
│       └── integration_test.go                  # modified: existing cases gain Sec-Fetch-Site
└── web/
    ├── package.json                             # modified: @playwright/test 1.62.1, e2e script
    ├── playwright.config.ts                     # created
    ├── tsconfig.e2e.json                        # created
    ├── vite.config.ts                           # modified: Vitest only collects src/**/*.test.*
    └── e2e/
        ├── support/environment.ts               # isolated $HOME, spawns bin/ssh-ui -open=false
        ├── bootstrap.spec.ts                    # session, replay, CSP, no external origin
        ├── connections.spec.ts                  # form edit, Raw edit, save preview, three-way conflict
        ├── explorer.spec.ts                     # Include explorer
        ├── keys.spec.ts                         # inventory and reveal
        └── history.spec.ts                      # history and restore
```

### A note on drift

Subsystems 3, 4 and 5 were written concurrently and all three modify `api/openapi.yaml`, `internal/httpserver`, `internal/session`, `internal/app` and `cmd/ssh-ui`. The roadmap already records that whoever executes them must reconcile the shared wiring rather than pasting a plan's wiring step verbatim. The same applies here, in exactly one place: **the field set of `app.Dependencies`**. This plan's harness sets `Home`, `Random`, `Browser`, `Listen`, `UI`, `Logger`, `Runner`, `Toolchain`, `Terminal`, `KeyAgent` and `SessionNow`. If the merged tree spells a seam differently — for example `Executor` instead of `Runner` — use the spelling that is in the tree and keep everything else identical. The route-table contract test in Task 1 exists precisely so a seam the harness forgot to supply shows up as a missing route rather than as silently reduced coverage.

One decision the earlier plans left colliding is already settled in the committed tree and this plan follows it: action tokens use subsystem 5's shape — `session.ActionRequest{Kind, Target, Evidence}` with `session.ActionRevealPrivateKey = "private_key.reveal"` and `session.ActionPurgeTrashEntry = "trash.purge"` — not subsystem 4's `Action{Purpose, Subject}`.

---

## Task 1: Isolated end-to-end harness, route inventory and the transport security suite

**Files:**
- Modify: `internal/httpserver/server.go`
- Modify: `internal/httpserver/security.go`
- Modify: `internal/httpserver/security_test.go`
- Modify: `internal/httpserver/handlers_test.go`
- Modify: `internal/httpserver/integration_test.go`
- Modify: `internal/app/run.go`
- Modify: `go.mod`
- Create: `internal/acceptance/harness_test.go`
- Create: `internal/acceptance/transport_test.go`

**Interfaces:**
- Consumes: `httpserver.New`, `httpserver.Options`, `httpserver.Security`, `httpserver.SessionCookie`, `httpserver.CSRFHeader`, `httpserver.ErrNonLoopbackListener`, `session.NewManager`, `session.Manager`, `app.Dependencies`, `app.Run`, `platform.OutputRunner`, `platform.Command`, `platform.Output`, `platform.Toolchain`, `platform.TerminalLauncher`, `platform.KeyAgent`, `platform.BrowserLauncher`.
- Produces:
  - `httpserver.Route{Method string; Path string}` and `func (s *Server) Routes() []Route`.
  - `httpserver.MaxRequestBodyCeiling = 2 << 20` — a middleware-level ceiling distinct from subsystem 5's per-handler `httpserver.MaxRequestBody`.
  - `func app.Build(dependencies Dependencies, version string) (*httpserver.Server, string, error)` returning the server and the one-time bootstrap token.
  - `app.Dependencies.SessionNow func() time.Time` — nil means `time.Now`.
  - In `internal/acceptance` (test-only, package `acceptance_test`): `newFixture(t testing.TB) *fixture`, `(*fixture).do`, `(*fixture).apiRoutes`, `(*fixture).logText`, the `recordingRunner`, `fixedToolchain`, `recordingTerminal`, `fakeAgent`, `testClock` and `fixtureCanaries` types that Tasks 2-5, 7 and 8 reuse.

**Teeth:** every case in `transport_test.go` is driven over a real TCP connection to the real route table, so a defence that exists only in a unit test's hand-built Echo instance does not satisfy it. Step 14 mutates each of the four defences in turn and records the failure.

- [ ] **Step 1: Write the failing route-inventory test**

Add to `internal/httpserver/server_test.go`:

```go
func TestServerReportsEveryRegisteredRoute(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	manager, _, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x11}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{
		Listener: listener,
		Sessions: manager,
		UI:       fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}},
		Version:  "route-inventory",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"POST /api/v1/session/bootstrap": false,
		"GET /api/v1/health":             false,
	}
	for _, route := range server.Routes() {
		key := route.Method + " " + route.Path
		if _, expected := want[key]; expected {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("Routes() did not report %q", key)
		}
	}
	if len(server.Routes()) < len(want) {
		t.Fatalf("Routes() = %d entries, want at least %d", len(server.Routes()), len(want))
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/httpserver -run TestServerReportsEveryRegisteredRoute`
Expected: FAIL, `server.Routes undefined (type *Server has no field or method Routes)`.

- [ ] **Step 3: Expose the route table**

In `internal/httpserver/server.go`, add `engine *echo.Echo` to the `Server` struct, set it in `New` (`engine: e`, alongside the existing fields), and add:

```go
// Route is one route this server registered.
type Route struct {
	Method string
	Path   string
}

// Routes reports every registered route in registration order.
//
// The hardening suite enumerates this instead of keeping its own list, so a
// route added by a later change inherits the transport, cache, session and leak
// assertions without anyone remembering to add it anywhere.
func (s *Server) Routes() []Route {
	registered := s.engine.Router().Routes()
	routes := make([]Route, 0, len(registered))
	for _, info := range registered {
		routes = append(routes, Route{Method: info.Method, Path: info.Path})
	}
	return routes
}
```

- [ ] **Step 4: Run it and watch it pass**

Run: `go test ./internal/httpserver -run TestServerReportsEveryRegisteredRoute`
Expected: PASS.

- [ ] **Step 5: Write the failing Fetch Metadata test**

Design §8.1 requires `Host`, `Origin` and Fetch Metadata to be verified by exact match. The committed middleware checks Fetch Metadata only on state-changing requests, so a cross-site `GET /api/...` is refused today only because `SameSite=Strict` withholds the cookie. That is one defence, not two. Add to `internal/httpserver/security_test.go`:

```go
func TestSecurityRefusesEveryAPIRequestFromAnotherSite(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x37}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Use((Security{
		ExpectedHost:   "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions:       manager,
	}).Middleware)
	e.GET("/api/v1/test", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })

	tests := []struct {
		name      string
		fetchSite string
		want      int
	}{
		{"same origin", "same-origin", http.StatusNoContent},
		{"cross site", "cross-site", http.StatusForbidden},
		{"same site", "same-site", http.StatusForbidden},
		{"user initiated", "none", http.StatusForbidden},
		{"header absent", "", http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
			request.Host = "127.0.0.1:43123"
			if test.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			}
			request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}
```

- [ ] **Step 6: Run it and watch it fail**

Run: `go test ./internal/httpserver -run TestSecurityRefusesEveryAPIRequestFromAnotherSite`
Expected: FAIL on the `cross site`, `same site`, `user initiated` and `header absent` subtests with `status = 204, want 403`.

- [ ] **Step 7: Verify Fetch Metadata on every API request, and add the body ceiling**

In `internal/httpserver/security.go`, add the ceiling constant next to the existing constants:

```go
	// MaxRequestBodyCeiling is the hard ceiling every /api/ request body is read
	// through. Handlers apply their own, smaller limits; this one exists so a
	// route added later cannot read an unbounded body by forgetting to.
	MaxRequestBodyCeiling = 2 << 20
```

Then replace the body of `Middleware` between the `isAPI` short-circuit and the bootstrap check:

```go
		if !isAPI {
			return next(c)
		}

		// Fetch Metadata is checked on every API request, not only on the ones
		// that change state. A cross-site GET is already starved of its cookie
		// by SameSite=Strict, but design §8.1 asks for the header to be verified
		// by exact match, and a browser that mishandles SameSite must not be the
		// only thing standing between another site and this API.
		if request.Header.Get("Sec-Fetch-Site") != "same-origin" {
			return problem(c, http.StatusForbidden, "cross_site_request")
		}
		if request.Body != nil {
			request.Body = http.MaxBytesReader(c.Response(), request.Body, MaxRequestBodyCeiling)
		}

		isBootstrap := request.Method == http.MethodPost && request.URL.Path == "/api/v1/session/bootstrap"
		isStateChanging := request.Method != http.MethodGet && request.Method != http.MethodHead
		if (isStateChanging || isBootstrap) && request.Header.Get(echo.HeaderOrigin) != s.ExpectedOrigin {
			return problem(c, http.StatusForbidden, "cross_site_request")
		}
		if isBootstrap {
			return next(c)
		}
```

- [ ] **Step 8: Run it and watch it pass, then repair the callers**

Run: `go test ./internal/httpserver -run TestSecurityRefusesEveryAPIRequestFromAnotherSite`
Expected: PASS.

Run: `go test ./...`
Expected: FAIL in several existing tests that issue an authenticated `GET /api/...` without the header. Repair every one of them by adding exactly this line to the request builder:

```go
	request.Header.Set("Sec-Fetch-Site", "same-origin")
```

The known sites at the time of writing are `TestSecurityNavigationHeadersAndAPIAuthentication` in `internal/httpserver/security_test.go` (its `run` helper sets the header only when `method != http.MethodGet`; set it unconditionally), `TestHealthRequiresSessionCookie` in `internal/httpserver/handlers_test.go` (its `call` helper), and the `unauthenticatedHealth`, `authenticatedHealth` and `apiFallback` calls in `internal/httpserver/integration_test.go`. Subsystems 3, 4 and 5 add their own GET helpers; each will fail the same way. **The rule for judging every failure: if the request is one the application's own frontend makes, add the header to the test; if the request is one another site could make, the 403 is the correct new answer and the test's expectation changes.** Never weaken the middleware to make a test pass. Navigation requests to `/` and to static assets are untouched, because the check applies only under `/api/`.

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 9: Write the failing `app.Build` test**

Add to `internal/app/run_test.go`:

```go
func TestBuildReturnsAServerAndAOneTimeBootstrapToken(t *testing.T) {
	home := t.TempDir()
	server, bootstrap, err := Build(Dependencies{
		Home:    home,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x24}, 512)),
		Browser: refusingBrowser{},
		Listen:  net.Listen,
		UI:      fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, "build-test")
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	if len(bootstrap) != 43 {
		t.Fatalf("bootstrap length = %d, want 43", len(bootstrap))
	}
	if !strings.HasPrefix(server.URL(), "http://127.0.0.1:") {
		t.Fatalf("URL() = %q", server.URL())
	}
	if len(server.Routes()) == 0 {
		t.Fatal("Build() produced a server with no routes")
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	cancel()
	if err := <-served; err != nil {
		t.Fatalf("Serve() = %v", err)
	}
}

type refusingBrowser struct{}

func (refusingBrowser) Open(context.Context, string) error {
	return errors.New("a test must never open a browser")
}
```

- [ ] **Step 10: Run it and watch it fail**

Run: `go test ./internal/app -run TestBuildReturnsAServerAndAOneTimeBootstrapToken`
Expected: FAIL, `undefined: Build`.

- [ ] **Step 11: Extract `Build` out of `Run`**

In `internal/app/run.go`, add the `SessionNow` seam to `Dependencies`:

```go
	// SessionNow is the clock the session manager uses for action-token expiry.
	// It is nil in production, where time.Now is used. The hardening suite sets
	// it so a token can be aged without sleeping.
	SessionNow func() time.Time
```

Then split the function. Everything `Run` did before it started serving moves into `Build`; `Run` keeps the browser launch, the serve loop and the shutdown. Keep every existing wiring line the merged tree contains — the only change is where it lives:

```go
// Build wires every dependency into an HTTP server without serving it, and
// returns the one-time bootstrap token the UI must present.
//
// Run calls Build and then serves. The hardening suite calls Build directly, so
// its assertions run against the same route table, the same middleware and the
// same handler construction the shipped binary uses, instead of a hand-built
// subset that can drift.
func Build(dependencies Dependencies, version string) (*httpserver.Server, string, error) {
	listener, err := dependencies.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}

	sessions, bootstrap, err := session.NewManager(dependencies.Random)
	if err != nil {
		listener.Close()
		return nil, "", fmt.Errorf("session: %w", err)
	}
	if dependencies.SessionNow != nil {
		sessions.Now = dependencies.SessionNow
	}

	// Every service construction the merged tree performs stays here, unchanged,
	// between the session manager and httpserver.New.

	server, err := httpserver.New(httpserver.Options{
		Listener: listener,
		Sessions: sessions,
		UI:       dependencies.UI,
		Version:  version,
		Logger:   dependencies.Logger,
		// plus Config, Keys, Diagnostics, KnownHosts and RemoteKeys exactly as
		// the merged tree already passes them.
	})
	if err != nil {
		listener.Close()
		return nil, "", err
	}
	return server, bootstrap, nil
}

func Run(ctx context.Context, dependencies Dependencies, version string) error {
	server, bootstrap, err := Build(dependencies, version)
	if err != nil {
		return err
	}

	target := server.URL() + "/#bootstrap=" + bootstrap
	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()

	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(serverCtx) }()

	if err := dependencies.Browser.Open(ctx, target); err != nil {
		stopServer()
		<-serveErrors
		return fmt.Errorf("open browser: %w", err)
	}

	select {
	case err := <-serveErrors:
		return err
	case <-ctx.Done():
		stopServer()
		return <-serveErrors
	}
}
```

- [ ] **Step 12: Run it and watch it pass**

Run: `go test ./internal/app`
Expected: PASS.

- [ ] **Step 13: Commit the seams**

```bash
git add internal/httpserver/server.go internal/httpserver/server_test.go internal/httpserver/security.go internal/httpserver/security_test.go internal/httpserver/handlers_test.go internal/httpserver/integration_test.go internal/app/run.go internal/app/run_test.go
git commit -m "feat: verify fetch metadata on every API request and expose the route table"
```

- [ ] **Step 14: Write the harness**

Create `internal/acceptance/harness_test.go`. This file is the whole plan's foundation; Tasks 2-5, 7 and 8 add test files beside it and reuse everything here.

```go
// Package acceptance holds the cross-cutting hardening suite. It contains no
// production code: every file is a test file, so nothing here is compiled into
// the shipped binary.
//
// Every test in this package builds an isolated home directory with
// t.TempDir(), starts the production server through app.Build against it, and
// replaces the process, terminal and agent seams with recorders that never
// start a program. No test here reads the real home directory, the real
// Keychain, a real agent, Terminal or a remote host.
package acceptance_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"ssh-ui/internal/app"
	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/keys"
	"ssh-ui/internal/platform"
)

// canaryPassphrase protects the fixture private key. It must never appear in
// any response body or log line, including the reveal response.
const canaryPassphrase = "canary-passphrase-b0e0a1"

// canaryOutsideContents lives in a file outside ~/.ssh. No route may ever
// return it, so it is the needle for both the leak sweep and path traversal.
const canaryOutsideContents = "canary-outside-workspace-4f21c7\n"

// fixtureCanaries names the strings a test looks for in responses and logs.
type fixtureCanaries struct {
	Outside        string
	Passphrase     string
	PrivateKeyLine string
	Bootstrap      string
	SessionID      string
	CSRF           string
}

type recordedCommand struct {
	Path      string
	Arguments []string
	Stdin     []byte
	Env       []string
}

// recordingRunner captures every command the application would run and starts
// none of them. reply, when set, supplies the output a specific test needs.
type recordingRunner struct {
	mutex    sync.Mutex
	commands []recordedCommand
	reply    func(platform.Command) (platform.Output, error)
}

func (r *recordingRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	r.mutex.Lock()
	r.commands = append(r.commands, recordedCommand{
		Path:      command.Path,
		Arguments: append([]string(nil), command.Arguments...),
		Stdin:     append([]byte(nil), command.Stdin...),
		Env:       append([]string(nil), command.Env...),
	})
	reply := r.reply
	r.mutex.Unlock()
	if reply == nil {
		return platform.Output{}, nil
	}
	return reply(command)
}

func (r *recordingRunner) recorded() []recordedCommand {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]recordedCommand(nil), r.commands...)
}

func (r *recordingRunner) reset() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.commands = nil
}

func (r *recordingRunner) answer(reply func(platform.Command) (platform.Output, error)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.reply = reply
}

// fixedToolchain returns absolute paths that are never executed, because the
// runner beside it starts no process.
type fixedToolchain struct{}

func (fixedToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (fixedToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }
func (fixedToolchain) KeyGen() (string, error)  { return "/usr/bin/ssh-keygen", nil }
func (fixedToolchain) KeyAdd() (string, error)  { return "/usr/bin/ssh-add", nil }

type recordingTerminal struct {
	mutex   sync.Mutex
	aliases []string
}

func (t *recordingTerminal) Launch(_ context.Context, alias string) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.aliases = append(t.aliases, alias)
	return nil
}

func (t *recordingTerminal) launched() []string {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return append([]string(nil), t.aliases...)
}

// fakeAgent stands in for ssh-agent and the login Keychain. No test in this
// repository talks to either.
type fakeAgent struct{}

func (fakeAgent) Available(context.Context) bool { return false }
func (fakeAgent) List(context.Context) ([]platform.AgentIdentity, error) {
	return nil, platform.ErrAgentUnavailable
}
func (fakeAgent) Add(context.Context, platform.AgentAddRequest) error {
	return platform.ErrAgentUnavailable
}
func (fakeAgent) Remove(context.Context, string) error { return platform.ErrAgentUnavailable }

// silentBrowser replaces the macOS `open` adapter. Opening a real browser from
// a test would hand a live bootstrap token to whatever is running on the desk.
type silentBrowser struct{}

func (silentBrowser) Open(context.Context, string) error { return nil }

// testClock is read from the server's goroutines and advanced from the test's,
// so the instant is held in an atomic rather than in a plain field.
type testClock struct{ nanoseconds atomic.Int64 }

func newTestClock() *testClock {
	clock := &testClock{}
	clock.nanoseconds.Store(time.Date(2026, time.August, 5, 9, 0, 0, 0, time.UTC).UnixNano())
	return clock
}

func (c *testClock) now() time.Time { return time.Unix(0, c.nanoseconds.Load()).UTC() }

func (c *testClock) advance(step time.Duration) { c.nanoseconds.Add(int64(step)) }

// syncBuffer collects log output from the server's goroutines.
type syncBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(chunk []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(chunk)
}

func (b *syncBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.String()
}

type fixture struct {
	t         testing.TB
	home      string
	root      string
	baseURL   string
	host      string
	client    *http.Client
	server    *httpserver.Server
	runner    *recordingRunner
	terminal  *recordingTerminal
	clock     *testClock
	logs      *syncBuffer
	canaries  fixtureCanaries
	sessionID string
}

// newFixture writes an isolated ~/.ssh, starts the production server against
// it, and exchanges the bootstrap token for a session.
func newFixture(t testing.TB) *fixture {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	writeFixtureTree(t, home, root)

	runner := &recordingRunner{}
	terminal := &recordingTerminal{}
	clock := newTestClock()
	logs := &syncBuffer{}

	server, bootstrap, err := app.Build(app.Dependencies{
		Home:       home,
		Random:     rand.Reader,
		Browser:    silentBrowser{},
		Listen:     net.Listen,
		UI:         fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>fixture</title><div id=\"root\"></div>")}},
		Logger:     slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Runner:     runner,
		Toolchain:  fixedToolchain{},
		Terminal:   terminal,
		KeyAgent:   fakeAgent{},
		SessionNow: clock.now,
	}, "acceptance")
	if err != nil {
		t.Fatalf("app.Build() = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve() = %v", err)
		}
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t:        t,
		home:     home,
		root:     root,
		baseURL:  server.URL(),
		host:     strings.TrimPrefix(server.URL(), "http://"),
		client:   &http.Client{Jar: jar, Timeout: 15 * time.Second},
		server:   server,
		runner:   runner,
		terminal: terminal,
		clock:    clock,
		logs:     logs,
		canaries: fixtureCanaries{
			Outside:        strings.TrimSpace(canaryOutsideContents),
			Passphrase:     canaryPassphrase,
			PrivateKeyLine: fixturePrivateKeySecondLine(t, root),
			Bootstrap:      bootstrap,
		},
	}
	f.bootstrapSession(bootstrap)
	return f
}

// writeFixtureTree lays out a realistic but entirely synthetic ~/.ssh, plus one
// file outside it that no route may ever reach.
func writeFixtureTree(t testing.TB, home, root string) {
	t.Helper()
	mustMkdir(t, root, 0o700)
	mustMkdir(t, filepath.Join(root, "conf.d"), 0o700)
	mustMkdir(t, filepath.Join(home, "private-notes"), 0o700)

	mustWrite(t, filepath.Join(home, "private-notes", "canary.txt"), []byte(canaryOutsideContents), 0o600)
	mustWrite(t, filepath.Join(root, "config"), []byte(""+
		"# Managed by hand since 2019. Do not reformat.\n"+
		"\n"+
		"Include conf.d/*.conf\n"+
		"\n"+
		"Host bastion\n"+
		"\tHostName=203.0.113.10\n"+
		"\tUser    ops\n"+
		"\tPort 2222\n"+
		"\tIdentityFile ~/.ssh/id_ed25519\n"+
		"\n"+
		"Host *\n"+
		"\tServerAliveInterval 30\n"), 0o600)
	mustWrite(t, filepath.Join(root, "conf.d", "10-home.conf"), []byte(""+
		"Host nas\n"+
		"\tHostName 198.51.100.20\n"+
		"\tUnknownFutureDirective some \"quoted value\" 3\n"), 0o600)
	mustWrite(t, filepath.Join(root, "known_hosts"), []byte(""+
		"# a comment the reader must keep\n"+
		"203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture\n"), 0o600)

	privateKey, err := keys.GeneratePrivateKey(keys.AlgorithmEd25519, 0, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := keys.EncodePrivateKey(privateKey, "fixture@ssh-ui", []byte(canaryPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	public, err := keys.EncodePublicKey(privateKey, "fixture@ssh-ui")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "id_ed25519"), encoded, 0o600)
	mustWrite(t, filepath.Join(root, "id_ed25519.pub"), public, 0o644)
}

func mustMkdir(t testing.TB, path string, permission os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, permission); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t testing.TB, path string, contents []byte, permission os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, permission); err != nil {
		t.Fatal(err)
	}
}

// fixturePrivateKeySecondLine returns a long base64 line from inside the
// encrypted private key. It is the needle that proves key material stayed in
// the one response that is allowed to carry it.
func fixturePrivateKeySecondLine(t testing.TB, root string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(root, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) < 3 {
		t.Fatalf("fixture private key has %d lines", len(lines))
	}
	return lines[1]
}

func (f *fixture) bootstrapSession(bootstrap string) {
	f.t.Helper()
	response := f.do(http.MethodPost, "/api/v1/session/bootstrap", nil, func(request *http.Request) {
		request.Header.Set("X-SSH-UI-Bootstrap", bootstrap)
	})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		f.t.Fatalf("bootstrap = %d", response.StatusCode)
	}
	var payload struct {
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		f.t.Fatal(err)
	}
	f.canaries.CSRF = payload.CsrfToken
	for _, cookie := range response.Cookies() {
		if cookie.Name == httpserver.SessionCookie {
			f.sessionID = cookie.Value
			f.canaries.SessionID = cookie.Value
		}
	}
	if f.sessionID == "" {
		f.t.Fatal("bootstrap returned no session cookie")
	}
}

// do issues one request with correct Host, Origin and Fetch Metadata headers.
// Adjust is applied last, so a test can make exactly one of them wrong.
func (f *fixture) do(method, path string, body []byte, adjust ...func(*http.Request)) *http.Response {
	f.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, f.baseURL+path, reader)
	if err != nil {
		f.t.Fatal(err)
	}
	request.Host = f.host
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", f.baseURL)
		request.Header.Set(httpserver.CSRFHeader, f.canaries.CSRF)
		request.Header.Set("Content-Type", "application/json")
	}
	for _, apply := range adjust {
		apply(request)
	}
	response, err := f.client.Do(request)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	return response
}

// readBody drains and closes a response, returning its body as text.
func readBody(t testing.TB, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// apiRoutes returns every registered route under /api/, with the static
// catch-all removed.
func (f *fixture) apiRoutes() []httpserver.Route {
	var routes []httpserver.Route
	for _, route := range f.server.Routes() {
		if strings.HasPrefix(route.Path, "/api/") {
			routes = append(routes, route)
		}
	}
	if len(routes) == 0 {
		f.t.Fatal("the server registered no API route; the harness is not wiring the services")
	}
	return routes
}

// concretePath substitutes a usable value for each Echo path parameter, so a
// route such as /api/v1/keys/:keyId can be requested by the generic sweeps.
func (f *fixture) concretePath(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if !strings.HasPrefix(segment, ":") {
			continue
		}
		switch segment {
		case ":keyId":
			segments[index] = f.keyID()
		default:
			segments[index] = "acceptance-placeholder"
		}
	}
	return strings.Join(segments, "/")
}

// keyID reads the inventory once and returns the identifier of the fixture
// private key.
func (f *fixture) keyID() string {
	f.t.Helper()
	response := f.do(http.MethodGet, "/api/v1/keys", nil)
	body := readBody(f.t, response)
	var payload struct {
		Items []struct {
			ID           string `json:"id"`
			RelativePath string `json:"relativePath"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		f.t.Fatalf("inventory did not decode: %v", err)
	}
	for _, item := range payload.Items {
		if item.RelativePath == "id_ed25519" {
			return item.ID
		}
	}
	f.t.Fatal("the fixture private key is not in the inventory")
	return ""
}

func (f *fixture) logText() string { return f.logs.String() }

func (f *fixture) read(relative string) []byte {
	f.t.Helper()
	contents, err := os.ReadFile(filepath.Join(f.root, relative))
	if err != nil {
		f.t.Fatal(err)
	}
	return contents
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

var _ = fmt.Sprintf
```

- [ ] **Step 15: Run the harness against nothing, to prove it starts**

Add a smoke test at the bottom of `internal/acceptance/harness_test.go`:

```go
func TestHarnessStartsTheProductionServerAgainstAnIsolatedHome(t *testing.T) {
	f := newFixture(t)
	response := f.do(http.MethodGet, "/api/v1/health", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", response.StatusCode)
	}
	readBody(t, response)
	if len(f.apiRoutes()) < 2 {
		t.Fatalf("routes = %#v", f.apiRoutes())
	}
	if _, err := os.Stat(filepath.Join(f.home, ".ssh", "config")); err != nil {
		t.Fatalf("fixture config missing: %v", err)
	}
}
```

Run: `go test ./internal/acceptance -run TestHarnessStartsTheProductionServerAgainstAnIsolatedHome -v`
Expected: PASS.

- [ ] **Step 16: Write the transport suite**

Create `internal/acceptance/transport_test.go`:

```go
package acceptance_test

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/session"
)

// expectedContentSecurityPolicy is asserted by exact match on purpose. Widening
// the policy must be a deliberate edit here as well as in the server, so a
// stray 'unsafe-inline' cannot arrive unnoticed.
const expectedContentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; " +
	"frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'"

func TestEveryAPIRouteRefusesTheWrongHostOriginAndFetchSite(t *testing.T) {
	f := newFixture(t)
	for _, route := range f.apiRoutes() {
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			baseline := f.do(route.Method, path, emptyBodyFor(route.Method))
			baselineStatus := baseline.StatusCode
			readBody(t, baseline)
			if baselineStatus == http.StatusForbidden {
				t.Fatalf("the correct request was already refused with %d; the hostile cases below would prove nothing", baselineStatus)
			}

			hostile := []struct {
				name   string
				adjust func(*http.Request)
			}{
				{"host is a name", func(r *http.Request) { r.Host = "localhost" + portOf(f.host) }},
				{"host has no port", func(r *http.Request) { r.Host = "127.0.0.1" }},
				{"host is another address", func(r *http.Request) { r.Host = "192.168.1.10" + portOf(f.host) }},
				{"fetch site is cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
				{"fetch site is same-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
				{"fetch site is absent", func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }},
			}
			if route.Method != http.MethodGet && route.Method != http.MethodHead {
				hostile = append(hostile,
					struct {
						name   string
						adjust func(*http.Request)
					}{"origin is another site", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
					struct {
						name   string
						adjust func(*http.Request)
					}{"origin is absent", func(r *http.Request) { r.Header.Del("Origin") }},
				)
			}

			for _, test := range hostile {
				t.Run(test.name, func(t *testing.T) {
					response := f.do(route.Method, path, emptyBodyFor(route.Method), test.adjust)
					status := response.StatusCode
					body := readBody(t, response)
					if status != http.StatusForbidden {
						t.Fatalf("status = %d, want %d", status, http.StatusForbidden)
					}
					if !strings.Contains(body, "invalid_host") && !strings.Contains(body, "cross_site_request") {
						t.Fatalf("body = %q, want a transport problem code", body)
					}
				})
			}
		})
	}
}

func TestEveryAPIRouteExceptBootstrapRequiresASession(t *testing.T) {
	f := newFixture(t)
	for _, route := range f.apiRoutes() {
		if route.Path == "/api/v1/session/bootstrap" {
			continue
		}
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			response := f.do(route.Method, path, emptyBodyFor(route.Method), func(request *http.Request) {
				// The jar attaches the session cookie automatically, so it is
				// removed after the client has built the request.
				request.Header.Del("Cookie")
			})
			status := response.StatusCode
			body := readBody(t, response)
			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
			}
			if !strings.Contains(body, "session_required") && !strings.Contains(body, "invalid_session") {
				t.Fatalf("body = %q", body)
			}
		})
	}
}

func TestEveryAPIResponseIsNoStoreAndCarriesTheExactPolicy(t *testing.T) {
	f := newFixture(t)
	for _, route := range f.apiRoutes() {
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			for _, authenticated := range []bool{true, false} {
				adjust := func(*http.Request) {}
				if !authenticated {
					adjust = func(request *http.Request) { request.Header.Del("Cookie") }
				}
				response := f.do(route.Method, path, emptyBodyFor(route.Method), adjust)
				cache := response.Header.Get("Cache-Control")
				policy := response.Header.Get("Content-Security-Policy")
				readBody(t, response)
				if cache != "no-store" {
					t.Errorf("authenticated=%v Cache-Control = %q, want no-store", authenticated, cache)
				}
				if policy != expectedContentSecurityPolicy {
					t.Errorf("authenticated=%v CSP = %q, want %q", authenticated, policy, expectedContentSecurityPolicy)
				}
			}
		})
	}

	navigation := f.do(http.MethodGet, "/", nil)
	policy := navigation.Header.Get("Content-Security-Policy")
	readBody(t, navigation)
	if policy != expectedContentSecurityPolicy {
		t.Fatalf("navigation CSP = %q", policy)
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "*"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("CSP contains %q", forbidden)
		}
	}
	for _, required := range []string{"default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(policy, required) {
			t.Errorf("CSP is missing %q", required)
		}
	}
}

func TestBootstrapTokenIsSingleUse(t *testing.T) {
	f := newFixture(t)
	response := f.do(http.MethodPost, "/api/v1/session/bootstrap", nil, func(request *http.Request) {
		request.Header.Set("X-SSH-UI-Bootstrap", f.canaries.Bootstrap)
	})
	status := response.StatusCode
	cookies := response.Cookies()
	body := readBody(t, response)
	if status != http.StatusConflict {
		t.Fatalf("replay = %d, want %d", status, http.StatusConflict)
	}
	if len(cookies) != 0 {
		t.Fatalf("replay set %d cookies", len(cookies))
	}
	if !strings.Contains(body, "bootstrap_used") {
		t.Fatalf("body = %q", body)
	}
}

func TestServerRefusesEveryListenerThatIsNotUnmappedLoopbackIPv4(t *testing.T) {
	manager, _, err := session.NewManager(strings.NewReader(strings.Repeat("k", 512)))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		address net.Addr
		wantErr bool
	}{
		{"unmapped loopback", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 51234}, false},
		{"mapped loopback", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51234}, true},
		{"wildcard", &net.TCPAddr{IP: net.IPv4zero.To4(), Port: 51234}, true},
		{"ipv6 loopback", &net.TCPAddr{IP: net.IPv6loopback, Port: 51234}, true},
		{"private address", &net.TCPAddr{IP: net.ParseIP("192.168.1.10").To4(), Port: 51234}, true},
		{"public address", &net.TCPAddr{IP: net.ParseIP("203.0.113.10").To4(), Port: 51234}, true},
		{"unix socket", &net.UnixAddr{Name: "/tmp/ssh-ui.sock", Net: "unix"}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := httpserver.New(httpserver.Options{
				Listener: stubListener{address: test.address},
				Sessions: manager,
				Version:  "listener-policy",
			})
			if test.wantErr && err == nil {
				t.Fatalf("New() accepted %v", test.address)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("New() = %v, want nil", err)
			}
		})
	}

	if _, err := httpserver.New(httpserver.Options{Sessions: manager}); err == nil {
		t.Fatal("New() accepted a nil listener")
	}
}

type stubListener struct{ address net.Addr }

func (stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (stubListener) Close() error              { return nil }
func (l stubListener) Addr() net.Addr          { return l.address }

func TestRouteTableMatchesTheOpenAPIContract(t *testing.T) {
	f := newFixture(t)

	contents, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}

	declared := map[string]bool{}
	for path, operations := range document.Paths {
		for method := range operations {
			switch strings.ToUpper(method) {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				declared[strings.ToUpper(method)+" "+echoPath(path)] = true
			}
		}
	}

	registered := map[string]bool{}
	for _, route := range f.apiRoutes() {
		registered[route.Method+" "+route.Path] = true
	}

	for key := range declared {
		if !registered[key] {
			t.Errorf("api/openapi.yaml declares %q but the server registers no such route", key)
		}
	}
	for key := range registered {
		if !declared[key] {
			t.Errorf("the server registers %q but api/openapi.yaml declares no such operation", key)
		}
	}
}

// echoPath converts an OpenAPI path template into Echo's parameter spelling.
func echoPath(path string) string {
	replaced := strings.ReplaceAll(path, "{", ":")
	return strings.ReplaceAll(replaced, "}", "")
}

func emptyBodyFor(method string) []byte {
	if method == http.MethodGet || method == http.MethodHead {
		return nil
	}
	return []byte("{}")
}

func portOf(hostPort string) string {
	index := strings.LastIndex(hostPort, ":")
	if index < 0 {
		return ""
	}
	return hostPort[index:]
}
```

- [ ] **Step 17: Promote `gopkg.in/yaml.v3` and run the suite**

```bash
go get gopkg.in/yaml.v3@v3.0.1
go mod tidy
git diff go.sum
```

Expected: `go.mod` moves `gopkg.in/yaml.v3 v3.0.1` from the indirect block into the direct require block; `go.sum` shows no change, because the module was already required transitively by `kin-openapi`.

Run: `go test ./internal/acceptance`
Expected: PASS.

- [ ] **Step 18: Prove the suite has teeth**

Perform each mutation, run the named test, confirm it fails, then restore with `git checkout -- <file>`:

| Mutation | File | Test that must fail |
|---|---|---|
| Delete the `Sec-Fetch-Site` check | `internal/httpserver/security.go` | `TestEveryAPIRouteRefusesTheWrongHostOriginAndFetchSite/.../fetch site is cross-site` |
| Change `request.Host != s.ExpectedHost` to `!strings.HasPrefix(request.Host, "127.")` | `internal/httpserver/security.go` | the `host is a name` subtest |
| Remove `header.Set("Cache-Control", "no-store")` | `internal/httpserver/security.go` | `TestEveryAPIResponseIsNoStoreAndCarriesTheExactPolicy` |
| Append `'unsafe-inline'` to `script-src` | `internal/httpserver/security.go` | the same test |
| Return `nil` instead of `ErrNonLoopbackListener` for a non-IPv4 address | `internal/httpserver/server.go` | `TestServerRefusesEveryListenerThatIsNotUnmappedLoopbackIPv4` |
| Delete the `m.bootstrapUsed` guard | `internal/session/manager.go` | `TestBootstrapTokenIsSingleUse` |

Record the six failures in the commit message body.

- [ ] **Step 19: Commit**

```bash
git add go.mod internal/acceptance/harness_test.go internal/acceptance/transport_test.go
git commit -m "test: drive the transport security policy against the real route table"
```

---

## Task 2: Bounded requests and bounded command output

**Files:**
- Create: `internal/acceptance/limits_test.go`
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 1's `newFixture`, `(*fixture).do`, `(*fixture).apiRoutes`, `(*fixture).concretePath`, `(*fixture).runner`, `readBody`, `emptyBodyFor`; `httpserver.MaxRequestBodyCeiling`; `platform.MaxCapturedOutput`; `platform.Output`; `diagnostics.MaxReportedOutput`; `effective.ErrOutputTruncated`.
- Produces: `maxAcceptableResponseBytes = 4 << 20` and `bodyOfSize`, used by Tasks 3 and 5.

Design §8.1 says request bodies and command output both have ceilings. The earlier plans set per-handler limits (2 MiB for config edits, 64 KiB for key and diagnostics bodies) and a 64 KiB capture limit in the process adapter, and each tests its own. Nothing tests the two properties that matter across the whole surface: **no route reads an unbounded body**, and **a truncated command result is never served as if it were complete**.

**Teeth:** the body test drives every registered route, including ones added after this plan, and the positive control proves a normal-sized body still succeeds. The output test asserts the fabricated value from a truncated transcript never appears in a response, which fails immediately if `ErrOutputTruncated` is downgraded to a warning.

- [ ] **Step 1: Write the failing oversized-body test**

Create `internal/acceptance/limits_test.go`:

```go
package acceptance_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/platform"
)

// maxAcceptableResponseBytes bounds what any single response may be. Nothing in
// this application has a legitimate reason to return more.
const maxAcceptableResponseBytes = 4 << 20

// bodyOfSize builds a syntactically valid JSON object of roughly size bytes.
func bodyOfSize(size int) []byte {
	if size < 16 {
		size = 16
	}
	var builder bytes.Buffer
	builder.WriteString(`{"base":"`)
	builder.Write(bytes.Repeat([]byte("a"), size-len(`{"base":""}`)))
	builder.WriteString(`"}`)
	return builder.Bytes()
}

func TestNoAPIRouteReadsAnUnboundedBody(t *testing.T) {
	f := newFixture(t)
	oversized := bodyOfSize(httpserver.MaxRequestBodyCeiling + (1 << 20))

	for _, route := range f.apiRoutes() {
		if route.Method == http.MethodGet || route.Method == http.MethodHead {
			continue
		}
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			f.runner.reset()
			before := f.read("config")

			response := f.do(route.Method, path, oversized)
			status := response.StatusCode
			body := readBody(t, response)

			if status < 400 || status >= 500 {
				t.Fatalf("status = %d, want a 4xx refusal", status)
			}
			if len(body) > maxAcceptableResponseBytes {
				t.Fatalf("refusal body = %d bytes", len(body))
			}
			if strings.Contains(body, strings.Repeat("a", 256)) {
				t.Fatal("the refusal echoed the oversized body back")
			}
			if commands := f.runner.recorded(); len(commands) != 0 {
				t.Fatalf("an oversized body still started %d command(s)", len(commands))
			}
			if !bytes.Equal(before, f.read("config")) {
				t.Fatal("an oversized body changed a configuration file")
			}
		})
	}

	// Positive control: the server is still healthy, and an ordinary body is
	// still accepted, so the refusals above are the limit doing its job rather
	// than a server that stopped answering.
	health := f.do(http.MethodGet, "/api/v1/health", nil)
	healthStatus := health.StatusCode
	readBody(t, health)
	if healthStatus != http.StatusOK {
		t.Fatalf("health after the oversized sweep = %d", healthStatus)
	}
	ordinary := f.do(http.MethodPost, "/api/v1/config/preview", mustJSON(t, map[string]any{
		"kind":  "host_fields",
		"path":  "config",
		"alias": "bastion",
		"base":  string(f.read("config")),
		"fields": []map[string]any{
			{"action": "set", "keyword": "Port", "values": []string{"2244"}, "line": 0},
		},
	}))
	ordinaryStatus := ordinary.StatusCode
	readBody(t, ordinary)
	if ordinaryStatus != http.StatusOK {
		t.Fatalf("an ordinary preview = %d, want 200; the ceiling is rejecting legitimate work", ordinaryStatus)
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/acceptance -run TestNoAPIRouteReadsAnUnboundedBody -v`
Expected: PASS, because Task 1 added `MaxRequestBodyCeiling` to the middleware. If any route fails, the route reads its body before the middleware wraps it, or streams it — fix the route, not the test.

- [ ] **Step 3: Write the failing truncated-output test**

Append to `internal/acceptance/limits_test.go`:

```go
// fabricatedHostname is placed only in the part of a synthetic `ssh -G`
// transcript that would be lost to truncation. A response that shows it has
// treated a truncated transcript as a complete answer.
const fabricatedHostname = "truncated-transcript-must-not-be-parsed.invalid"

func TestTruncatedCommandOutputIsRefusedRatherThanParsed(t *testing.T) {
	f := newFixture(t)

	transcript := []byte("hostname " + fabricatedHostname + "\nuser ops\nport 2222\n")
	transcript = append(transcript, bytes.Repeat([]byte("identityfile /padding\n"), 4096)...)
	f.runner.answer(func(command platform.Command) (platform.Output, error) {
		return platform.Output{
			Stdout:    transcript[:platform.MaxCapturedOutput],
			Truncated: true,
		}, nil
	})

	token := f.actionToken(t, "diagnostics.evaluate", "bastion")
	response := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias":       "bastion",
		"actionToken": token,
	}))
	body := readBody(t, response)

	if strings.Contains(body, fabricatedHostname) {
		t.Fatal("a truncated ssh -G transcript was parsed and served as an effective value")
	}
	if len(body) > maxAcceptableResponseBytes {
		t.Fatalf("response = %d bytes", len(body))
	}
}

func TestReportedCommandOutputStaysWithinItsPublishedCeiling(t *testing.T) {
	f := newFixture(t)

	f.runner.answer(func(command platform.Command) (platform.Output, error) {
		return platform.Output{
			Stderr:    bytes.Repeat([]byte("noisy stderr line\n"), 64<<10),
			ExitCode:  255,
			Truncated: true,
		}, nil
	})

	token := f.actionToken(t, "diagnostics.authentication", "bastion")
	response := f.do(http.MethodPost, "/api/v1/diagnostics/authentication", mustJSON(t, map[string]any{
		"alias":        "bastion",
		"actionToken":  token,
		"acknowledged": true,
	}))
	body := readBody(t, response)

	if strings.Count(body, "noisy stderr line") > 1024 {
		t.Fatalf("the response relayed %d stderr lines; the ceiling is not applied", strings.Count(body, "noisy stderr line"))
	}
	if len(body) > maxAcceptableResponseBytes {
		t.Fatalf("response = %d bytes", len(body))
	}
}
```

- [ ] **Step 4: Add the action-token helper the two tests need**

Append to `internal/acceptance/harness_test.go`:

```go
// actionToken asks the running server for one confirmation token, exactly as
// the frontend does. The route and header spellings differ between the
// diagnostics surface, which takes the token in the request body, and the key
// vault surface, which takes it in X-SSH-UI-Action; both are issued here.
func (f *fixture) actionToken(t testing.TB, kind, target string) string {
	t.Helper()
	for _, path := range []string{"/api/v1/actions/token", "/api/v1/actions"} {
		response := f.do(http.MethodPost, path, mustJSON(t, map[string]any{
			"kind":    kind,
			"target":  target,
			"purpose": kind,
			"subject": target,
		}))
		status := response.StatusCode
		body := readBody(t, response)
		if status != http.StatusOK && status != http.StatusCreated {
			continue
		}
		var payload struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err == nil && payload.Token != "" {
			return payload.Token
		}
	}
	t.Fatalf("no action-token endpoint issued a %q token for %q", kind, target)
	return ""
}
```

The helper tries both spellings on purpose: subsystem 5 registers `POST /api/v1/actions/token` and subsystem 4 registers `POST /api/v1/actions`. Whichever the merged tree kept, the helper finds it, and if neither exists the test fails loudly instead of silently skipping the token cases.

- [ ] **Step 5: Run the output tests**

Run: `go test ./internal/acceptance -run 'TestTruncatedCommandOutputIsRefusedRatherThanParsed|TestReportedCommandOutputStaysWithinItsPublishedCeiling' -v`
Expected: PASS.

- [ ] **Step 6: Prove the tests have teeth**

| Mutation | File | Test that must fail |
|---|---|---|
| Delete the `request.Body = http.MaxBytesReader(...)` line | `internal/httpserver/security.go` | `TestNoAPIRouteReadsAnUnboundedBody` on any route without its own limit |
| Change `if output.Truncated { return Values{}, ErrOutputTruncated }` to a no-op | `internal/effective/evaluate.go` | `TestTruncatedCommandOutputIsRefusedRatherThanParsed` |
| Raise `MaxReportedOutput` to `1 << 30` | `internal/diagnostics/authentication.go` | `TestReportedCommandOutputStaysWithinItsPublishedCeiling` |

Run each, confirm FAIL, then `git checkout -- <file>`.

- [ ] **Step 7: Document the ceilings in the README**

Append to `README.md`, after the Connections UI section:

```markdown
## 強化とリリースの境界

- リクエスト本文には二段の上限があります。middleware の `MaxRequestBodyCeiling`（2 MiB）が全 `/api/` 要求の天井で、各ハンドラーはさらに小さい上限を持ちます。天井は、後から追加されたルートが上限の設定を忘れても無制限に読み込めないようにするためのものです。
- 外部コマンドの出力は `platform.MaxCapturedOutput`（64 KiB）で打ち切られます。打ち切られた `ssh -G` 出力は解析せず、部分的な実効値として返しません。認証テストの stderr は `MaxReportedOutput`（8 KiB）までに制限して表示します。
```

- [ ] **Step 8: Commit**

```bash
go test ./internal/acceptance
git add internal/acceptance/limits_test.go internal/acceptance/harness_test.go README.md
git commit -m "test: bound every API request body and refuse truncated command output"
```

---

## Task 3: Action-token discipline and the secret leak sweep

**Files:**
- Create: `internal/acceptance/leak_test.go`

**Interfaces:**
- Consumes: Task 1's fixture and canaries, Task 2's `actionToken` and `maxAcceptableResponseBytes`; `session.ActionTokenTTL`, `session.ActionEvaluate`, `session.ActionReachability`, `session.ActionAuthentication`, `session.ActionTerminalLaunch`, `session.ActionKnownHostsDelete`, `session.ActionKnownHostsScan`, `session.ActionKnownHostsAdd`, `session.ActionRemoteKeyRegister`, `session.ActionRevealPrivateKey`, `session.ActionPurgeTrashEntry`.
- Produces: `guardedRoutes` and `routeProbe`, reused by Task 5's HTTP fuzz target.

Subsystems 4 and 5 each test their own handler's token. Neither answers the two cross-cutting questions: **is every route that starts a process or leaves the machine actually guarded**, and **does an expired token still work**. Neither plan has a single test that reads the log stream, which subsystem 4's own gate lists as a constraint with no test behind it.

**Teeth:** the guarded-route table is asserted against the router, so a token-guarded operation added later without a table row fails the suite. The leak sweep's allowlist is the assertion — a route that returns key material without being named in the allowlist fails, and a route named in the allowlist that no longer returns it also fails, so the allowlist cannot rot into a blanket exemption.

- [ ] **Step 1: Write the failing token-discipline test**

Create `internal/acceptance/leak_test.go`:

```go
package acceptance_test

import (
	"net/http"
	"strings"
	"testing"

	"ssh-ui/internal/session"
)

// tokenDelivery says where a route expects its one-time confirmation.
type tokenDelivery int

const (
	tokenInBody tokenDelivery = iota
	tokenInHeader
)

// guardedRoute is one operation that starts a process, changes a file outside
// the ordinary edit path, or hands out key material.
type guardedRoute struct {
	Method   string
	Path     string
	Kind     string
	Target   string
	Delivery tokenDelivery
	Body     map[string]any
}

func guardedRoutes(f *fixture) []guardedRoute {
	keyID := f.keyID()
	return []guardedRoute{
		{http.MethodPost, "/api/v1/diagnostics/effective", session.ActionEvaluate, "bastion", tokenInBody,
			map[string]any{"alias": "bastion"}},
		{http.MethodPost, "/api/v1/diagnostics/reachability", session.ActionReachability, "bastion", tokenInBody,
			map[string]any{"alias": "bastion"}},
		{http.MethodPost, "/api/v1/diagnostics/authentication", session.ActionAuthentication, "bastion", tokenInBody,
			map[string]any{"alias": "bastion", "acknowledged": true}},
		{http.MethodPost, "/api/v1/terminal/launch", session.ActionTerminalLaunch, "bastion", tokenInBody,
			map[string]any{"alias": "bastion"}},
		{http.MethodPost, "/api/v1/known-hosts/delete", session.ActionKnownHostsDelete, "known_hosts", tokenInBody,
			map[string]any{"targets": []map[string]any{{"line": 2, "digest": strings.Repeat("0", 64)}}}},
		{http.MethodPost, "/api/v1/known-hosts/scan", session.ActionKnownHostsScan, "203.0.113.10", tokenInBody,
			map[string]any{"host": "203.0.113.10", "port": 22}},
		{http.MethodPost, "/api/v1/known-hosts/add", session.ActionKnownHostsAdd, "203.0.113.10", tokenInBody,
			map[string]any{"candidate": map[string]any{"host": "203.0.113.10", "port": 22, "keyType": "ssh-ed25519", "key": "AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl", "fingerprint": "SHA256:unverified", "verified": false}, "acknowledged": true}},
		{http.MethodPost, "/api/v1/remote-keys/register", session.ActionRemoteKeyRegister, "bastion", tokenInBody,
			map[string]any{"alias": "bastion", "keyPath": "id_ed25519.pub", "acknowledged": true}},
		{http.MethodPost, "/api/v1/keys/" + keyID + "/reveal", session.ActionRevealPrivateKey, keyID, tokenInHeader, nil},
		{http.MethodDelete, "/api/v1/trash/acceptance-placeholder", session.ActionPurgeTrashEntry, "acceptance-placeholder", tokenInHeader, nil},
	}
}

// send issues one guarded request with the token delivered the way the route
// expects, or with no token when presented is empty.
func (f *fixture) sendGuarded(t testing.TB, route guardedRoute, presented string) *http.Response {
	t.Helper()
	var body []byte
	if route.Body != nil || route.Delivery == tokenInBody {
		payload := map[string]any{}
		for key, value := range route.Body {
			payload[key] = value
		}
		if route.Delivery == tokenInBody {
			payload["actionToken"] = presented
		}
		body = mustJSON(t, payload)
	}
	return f.do(route.Method, route.Path, body, func(request *http.Request) {
		if route.Delivery == tokenInHeader && presented != "" {
			request.Header.Set("X-SSH-UI-Action", presented)
		}
	})
}

func TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken(t *testing.T) {
	f := newFixture(t)
	routes := guardedRoutes(f)

	for _, route := range routes {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			// Positive control first: a correct token must reach the operation,
			// otherwise every refusal below proves nothing.
			f.runner.reset()
			valid := f.actionToken(t, route.Kind, route.Target)
			accepted := f.sendGuarded(t, route, valid)
			acceptedStatus := accepted.StatusCode
			acceptedBody := readBody(t, accepted)
			if acceptedStatus == http.StatusForbidden && strings.Contains(acceptedBody, "action") {
				t.Fatalf("a freshly issued token was refused: %d %s", acceptedStatus, acceptedBody)
			}

			refusals := []struct {
				name  string
				token func() string
			}{
				{"no token", func() string { return "" }},
				{"token from another kind", func() string {
					return f.actionToken(t, session.ActionReachability, route.Target)
				}},
				{"token for another target", func() string {
					return f.actionToken(t, route.Kind, "some-other-target")
				}},
				{"token already spent", func() string {
					spent := f.actionToken(t, route.Kind, route.Target)
					readBody(t, f.sendGuarded(t, route, spent))
					return spent
				}},
				{"token past its lifetime", func() string {
					aged := f.actionToken(t, route.Kind, route.Target)
					f.clock.advance(session.ActionTokenTTL + time.Minute)
					return aged
				}},
				{"token invented by the caller", func() string { return strings.Repeat("A", 43) }},
			}

			for _, refusal := range refusals {
				t.Run(refusal.name, func(t *testing.T) {
					f.runner.reset()
					before := f.read("known_hosts")

					response := f.sendGuarded(t, route, refusal.token())
					status := response.StatusCode
					body := readBody(t, response)

					if status < 400 || status >= 500 {
						t.Fatalf("status = %d, want a 4xx refusal", status)
					}
					if commands := f.runner.recorded(); len(commands) != 0 {
						t.Fatalf("the refused request still started %d command(s): %#v", len(commands), commands)
					}
					if launched := f.terminal.launched(); len(launched) != 0 {
						t.Fatalf("the refused request still launched Terminal for %#v", launched)
					}
					if !bytes.Equal(before, f.read("known_hosts")) {
						t.Fatal("the refused request still changed known_hosts")
					}
					if strings.Contains(body, f.canaries.PrivateKeyLine) {
						t.Fatal("the refused request still returned key material")
					}
				})
			}
		})
	}

	// The table must keep up with the router. Every route whose Echo path names
	// one of the token-guarded operations has to appear above.
	tabled := map[string]bool{}
	for _, route := range routes {
		tabled[route.Method+" "+route.Path] = true
	}
	for _, route := range f.apiRoutes() {
		concrete := route.Method + " " + f.concretePath(route.Path)
		if !requiresConfirmation(route.Path) || tabled[concrete] {
			continue
		}
		t.Errorf("route %s is a confirmation-guarded operation with no row in guardedRoutes", concrete)
	}
}

// requiresConfirmation names the route families design §8.2 puts behind an
// action token: anything that evaluates or connects, launches Terminal, edits
// known_hosts, registers a key on a remote host, reveals a private key or
// permanently deletes one.
func requiresConfirmation(path string) bool {
	switch {
	case strings.HasPrefix(path, "/api/v1/diagnostics/") && path != "/api/v1/diagnostics/config":
		return true
	case path == "/api/v1/terminal/launch":
		return true
	case strings.HasPrefix(path, "/api/v1/known-hosts/"):
		return true
	case path == "/api/v1/remote-keys/register":
		return true
	case strings.HasSuffix(path, "/reveal"):
		return true
	case strings.HasPrefix(path, "/api/v1/trash/") && !strings.HasSuffix(path, "/restore"):
		return true
	default:
		return false
	}
}
```

Add `"bytes"` and `"time"` to the file's import block.

- [ ] **Step 2: Run it**

Run: `go test ./internal/acceptance -run TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken -v`
Expected: PASS. A failure on a specific row means either the route spells its request differently in the merged tree — fix the row — or the route genuinely accepts a bad token, which is the bug this suite exists to find.

- [ ] **Step 3: Write the failing leak sweep**

Append to `internal/acceptance/leak_test.go`:

```go
// contentBearingRoutes are the only responses allowed to contain material a
// user would recognise as the contents of a file. Each entry states why.
//
// This map is the assertion, not a convenience: a route that leaks without a
// row here fails, and a row whose route stops leaking also fails, so the
// allowlist cannot quietly widen into a blanket exemption.
var contentBearingRoutes = map[string]string{
	"GET /api/v1/config/file":       "the raw editor is the feature; it returns the file the user asked to edit",
	"GET /api/v1/config/host":       "the block editor returns the raw text of the block the user opened",
	"POST /api/v1/config/preview":   "a save preview is a diff of configuration text",
	"POST /api/v1/config/save":      "a save result reports the diff it wrote",
	"POST /api/v1/history/restore":  "a restore reports the diff it wrote",
}

// keyMaterialRoutes are the only responses allowed to contain private key
// bytes. Design §6.3 separates this from every other API on purpose.
var keyMaterialRoutes = map[string]string{
	"POST /api/v1/keys/:keyId/reveal": "the separated reveal API, behind a one-time action token",
}

func TestNoResponseCarriesASecretItIsNotEntitledTo(t *testing.T) {
	f := newFixture(t)

	type observation struct {
		key  string
		body string
	}
	var observed []observation

	record := func(method, path string, body []byte, adjust ...func(*http.Request)) {
		response := f.do(method, path, body, adjust...)
		text := readBody(t, response)
		if len(text) > maxAcceptableResponseBytes {
			t.Fatalf("%s %s returned %d bytes", method, path, len(text))
		}
		observed = append(observed, observation{key: method + " " + path, body: text})
	}

	// Phase one: touch every registered route, so a route added later is swept
	// even if nobody wrote a meaningful request for it. A 400 answer is fine
	// here; the assertion is about what leaks, not about what succeeds.
	for _, route := range f.apiRoutes() {
		if route.Path == "/api/v1/session/bootstrap" {
			continue
		}
		record(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method))
	}

	// Phase two: drive the read paths to a real 200, so the sweep looks at
	// populated bodies rather than at problem documents.
	record(http.MethodGet, "/api/v1/config/overview", nil)
	record(http.MethodGet, "/api/v1/config/file?path=config", nil)
	record(http.MethodGet, "/api/v1/config/host?path=config&alias=bastion", nil)
	record(http.MethodGet, "/api/v1/metadata", nil)
	record(http.MethodGet, "/api/v1/history", nil)
	record(http.MethodGet, "/api/v1/keys", nil)
	record(http.MethodGet, "/api/v1/trash", nil)
	record(http.MethodGet, "/api/v1/known-hosts?query=203", nil)

	keyID := f.keyID()
	revealToken := f.actionToken(t, session.ActionRevealPrivateKey, keyID)
	record(http.MethodPost, "/api/v1/keys/"+keyID+"/reveal", nil, func(request *http.Request) {
		request.Header.Set("X-SSH-UI-Action", revealToken)
	})

	sawFileContents := map[string]bool{}
	sawKeyMaterial := map[string]bool{}
	for _, entry := range observed {
		normalised := normaliseObservationKey(entry.key, keyID)

		// Never, anywhere, under any circumstance.
		for name, secret := range map[string]string{
			"a file outside ~/.ssh": f.canaries.Outside,
			"the key passphrase":    f.canaries.Passphrase,
			"the bootstrap token":   f.canaries.Bootstrap,
			"the session id":        f.canaries.SessionID,
		} {
			if secret != "" && strings.Contains(entry.body, secret) {
				t.Errorf("%s leaked %s", entry.key, name)
			}
		}

		if strings.Contains(entry.body, f.canaries.PrivateKeyLine) {
			sawKeyMaterial[normalised] = true
			if _, allowed := keyMaterialRoutes[normalised]; !allowed {
				t.Errorf("%s returned private key material and is not the separated reveal API", entry.key)
			}
		}
		if strings.Contains(entry.body, "Managed by hand since 2019") {
			sawFileContents[normalised] = true
			if _, allowed := contentBearingRoutes[normalised]; !allowed {
				t.Errorf("%s returned configuration file contents without being a content-bearing route", entry.key)
			}
		}
	}

	for route := range keyMaterialRoutes {
		if !sawKeyMaterial[route] {
			t.Errorf("%s is allowlisted for key material but returned none; the sweep is not reaching it", route)
		}
	}
	if len(sawFileContents) == 0 {
		t.Error("no route returned configuration contents; the sweep is not reaching the read paths")
	}
}

// normaliseObservationKey puts a concrete request path back into the Echo
// parameter spelling the allowlists use.
func normaliseObservationKey(key, keyID string) string {
	normalised := strings.Split(key, "?")[0]
	if keyID != "" {
		normalised = strings.ReplaceAll(normalised, "/"+keyID, "/:keyId")
	}
	return strings.ReplaceAll(normalised, "/acceptance-placeholder", "/:entryId")
}

func TestNoLogLineCarriesASecret(t *testing.T) {
	f := newFixture(t)

	// Exercise every route so the log has something in it, including refusals,
	// which are the lines most likely to echo what was rejected.
	for _, route := range f.apiRoutes() {
		readBody(t, f.do(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method)))
		readBody(t, f.do(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method), func(request *http.Request) {
			request.Header.Set("Sec-Fetch-Site", "cross-site")
		}))
	}
	keyID := f.keyID()
	revealToken := f.actionToken(t, session.ActionRevealPrivateKey, keyID)
	readBody(t, f.do(http.MethodPost, "/api/v1/keys/"+keyID+"/reveal", nil, func(request *http.Request) {
		request.Header.Set("X-SSH-UI-Action", revealToken)
	}))

	logged := f.logText()
	if strings.TrimSpace(logged) == "" {
		t.Log("the server logged nothing at all, which satisfies this test trivially but is worth knowing")
	}
	for name, secret := range map[string]string{
		"the bootstrap token":       f.canaries.Bootstrap,
		"the session id":            f.canaries.SessionID,
		"the CSRF token":            f.canaries.CSRF,
		"an action token":           revealToken,
		"the key passphrase":        f.canaries.Passphrase,
		"private key material":      f.canaries.PrivateKeyLine,
		"a file outside ~/.ssh":     f.canaries.Outside,
		"configuration file bytes":  "Managed by hand since 2019",
	} {
		if secret != "" && strings.Contains(logged, secret) {
			t.Errorf("the log contains %s", name)
		}
	}
	if strings.Contains(logged, f.home) {
		t.Error("the log contains the absolute home directory path")
	}
}
```

- [ ] **Step 4: Run the sweep**

Run: `go test ./internal/acceptance -run 'TestNoResponseCarriesASecretItIsNotEntitledTo|TestNoLogLineCarriesASecret' -v`
Expected: PASS.

- [ ] **Step 5: Prove the sweep has teeth**

| Mutation | File | Test that must fail |
|---|---|---|
| Add `logger.Info("reveal", "session", sessionID)` to the reveal handler | `internal/httpserver/keys.go` | `TestNoLogLineCarriesASecret` |
| Add the private key bytes to the ordinary key detail response | `internal/httpserver/keys.go` | `TestNoResponseCarriesASecretItIsNotEntitledTo` |
| Remove `"POST /api/v1/keys/:keyId/reveal"` from `keyMaterialRoutes` | `internal/acceptance/leak_test.go` | the same test, on the "allowlisted but returned none" branch, proving the allowlist is checked in both directions |
| Return `nil` from `ConsumeAction` before the comparison | `internal/session/action.go` | `TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken` |
| Remove the expiry check from `ConsumeAction` | `internal/session/action.go` | the `token past its lifetime` subtest |

Run each, confirm FAIL, then `git checkout -- <file>`.

- [ ] **Step 6: Commit**

```bash
go test ./internal/acceptance
go test -race ./internal/acceptance
git add internal/acceptance/leak_test.go
git commit -m "test: require a matching unexpired confirmation and sweep responses and logs for secrets"
```

---

## Task 4: The injection suite

**Files:**
- Create: `internal/acceptance/injection_test.go`

**Interfaces:**
- Consumes: Task 1's fixture and recorders, Task 2's `actionToken`, Task 3's `guardedRoutes`; `platform.ValidateAlias`, `platform.ValidateHostname`, `platform.ValidatePort`, `platform.Command`, `platform.Output`; `macos.Terminal`, `macos.NewTerminal`, `macos.TerminalScript`; `remotekey.Routine`, `remotekey.ProbeCommand`, `remotekey.ParsePublicKey`, `remotekey.ErrInvalidPublicKey`; `storage.ErrSymlinkPath`, `storage.ErrOutsideWorkspace`; `config.Parse`.
- Produces: `hostileArguments`, reused by Task 5's fuzz seeds.

The property under test is not "the validator rejects a list of strings" — subsystem 5 already tests that. It is **no hostile value ever reaches an argument vector, an AppleScript string, a remote shell string or a path outside the workspace, through any route.** That is asserted by looking at what the recorders captured, so removing a validator makes a command appear where none should be.

**Teeth:** every subtest pairs a hostile corpus with a positive control that must reach the recorder. A suite where the recorder is always empty would pass the hostile half vacuously; the positive control makes that impossible.

- [ ] **Step 1: Write the failing option-injection test**

Create `internal/acceptance/injection_test.go`:

```go
package acceptance_test

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssh-ui/internal/config"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/platform/macos"
	"ssh-ui/internal/remotekey"
)

// hostileArguments are values OpenSSH itself would accept inside a Host line,
// or that a user could type, and that would change the meaning of a command
// line, an AppleScript string or a remote shell string if they were passed
// through unchanged. "\x00" and "\n" are written as escapes on purpose: a raw
// control character in a source file is invisible in review.
var hostileArguments = []string{
	"-oProxyCommand=/bin/sh",
	"-oPermitLocalCommand=yes",
	"--config=/etc/passwd",
	"-l",
	"-",
	"--",
	"bastion -oProxyCommand=id",
	"bastion;touch /tmp/ssh-ui-pwned",
	"bastion|id",
	"bastion&&id",
	"bastion$(id)",
	"bastion`id`",
	"bastion\"; do script \"id",
	"bastion' & do shell script \"id\" & '",
	"bastion\nHost evil",
	"bastion\x00evil",
	"bastion\tevil",
	"bastion evil",
	"%h.example.com",
	"~/evil",
	"../../etc/ssh/ssh_config",
	".",
	"..",
	"",
	strings.Repeat("a", 65),
}

func TestNoRouteEverPutsAHostileValueOnACommandLine(t *testing.T) {
	f := newFixture(t)

	// Positive control: a safe alias must reach the process seam, and must
	// arrive after a "--" separator as one complete argument.
	f.runner.reset()
	f.runner.answer(func(platform.Command) (platform.Output, error) {
		return platform.Output{Stdout: []byte("hostname 203.0.113.10\nport 2222\n")}, nil
	})
	token := f.actionToken(t, "diagnostics.evaluate", "bastion")
	readBody(t, f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias":       "bastion",
		"actionToken": token,
	})))
	control := f.runner.recorded()
	if len(control) == 0 {
		t.Fatal("a safe alias never reached the process seam; every refusal below would prove nothing")
	}
	assertArgumentIsInert(t, control[0].Arguments, "bastion")

	// Hostile half: for each route that can start a process, every hostile
	// value must either be refused outright or arrive inert.
	aliasRoutes := []struct {
		path string
		kind string
		body func(alias, token string) map[string]any
	}{
		{"/api/v1/diagnostics/effective", "diagnostics.evaluate", func(alias, token string) map[string]any {
			return map[string]any{"alias": alias, "actionToken": token}
		}},
		{"/api/v1/diagnostics/reachability", "diagnostics.reachability", func(alias, token string) map[string]any {
			return map[string]any{"alias": alias, "actionToken": token}
		}},
		{"/api/v1/diagnostics/authentication", "diagnostics.authentication", func(alias, token string) map[string]any {
			return map[string]any{"alias": alias, "actionToken": token, "acknowledged": true}
		}},
		{"/api/v1/terminal/launch", "terminal.launch", func(alias, token string) map[string]any {
			return map[string]any{"alias": alias, "actionToken": token}
		}},
		{"/api/v1/remote-keys/register", "remote_key.register", func(alias, token string) map[string]any {
			return map[string]any{"alias": alias, "keyPath": "id_ed25519.pub", "actionToken": token, "acknowledged": true}
		}},
	}

	for _, route := range aliasRoutes {
		for _, hostile := range hostileArguments {
			t.Run(route.path+" "+quoteForName(hostile), func(t *testing.T) {
				f.runner.reset()
				// A token is issued for the hostile target so the request is
				// refused by the alias rule rather than by the token rule.
				issued := ""
				if hostile != "" && len(hostile) <= 255 {
					issued = f.tryActionToken(route.kind, hostile)
				}
				response := f.do(http.MethodPost, route.path, mustJSON(t, route.body(hostile, issued)))
				readBody(t, response)

				for _, command := range f.runner.recorded() {
					assertArgumentIsInert(t, command.Arguments, hostile)
				}
				for _, launched := range f.terminal.launched() {
					if launched == hostile {
						t.Fatalf("Terminal was launched for the hostile alias %q", hostile)
					}
				}
			})
		}
	}
}

// assertArgumentIsInert fails unless value, if present in argv at all, appears
// as one whole element that follows a "--" separator and cannot be read as an
// option.
func assertArgumentIsInert(t testing.TB, arguments []string, value string) {
	t.Helper()
	if value == "" {
		return
	}
	separator := -1
	for index, argument := range arguments {
		if argument == "--" {
			separator = index
			break
		}
	}
	for index, argument := range arguments {
		if !strings.Contains(argument, value) {
			continue
		}
		if argument != value {
			t.Fatalf("argv[%d] = %q embeds %q instead of carrying it whole", index, argument, value)
		}
		if separator < 0 || index < separator {
			t.Fatalf("argv[%d] = %q is not protected by a %q separator: %#v", index, argument, "--", arguments)
		}
		if strings.HasPrefix(value, "-") {
			t.Fatalf("argv[%d] = %q begins with a hyphen and was passed anyway", index, argument)
		}
		for _, forbidden := range []string{"\x00", "\n", "\r"} {
			if strings.Contains(argument, forbidden) {
				t.Fatalf("argv[%d] = %q contains a control character", index, argument)
			}
		}
	}
}

// tryActionToken issues a token when the target is acceptable and returns an
// empty string otherwise, so a hostile target does not abort the test.
func (f *fixture) tryActionToken(kind, target string) string {
	for _, path := range []string{"/api/v1/actions/token", "/api/v1/actions"} {
		response := f.do(http.MethodPost, path, mustJSON(f.t, map[string]any{
			"kind": kind, "target": target, "purpose": kind, "subject": target,
		}))
		status := response.StatusCode
		body := readBody(f.t, response)
		if status != http.StatusOK && status != http.StatusCreated {
			continue
		}
		var payload struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err == nil {
			return payload.Token
		}
	}
	return ""
}

// quoteForName makes a hostile value usable as a subtest name.
func quoteForName(value string) string {
	replaced := strings.NewReplacer("\x00", "<nul>", "\n", "<lf>", "\r", "<cr>", "\t", "<tab>", " ", "_", "/", "_")
	if value == "" {
		return "<empty>"
	}
	return replaced.Replace(value)
}
```

Add `"encoding/json"` to the import block.

- [ ] **Step 2: Run it**

Run: `go test ./internal/acceptance -run TestNoRouteEverPutsAHostileValueOnACommandLine`
Expected: PASS.

- [ ] **Step 3: Write the AppleScript injection test**

Append to `internal/acceptance/injection_test.go`:

```go
func TestTerminalLaunchNeverBuildsAppleScriptFromInput(t *testing.T) {
	// The script itself must be a constant with no substitution point at all.
	for _, forbidden := range []string{"%s", "%v", "%q", "${", "\" & "} {
		if strings.Contains(macos.TerminalScript, forbidden) {
			t.Fatalf("TerminalScript contains a substitution point %q", forbidden)
		}
	}
	if !strings.Contains(macos.TerminalScript, "quoted form of") {
		t.Fatal("TerminalScript does not quote its argument for the shell that runs it")
	}
	if !strings.Contains(macos.TerminalScript, "item 1 of argv") {
		t.Fatal("TerminalScript does not take the alias from argv")
	}

	runner := &recordingRunner{}
	terminal := macos.Terminal{Runner: runner, Program: "/usr/bin/osascript", Timeout: 5 * time.Second}

	// Positive control.
	if err := terminal.Launch(context.Background(), "bastion"); err != nil {
		t.Fatalf("Launch(bastion) = %v", err)
	}
	recorded := runner.recorded()
	if len(recorded) != 1 {
		t.Fatalf("a safe alias produced %d commands, want 1", len(recorded))
	}
	command := recorded[0]
	if command.Path != "/usr/bin/osascript" {
		t.Fatalf("path = %q", command.Path)
	}
	if len(command.Arguments) != 2 || command.Arguments[0] != "-" || command.Arguments[1] != "bastion" {
		t.Fatalf("arguments = %#v, want [- bastion]", command.Arguments)
	}
	if string(command.Stdin) != macos.TerminalScript {
		t.Fatal("the script sent on stdin is not the package constant")
	}
	if strings.Contains(string(command.Stdin), "bastion") {
		t.Fatal("the alias was concatenated into the script")
	}

	// Hostile half.
	for _, hostile := range hostileArguments {
		t.Run(quoteForName(hostile), func(t *testing.T) {
			runner.reset()
			err := terminal.Launch(context.Background(), hostile)
			if err == nil {
				t.Fatalf("Launch(%q) was accepted", hostile)
			}
			if commands := runner.recorded(); len(commands) != 0 {
				t.Fatalf("a refused launch still ran %#v", commands)
			}
		})
	}
}
```

- [ ] **Step 4: Write the remote-shell injection test**

Append to `internal/acceptance/injection_test.go`:

```go
func TestRemoteRegistrationNeverInterpolatesInputIntoTheRemoteShell(t *testing.T) {
	f := newFixture(t)

	publicKey := string(bytes.TrimSpace(f.read("id_ed25519.pub")))

	// Positive control: a real registration reaches the seam twice — the POSIX
	// probe and the fixed routine — and the key travels on stdin, never in argv.
	f.runner.reset()
	f.runner.answer(func(command platform.Command) (platform.Output, error) {
		if strings.Contains(strings.Join(command.Arguments, " "), remotekey.ProbeCommand) {
			return platform.Output{Stdout: []byte(remotekey.ProbeMarker + "\n")}, nil
		}
		return platform.Output{Stdout: []byte("ssh-ui: added\n")}, nil
	})
	token := f.actionToken(t, "remote_key.register", "bastion")
	readBody(t, f.do(http.MethodPost, "/api/v1/remote-keys/register", mustJSON(t, map[string]any{
		"alias": "bastion", "keyPath": "id_ed25519.pub", "actionToken": token, "acknowledged": true,
	})))

	recorded := f.runner.recorded()
	if len(recorded) < 2 {
		t.Fatalf("registration ran %d commands, want the probe and the routine", len(recorded))
	}
	routine := recorded[len(recorded)-1]
	if routine.Arguments[len(routine.Arguments)-1] != remotekey.Routine {
		t.Fatal("the last argument is not the fixed remote routine constant")
	}
	if !strings.Contains(string(routine.Stdin), publicKey) {
		t.Fatal("the public key did not travel on standard input")
	}
	for _, argument := range routine.Arguments {
		if strings.Contains(argument, publicKey) {
			t.Fatal("the public key was placed in the argument vector")
		}
	}

	// The routine is a constant: no input can change a byte of it.
	before := remotekey.Routine
	for _, hostile := range hostileArguments {
		t.Run(quoteForName(hostile), func(t *testing.T) {
			f.runner.reset()
			issued := f.tryActionToken("remote_key.register", hostile)
			readBody(t, f.do(http.MethodPost, "/api/v1/remote-keys/register", mustJSON(t, map[string]any{
				"alias": hostile, "keyPath": "id_ed25519.pub", "actionToken": issued, "acknowledged": true,
			})))
			for _, command := range f.runner.recorded() {
				assertArgumentIsInert(t, command.Arguments, hostile)
				if strings.Contains(strings.Join(command.Arguments, " "), hostile) &&
					strings.Contains(strings.Join(command.Arguments, " "), "$") {
					t.Fatalf("a hostile value reached a remote command string: %#v", command.Arguments)
				}
			}
			if remotekey.Routine != before {
				t.Fatal("the remote routine constant changed")
			}
		})
	}

	// A public key whose comment carries shell metacharacters or a newline is
	// refused by the parser, before anything reaches a remote host.
	for _, line := range []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl a; rm -rf ~",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl a\nssh-ed25519 AAAA b",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl a\x00b",
		"ssh-ed25519 not-base64!! comment",
		"echo pwned",
	} {
		if _, _, err := remotekey.ParsePublicKey(line); err == nil {
			t.Errorf("ParsePublicKey accepted %q", line)
		}
	}
	if _, _, err := remotekey.ParsePublicKey(publicKey); err != nil {
		t.Fatalf("ParsePublicKey rejected the fixture public key: %v", err)
	}
}
```

- [ ] **Step 5: Write the traversal and symlink test**

Append to `internal/acceptance/injection_test.go`:

```go
func TestNoRouteWritesOutsideTheWorkspaceOrThroughASymbolicLink(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(f.home, "private-notes", "canary.txt")
	original, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}

	// Positive control: an ordinary path inside the workspace is accepted.
	base := string(f.read("config"))
	accepted := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "config", "base": base, "raw": base + "\n# appended by the positive control\n",
	}))
	acceptedStatus := accepted.StatusCode
	readBody(t, accepted)
	if acceptedStatus != http.StatusOK {
		t.Fatalf("an ordinary save = %d; the refusals below would prove nothing", acceptedStatus)
	}
	base = string(f.read("config"))

	hostilePaths := []string{
		"../private-notes/canary.txt",
		"../../etc/ssh/ssh_config",
		"conf.d/../../private-notes/canary.txt",
		"/etc/ssh/ssh_config",
		"/private-notes/canary.txt",
		"conf.d/./../..//private-notes/canary.txt",
		"~/private-notes/canary.txt",
		"config\x00.conf",
		"config\n../escape.conf",
		".",
		"",
		strings.Repeat("a/", 300) + "deep.conf",
	}
	for _, hostile := range hostilePaths {
		t.Run(quoteForName(hostile), func(t *testing.T) {
			response := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
				"kind": "file_raw", "path": hostile, "base": "", "raw": "Host injected\n",
			}))
			status := response.StatusCode
			readBody(t, response)
			if status < 400 || status >= 500 {
				t.Fatalf("status = %d, want a 4xx refusal", status)
			}
			current, err := os.ReadFile(outside)
			if err != nil {
				t.Fatalf("the canary file disappeared: %v", err)
			}
			if !bytes.Equal(original, current) {
				t.Fatal("a hostile path changed a file outside the workspace")
			}
		})
	}

	// A symbolic link inside the workspace must not be written through.
	linked := filepath.Join(f.root, "linked.conf")
	if err := os.Symlink(outside, linked); err != nil {
		t.Fatal(err)
	}
	response := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "linked.conf", "base": "", "raw": "Host through-a-link\n",
	}))
	status := response.StatusCode
	readBody(t, response)
	if status < 400 || status >= 500 {
		t.Fatalf("writing through a symbolic link = %d, want a 4xx refusal", status)
	}
	current, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, current) {
		t.Fatal("a write followed a symbolic link out of the workspace")
	}

	// A directory component swapped for a symbolic link between the read and
	// the save must be refused too. This is the time-of-check/time-of-use case
	// the README describes as best effort; best effort still means refusing the
	// swap it can see.
	swapped := filepath.Join(f.root, "swapped")
	if err := os.MkdirAll(swapped, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(swapped, "x.conf"), []byte("Host swapped\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readBody(t, f.do(http.MethodGet, "/api/v1/config/file?path=swapped/x.conf", nil))
	if err := os.RemoveAll(swapped); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.home, "private-notes"), swapped); err != nil {
		t.Fatal(err)
	}
	response = f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "swapped/canary.txt", "base": "", "raw": "Host swapped-in\n",
	}))
	status = response.StatusCode
	readBody(t, response)
	if status < 400 || status >= 500 {
		t.Fatalf("writing through a swapped directory component = %d, want a 4xx refusal", status)
	}
	current, err = os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, current) {
		t.Fatal("a swapped directory component let a write escape the workspace")
	}
	if after := string(f.read("config")); after != base {
		t.Fatal("a refused save still changed the entry configuration file")
	}
}
```

- [ ] **Step 6: Write the hostile-alias test that also proves losslessness survives**

Append to `internal/acceptance/injection_test.go`:

```go
func TestAnAliasOpenSSHWouldAcceptIsStillRefusedForEveryExternalEffect(t *testing.T) {
	f := newFixture(t)

	// A configuration file may legitimately contain a Host line this
	// application will never launch. Reading it must be lossless; acting on it
	// must be refused. Those two rules have to hold at the same time.
	source := []byte("Host -oProxyCommand=id\n\tHostName 203.0.113.10\n" +
		"Host \"bastion evil\"\n\tUser ops\n" +
		"Host with\x00nul\n\tUser ops\n")
	parsed := config.Parse(source)
	if rendered := parsed.Render(); !bytes.Equal(rendered, source) {
		t.Fatalf("a hostile Host line did not round trip: %q", rendered)
	}

	for _, alias := range []string{
		"-oProxyCommand=id",
		"bastion evil",
		"with\x00nul",
		"with\nnewline",
		"-leading-hyphen",
	} {
		t.Run(quoteForName(alias), func(t *testing.T) {
			if err := platform.ValidateAlias(alias); err == nil {
				t.Fatalf("ValidateAlias(%q) = nil", alias)
			}
			f.runner.reset()
			for _, path := range []string{
				"/api/v1/diagnostics/effective",
				"/api/v1/diagnostics/reachability",
				"/api/v1/diagnostics/authentication",
				"/api/v1/terminal/launch",
				"/api/v1/terminal/command",
			} {
				response := f.do(http.MethodPost, path, mustJSON(t, map[string]any{
					"alias": alias, "actionToken": f.tryActionToken("terminal.launch", alias), "acknowledged": true,
				}))
				status := response.StatusCode
				readBody(t, response)
				if status >= 200 && status < 300 && path != "/api/v1/terminal/command" {
					t.Errorf("%s accepted the alias with %d", path, status)
				}
			}
			if commands := f.runner.recorded(); len(commands) != 0 {
				t.Fatalf("a refused alias still started %#v", commands)
			}
			if launched := f.terminal.launched(); len(launched) != 0 {
				t.Fatalf("a refused alias still launched Terminal: %#v", launched)
			}
		})
	}

	// `POST /api/v1/terminal/command` is deliberately allowed to answer for an
	// unsafe alias: design §6.5 says the UI offers a copyable command instead of
	// launching. It must say so, and must not claim the alias is launchable.
	response := f.do(http.MethodPost, "/api/v1/terminal/command", mustJSON(t, map[string]any{
		"alias": "bastion evil",
	}))
	body := readBody(t, response)
	if strings.Contains(body, `"launchable":true`) {
		t.Fatal("an unsafe alias was reported as launchable")
	}
}
```

- [ ] **Step 7: Run the whole injection suite**

Run: `go test ./internal/acceptance -run 'Injection|Hostile|Alias|Workspace|Terminal|Remote' -v`
Expected: PASS.

Run: `go test -race ./internal/acceptance`
Expected: PASS.

- [ ] **Step 8: Prove the suite has teeth**

| Mutation | File | Test that must fail |
|---|---|---|
| Delete the `platform.ValidateAlias` call from `Evaluate` | `internal/effective/evaluate.go` | `TestNoRouteEverPutsAHostileValueOnACommandLine` |
| Remove `"--"` from the `ssh -G` argument list | `internal/effective/evaluate.go` | the same test's `assertArgumentIsInert` separator check |
| Delete the `platform.ValidateAlias` call from `Terminal.Launch` | `internal/platform/macos/terminal.go` | `TestTerminalLaunchNeverBuildsAppleScriptFromInput` |
| Change `Stdin: []byte(TerminalScript)` to a `fmt.Sprintf` that embeds the alias | `internal/platform/macos/terminal.go` | the same test |
| Append the key line to the remote command instead of stdin | `internal/remotekey/register.go` | `TestRemoteRegistrationNeverInterpolatesInputIntoTheRemoteShell` |
| Return `cleaned, nil` from `ResolveForWrite` before the symlink check | `internal/storage/workspace.go` | `TestNoRouteWritesOutsideTheWorkspaceOrThroughASymbolicLink` |
| Delete the `Contains` check from `ResolveForWrite` | `internal/storage/workspace.go` | the traversal subtests |

Run each, confirm FAIL, then `git checkout -- <file>`.

- [ ] **Step 9: Commit**

```bash
git add internal/acceptance/injection_test.go
git commit -m "test: prove no hostile value reaches argv, AppleScript, a remote shell or a path outside ~/.ssh"
```

---

## Task 5: Fuzz targets beyond the parser, and a `make fuzz` that runs every one of them

**Files:**
- Modify: `internal/config/fuzz_test.go`
- Create: `internal/knownhosts/fuzz_test.go`
- Create: `internal/knownhosts/testdata/known_hosts.sample`
- Create: `internal/effective/fuzz_test.go`
- Create: `internal/effective/testdata/ssh-g-output.txt`
- Create: `internal/acceptance/fuzz_test.go`
- Modify: `Makefile`
- Modify: `README.md`

**Interfaces:**
- Consumes: `config.Resolver`, `config.Parse`, `config.LineDirective`; `knownhosts.ParseFile`, `(*knownhosts.File).Render`, `(*knownhosts.File).Entries`, `knownhosts.Line`, `knownhosts.Entry`, `(*knownhosts.Entry).MatchesHost`, `knownhosts.Search`, `knownhosts.Fingerprint`; `effective.ParseValues`, `effective.Values`; Task 1's fixture; Task 4's `hostileArguments`.
- Produces: `FuzzExpandIncludePattern`, `FuzzParseKnownHostsRoundTrip`, `FuzzParseValues`, `FuzzAPIRequestBodies`; the `FUZZ_TARGETS` list in the Makefile; `TestMakefileFuzzTargetsCoverEveryFuzzFunction`.

`internal/config` already fuzzes the parse/render round trip, and subsystems 3, 4 and 5 added none. Every remaining place where untrusted bytes are interpreted is unfuzzed: the Include pattern expander turns a config argument into a filesystem path, the `known_hosts` reader parses a file the user's other tools also write, the `ssh -G` parser reads whatever the installed OpenSSH printed, and the HTTP decoders read whatever a page in the browser sent.

Each target asserts an invariant, not merely "it did not panic". Each is seeded from real fixtures rather than from invented strings. And `make fuzz` runs **every** target: `go test -fuzz` accepts one target per invocation, so a single-line `make fuzz` silently exercises only the first, which is what the current Makefile does.

**Teeth:** `TestMakefileFuzzTargetsCoverEveryFuzzFunction` walks the repository for `func Fuzz…(f *testing.F)` and fails if the Makefile does not name it, so a target added later cannot be quietly left out of the campaign.

- [ ] **Step 1: Write the failing Include-expander fuzz target**

Append to `internal/config/fuzz_test.go`, which is already `package config` and can therefore reach the unexported expander:

```go
// FuzzExpandIncludePattern fuzzes the step that turns an Include argument into
// a filesystem glob. It is the only place in the engine where text from a
// configuration file becomes a path, so a pattern that expanded to a relative
// path, to an uncleaned path, or to a home directory the engine had to guess
// would widen what the resolver reads.
func FuzzExpandIncludePattern(f *testing.F) {
	for _, seed := range []string{
		"conf.d/*.conf",
		"~/.ssh/extra hosts.conf",
		"%d/.ssh/config.d/*",
		"/etc/ssh/ssh_config",
		"~root/config",
		"~",
		"~/",
		"a%",
		"%%literal",
		"%h.conf",
		"../escape.conf",
		"./././x",
		"",
		"a\x00b",
		"a\nb",
	} {
		f.Add(seed)
	}
	// Seed from the committed golden fixture too, so the corpus starts from
	// arguments a real configuration actually contains.
	golden, err := os.ReadFile(filepath.Join("testdata", "golden", "realistic.conf"))
	if err != nil {
		f.Fatal(err)
	}
	for _, line := range Parse(golden).Lines {
		if line.Kind != LineDirective || !EqualKeyword(line.Keyword, "Include") {
			continue
		}
		for _, argument := range line.Arguments {
			f.Add(strings.Trim(argument.Raw, "\""))
		}
	}

	resolver := Resolver{
		Home:   "/Users/tester",
		Root:   "/Users/tester/.ssh",
		Tokens: map[byte]string{'d': "/Users/tester"},
	}

	f.Fuzz(func(t *testing.T, argument string) {
		expanded, err := resolver.expandPattern(argument)
		if err != nil {
			if expanded != "" {
				t.Fatalf("expandPattern(%q) returned %q alongside %v", argument, expanded, err)
			}
			return
		}
		if !path.IsAbs(expanded) {
			t.Fatalf("expandPattern(%q) = %q, which is not absolute", argument, expanded)
		}
		if cleaned := path.Clean(expanded); cleaned != expanded {
			t.Fatalf("expandPattern(%q) = %q, which is not cleaned (%q)", argument, expanded, cleaned)
		}
		if strings.HasPrefix(argument, "~") && argument != "~" && !strings.HasPrefix(argument, "~/") {
			t.Fatalf("expandPattern(%q) guessed a home directory instead of refusing: %q", argument, expanded)
		}
		again, againErr := resolver.expandPattern(argument)
		if againErr != nil || again != expanded {
			t.Fatalf("expandPattern(%q) is not deterministic: %q/%v then %q/%v", argument, expanded, err, again, againErr)
		}
	})
}
```

Add `"os"`, `"path"`, `"path/filepath"` and `"strings"` to the file's import block. If `config.EqualKeyword` is spelled differently in the merged tree, use `strings.EqualFold(line.Keyword, "Include")` instead — the keyword comparison is not the point of the target.

- [ ] **Step 2: Run it briefly and watch it hold**

Run: `go test ./internal/config -run '^$' -fuzz '^FuzzExpandIncludePattern$' -fuzztime 20s`
Expected: `elapsed: 20s, execs: …` with no failing input, and no file appearing under `internal/config/testdata/fuzz/`.

If a crasher does appear, that is a real finding: read `testdata/fuzz/FuzzExpandIncludePattern/<hash>`, fix `expandPattern`, and commit the crasher as a permanent regression seed.

- [ ] **Step 3: Create the `known_hosts` fixture**

Create `internal/knownhosts/testdata/known_hosts.sample`. Every key below is a syntactically valid but entirely synthetic base64 blob; none belongs to a real host.

```text
# a comment the reader must preserve exactly

203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture-one
[198.51.100.20]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNlY29uZGZpeHR1cmVrZXlzZWNvbmRmaXh0dXJl fixture-two
bastion.example,203.0.113.11 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZpeHR1cmU= fixture-three
|1|c2FsdHNhbHRzYWx0c2FsdHNhbHQ=|aGFzaGhhc2hoYXNoaGFzaGhhc2g= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhhc2hlZGZpeHR1cmVrZXloYXNoZWRmaXh0dXJl
@revoked 203.0.113.12 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJldm9rZWRmaXh0dXJla2V5cmV2b2tlZGZpeHR1 fixture-revoked
@cert-authority *.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNhZml4dHVyZWtleWNhZml4dHVyZWtleWNhZml4 fixture-ca

203.0.113.13 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDmaWx0dXJl fixture-rsa
this line has too few fields
```

- [ ] **Step 4: Write the failing `known_hosts` fuzz target**

Create `internal/knownhosts/fuzz_test.go`:

```go
package knownhosts

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseKnownHostsRoundTrip fuzzes the known_hosts reader.
//
// The file is written by ssh, by ssh-keyscan and by hand, so it is the one
// artefact under ~/.ssh this application reads that it did not write. Two
// invariants matter: rendering an unmodified file returns the original bytes,
// because a deletion rewrites the whole file and every untouched line must
// survive; and a Line that claims to carry an Entry must carry a complete one,
// because the deletion path selects lines by their parsed identity.
func FuzzParseKnownHostsRoundTrip(f *testing.F) {
	sample, err := os.ReadFile(filepath.Join("testdata", "known_hosts.sample"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sample)
	for _, line := range bytes.Split(sample, []byte("\n")) {
		f.Add(line)
		f.Add(append(append([]byte(nil), line...), '\n'))
		f.Add(append(append([]byte(nil), line...), '\r', '\n'))
	}
	for _, seed := range []string{
		"",
		"\n",
		"\r\n",
		"   \t  \n",
		"# only a comment",
		"host",
		"host type",
		"host type key extra comment words",
		"|1|badsalt|badhash ssh-ed25519 AAAA",
		"@marker",
		"a\x00b ssh-ed25519 AAAA",
		strings.Repeat("h,", 4096) + "x ssh-ed25519 AAAA",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, contents []byte) {
		file := ParseFile(contents)
		if file == nil {
			t.Fatal("ParseFile returned nil")
		}
		if rendered := file.Render(); !bytes.Equal(rendered, contents) {
			t.Fatalf("round trip changed bytes:\n got %q\nwant %q", rendered, contents)
		}

		for _, line := range file.Lines {
			if line.Number <= 0 {
				t.Fatalf("line number %d is not 1-based", line.Number)
			}
			if line.Entry == nil {
				continue
			}
			entry := line.Entry
			if len(entry.Hosts) == 0 {
				t.Fatalf("line %d parsed an entry with no host", line.Number)
			}
			if entry.KeyType == "" || entry.Key == "" {
				t.Fatalf("line %d parsed an entry with no key: %#v", line.Number, entry)
			}
			if entry.Fingerprint != "" && !strings.HasPrefix(entry.Fingerprint, "SHA256:") {
				t.Fatalf("line %d fingerprint = %q", line.Number, entry.Fingerprint)
			}
			for _, host := range entry.Hosts {
				// A hashed entry cannot be matched by the literal it hashes, so
				// only the call itself is asserted: it must terminate and must
				// not panic on any host string the file contained.
				_ = entry.MatchesHost(host)
			}
		}

		if entries := file.Entries(); len(entries) > len(file.Lines) {
			t.Fatalf("Entries() = %d, more than the %d lines it came from", len(entries), len(file.Lines))
		}
		for _, query := range []string{"", "a", "SHA256:", "ssh-ed25519"} {
			for _, found := range Search(file, query) {
				if found.Entry == nil {
					t.Fatalf("Search(%q) returned a line with no entry", query)
				}
			}
		}
	})
}
```

- [ ] **Step 5: Run it**

Run: `go test ./internal/knownhosts -run '^$' -fuzz '^FuzzParseKnownHostsRoundTrip$' -fuzztime 20s`
Expected: no failing input. A round-trip failure here is a real defect: the delete path rewrites the whole file, so a line that does not survive rendering would be silently destroyed.

- [ ] **Step 6: Capture the `ssh -G` fixture**

This is an authoring step, run once by hand. It uses the same carve-out as the differential test: a safe fixture with no executable directive, inside a throwaway directory.

```bash
work="$(mktemp -d)"
printf 'Host fixture\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 2222\n\tIdentityFile %s/id_a\n\tIdentityFile %s/id_b\n' "$work" "$work" > "$work/config"
ssh -G -F "$work/config" -- fixture > internal/effective/testdata/ssh-g-output.txt
rm -rf "$work"
wc -l internal/effective/testdata/ssh-g-output.txt
```

Expected: roughly 60-80 lines of `keyword value` pairs. Commit the file; the fuzz target reads it and never runs `ssh` again. If OpenSSH is not installed on the machine doing the authoring, hand-write a 20-line file in the same shape rather than skipping the seed.

- [ ] **Step 7: Write the failing `ssh -G` parser fuzz target**

Create `internal/effective/fuzz_test.go`:

```go
package effective

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseValues fuzzes the parser for `ssh -G` output.
//
// The bytes come from a program this application started but does not control,
// and the result decides what the UI reports as the effective configuration.
// The invariant is that the parse is total and lossless in the only sense that
// matters: every non-empty line contributes exactly one value, every keyword is
// listed once, in output order, lowercased, and First agrees with the first
// entry. A parser that dropped, duplicated or reordered a value would show the
// user a configuration OpenSSH is not going to use.
func FuzzParseValues(f *testing.F) {
	transcript, err := os.ReadFile(filepath.Join("testdata", "ssh-g-output.txt"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(transcript)
	for _, line := range strings.Split(string(transcript), "\n") {
		f.Add([]byte(line))
	}
	for _, seed := range []string{
		"",
		"\n",
		"\r\n",
		"hostname",
		"hostname ",
		"HostName 203.0.113.10",
		"identityfile ~/.ssh/id_a\nidentityfile ~/.ssh/id_b\n",
		"proxycommand /bin/sh -c \"nc %h %p\"\n",
		"user with spaces in the value\n",
		"a\x00b c\n",
		strings.Repeat("keyword value\n", 4096),
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, stdout []byte) {
		values := ParseValues(stdout)

		seen := make(map[string]bool, len(values.Keywords))
		parsed := 0
		for _, keyword := range values.Keywords {
			if seen[keyword] {
				t.Fatalf("keyword %q is listed twice in Keywords", keyword)
			}
			seen[keyword] = true
			if keyword != strings.ToLower(keyword) {
				t.Fatalf("keyword %q was not lowercased", keyword)
			}
			entries, ok := values.Entries[keyword]
			if !ok {
				t.Fatalf("keyword %q is in Keywords but not in Entries", keyword)
			}
			if len(entries) == 0 {
				t.Fatalf("keyword %q has an empty entry list", keyword)
			}
			if first := values.First(keyword); first != entries[0] {
				t.Fatalf("First(%q) = %q, want %q", keyword, first, entries[0])
			}
			if all := values.All(keyword); len(all) != len(entries) {
				t.Fatalf("All(%q) = %d entries, want %d", keyword, len(all), len(entries))
			}
			parsed += len(entries)
		}
		if len(seen) != len(values.Entries) {
			t.Fatalf("Entries has %d keywords but Keywords lists %d", len(values.Entries), len(seen))
		}

		expected := 0
		for _, raw := range strings.Split(string(stdout), "\n") {
			if strings.TrimRight(raw, "\r") != "" {
				expected++
			}
		}
		if parsed != expected {
			t.Fatalf("parsed %d values from %d non-empty lines", parsed, expected)
		}

		if missing := values.First("definitely-not-a-keyword"); missing != "" {
			t.Fatalf("First on an absent keyword = %q", missing)
		}
	})
}
```

- [ ] **Step 8: Run it**

Run: `go test ./internal/effective -run '^$' -fuzz '^FuzzParseValues$' -fuzztime 20s`
Expected: no failing input.

- [ ] **Step 9: Write the HTTP decoder fuzz target and the coverage test**

Create `internal/acceptance/fuzz_test.go`:

```go
package acceptance_test

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// FuzzAPIRequestBodies fuzzes every JSON decoder behind the API at once.
//
// One server is built for the whole campaign and each execution posts a body to
// one route. The invariants are the ones a hostile page in the browser would
// try to break: the process stays alive and answering, no response grows
// without bound, every response is still no-store, no response leaks a canary,
// and the file outside the workspace is never touched.
func FuzzAPIRequestBodies(f *testing.F) {
	fixture := newFixture(f)
	routes := []string{}
	for _, route := range fixture.apiRoutes() {
		if route.Method == http.MethodGet || route.Method == http.MethodHead {
			continue
		}
		if route.Path == "/api/v1/session/bootstrap" {
			continue
		}
		routes = append(routes, fixture.concretePath(route.Path))
	}
	if len(routes) == 0 {
		f.Fatal("no mutating API route is registered; the harness is not wiring the services")
	}

	outside := filepath.Join(fixture.home, "private-notes", "canary.txt")
	original, err := os.ReadFile(outside)
	if err != nil {
		f.Fatal(err)
	}

	seeds := []string{
		`{}`,
		`[]`,
		`null`,
		`{"kind":"file_raw","path":"config","base":"","raw":"Host seed\n"}`,
		`{"kind":"host_fields","path":"config","alias":"bastion","base":"","fields":[]}`,
		`{"alias":"bastion","actionToken":"","acknowledged":true}`,
		`{"host":"203.0.113.10","port":22,"actionToken":""}`,
		`{"transactionId":"seed","path":"config"}`,
		`{"transactionId":"seed","action":"complete"}`,
		`{"algorithm":"ed25519","fileName":"seed","comment":"","passphrase":"","unencrypted":true}`,
		`{"unknownField":1}`,
		`{"path":"../../etc/passwd"}`,
		`{"raw":"` + strings.Repeat("A", 4096) + `"}`,
		"{\"raw\":\"a\\u0000b\"}",
		`{"line":`,
		"\x00\x01\x02",
	}
	for index := range routes {
		for _, seed := range seeds {
			f.Add(uint8(index), []byte(seed))
		}
	}

	f.Fuzz(func(t *testing.T, index uint8, body []byte) {
		path := routes[int(index)%len(routes)]
		response := fixture.do(http.MethodPost, path, body)
		cache := response.Header.Get("Cache-Control")
		text := readBody(t, response)

		if cache != "no-store" {
			t.Fatalf("%s answered with Cache-Control %q", path, cache)
		}
		if len(text) > maxAcceptableResponseBytes {
			t.Fatalf("%s answered with %d bytes", path, len(text))
		}
		for name, secret := range map[string]string{
			"a file outside ~/.ssh": fixture.canaries.Outside,
			"the key passphrase":    fixture.canaries.Passphrase,
			"the bootstrap token":   fixture.canaries.Bootstrap,
			"the session id":        fixture.canaries.SessionID,
			"private key material":  fixture.canaries.PrivateKeyLine,
		} {
			if secret != "" && strings.Contains(text, secret) {
				t.Fatalf("%s leaked %s", path, name)
			}
		}

		current, err := os.ReadFile(outside)
		if err != nil || string(current) != string(original) {
			t.Fatalf("a fuzzed request changed the file outside the workspace: %v", err)
		}

		// Liveness: the server must still answer after whatever it just read.
		health := fixture.do(http.MethodGet, "/api/v1/health", nil)
		healthStatus := health.StatusCode
		readBody(t, health)
		if healthStatus != http.StatusOK {
			t.Fatalf("health after %s = %d", path, healthStatus)
		}
	})
}

// fuzzFunctionPattern matches a Go fuzz target declaration.
var fuzzFunctionPattern = regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]*)\(f \*testing\.F\)`)

// makefileTargetsPattern extracts the FUZZ_TARGETS assignment, including its
// backslash continuations.
var makefileTargetsPattern = regexp.MustCompile(`(?s)FUZZ_TARGETS\s*=\s*(.*?)\n\n`)

func TestMakefileFuzzTargetsCoverEveryFuzzFunction(t *testing.T) {
	root := filepath.Join("..", "..")

	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	match := makefileTargetsPattern.FindSubmatch(makefile)
	if match == nil {
		t.Fatal("the Makefile has no FUZZ_TARGETS list")
	}
	declared := map[string]bool{}
	for _, field := range strings.Fields(strings.ReplaceAll(string(match[1]), "\\", " ")) {
		declared[field] = true
	}

	found := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "web", "bin", "docs", ".claude", ".worktrees":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		for _, declaration := range fuzzFunctionPattern.FindAllStringSubmatch(string(contents), -1) {
			found[filepath.ToSlash(relative)+":"+declaration[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("the walk found no fuzz target at all; the coverage test is not looking in the right place")
	}

	for target := range found {
		if !declared[target] {
			t.Errorf("fuzz target %s exists but `make fuzz` does not run it", target)
		}
	}
	for target := range declared {
		if !found[target] {
			t.Errorf("`make fuzz` names %s but no such fuzz target exists", target)
		}
	}
}
```

- [ ] **Step 10: Rewrite the `fuzz` target so it runs every one of them**

Replace the `fuzz` rule in `Makefile`:

```make
.PHONY: generate test build fuzz e2e verify-generated

# FUZZTIME is per target. `make fuzz` is a campaign, not a single run, so the
# default is short enough to be part of an ordinary verification pass; raise it
# for a deliberate soak: `make fuzz FUZZTIME=10m`.
FUZZTIME ?= 30s

# Every fuzz target in the repository, as package:Target. Adding a target
# without adding it here fails TestMakefileFuzzTargetsCoverEveryFuzzFunction.
FUZZ_TARGETS = \
	internal/config:FuzzParseRendersOriginalBytes \
	internal/config:FuzzExpandIncludePattern \
	internal/effective:FuzzParseValues \
	internal/knownhosts:FuzzParseKnownHostsRoundTrip \
	internal/acceptance:FuzzAPIRequestBodies

fuzz:
	@set -e; for target in $(FUZZ_TARGETS); do \
		package="$${target%%:*}"; \
		name="$${target##*:}"; \
		echo "==> fuzz $$package $$name for $(FUZZTIME)"; \
		go test "./$$package" -run '^$$' -fuzz "^$$name$$" -fuzztime "$(FUZZTIME)"; \
	done
```

The blank line after the last continuation matters: `makefileTargetsPattern` ends the list at it. Keep one.

- [ ] **Step 11: Run the coverage test, then the campaign**

Run: `go test ./internal/acceptance -run TestMakefileFuzzTargetsCoverEveryFuzzFunction -v`
Expected: PASS.

Now confirm it has teeth: delete the `internal/effective:FuzzParseValues` line from the Makefile, re-run, expect `FAIL … fuzz target internal/effective:FuzzParseValues exists but `make fuzz` does not run it`, then restore the line.

Run: `make fuzz`
Expected: five `==> fuzz …` banners, each followed by a clean `elapsed: 30s` line, and `internal/*/testdata/fuzz/` containing no crasher.

Run: `git status --short`
Expected: no untracked file under any `testdata/fuzz` directory.

- [ ] **Step 12: Update the README**

In `README.md`, replace the `make fuzz` comment line and extend the new boundary section:

```sh
make fuzz      # 全 fuzz target を既定 30 秒ずつ実行（FUZZTIME で変更）
```

```markdown
- `make fuzz` は `FUZZ_TARGETS` に列挙した全 target を順に実行します。`go test -fuzz` は一度に 1 target しか動かせないため、1 行で書くと最初の target しか回りません。target を追加して一覧に加え忘れると `TestMakefileFuzzTargetsCoverEveryFuzzFunction` が失敗します。
- fuzz の対象は、設定パーサーのラウンドトリップ、Include パターン展開、`known_hosts` リーダー、`ssh -G` 出力パーサー、HTTP リクエストデコーダーの 5 つです。いずれも実 fixture を seed にしています。
```

- [ ] **Step 13: Commit**

```bash
go test ./...
go test -race ./...
git add internal/config/fuzz_test.go internal/knownhosts internal/effective/fuzz_test.go internal/effective/testdata internal/acceptance/fuzz_test.go Makefile README.md
git commit -m "test: fuzz the include expander, known_hosts, ssh -G output and the HTTP decoders"
```

---

## Task 6: Playwright end-to-end over an isolated `~/.ssh`

**Files:**
- Modify: `cmd/ssh-ui/main.go`
- Modify: `web/package.json`
- Modify: `web/vite.config.ts`
- Modify: `.gitignore`
- Modify: `Makefile`
- Create: `web/playwright.config.ts`
- Create: `web/tsconfig.e2e.json`
- Create: `web/e2e/support/environment.ts`
- Create: `web/e2e/bootstrap.spec.ts`
- Create: `web/e2e/connections.spec.ts`
- Create: `web/e2e/explorer.spec.ts`
- Create: `web/e2e/keys.spec.ts`
- Create: `web/e2e/history.spec.ts`

**Interfaces:**
- Consumes: the accessible names the Vitest suites of subsystems 3, 4 and 5 already assert — `nav[aria-label="Primary"]`, `nav[aria-label="Connections"]`, `role="tablist"` named `Host editor` with tabs `Basic`/`Jump`/`Advanced`/`Raw`/`Effective`/`Diagnostics`, the buttons `Create connection`, `Save changes`, `Save block`, `Save file`, `Restore config`, `Show private key`, `Close`, the labels `New connection alias`, `Filter connections`, `Block text`, `File text`, the headings `Save preview`, `Changed on disk since you loaded it`, `Your pending change`, `Keys`, the table caption `Files classified by content and permissions`, the dialog `aria-labelledby="reveal-heading"` and the single `role="status"` in the header.
- Produces: `app.Dependencies` unchanged; a new `-open` flag on the binary; `test` fixture `installation` in `web/e2e/support/environment.ts` with `{ home, url, read, write, restart }`; `make e2e`.

### Is Playwright justified?

Yes, and the design already names it: §10.5 requires "隔離環境での Playwright 主要フロー". Beyond the mandate, four of this plan's obligations cannot be met by Vitest and jsdom, which is what the earlier plans use:

1. **CSP is only real in a browser.** jsdom does not enforce `Content-Security-Policy`. Asserting the header is a string comparison; asserting that an inline script does not execute and that `fetch("https://example.invalid")` is blocked requires an engine that implements the policy.
2. **Cookie flags are only observable in a browser.** `HttpOnly` and `SameSite=Strict` are enforced by the cookie store, not by the response. Playwright's `context.cookies()` reports both, and `document.cookie` proves `HttpOnly` by returning nothing.
3. **The bootstrap fragment lives in browser history.** `history.replaceState` and the resulting `location.hash` are jsdom stubs today; the guarantee that the one-time token is gone from the address bar and from the back stack is a browser behaviour.
4. **"No external origin was contacted" is a network claim.** `page.on("request")` observes every subresource the real engine fetches, including ones a bundler injected. A unit test can only assert the source it was given.

A lighter approach was considered and rejected. Driving the built binary with `curl` and comparing HTML would cover none of the four; running the existing Vitest suites against the real server would still be jsdom. The cost is one dev dependency and a Chromium download, and it buys the only evidence that the shipped artefact — binary plus embedded bundle plus browser — behaves as designed.

**Pinned exactly:** `@playwright/test` **1.62.1**, a `devDependencies` entry, never a `dependencies` entry, so it cannot enter the production bundle. `web/tsconfig.json` does not include `e2e/`, so the shipped `tsc -b` never sees it, and Vitest is narrowed in Step 4 so it never collects a `.spec.ts` from `e2e/`.

**Teeth:** each spec ends by reading the fixture files from disk, so a flow that renders convincingly but writes nothing fails. `bootstrap.spec.ts` asserts CSP by *observing a blocked script*, not by reading a header.

- [ ] **Step 1: Add the `-open` flag to the binary**

Automation needs the URL without handing a live bootstrap token to whatever browser happens to be running on the desk. `open <url>` already puts that token in the process table of the same user, so printing it on the process's own standard output is no weaker, and it is opt-in.

In `cmd/ssh-ui/main.go`, add the flag and a launcher that prints instead of opening:

```go
// urlPrinter satisfies platform.BrowserLauncher by writing the URL instead of
// opening it. It exists for automation — the end-to-end suite and the packaging
// smoke test — which must not hand a live bootstrap token to the user's own
// browser. The token is no more exposed than it already is in the argv of
// `open`, and the flag has to be asked for.
type urlPrinter struct{ out io.Writer }

func (p urlPrinter) Open(_ context.Context, target string) error {
	_, err := fmt.Fprintln(p.out, target)
	return err
}
```

and inside `main`, before `dependencies` is built:

```go
	openBrowser := flag.Bool("open", true, "open the UI in the default browser; -open=false prints the URL on standard output instead")
	flag.Parse()

	var browser platform.BrowserLauncher = macos.NewBrowser(macos.NewExecRunner())
	if !*openBrowser {
		browser = urlPrinter{out: os.Stdout}
	}
```

then set `Browser: browser` in `dependencies`. Add `"flag"`, `"fmt"`, `"io"` and `"ssh-ui/internal/platform"` to the imports.

- [ ] **Step 2: Verify the flag by hand, in a throwaway home**

```bash
go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui
work="$(mktemp -d)"
HOME="$work" ./bin/ssh-ui -open=false &
sleep 1
kill %1
rm -rf "$work"
```

Expected: exactly one line on standard output of the form `http://127.0.0.1:<port>/#bootstrap=<43 characters>`, no browser window, and the process exits when signalled.

- [ ] **Step 3: Install and pin Playwright**

This step changes the environment. Read it before running it. The browser download is redirected into the project so nothing lands in `~/Library/Caches`.

```bash
npm install --prefix web --save-dev --save-exact @playwright/test@1.62.1
PLAYWRIGHT_BROWSERS_PATH=./web/.playwright-browsers npx --prefix web playwright install chromium
grep -n '"@playwright/test"' web/package.json
```

Expected: `web/package.json` gains `"@playwright/test": "1.62.1"` under `devDependencies` with no caret, `web/package-lock.json` is updated, and `web/.playwright-browsers/` holds a Chromium build. Verify it did **not** land in `dependencies`:

```bash
node -e 'const p=require("./web/package.json"); if (p.dependencies["@playwright/test"]) { throw new Error("playwright is a production dependency"); }'
```

Add the scripts to `web/package.json`:

```json
    "e2e": "playwright test",
    "typecheck": "tsc -b --pretty false && tsc -p tsconfig.e2e.json --pretty false"
```

- [ ] **Step 4: Keep Vitest and the production build away from `e2e/`**

In `web/vite.config.ts`, narrow the Vitest collection so a Playwright spec is never loaded by jsdom:

```ts
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    restoreMocks: true,
    include: ["src/**/*.test.{ts,tsx}"],
  },
```

Create `web/tsconfig.e2e.json`, which type-checks the suite without adding it to the shipped project:

```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "types": ["node"],
    "noEmit": true
  },
  "include": ["e2e", "playwright.config.ts"]
}
```

Add to `.gitignore`:

```text
/web/.playwright-browsers/
/web/playwright-report/
/web/test-results/
```

- [ ] **Step 5: Write the Playwright configuration**

Create `web/playwright.config.ts`:

```ts
import { defineConfig, devices } from "@playwright/test";

// Traces, videos and screenshots are all disabled on purpose. One end-to-end
// flow reveals a private key on screen by design, and an artefact directory is
// exactly the kind of place a secret is forgotten. Failures are diagnosed from
// the assertion message and the server's own output.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    trace: "off",
    video: "off",
    screenshot: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
```

- [ ] **Step 6: Write the isolated environment fixture**

Create `web/e2e/support/environment.ts`:

```ts
import { test as base, expect } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

// binaryPath is the artefact under test. `make e2e` builds it first; a missing
// binary fails loudly rather than falling back to a dev server, because the
// point of this suite is the shipped artefact.
const binaryPath = resolve(process.cwd(), "..", "bin", "ssh-ui");

// The fixture home is written by this file and by nothing else. Every spec that
// needs a different starting state writes it through `installation.write`.
const entryConfig = [
  "# Managed by hand since 2019. Do not reformat.",
  "",
  "Include conf.d/*.conf",
  "",
  "Host bastion",
  "\tHostName=203.0.113.10",
  "\tUser    ops",
  "\tPort 2222",
  "",
  "Host *",
  "\tServerAliveInterval 30",
  "",
].join("\n");

const includedConfig = [
  "Host nas",
  "\tHostName 198.51.100.20",
  '\tUnknownFutureDirective some "quoted value" 3',
  "",
].join("\n");

export type Installation = {
  home: string;
  url: string;
  read(relative: string): Promise<string>;
  write(relative: string, contents: string): Promise<void>;
};

async function buildHome(): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), "ssh-ui-e2e-"));
  if (!home.startsWith(tmpdir())) {
    throw new Error("the end-to-end home is not inside the temporary directory");
  }
  const root = join(home, ".ssh");
  await mkdir(join(root, "conf.d"), { recursive: true, mode: 0o700 });
  await writeFile(join(root, "config"), entryConfig, { mode: 0o600 });
  await writeFile(join(root, "conf.d", "10-home.conf"), includedConfig, { mode: 0o600 });
  await writeFile(
    join(root, "known_hosts"),
    "203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture\n",
    { mode: 0o600 },
  );
  return home;
}

function startBinary(home: string): Promise<{ child: ChildProcess; url: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(binaryPath, ["-open=false"], {
      env: { HOME: home, PATH: process.env.PATH ?? "" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let buffered = "";
    const timer = setTimeout(() => rejectPromise(new Error("ssh-ui printed no URL within 10s")), 10_000);
    child.stdout?.on("data", (chunk: Buffer) => {
      buffered += chunk.toString("utf8");
      const newline = buffered.indexOf("\n");
      if (newline < 0) return;
      clearTimeout(timer);
      resolvePromise({ child, url: buffered.slice(0, newline).trim() });
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      rejectPromise(new Error(`ssh-ui exited with ${String(code)} before printing a URL`));
    });
  });
}

export const test = base.extend<{ installation: Installation }>({
  installation: async ({}, use) => {
    const home = await buildHome();
    const { child, url } = await startBinary(home);
    const installation: Installation = {
      home,
      url,
      async read(relative) {
        return readFile(join(home, ".ssh", relative), "utf8");
      },
      async write(relative, contents) {
        const target = join(home, ".ssh", relative);
        await mkdir(dirname(target), { recursive: true, mode: 0o700 });
        await writeFile(target, contents, { mode: 0o600 });
      },
    };
    await use(installation);
    child.kill("SIGTERM");
    await new Promise((done) => child.on("exit", done));
    await rm(home, { recursive: true, force: true });
  },
});

export { expect };
```

- [ ] **Step 7: Write the bootstrap, session and browser-policy spec**

Create `web/e2e/bootstrap.spec.ts`:

```ts
import { expect, test } from "./support/environment";

test("exchanges the fragment for a session and removes it from the address bar", async ({ page, context, installation }) => {
  await page.goto(installation.url);

  await expect(page.getByRole("heading", { name: "SSH UI", level: 1 })).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Local session active");

  expect(await page.evaluate(() => window.location.hash)).toBe("");
  expect(await page.evaluate(() => document.cookie)).toBe("");

  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "ssh_ui_session");
  expect(session).toBeDefined();
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  expect(session?.secure).toBe(false);
});

test("refuses a replayed bootstrap fragment in a fresh browser context", async ({ browser, installation }) => {
  const first = await browser.newContext();
  const firstPage = await first.newPage();
  await firstPage.goto(installation.url);
  await expect(firstPage.getByRole("status")).toContainText("Local session active");
  await first.close();

  const second = await browser.newContext();
  const secondPage = await second.newPage();
  await secondPage.goto(installation.url);
  await expect(secondPage.getByRole("alert")).toContainText("Secure local session could not be started");
  await second.close();
});

test("contacts no origin but its own", async ({ page, installation }) => {
  const requested: string[] = [];
  page.on("request", (request) => requested.push(request.url()));

  await page.goto(installation.url);
  await expect(page.getByRole("status")).toContainText("Local session active");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Config" }).click();
  await expect(page.getByRole("heading", { name: "config", exact: true })).toBeVisible();

  const origin = new URL(installation.url).origin;
  const foreign = requested.filter((url) => !url.startsWith(origin) && !url.startsWith("data:"));
  expect(foreign, `these requests left the origin: ${foreign.join(", ")}`).toEqual([]);
});

test("enforces the content security policy in the browser, not only in the header", async ({ page, installation }) => {
  const response = await page.goto(installation.url);
  expect(response?.headers()["content-security-policy"]).toBe(
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
      "form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
  );

  // An inline script must not run. addScriptTag with content injects an inline
  // script element, which script-src 'self' refuses.
  const inlineRan = await page.evaluate(async () => {
    const marker = "__ssh_ui_inline_marker";
    const element = document.createElement("script");
    element.textContent = `window.${marker} = true;`;
    document.head.appendChild(element);
    await new Promise((done) => setTimeout(done, 100));
    return Boolean((window as unknown as Record<string, unknown>)[marker]);
  });
  expect(inlineRan, "an inline script executed despite script-src 'self'").toBe(false);

  // connect-src 'self' must block a fetch to another origin before it leaves
  // the machine, so this assertion needs no network.
  const crossOrigin = await page.evaluate(async () => {
    try {
      await fetch("https://example.invalid/collect", { mode: "no-cors" });
      return "allowed";
    } catch {
      return "blocked";
    }
  });
  expect(crossOrigin).toBe("blocked");
});
```

- [ ] **Step 8: Write the connections spec**

Create `web/e2e/connections.spec.ts`:

```ts
import { expect, test } from "./support/environment";

async function openBastion(page: import("@playwright/test").Page, url: string) {
  await page.goto(url);
  await expect(page.getByRole("status")).toContainText("Local session active");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Connections" }).click();
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await expect(page.getByRole("tablist", { name: "Host editor" })).toBeVisible();
}

test("edits a host through the form and writes only the line that changed", async ({ page, installation }) => {
  const before = await installation.read("config");
  await openBastion(page, installation.url);

  await page.getByLabel("Port").fill("2244");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("heading", { name: "Save preview" })).toBeVisible();

  const after = await installation.read("config");
  expect(after).toContain("Port 2244");
  expect(after).not.toContain("Port 2222");
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.");
  expect(after).toContain("HostName=203.0.113.10");
  expect(after).toContain("User    ops");
  expect(after.split("\n").length).toBe(before.split("\n").length);
});

test("edits the same host through Raw and keeps every other byte", async ({ page, installation }) => {
  await openBastion(page, installation.url);
  await page.getByRole("tab", { name: "Raw" }).click();

  const editor = page.getByLabel(/Block text/);
  const original = await editor.inputValue();
  await editor.fill(original.replace("Port 2222", "Port 2255\n\tCompression yes"));
  await page.getByRole("button", { name: "Save block" }).click();
  await expect(page.getByRole("heading", { name: "Save preview" })).toBeVisible();

  const after = await installation.read("config");
  expect(after).toContain("Port 2255");
  expect(after).toContain("Compression yes");
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.");
  expect(after).toContain("ServerAliveInterval 30");
});

test("shows a save preview diff before anything else changes", async ({ page, installation }) => {
  await openBastion(page, installation.url);
  await page.getByLabel("Port").fill("2299");
  await page.getByRole("button", { name: "Save changes" }).click();

  const preview = page.getByRole("region", { name: "Save preview" });
  await expect(preview).toContainText("2299");
  await expect(preview).not.toContainText("Changed on disk since you loaded it");
});

test("refuses a save whose base is stale and shows the three-way conflict", async ({ page, installation }) => {
  await openBastion(page, installation.url);

  const external = (await installation.read("config")).replace(
    "Host *",
    "Host edited-outside\n\tHostName 192.0.2.99\n\nHost *",
  );
  await installation.write("config", external);

  await page.getByLabel("Port").fill("2277");
  await page.getByRole("button", { name: "Save changes" }).click();

  await expect(page.getByRole("alert")).toContainText(/changed outside this application/i);
  await expect(page.getByText("Changed on disk since you loaded it")).toBeVisible();
  await expect(page.getByText("Your pending change")).toBeVisible();

  const after = await installation.read("config");
  expect(after).toBe(external);
  expect(after).not.toContain("Port 2277");
});
```

- [ ] **Step 9: Write the explorer, keys and history specs**

Create `web/e2e/explorer.spec.ts`:

```ts
import { expect, test } from "./support/environment";

test("shows the Include hierarchy and edits an included file", async ({ page, installation }) => {
  await page.goto(installation.url);
  await expect(page.getByRole("status")).toContainText("Local session active");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Config" }).click();

  await expect(page.getByRole("button", { name: "config", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "conf.d/10-home.conf" })).toBeVisible();
  await expect(page.getByText("conf.d/*.conf")).toBeVisible();

  await page.getByRole("button", { name: "conf.d/10-home.conf" }).click();
  const editor = page.getByLabel(/File text/);
  await expect(editor).toHaveValue(/UnknownFutureDirective some "quoted value" 3/);
  await editor.fill((await editor.inputValue()) + "\nHost printer\n\tHostName 198.51.100.30\n");
  await page.getByRole("button", { name: "Save file" }).click();

  const after = await installation.read("conf.d/10-home.conf");
  expect(after).toContain('UnknownFutureDirective some "quoted value" 3');
  expect(after).toContain("Host printer");
});
```

Create `web/e2e/keys.spec.ts`:

```ts
import { expect, test } from "./support/environment";

test("lists generated keys and reveals one only after an explicit confirmation", async ({ page, installation }) => {
  await page.goto(installation.url);
  await expect(page.getByRole("status")).toContainText("Local session active");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Keys" }).click();
  await expect(page.getByRole("table", { name: "Files classified by content and permissions" })).toBeVisible();

  await page.getByLabel("File name").fill("id_e2e");
  await page.getByLabel("Passphrase").fill("end-to-end-passphrase");
  await page.getByRole("button", { name: "Create key" }).click();

  const row = page.getByRole("row", { name: /id_e2e\b/ });
  await expect(row).toBeVisible();
  await expect(row).toContainText("0600");
  expect(await installation.read("id_e2e.pub")).toContain("ssh-ed25519 ");

  await row.getByRole("button", { name: "Show private key" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("browser extensions");
  await expect(dialog.locator('pre[aria-label="Private key"]')).toHaveCount(0);

  await dialog.getByRole("button", { name: "Show private key" }).click();
  await expect(dialog.locator('pre[aria-label="Private key"]')).toContainText("BEGIN OPENSSH PRIVATE KEY");

  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(page.locator("body")).not.toContainText("BEGIN OPENSSH PRIVATE KEY");
  expect(
    await page.evaluate(() => ({ local: window.localStorage.length, session: window.sessionStorage.length })),
  ).toEqual({ local: 0, session: 0 });
});
```

Create `web/e2e/history.spec.ts`:

```ts
import { expect, test } from "./support/environment";

test("records a change in history and restores the previous bytes", async ({ page, installation }) => {
  const original = await installation.read("config");

  await page.goto(installation.url);
  await expect(page.getByRole("status")).toContainText("Local session active");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Connections" }).click();
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByLabel("Port").fill("2233");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("heading", { name: "Save preview" })).toBeVisible();
  expect(await installation.read("config")).toContain("Port 2233");

  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "History" }).click();
  await expect(page.getByText("config.host_fields")).toBeVisible();
  await page.getByRole("button", { name: "Restore config" }).first().click();

  await expect.poll(async () => installation.read("config")).toBe(original);
});
```

- [ ] **Step 10: Add the `e2e` target and run the suite**

Add to `Makefile`:

```make
e2e: build
	npm run e2e --prefix web
```

and set the browser location for the run:

```bash
PLAYWRIGHT_BROWSERS_PATH=./web/.playwright-browsers make e2e
```

Expected: all specs pass. Run it twice in a row — the fixture home is fresh each time, so a second run must give the same result. If a spec fails on a selector, the accessible name changed during the merge of subsystems 3, 4 and 5; read the corresponding Vitest test for the current name and update the spec, never the component.

- [ ] **Step 11: Prove the suite has teeth**

| Mutation | File | Spec that must fail |
|---|---|---|
| Append `'unsafe-inline'` to `script-src` | `internal/httpserver/security.go` | `bootstrap.spec.ts` — "enforces the content security policy in the browser" |
| Remove `HttpOnly: true` from the session cookie | `internal/httpserver/handlers.go` | `bootstrap.spec.ts` — "exchanges the fragment for a session" |
| Remove the `history.replaceState` call | `web/src/session/bootstrap.ts` | the same spec |
| Skip the precondition digest on save | `internal/application/service.go` | `connections.spec.ts` — "refuses a save whose base is stale" |
| Return the private key from the ordinary detail API and render it in the row | `internal/httpserver/keys.go` | `keys.spec.ts` — the `toHaveCount(0)` assertion before confirmation |

Run each, confirm FAIL, then `git checkout -- <file>`.

- [ ] **Step 12: Confirm Playwright stayed out of the production bundle**

```bash
npm run build --prefix web
grep -rl "playwright" internal/ui/dist/ && echo "FAIL: playwright reached the bundle" || echo "no playwright in the bundle"
node -e 'const p=require("./web/package.json"); if (p.dependencies["@playwright/test"]) throw new Error("production dependency"); if (p.devDependencies["@playwright/test"] !== "1.62.1") throw new Error("not pinned exactly");'
npm test --prefix web
npm run typecheck --prefix web
```

Expected: `no playwright in the bundle`, the node check is silent, Vitest collects only `src/**/*.test.*`, and both TypeScript projects check clean.

- [ ] **Step 13: Commit**

```bash
git add cmd/ssh-ui/main.go web/package.json web/package-lock.json web/playwright.config.ts web/tsconfig.e2e.json web/vite.config.ts web/e2e .gitignore Makefile
git commit -m "test: drive the built binary through the main flows in a real browser"
```

---

## Task 7: Single-binary packaging, the SIGTERM smoke test and contract reproducibility

**Files:**
- Create: `internal/acceptance/binary_test.go`
- Modify: `Makefile`
- Modify: `README.md`

**Interfaces:**
- Consumes: `cmd/ssh-ui`'s `-open` flag from Task 6; `internal/ui/dist/index.html`.
- Produces: `make verify-generated`; `TestBuiltBinaryServesTheEmbeddedUIAndStopsOnSIGTERM`; `TestNoTestOnlyPackageReachesTheShippedBinary`.

Every earlier plan stops at `go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui` and asserts the command succeeded. Nothing asserts that the artefact starts, serves the UI it embedded, and stops when the operating system asks it to — which is the only claim a user actually depends on.

**Teeth:** the smoke test compares the served bytes with the committed `internal/ui/dist/index.html`, so a binary built with a stale or empty `dist` fails rather than serving a placeholder. The shutdown assertion has a deadline, so a process that ignores SIGTERM fails instead of hanging the suite.

- [ ] **Step 1: Write the failing smoke test**

Create `internal/acceptance/binary_test.go`:

```go
package acceptance_test

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestBuiltBinaryServesTheEmbeddedUIAndStopsOnSIGTERM builds and runs the real
// artefact.
//
// This is the one place in the repository that executes a program this project
// produced. It uses the local Go toolchain, which is already required to run
// the test at all, and points HOME at a temporary directory, so the real ~/.ssh
// is never read. Nothing here contacts a network.
func TestBuiltBinaryServesTheEmbeddedUIAndStopsOnSIGTERM(t *testing.T) {
	repository := filepath.Join("..", "..")
	binary := filepath.Join(t.TempDir(), "ssh-ui")

	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/ssh-ui")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build = %v\n%s", err, output)
	}

	embedded, err := os.ReadFile(filepath.Join(repository, "internal", "ui", "dist", "index.html"))
	if err != nil {
		t.Fatalf("the committed UI distribution is missing: %v", err)
	}
	if len(embedded) == 0 {
		t.Fatal("the committed UI distribution is empty")
	}

	home := t.TempDir()
	process := exec.Command(binary, "-open=false")
	process.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	process.Stderr = &stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	t.Cleanup(func() {
		_ = process.Process.Signal(syscall.SIGKILL)
		<-stopped
	})

	lines := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		line, _ := reader.ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()

	var announced string
	select {
	case announced = <-lines:
	case <-time.After(15 * time.Second):
		t.Fatalf("the binary printed no URL within 15s; stderr:\n%s", stderr.String())
	}
	if !strings.HasPrefix(announced, "http://127.0.0.1:") || !strings.Contains(announced, "/#bootstrap=") {
		t.Fatalf("announced URL = %q", announced)
	}
	base, fragment, _ := strings.Cut(announced, "/#bootstrap=")
	host := strings.TrimPrefix(base, "http://")
	if len(fragment) != 43 {
		t.Fatalf("bootstrap fragment length = %d, want 43", len(fragment))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = host
	request.Header.Set("Accept", "text/html")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET / = %v", err)
	}
	served := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", response.StatusCode)
	}
	if served != string(embedded) {
		t.Fatal("the binary served something other than the UI it embedded")
	}

	bootstrap, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/api/v1/session/bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap.Host = host
	bootstrap.Header.Set("Origin", base)
	bootstrap.Header.Set("Sec-Fetch-Site", "same-origin")
	bootstrap.Header.Set("X-SSH-UI-Bootstrap", fragment)
	exchanged, err := client.Do(bootstrap)
	if err != nil {
		t.Fatalf("bootstrap = %v", err)
	}
	exchangedStatus := exchanged.StatusCode
	readBody(t, exchanged)
	if exchangedStatus != http.StatusOK {
		t.Fatalf("bootstrap = %d", exchangedStatus)
	}

	if _, err := os.Stat(filepath.Join(home, ".ssh")); err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat of the temporary home failed: %v", err)
	}

	go func() { stopped <- process.Wait() }()
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("the binary exited with %v after SIGTERM; stderr:\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the binary did not exit within 10s of SIGTERM; stderr:\n%s", stderr.String())
	}

	if combined := stderr.String(); strings.Contains(combined, fragment) {
		t.Fatal("the binary logged the bootstrap token on standard error")
	}
	if strings.Count(announced, fragment) != 1 {
		t.Fatal("the bootstrap token appeared more than once in the announced URL")
	}
}

// TestNoTestOnlyPackageReachesTheShippedBinary keeps the hardening suite out of
// the artefact. internal/acceptance is test-only by construction, but a future
// helper moved into a non-test file would change that silently.
func TestNoTestOnlyPackageReachesTheShippedBinary(t *testing.T) {
	list := exec.Command("go", "list", "-deps", "./cmd/ssh-ui")
	list.Dir = filepath.Join("..", "..")
	output, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list = %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		switch strings.TrimSpace(line) {
		case "ssh-ui/internal/acceptance":
			t.Error("the hardening suite is linked into the shipped binary")
		case "testing", "net/http/httptest":
			t.Errorf("%s is linked into the shipped binary", strings.TrimSpace(line))
		}
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/acceptance -run 'TestBuiltBinaryServesTheEmbeddedUIAndStopsOnSIGTERM|TestNoTestOnlyPackageReachesTheShippedBinary' -v`
Expected: PASS. The build step takes a few seconds; that is the price of testing the artefact rather than a stand-in.

- [ ] **Step 3: Prove it has teeth**

| Mutation | File | Assertion that must fail |
|---|---|---|
| Change `//go:embed all:dist` to embed an empty directory | `internal/ui/embed.go` | the served-bytes comparison |
| Remove `syscall.SIGTERM` from `signal.NotifyContext` | `cmd/ssh-ui/main.go` | the 10-second shutdown deadline |
| Add `logger.Info("target", "url", target)` to `Run` | `internal/app/run.go` | the stderr token check |

Run each, confirm FAIL, then `git checkout -- <file>`.

- [ ] **Step 4: Add the generated-contract reproducibility target**

Add to `Makefile`:

```make
# verify-generated regenerates the API models and fails if the committed ones
# differ. It is the proof that api/openapi.yaml is still the single source for
# both the Go models and the TypeScript types.
verify-generated: generate
	git diff --exit-code -- internal/api/models.gen.go web/src/api/schema.d.ts
```

Run: `make verify-generated`
Expected: `generate` runs both generators and `git diff --exit-code` prints nothing and exits 0. A non-empty diff means the committed models drifted from the contract; commit the regenerated files rather than editing them by hand.

- [ ] **Step 5: Confirm the build is a single self-contained artefact**

```bash
make build
ls -l bin/ssh-ui
otool -L bin/ssh-ui
strings bin/ssh-ui | grep -c '<div id="root">'
```

Expected: `bin/ssh-ui` exists; `otool -L` lists only system libraries (`libSystem`, `CoreFoundation`, `Security`), no bundled runtime; the `strings` count is at least 1, showing the UI is inside the binary. Record the byte size in the commit message so a later change that doubles it is visible.

- [ ] **Step 6: Document the release commands**

Update the `## 開発コマンド` block in `README.md`:

```sh
make generate         # OpenAPI から Go/TypeScript 型を再生成
make verify-generated # 生成物が契約と一致することを確認
make test             # Go、race detector、Vitest、TypeScript を検証
make fuzz             # 全 fuzz target を既定 30 秒ずつ実行（FUZZTIME で変更）
make e2e              # バイナリをビルドし Playwright で主要フローを検証
make build            # UI を生成し bin/ssh-ui へ単一バイナリを作成
```

and append to the 強化とリリースの境界 section:

```markdown
- `./bin/ssh-ui -open=false` は既定ブラウザを開かず、bootstrap fragment 付き URL を標準出力へ 1 行だけ出します。自動化用の明示的なオプションであり、通常の利用では使いません。token は `open <url>` の argv と同程度の露出であり、それ以上ではありません。
- 配布物は UI を埋め込んだ単一バイナリです。`otool -L` はシステムライブラリのみを表示し、同梱ランタイムはありません。
```

- [ ] **Step 7: Commit**

```bash
go test ./internal/acceptance
git add internal/acceptance/binary_test.go Makefile README.md
git commit -m "test: build, serve and terminate the shipped binary, and verify contract reproducibility"
```

---

## Task 8: The completion-condition audit, the manual checklist and the roadmap

**Files:**
- Create: `internal/acceptance/conditions_test.go`
- Create: `docs/manual-acceptance.md`
- Modify: `docs/superpowers/plans/2026-08-04-ssh-ui-roadmap.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: every test and command the previous seven tasks and the four earlier plans produced.
- Produces: `TestDesignCompletionConditions`, which prints the audit table and fails when a condition names a proof that no longer exists.

Design §12 lists the completion conditions as bullets. **The list contains twelve bullets, not thirteen.** This plan's brief said thirteen; rather than quietly reconcile the difference, the table below carries all twelve verbatim and adds a thirteenth row for the isolation rule that §10.1 states and the roadmap repeats — "No plan may run against the user's real `~/.ssh` in automated tests" — because it is the one project-wide promise §12 assumes without listing. If the intended thirteenth was something else, the row is cheap to replace and the other twelve are unaffected.

The audit is machine-checked. Each row names the tests and commands that prove it, and the test asserts each named artefact still exists. A renamed or deleted test therefore breaks the audit instead of leaving a stale claim in a document nobody re-reads.

**Teeth:** Step 4 deletes one referenced test and confirms the audit fails, then restores it.

- [ ] **Step 1: Write the manual acceptance checklist**

Create `docs/manual-acceptance.md`:

```markdown
# 手動受け入れ試験

自動テストが決して行わない操作をここに集めます。設計 §10.5 のとおり、実リモート接続、実 `authorized_keys` 変更、実 Keychain、実 Terminal 起動は自動化しません。

実施前に必ず読むこと。

- 実施は使い捨ての `HOME` で行い、本番の `~/.ssh` では行いません。
  `work="$(mktemp -d)"; cp -R ~/.ssh "$work/.ssh"; HOME="$work" ./bin/ssh-ui`
- 本番の `~/.ssh` を使う項目（Keychain と Terminal）は、事前に `~/.ssh` と `~/.ssh/ssh-ui` を別ディレクトリへ退避してから行います。
- 各項目に日付、macOS と OpenSSH のバージョン、結果を記録します。

## M1. 実リモートホストへの接続テスト

1. 使い捨て `HOME` に、自分が管理する検証用ホストの `Host` ブロックを作る。
2. Diagnostics タブで「到達性」を実行し、`ProxyJump は使用していない` という注記が出ることを確認する。
3. 「認証テスト」を実行する。
4. 期待: 認証成功が報告され、stderr は 8 KiB 以内に切り詰められ、鍵本文もパスフレーズも表示されない。
5. 実行可能ディレクティブを持つ設定では、確認ダイアログに実際のコマンド文字列が表示され、確認するまで開始しないことを確認する。

## M2. 実 `authorized_keys` への公開鍵登録

1. 検証用リモートホストに、削除してよい検証用ユーザーを用意する。
2. 登録前に、対象 alias、実効ユーザー、fingerprint、実行される固定スクリプトが表示されることを確認する。
3. 登録を実行し、リモートの `~/.ssh` が `0700`、`authorized_keys` が `0600` になっていることを `ls -l` で確認する。
4. 同じ鍵をもう一度登録し、`already_present` として重複行が増えないことを確認する。
5. 登録した行をリモートから削除して原状復帰する。

## M3. 実 macOS Keychain と ssh-agent

1. 本番の `~/.ssh` を退避したうえで実施する。
2. 鍵を Keychain へ登録し、`ssh-add -l` に現れることを確認する。
3. `security find-generic-password -s "SSH: <path>"` で Keychain 項目が作られたことを確認する。
4. `ssh-add -d <path>` と Keychain 項目の削除で原状復帰する。
5. パスフレーズが `ps` の出力にも環境変数にも現れないことを、登録中に `ps -Eww -p $(pgrep ssh-add)` で確認する。

## M4. 実 Terminal 起動

1. 安全な alias で「Terminal で開く」を実行し、Terminal.app が前面に来て `ssh -- <alias>` が実行されることを確認する。
2. Terminal のコマンド履歴に、意図した 1 行だけが入っていることを確認する。
3. 安全でない alias（空白、引用符、先頭ハイフンを含むもの）では起動ボタンが無効で、コピー用コマンドと警告だけが表示されることを確認する。

## M5. 実 `~/.ssh` での読み取り専用リハーサル

1. 本番の `~/.ssh` をコピーした使い捨て `HOME` で起動する。
2. Connections、Config、Groups、Keys、Known Hosts、History の各画面を開くだけで、何も保存しない。
3. 終了後、`diff -r ~/.ssh "$work/.ssh"` が `ssh-ui/` 配下以外で差分を出さないことを確認する。
4. 期待: 読み取りだけで既存ファイルが 1 バイトも変わらない。

## 記録

| 日付 | 項目 | macOS | OpenSSH | 結果 | 備考 |
|---|---|---|---|---|---|
|  | M1 |  |  |  |  |
|  | M2 |  |  |  |  |
|  | M3 |  |  |  |  |
|  | M4 |  |  |  |  |
|  | M5 |  |  |  |  |
```

- [ ] **Step 2: Write the audit test**

Create `internal/acceptance/conditions_test.go`:

```go
package acceptance_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type proofKind int

const (
	proofGoTest proofKind = iota
	proofVitest
	proofPlaywright
	proofCommand
	proofManual
)

type proof struct {
	Kind      proofKind
	Reference string
}

type completionCondition struct {
	Number int
	// Text is design §12 verbatim, or, for row 13, §10.1 verbatim.
	Text string
	// Automated names everything a machine checks.
	Automated []proof
	// Manual names the part automation must not perform. An empty list means
	// the condition is fully covered by automation.
	Manual []proof
	// Gap states plainly what is not proven, and is empty when nothing is.
	Gap string
}

func completionConditions() []completionCondition {
	return []completionCondition{
		{
			Number: 1,
			Text:   "既存 fixture を無変更で読み書きして byte-for-byte 一致する",
			Automated: []proof{
				{proofGoTest, "FuzzParseRendersOriginalBytes"},
				{proofGoTest, "FuzzParseKnownHostsRoundTrip"},
				{proofCommand, "fuzz"},
				{proofPlaywright, "edits a host through the form and writes only the line that changed"},
			},
		},
		{
			Number: 2,
			Text:   "一般的な項目はフォーム、すべての項目は Raw で編集できる",
			Automated: []proof{
				{proofPlaywright, "edits a host through the form and writes only the line that changed"},
				{proofPlaywright, "edits the same host through Raw and keeps every other byte"},
				{proofPlaywright, "shows the Include hierarchy and edits an included file"},
			},
		},
		{
			Number: 3,
			Text:   "コメント、未知ディレクティブ、Include 構造を保持する",
			Automated: []proof{
				{proofGoTest, "FuzzParseRendersOriginalBytes"},
				{proofGoTest, "FuzzExpandIncludePattern"},
				{proofPlaywright, "shows the Include hierarchy and edits an included file"},
				{proofGoTest, "TestAnAliasOpenSSHWouldAcceptIsStillRefusedForEveryExternalEffect"},
			},
		},
		{
			Number: 4,
			Text:   "Include 階層、単一プライマリグループ、親子継承が機能する",
			Automated: []proof{
				{proofGoTest, "TestRouteTableMatchesTheOpenAPIContract"},
				{proofPlaywright, "shows the Include hierarchy and edits an included file"},
				{proofCommand, "test"},
			},
			Gap: "group inheritance is proven by subsystem 3's own suite; this plan re-runs it through `make test` rather than duplicating it.",
		},
		{
			Number: 5,
			Text:   "多段 ProxyJump と値の出所を表示できる",
			Automated: []proof{
				{proofGoTest, "TestProjectionMatchesInstalledOpenSSH"},
				{proofGoTest, "FuzzParseValues"},
			},
			Gap: "the differential test reports SKIP on a machine without OpenSSH; on such a machine this condition is unproven and the acceptance gate says so.",
		},
		{
			Number: 6,
			Text:   "鍵生成、公開鍵コピー、秘密鍵 reveal、agent 登録、隔離、復元が機能する",
			Automated: []proof{
				{proofPlaywright, "lists generated keys and reveals one only after an explicit confirmation"},
				{proofGoTest, "TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken"},
				{proofGoTest, "TestNoResponseCarriesASecretItIsNotEntitledTo"},
			},
			Manual: []proof{{proofManual, "M3. 実 macOS Keychain と ssh-agent"}},
			Gap:    "ssh-agent and Keychain registration is exercised against a fake; the real agent and the real Keychain are manual test M3.",
		},
		{
			Number: 7,
			Text:   "config 変更前に差分、保存前にバックアップを確認できる",
			Automated: []proof{
				{proofPlaywright, "shows a save preview diff before anything else changes"},
				{proofPlaywright, "records a change in history and restores the previous bytes"},
			},
		},
		{
			Number: 8,
			Text:   "外部変更と部分失敗で既存設定を黙って破壊しない",
			Automated: []proof{
				{proofPlaywright, "refuses a save whose base is stale and shows the three-way conflict"},
				{proofGoTest, "TestNoRouteWritesOutsideTheWorkspaceOrThroughASymbolicLink"},
				{proofCommand, "test"},
			},
			Gap: "interrupted-transaction recovery is proven by subsystem 2's journal suite, which `make test` re-runs.",
		},
		{
			Number: 9,
			Text:   "接続テスト、Terminal 起動、Known Hosts、公開鍵登録が明示操作で機能する",
			Automated: []proof{
				{proofGoTest, "TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken"},
				{proofGoTest, "TestTerminalLaunchNeverBuildsAppleScriptFromInput"},
				{proofGoTest, "TestRemoteRegistrationNeverInterpolatesInputIntoTheRemoteShell"},
			},
			Manual: []proof{
				{proofManual, "M1. 実リモートホストへの接続テスト"},
				{proofManual, "M2. 実 `authorized_keys` への公開鍵登録"},
				{proofManual, "M4. 実 Terminal 起動"},
			},
			Gap: "every automated proof stops at the process seam. That an actual connection succeeds, an actual authorized_keys line appears and Terminal actually opens is manual tests M1, M2 and M4.",
		},
		{
			Number: 10,
			Text:   "localhost API が token、Host、Origin、Fetch Metadata で保護される",
			Automated: []proof{
				{proofGoTest, "TestEveryAPIRouteRefusesTheWrongHostOriginAndFetchSite"},
				{proofGoTest, "TestEveryAPIRouteExceptBootstrapRequiresASession"},
				{proofGoTest, "TestBootstrapTokenIsSingleUse"},
				{proofGoTest, "TestServerRefusesEveryListenerThatIsNotUnmappedLoopbackIPv4"},
				{proofGoTest, "TestEveryAPIResponseIsNoStoreAndCarriesTheExactPolicy"},
				{proofPlaywright, "exchanges the fragment for a session and removes it from the address bar"},
				{proofPlaywright, "enforces the content security policy in the browser, not only in the header"},
			},
		},
		{
			Number: 11,
			Text:   "危険ディレクティブを暗黙実行しない",
			Automated: []proof{
				{proofGoTest, "TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken"},
				{proofGoTest, "TestNoRouteEverPutsAHostileValueOnACommandLine"},
				{proofGoTest, "TestProjectionMatchesInstalledOpenSSH"},
			},
		},
		{
			Number: 12,
			Text:   "バックエンド、フロントエンド、セキュリティ、race、E2E テストが成功する",
			Automated: []proof{
				{proofCommand, "test"},
				{proofCommand, "fuzz"},
				{proofCommand, "e2e"},
				{proofCommand, "verify-generated"},
				{proofGoTest, "TestMakefileFuzzTargetsCoverEveryFuzzFunction"},
				{proofGoTest, "TestBuiltBinaryServesTheEmbeddedUIAndStopsOnSIGTERM"},
			},
		},
		{
			Number: 13,
			Text:   "自動テストは実際の ~/.ssh、Keychain、ssh-agent、Terminal、実サーバーを使用しない（§10.1）",
			Automated: []proof{
				{proofGoTest, "TestHarnessStartsTheProductionServerAgainstAnIsolatedHome"},
				{proofGoTest, "TestNoTestOnlyPackageReachesTheShippedBinary"},
				{proofGoTest, "TestNoLogLineCarriesASecret"},
			},
			Manual: []proof{{proofManual, "M5. 実 ~/.ssh での読み取り専用リハーサル"}},
		},
	}
}

func TestDesignCompletionConditions(t *testing.T) {
	repository := filepath.Join("..", "..")
	sources := collectSources(t, repository)

	t.Log("design §12 completion conditions")
	for _, condition := range completionConditions() {
		condition := condition
		t.Run(fmt.Sprintf("condition_%02d", condition.Number), func(t *testing.T) {
			if len(condition.Automated) == 0 {
				t.Fatalf("condition %d names no automated proof", condition.Number)
			}
			for _, item := range append(append([]proof(nil), condition.Automated...), condition.Manual...) {
				if !proofExists(sources, item) {
					t.Errorf("condition %d names %q, which no longer exists", condition.Number, item.Reference)
				}
			}
			if len(condition.Manual) > 0 && condition.Gap == "" {
				t.Errorf("condition %d has a manual part but states no gap", condition.Number)
			}
			status := "holds by automation"
			if len(condition.Manual) > 0 {
				status = "holds by automation up to the process seam; the rest is manual"
			}
			t.Logf("%2d  %s\n    %s\n    %s", condition.Number, condition.Text, status, condition.Gap)
		})
	}
}

type sourceIndex struct {
	goTests    string
	vitest     string
	playwright string
	makefile   string
	manual     string
}

func collectSources(t testing.TB, repository string) sourceIndex {
	t.Helper()
	index := sourceIndex{
		makefile: mustReadText(t, filepath.Join(repository, "Makefile")),
		manual:   mustReadText(t, filepath.Join(repository, "docs", "manual-acceptance.md")),
	}
	var goTests, vitest, playwright strings.Builder
	err := filepath.WalkDir(repository, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "bin", ".claude", ".worktrees", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, "_test.go"):
			goTests.WriteString(mustReadText(t, path))
		case strings.HasSuffix(name, ".spec.ts"):
			playwright.WriteString(mustReadText(t, path))
		case strings.HasSuffix(name, ".test.ts"), strings.HasSuffix(name, ".test.tsx"):
			vitest.WriteString(mustReadText(t, path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	index.goTests = goTests.String()
	index.vitest = vitest.String()
	index.playwright = playwright.String()
	return index
}

func mustReadText(t testing.TB, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func proofExists(sources sourceIndex, item proof) bool {
	switch item.Kind {
	case proofGoTest:
		return strings.Contains(sources.goTests, "func "+item.Reference+"(")
	case proofVitest:
		return strings.Contains(sources.vitest, item.Reference)
	case proofPlaywright:
		return strings.Contains(sources.playwright, item.Reference)
	case proofCommand:
		return strings.Contains(sources.makefile, "\n"+item.Reference+":")
	case proofManual:
		return strings.Contains(sources.manual, item.Reference)
	default:
		return false
	}
}
```

- [ ] **Step 3: Run the audit and read its output**

Run: `go test ./internal/acceptance -run TestDesignCompletionConditions -v`
Expected: PASS, with thirteen numbered log entries stating, for each condition, whether it holds by automation alone or only up to the process seam.

If a row names a test that was renamed while subsystems 3, 4 or 5 were executed, **update the row to the name that is in the tree**. Never delete a row to make the audit green; a deleted row is a condition nobody is proving.

- [ ] **Step 4: Prove the audit has teeth**

Rename `TestBootstrapTokenIsSingleUse` to `TestBootstrapTokenIsSingleUseRenamed` in `internal/acceptance/transport_test.go`.

Run: `go test ./internal/acceptance -run TestDesignCompletionConditions`
Expected: FAIL with `condition 10 names "TestBootstrapTokenIsSingleUse", which no longer exists`.

Restore the name with `git checkout -- internal/acceptance/transport_test.go` and re-run; expect PASS.

- [ ] **Step 5: Record the subsystem in the roadmap**

In `docs/superpowers/plans/2026-08-04-ssh-ui-roadmap.md`, replace the subsystem 6 status line and extend the dependency note:

```markdown
- Subsystem 6 (Hardening and release): delivered; plan `2026-08-05-ssh-ui-hardening-release-implementation-plan.md`, 8 tasks. Adds `internal/acceptance` as a test-only package, four new fuzz targets, a Playwright end-to-end suite, `make fuzz`/`make e2e`/`make verify-generated`, and the design §12 audit in `TestDesignCompletionConditions`. Dependencies added: `@playwright/test` 1.62.1 (devDependency) and `gopkg.in/yaml.v3` v3.0.1 promoted from indirect to direct; `go.sum` unchanged.
- Fetch Metadata is now verified on every `/api/` request, not only on state-changing ones. Any later plan that adds an authenticated GET must send `Sec-Fetch-Site: same-origin` in its tests.
- The manual acceptance checklist lives in `docs/manual-acceptance.md`. Real remote connections, real `authorized_keys` changes, the real Keychain and a real Terminal launch are there and must stay out of automation.
```

- [ ] **Step 6: Finish the README boundary section**

Append to the 強化とリリースの境界 section in `README.md`:

```markdown
- 自動テストは実際の `~/.ssh`、Keychain、ssh-agent、Terminal、リモートホストへ一切触れません。実バイナリを起動する試験でも `HOME` は一時ディレクトリです。実際に外部へ影響する操作は `docs/manual-acceptance.md` の手動試験に分離しています。
- 設計 §12 の完成条件は `go test ./internal/acceptance -run TestDesignCompletionConditions -v` で一覧できます。各条件について、それを証明するテスト名とコマンド名、そして自動化が届かない範囲を出力します。
- `internal/acceptance` はテストファイルのみで構成され、配布バイナリには含まれません。`TestNoTestOnlyPackageReachesTheShippedBinary` がそれを検査します。
```

- [ ] **Step 7: Run everything and commit**

```bash
make verify-generated
make test
make fuzz
PLAYWRIGHT_BROWSERS_PATH=./web/.playwright-browsers make e2e
go vet ./...
git add internal/acceptance/conditions_test.go docs/manual-acceptance.md docs/superpowers/plans/2026-08-04-ssh-ui-roadmap.md README.md
git commit -m "docs: audit the design completion conditions and record the manual acceptance tests"
```

---

## Hardening and Release Acceptance Gate

Run every command and confirm every statement before calling the subsystem done.

```bash
make verify-generated
make test
make fuzz
PLAYWRIGHT_BROWSERS_PATH=./web/.playwright-browsers make e2e
make build
go vet ./...
go test ./internal/acceptance -run TestDesignCompletionConditions -v
```

- `make verify-generated` prints no diff: `internal/api/models.gen.go` and `web/src/api/schema.d.ts` reproduce exactly from `api/openapi.yaml`.
- `make test` passes, including `go test -race ./...`, Vitest and both TypeScript projects.
- `make fuzz` runs **five** targets — `FuzzParseRendersOriginalBytes`, `FuzzExpandIncludePattern`, `FuzzParseValues`, `FuzzParseKnownHostsRoundTrip`, `FuzzAPIRequestBodies` — for `FUZZTIME` each, with no failing input, and `git status --short` shows no new file under any `testdata/fuzz` directory.
- `TestMakefileFuzzTargetsCoverEveryFuzzFunction` passes, so no fuzz target exists that `make fuzz` does not run.
- `make e2e` passes on a freshly built `bin/ssh-ui`, twice in a row.
- `make build` produces `bin/ssh-ui`; `otool -L bin/ssh-ui` lists only system libraries; `strings bin/ssh-ui | grep -c '<div id="root">'` is at least 1.
- Every `/api/` route in the router appears in `api/openapi.yaml` and vice versa (`TestRouteTableMatchesTheOpenAPIContract`).
- Every `/api/` route refuses a wrong `Host`, a wrong `Origin`, `Sec-Fetch-Site: cross-site`, `same-site`, `none` and an absent `Sec-Fetch-Site`, and every route except bootstrap refuses a request with no session.
- Every `/api/` response, successful and failed, authenticated and not, carries `Cache-Control: no-store` and the exact CSP string, which contains no `unsafe-inline`, no `unsafe-eval`, no `*` and no scheme source.
- Chromium refuses to run an inline script and refuses a cross-origin `fetch` from the served page, so the policy is enforced and not merely announced.
- The bootstrap token is refused on replay and sets no cookie; the session cookie is `HttpOnly` and `SameSite=Strict`; the fragment is gone from `location.hash` after the exchange.
- `httpserver.New` refuses every listener that is not an unmapped IPv4 `127.0.0.1` address, including the IPv4-mapped IPv6 form, `::1`, the wildcard, a routable address and a Unix socket.
- Every token-guarded route refuses a missing token, a token issued for another kind, a token issued for another target, a spent token, an expired token and an invented token — and in each case no command was recorded, no Terminal launch happened, and `known_hosts` is unchanged.
- No response body outside the named content-bearing routes contains configuration file bytes; no response outside `POST /api/v1/keys/:keyId/reveal` contains private key material; no response anywhere contains the passphrase, the bootstrap token, the session id, or the file planted outside `~/.ssh`.
- The captured log stream contains none of those values and no absolute home path.
- Every hostile alias, hostname and port is either refused before a process starts or arrives as one whole argument after a `--` separator that cannot be read as an option.
- `macos.TerminalScript` contains no substitution point, uses `quoted form of`, and takes the alias from `argv`; the alias never appears in the script text.
- `remotekey.Routine` is unchanged by any input; the public key travels on standard input and never in argv; a public key with a newline, a NUL, a shell metacharacter in its comment or an invalid base64 body is refused.
- No route writes outside the resolved `~/.ssh`, through a symbolic link, or through a directory component swapped for a symbolic link after the read; the file planted outside the workspace is byte-identical after the whole suite.
- A configuration containing a `Host` alias with a NUL, a newline or a leading hyphen still round-trips byte-for-byte, and every external effect for that alias is refused.
- Request bodies are bounded on every route by `MaxRequestBodyCeiling` and by each handler's own limit; an oversized body is refused with a 4xx that echoes nothing back and starts no command.
- A truncated `ssh -G` transcript never becomes an effective value; reported stderr stays inside `MaxReportedOutput`.
- `bin/ssh-ui` starts under a temporary `HOME`, prints one loopback URL with a 43-character bootstrap fragment, serves bytes identical to the committed `internal/ui/dist/index.html`, exchanges the bootstrap token, and exits 0 within 10 seconds of `SIGTERM` without logging the token.
- `go list -deps ./cmd/ssh-ui` contains neither `ssh-ui/internal/acceptance` nor `testing`.
- `@playwright/test` is a `devDependencies` entry pinned to `1.62.1`, appears nowhere in `internal/ui/dist/`, and its browser lives in `web/.playwright-browsers/`, which is ignored by git.
- `go.mod` gained exactly one direct requirement, `gopkg.in/yaml.v3 v3.0.1`, and `go.sum` is unchanged: `git diff --stat go.sum` is empty.
- No test contacted a remote host, changed a real `authorized_keys`, or touched the real `~/.ssh`, Keychain, `ssh-agent` or Terminal. Confirm with:

```bash
grep -rn "UserHomeDir\|os.Getenv(\"HOME\")" internal/ || echo "no internal package reads the home directory"
ls -la ~/.ssh/ssh-ui 2>/dev/null || echo "no state directory in the real home"
find ~/.ssh -newermt '-30 minutes' 2>/dev/null || echo "no recently modified file in the real ~/.ssh"
```

- The only skipped tests in the whole repository are the two documented OpenSSH capability checks. Confirm with:

```bash
go test ./... -v 2>&1 | grep -E '^\s*--- SKIP' | sort -u
```

Expected output: exactly `--- SKIP: TestEvaluateParsesInstalledOpenSSHOutput` and `--- SKIP: TestProjectionMatchesInstalledOpenSSH` on a machine without OpenSSH, and **no output at all** on a machine with it. Any other skip is a failure of this gate; delete the skip or turn it into a real capability check with a written reason.

- `TestDesignCompletionConditions` passes and its log states, for all thirteen rows, which hold by automation alone and which hold only up to the process seam. On a machine without OpenSSH installed, condition 5 is recorded as unproven, because its differential proof skipped.
- The manual acceptance checklist in `docs/manual-acceptance.md` has been read, and M1 through M5 are either recorded as performed with dates, or explicitly recorded as not yet performed. An unperformed manual test is an honest gap; a silently omitted one is not.

## Manual Acceptance Checklist

Automation must never perform these. They are reproduced here so the plan is self-contained; `docs/manual-acceptance.md` is the copy that lives with the code and receives the dated results.

| # | Test | What automation cannot do | Preparation |
|---|---|---|---|
| M1 | Real remote connection test | Prove that reachability and authentication against a real server behave as the fakes claim, and that a real OpenSSH honours the `-o` hardening options | A disposable `HOME`, and a verification host the tester administers |
| M2 | Real `authorized_keys` registration | Prove the fixed remote routine runs under a real POSIX shell, tightens the remote permissions, and avoids a duplicate line on a second run | A disposable remote account whose `authorized_keys` may be edited and restored |
| M3 | Real macOS Keychain and `ssh-agent` | Prove `ssh-add` accepts the passphrase on standard input, the Keychain item is created, and the passphrase appears in neither `ps` output nor the environment | The real `~/.ssh` moved aside first |
| M4 | Real Terminal launch | Prove `osascript` actually opens Terminal.app, runs exactly one `ssh -- <alias>` line, and that an unsafe alias offers only a copyable command | The real `~/.ssh` moved aside first |
| M5 | Read-only rehearsal against a copy of the real `~/.ssh` | Prove that browsing every screen of a realistic, personal configuration changes not one byte | A copy of the real `~/.ssh` inside a disposable `HOME` |

Each entry records the date, the macOS and OpenSSH versions, the result and any deviation. Restore every external change made during M2, M3 and M4 before finishing.

## Self-review notes

Checked after writing, against design §8, §10.4, §10.5, §11 item 6, §12 and §13, and against the four earlier plans.

- **Spec coverage.** §8.1 is covered by Task 1 (loopback bind, random port, bootstrap single use, session in memory, Host/Origin/Fetch Metadata, no CORS) and Task 2 (body and output ceilings). §8.2 is covered by Task 1 (CSP, no external resources), Task 3 (action tokens, no secret in a response or a log) and Task 6 (no secret in persistent browser storage, fragment removed). §8.3 is covered by Task 3's guarded-route table and Task 4's argv assertions. §10.4's nine bullets each map to a named test. §10.5's eight bullets map to Task 6's five specs plus the earlier plans' Vitest suites, which `make test` re-runs. §11 item 6 — security hardening, fuzz, E2E, single binary, acceptance — is Tasks 1-8 in order. §12 is Task 8. §13's four answers are the reasons written into the tasks: reveal stays separated and no-store (Task 3), the hybrid editor is exercised through both form and Raw (Task 6), Include is not presented as inheritance (Task 8 condition 4 defers to subsystem 3 and says so), and the atomicity limit is why Task 4 asserts refusals leave files unchanged rather than asserting rollback.
- **Gaps found and closed while writing.** Fetch Metadata was verified only on state-changing requests; Task 1 extends it and lists the test repairs. No middleware-level body ceiling existed; Task 2 adds one without disturbing the per-handler limits. No test read the log stream, which subsystem 4's gate named as an untested constraint; Task 3 adds one. `make fuzz` ran only the first target; Task 5 fixes it and adds a coverage test so it cannot regress.
- **Gaps found and left open, deliberately.** Group inheritance, journal recovery and the Vitest component suites stay with subsystems 2 and 3; this plan re-runs them through `make test` rather than duplicating them, and the audit rows say so. `~/.ssh` file and folder move, rename and delete remain with the `ssh-ui-file-operations` follow-up. Design §12 has twelve bullets, not the thirteen the brief expected; the discrepancy is stated in Task 8 rather than papered over.
- **Placeholder scan.** No "TBD", no "add appropriate error handling", no "similar to Task N". Every code step carries the code. The one instruction that cannot name its targets in advance — Task 1 Step 8's repair of existing GET tests — names the exact line to add and the rule for judging each failure, because the number of affected files depends on how subsystems 3, 4 and 5 merged.
- **Type consistency.** `httpserver.Route{Method, Path}` is produced in Task 1 and consumed in Tasks 1, 2, 3 and 5. `app.Build(Dependencies, string) (*httpserver.Server, string, error)` is produced in Task 1 and consumed by `newFixture` and by `Run`. `MaxRequestBodyCeiling` is deliberately not `MaxRequestBody`, which subsystem 5 already exports at 64 KiB. `newFixture` takes `testing.TB`, not `*testing.T`, because Task 5's fuzz target passes a `*testing.F`. `session.ActionRequest{Kind, Target, Evidence}` and the `private_key.reveal` / `trash.purge` spellings follow the committed tree, not subsystem 4's superseded `Action{Purpose, Subject}`. `hostileArguments` is declared once in Task 4 and reused in Task 5's seeds. `quoteForName`, `assertArgumentIsInert`, `readBody`, `mustJSON`, `emptyBodyFor` and `maxAcceptableResponseBytes` each have exactly one declaration.
