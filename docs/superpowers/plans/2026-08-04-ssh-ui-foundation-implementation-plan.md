# SSH UI Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable macOS `ssh-ui` command that starts a token-protected loopback server, opens an embedded React shell, bootstraps a same-origin session, and exposes an authenticated health endpoint.

**Architecture:** A Go 1.26 CLI owns a `127.0.0.1:0` listener and Echo v5 server. It generates a one-time bootstrap secret, opens a fragment-bearing URL through a macOS adapter, exchanges the secret for an in-memory HttpOnly session and CSRF token, and serves a Vite-built React application from the same binary. OpenAPI is the API contract for generated Go models and TypeScript types.

**Tech Stack:** Go 1.26.5, Echo v5.3.1, oapi-codegen v2.7.0, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, React Testing Library 16.3.2, npm 11.7.0.

## Global Constraints

- Bind only to `127.0.0.1` on an OS-assigned random port; never bind to `0.0.0.0`, `::`, or a fixed port.
- The server exists only while the `ssh-ui` process runs; this plan must not create a LaunchAgent or background daemon.
- Automated tests must not read or modify the user's real `~/.ssh`, Keychain, ssh-agent, Terminal, or remote hosts.
- Do not log request bodies, cookies, authorization values, bootstrap tokens, CSRF tokens, keys, or passphrases.
- Do not use external scripts, CDNs, fonts, analytics, telemetry, or remote frontend assets.
- API and UI are same-origin; do not enable CORS.
- Keep all secrets in process memory only. The bootstrap token is single-use and the session dies with the process.
- Keep macOS-specific behavior behind a platform interface; do not claim Linux or Windows support.
- Use Echo v5 APIs, including `*echo.Context` handler parameters; do not introduce Echo v4 compatibility code.
- Pin direct dependencies exactly and commit `go.sum` and `web/package-lock.json`.
- Go, npm and project dependency installation are explicitly approved; keep installations project-scoped except for the approved Go toolchain switch.

---

## File Structure

```text
.
├── api/
│   ├── openapi.yaml                   # HTTP contract
│   └── oapi-codegen.yaml              # Go model generator settings
├── cmd/ssh-ui/main.go                 # process entrypoint and signal handling
├── internal/
│   ├── api/
│   │   ├── generate.go                # pinned go:generate command
│   │   └── models.gen.go              # generated OpenAPI models
│   ├── app/run.go                     # listener, token, browser and server orchestration
│   ├── httpserver/
│   │   ├── handlers.go                # bootstrap and health handlers
│   │   ├── security.go                # Host, Origin, session, CSRF and response headers
│   │   └── server.go                  # Echo routes and listener lifecycle
│   ├── platform/
│   │   ├── browser.go                 # BrowserLauncher and CommandRunner contracts
│   │   └── macos/browser.go           # `open` adapter without a shell
│   ├── session/manager.go             # one-use bootstrap and in-memory sessions
│   └── ui/
│       ├── embed.go                   # embedded Vite distribution
│       └── dist/                      # generated static assets
├── web/
│   ├── src/
│   │   ├── api/client.ts              # same-origin fetch and in-memory CSRF state
│   │   ├── api/schema.d.ts            # generated OpenAPI types
│   │   ├── session/bootstrap.ts       # fragment exchange and history cleanup
│   │   ├── App.tsx                    # authenticated application shell
│   │   ├── index.css                  # local Tailwind import and theme tokens
│   │   └── main.tsx                   # React entrypoint
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── vitest.setup.ts
├── Makefile                           # reproducible generate/test/build commands
├── README.md                          # local development and security notes
├── go.mod
└── go.sum
```

## Task 1: Pin the toolchain and generate the API contract

**Files:**
- Create: `.gitignore`
- Create: `go.mod`
- Create: `api/openapi.yaml`
- Create: `api/oapi-codegen.yaml`
- Create: `internal/api/generate.go`
- Create: `internal/api/contract_test.go`
- Generate: `internal/api/models.gen.go`
- Create: `web/package.json`
- Generate: `web/package-lock.json`
- Create: `web/tsconfig.json`
- Create: `web/vite.config.ts`
- Generate: `web/src/api/schema.d.ts`

**Interfaces:**
- Produces: `api.HealthResponse{Status string, Version string}`.
- Produces: `api.BootstrapResponse{CsrfToken string}`.
- Produces: TypeScript `paths` definitions for `/api/v1/session/bootstrap` and `/api/v1/health`.
- Consumes: no application interfaces.

- [ ] **Step 1: Create the minimal module and write the failing generated-contract test**

```go
// go.mod
module ssh-ui

go 1.26.0
```

```go
// internal/api/contract_test.go
package api

import "testing"

func TestGeneratedFoundationModels(t *testing.T) {
	health := HealthResponse{Status: "ok", Version: "dev"}
	if health.Status != "ok" || health.Version != "dev" {
		t.Fatalf("unexpected health response: %#v", health)
	}
	bootstrap := BootstrapResponse{CsrfToken: "csrf"}
	if bootstrap.CsrfToken != "csrf" {
		t.Fatalf("unexpected bootstrap response: %#v", bootstrap)
	}
}
```

- [ ] **Step 2: Run the test and verify generation is missing**

Run: `go test ./internal/api`

Expected: FAIL to compile with `undefined: HealthResponse` and `undefined: BootstrapResponse`.

- [ ] **Step 3: Create the OpenAPI contract**

```yaml
# api/openapi.yaml
openapi: 3.1.0
info:
  title: SSH UI Local API
  version: 0.1.0
paths:
  /api/v1/session/bootstrap:
    post:
      operationId: bootstrapSession
      parameters:
        - name: X-SSH-UI-Bootstrap
          in: header
          required: true
          schema: { type: string, minLength: 43, maxLength: 43 }
      responses:
        "200":
          description: Session established
          headers:
            Cache-Control:
              schema: { type: string, const: no-store }
          content:
            application/json:
              schema: { $ref: "#/components/schemas/BootstrapResponse" }
        "401": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
  /api/v1/health:
    get:
      operationId: getHealth
      responses:
        "200":
          description: Authenticated process health
          content:
            application/json:
              schema: { $ref: "#/components/schemas/HealthResponse" }
        "401": { $ref: "#/components/responses/Problem" }
components:
  schemas:
    BootstrapResponse:
      type: object
      additionalProperties: false
      required: [csrfToken]
      properties:
        csrfToken: { type: string, minLength: 43, maxLength: 43 }
    HealthResponse:
      type: object
      additionalProperties: false
      required: [status, version]
      properties:
        status: { type: string, const: ok }
        version: { type: string, minLength: 1 }
    Problem:
      type: object
      additionalProperties: false
      required: [code, message]
      properties:
        code: { type: string }
        message: { type: string }
  responses:
    Problem:
      description: Request rejected
      content:
        application/problem+json:
          schema: { $ref: "#/components/schemas/Problem" }
```

- [ ] **Step 4: Create pinned Go module and generator configuration**

```go
// internal/api/generate.go
package api

//go:generate go tool oapi-codegen -config ../../api/oapi-codegen.yaml ../../api/openapi.yaml
```

```yaml
# api/oapi-codegen.yaml
package: api
output: models.gen.go
generate:
  models: true
output-options:
  skip-prune: false
```

Install the approved Go dependencies:

```bash
go get github.com/labstack/echo/v5@v5.3.1
go get -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.0
go generate ./internal/api
```

Expected: `go.mod`, `go.sum`, and `internal/api/models.gen.go` are created; `go.mod` declares `go 1.26` and exact direct versions.

- [ ] **Step 5: Create the pinned frontend manifest**

```json
{
  "name": "ssh-ui-web",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "generate:api": "openapi-typescript ../api/openapi.yaml -o src/api/schema.d.ts",
    "test": "vitest run",
    "typecheck": "tsc -b --pretty false"
  },
  "dependencies": {
    "react": "19.2.8",
    "react-dom": "19.2.8"
  },
  "devDependencies": {
    "@tailwindcss/vite": "4.3.3",
    "@testing-library/dom": "10.4.1",
    "@testing-library/jest-dom": "6.9.1",
    "@testing-library/react": "16.3.2",
    "@testing-library/user-event": "14.6.1",
    "@types/node": "22.20.1",
    "@types/react": "19.2.17",
    "@types/react-dom": "19.2.3",
    "@vitejs/plugin-react": "6.0.4",
    "jsdom": "29.1.1",
    "openapi-typescript": "7.13.0",
    "tailwindcss": "4.3.3",
    "typescript": "5.9.3",
    "vite": "8.1.5",
    "vitest": "4.1.1"
  }
}
```

Install the approved frontend dependencies with npm: `npm install --prefix web`

Expected: `web/package-lock.json` records the exact dependency graph and npm reports no install failure.

- [ ] **Step 6: Add strict TypeScript and Vite configuration**

```json
// web/tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "allowImportingTsExtensions": false,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "types": ["vitest/globals", "@testing-library/jest-dom/vitest"]
  },
  "include": ["src", "vite.config.ts", "vitest.setup.ts"]
}
```

```ts
// web/vite.config.ts
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../internal/ui/dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    restoreMocks: true,
  },
});
```

- [ ] **Step 7: Generate both languages and run the contract checks**

Run:

```bash
go generate ./internal/api
npm run generate:api --prefix web
go test ./internal/api
npm run typecheck --prefix web
```

Expected: all four commands exit 0; generated files contain the two response models and two path definitions.

- [ ] **Step 8: Ignore only generated build/cache output**

```gitignore
# .gitignore
/bin/
/coverage/
/web/node_modules/
.DS_Store
```

Do not ignore `go.sum`, `web/package-lock.json`, or generated API source files.

- [ ] **Step 9: Commit the contract and toolchain**

```bash
git add .gitignore go.mod go.sum api internal/api web/package.json web/package-lock.json web/tsconfig.json web/vite.config.ts
git commit -m "build: pin foundation toolchain and API contract"
```

## Task 2: Implement one-time bootstrap and in-memory sessions

**Files:**
- Create: `internal/session/manager.go`
- Create: `internal/session/manager_test.go`

**Interfaces:**
- Produces: `session.NewManager(random io.Reader) (*Manager, string, error)`.
- Produces: `(*Manager).Bootstrap(token string) (Credentials, error)`.
- Produces: `(*Manager).Authenticate(sessionID string) (Session, bool)`.
- Produces: `(*Manager).VerifyCSRF(sessionID, csrf string) bool`.
- Produces: `session.ErrInvalidBootstrap` and `session.ErrBootstrapUsed`.
- Consumes: `io.Reader` as the only randomness source so tests remain deterministic.

- [ ] **Step 1: Write failing lifecycle and replay tests**

```go
// internal/session/manager_test.go
package session

import (
	"bytes"
	"errors"
	"testing"
)

func TestBootstrapCreatesAuthenticatedSessionOnce(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 96))
	manager, bootstrap, err := NewManager(random)
	if err != nil { t.Fatal(err) }
	if len(bootstrap) != 43 { t.Fatalf("bootstrap length = %d", len(bootstrap)) }

	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil { t.Fatal(err) }
	if _, ok := manager.Authenticate(credentials.SessionID); !ok {
		t.Fatal("new session was not authenticated")
	}
	if !manager.VerifyCSRF(credentials.SessionID, credentials.CSRFToken) {
		t.Fatal("csrf token was rejected")
	}
	if _, err := manager.Bootstrap(bootstrap); !errors.Is(err, ErrBootstrapUsed) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestBootstrapRejectsWrongTokenWithoutConsumingRealToken(t *testing.T) {
	manager, bootstrap, err := NewManager(bytes.NewReader(bytes.Repeat([]byte{0x21}, 96)))
	if err != nil { t.Fatal(err) }
	if _, err := manager.Bootstrap("wrong"); !errors.Is(err, ErrInvalidBootstrap) {
		t.Fatalf("wrong-token error = %v", err)
	}
	if _, err := manager.Bootstrap(bootstrap); err != nil {
		t.Fatalf("valid bootstrap after rejection: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests and verify the package is absent**

Run: `go test ./internal/session`

Expected: FAIL because `NewManager`, `Credentials`, and the error values are undefined.

- [ ] **Step 3: Implement fixed-length URL-safe secrets and hashed storage**

```go
// internal/session/manager.go
package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
)

var (
	ErrInvalidBootstrap = errors.New("invalid bootstrap token")
	ErrBootstrapUsed = errors.New("bootstrap token already used")
)

type Credentials struct {
	SessionID string
	CSRFToken string
}

type Session struct {
	csrfHash [sha256.Size]byte
}

type Manager struct {
	mu sync.RWMutex
	random io.Reader
	bootstrapHash [sha256.Size]byte
	bootstrapUsed bool
	sessions map[[sha256.Size]byte]Session
}

func token(random io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func NewManager(random io.Reader) (*Manager, string, error) {
	bootstrap, err := token(random)
	if err != nil { return nil, "", err }
	return &Manager{
		random: random,
		bootstrapHash: sha256.Sum256([]byte(bootstrap)),
		sessions: make(map[[sha256.Size]byte]Session),
	}, bootstrap, nil
}

func (m *Manager) Bootstrap(presented string) (Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bootstrapUsed { return Credentials{}, ErrBootstrapUsed }
	presentedHash := sha256.Sum256([]byte(presented))
	if subtle.ConstantTimeCompare(presentedHash[:], m.bootstrapHash[:]) != 1 {
		return Credentials{}, ErrInvalidBootstrap
	}
	sessionID, err := token(m.random)
	if err != nil { return Credentials{}, err }
	csrf, err := token(m.random)
	if err != nil { return Credentials{}, err }
	m.bootstrapUsed = true
	m.sessions[sha256.Sum256([]byte(sessionID))] = Session{csrfHash: sha256.Sum256([]byte(csrf))}
	return Credentials{SessionID: sessionID, CSRFToken: csrf}, nil
}

func (m *Manager) Authenticate(sessionID string) (Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessionValue, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	return sessionValue, ok
}

func (m *Manager) VerifyCSRF(sessionID, csrf string) bool {
	sessionValue, ok := m.Authenticate(sessionID)
	if !ok { return false }
	presentedHash := sha256.Sum256([]byte(csrf))
	return subtle.ConstantTimeCompare(presentedHash[:], sessionValue.csrfHash[:]) == 1
}
```

- [ ] **Step 4: Add deterministic random-failure coverage**

```go
var errRandom = errors.New("random source failed")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errRandom }

func TestNewManagerPropagatesRandomFailure(t *testing.T) {
	if _, _, err := NewManager(errReader{}); !errors.Is(err, errRandom) {
		t.Fatalf("NewManager error = %v", err)
	}
}

func TestBootstrapPropagatesSessionRandomFailure(t *testing.T) {
	initial := bytes.NewReader(bytes.Repeat([]byte{0x31}, 32))
	manager, bootstrap, err := NewManager(io.MultiReader(initial, errReader{}))
	if err != nil { t.Fatal(err) }
	if _, err := manager.Bootstrap(bootstrap); !errors.Is(err, errRandom) {
		t.Fatalf("Bootstrap error = %v", err)
	}
	if _, ok := manager.Authenticate(""); ok {
		t.Fatal("failed bootstrap created a session")
	}
}
```

- [ ] **Step 5: Run unit and race tests**

Run:

```bash
go test ./internal/session
go test -race ./internal/session
```

Expected: both commands PASS.

- [ ] **Step 6: Commit session management**

```bash
git add internal/session
git commit -m "feat: add one-time local session bootstrap"
```

## Task 3: Enforce loopback HTTP security policy

**Files:**
- Create: `internal/httpserver/security.go`
- Create: `internal/httpserver/security_test.go`

**Interfaces:**
- Consumes: `*session.Manager` from Task 2.
- Produces: `httpserver.Security{ExpectedHost string, ExpectedOrigin string, Sessions *session.Manager}`.
- Produces: `Security.Middleware(next echo.HandlerFunc) echo.HandlerFunc`.
- Produces: request context key `httpserver.SessionContextKey` after successful cookie authentication.

- [ ] **Step 1: Write table-driven rejection tests**

```go
// internal/httpserver/security_test.go
package httpserver

func TestSecurityRejectsCrossSiteAndWrongHost(t *testing.T) {
	manager, _, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x42}, 96)))
	if err != nil { t.Fatal(err) }
	security := Security{
		ExpectedHost: "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions: manager,
	}
	tests := []struct {
		name string
		host string
		origin string
		fetchSite string
		want int
	}{
		{"valid", "127.0.0.1:43123", "http://127.0.0.1:43123", "same-origin", 204},
		{"wrong host", "localhost:43123", "http://127.0.0.1:43123", "same-origin", 403},
		{"cross origin", "127.0.0.1:43123", "https://evil.example", "cross-site", 403},
		{"missing origin", "127.0.0.1:43123", "", "same-origin", 403},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := echo.New()
			e.Use(security.Middleware)
			e.POST("/api/v1/session/bootstrap", func(c *echo.Context) error {
				return c.NoContent(http.StatusNoContent)
			})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/session/bootstrap", nil)
			request.Host = test.host
			if test.origin != "" { request.Header.Set(echo.HeaderOrigin, test.origin) }
			request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}
```

```go
func TestSecurityNavigationHeadersAndAPIAuthentication(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x52}, 96)))
	if err != nil { t.Fatal(err) }
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil { t.Fatal(err) }
	e := echo.New()
	e.Use((Security{
		ExpectedHost: "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions: manager,
	}).Middleware)
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	e.GET("/api/v1/test", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	e.POST("/api/v1/test", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })

	run := func(method, path string, authenticated, csrf bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, nil)
		request.Host = "127.0.0.1:43123"
		if method != http.MethodGet {
			request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
			request.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		if authenticated {
			request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
		}
		if csrf { request.Header.Set(CSRFHeader, credentials.CSRFToken) }
		response := httptest.NewRecorder()
		e.ServeHTTP(response, request)
		return response
	}

	navigation := run(http.MethodGet, "/", false, false)
	if navigation.Code != http.StatusNoContent { t.Fatalf("navigation status = %d", navigation.Code) }
	for name, value := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy": "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := navigation.Header().Get(name); got != value { t.Errorf("%s = %q", name, got) }
	}
	if got := navigation.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Errorf("CSP = %q", got)
	}
	if got := run(http.MethodGet, "/api/v1/test", false, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d", got)
	}
	if response := run(http.MethodGet, "/api/v1/test", true, false); response.Code != http.StatusNoContent || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authenticated GET = %d, cache = %q", response.Code, response.Header().Get("Cache-Control"))
	}
	if got := run(http.MethodPost, "/api/v1/test", true, false).Code; got != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d", got)
	}
	if got := run(http.MethodPost, "/api/v1/test", true, true).Code; got != http.StatusNoContent {
		t.Fatalf("POST with CSRF = %d", got)
	}
}
```

- [ ] **Step 2: Run the tests and verify missing middleware failure**

Run: `go test ./internal/httpserver -run TestSecurity -v`

Expected: FAIL because `Security` is undefined.

- [ ] **Step 3: Implement one middleware with explicit route classes**

```go
// internal/httpserver/security.go
package httpserver

const (
	SessionCookie = "ssh_ui_session"
	CSRFHeader = "X-SSH-UI-CSRF"
	SessionContextKey = "ssh-ui-session"
)

type Security struct {
	ExpectedHost string
	ExpectedOrigin string
	Sessions *session.Manager
}

func (s Security) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		request := c.Request()
		response := c.Response()
		setSecurityHeaders(response.Header(), strings.HasPrefix(request.URL.Path, "/api/"))
		if request.Host != s.ExpectedHost { return problem(c, http.StatusForbidden, "invalid_host") }

		isAPI := strings.HasPrefix(request.URL.Path, "/api/")
		isBootstrap := request.URL.Path == "/api/v1/session/bootstrap" && request.Method == http.MethodPost
		if !isAPI { return next(c) }
		if request.Method != http.MethodGet || isBootstrap {
			if request.Header.Get(echo.HeaderOrigin) != s.ExpectedOrigin || request.Header.Get("Sec-Fetch-Site") != "same-origin" {
				return problem(c, http.StatusForbidden, "cross_site_request")
			}
		}
		if isBootstrap { return next(c) }

		cookie, err := request.Cookie(SessionCookie)
		if err != nil { return problem(c, http.StatusUnauthorized, "session_required") }
		if _, ok := s.Sessions.Authenticate(cookie.Value); !ok {
			return problem(c, http.StatusUnauthorized, "invalid_session")
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			if !s.Sessions.VerifyCSRF(cookie.Value, request.Header.Get(CSRFHeader)) {
				return problem(c, http.StatusForbidden, "invalid_csrf")
			}
		}
		c.Set(SessionContextKey, cookie.Value)
		return next(c)
	}
}
```

Implement `setSecurityHeaders` with this exact CSP:

```text
default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'
```

```go
const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"

func setSecurityHeaders(header http.Header, apiResponse bool) {
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	if apiResponse { header.Set("Cache-Control", "no-store") }
}

func problem(c *echo.Context, status int, code string) error {
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, api.Problem{Code: code, Message: "request rejected"})
}
```

The problem body contains only the stable code and generic message; it never echoes request header values.

- [ ] **Step 4: Run middleware and package tests**

Run:

```bash
go test ./internal/httpserver
go test -race ./internal/httpserver
```

Expected: PASS with no request data printed.

- [ ] **Step 5: Commit HTTP security policy**

```bash
git add internal/httpserver/security.go internal/httpserver/security_test.go
git commit -m "feat: enforce localhost request security policy"
```

## Task 4: Serve bootstrap and authenticated health routes

**Files:**
- Create: `internal/httpserver/handlers.go`
- Create: `internal/httpserver/handlers_test.go`
- Create: `internal/httpserver/server.go`
- Create: `internal/httpserver/server_test.go`

**Interfaces:**
- Consumes: Task 1 generated API models.
- Consumes: Task 2 `*session.Manager`.
- Consumes: Task 3 security middleware.
- Produces: `httpserver.Options{Listener net.Listener, Sessions *session.Manager, UI fs.FS, Version string, Logger *slog.Logger}`.
- Produces: `httpserver.New(Options) (*Server, error)`.
- Produces: `(*Server).Serve(context.Context) error` and `(*Server).URL() string`.

- [ ] **Step 1: Write bootstrap route tests**

Create an Echo test server with deterministic session randomness and assert:

```go
request := httptest.NewRequest(http.MethodPost, "/api/v1/session/bootstrap", nil)
request.Host = "127.0.0.1:43123"
request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
request.Header.Set("Sec-Fetch-Site", "same-origin")
request.Header.Set("X-SSH-UI-Bootstrap", bootstrap)
```

Expected assertions:

- status 200;
- one `ssh_ui_session` cookie with `HttpOnly`, `SameSite=Strict`, `Path=/`;
- no `Secure` flag because the approved foundation is loopback HTTP;
- JSON contains a 43-character `csrfToken`;
- response is `no-store`;
- second use of the same bootstrap token returns 409;
- wrong token returns 401 and sets no cookie.

Use this concrete test shape:

```go
func TestBootstrapHandlerSetsStrictSessionCookieAndRejectsReplay(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x61}, 96)))
	if err != nil { t.Fatal(err) }
	e := echo.New()
	e.Use((Security{
		ExpectedHost: "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions: manager,
	}).Middleware)
	handlers := Handlers{Sessions: manager, Version: "test-version"}
	e.POST("/api/v1/session/bootstrap", handlers.Bootstrap)

	call := func(token string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/session/bootstrap", nil)
		request.Host = "127.0.0.1:43123"
		request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("X-SSH-UI-Bootstrap", token)
		response := httptest.NewRecorder()
		e.ServeHTTP(response, request)
		return response
	}

	response := call(bootstrap)
	if response.Code != http.StatusOK { t.Fatalf("status = %d", response.Code) }
	result := response.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 { t.Fatalf("cookies = %#v", cookies) }
	cookie := cookies[0]
	if cookie.Name != SessionCookie || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Secure {
		t.Fatalf("cookie = %#v", cookie)
	}
	var payload api.BootstrapResponse
	if err := json.NewDecoder(result.Body).Decode(&payload); err != nil { t.Fatal(err) }
	if len(payload.CsrfToken) != 43 { t.Fatalf("csrf length = %d", len(payload.CsrfToken)) }
	if got := call(bootstrap).Code; got != http.StatusConflict { t.Fatalf("replay = %d", got) }
}
```

- [ ] **Step 2: Write authenticated health route tests**

Bootstrap a session, call `/api/v1/health` with and without the cookie, and assert:

```json
{"status":"ok","version":"test-version"}
```

Expected: 200 with the cookie and 401 without it.

```go
func TestHealthRequiresSessionCookie(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x71}, 96)))
	if err != nil { t.Fatal(err) }
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil { t.Fatal(err) }
	e := echo.New()
	e.Use((Security{
		ExpectedHost: "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions: manager,
	}).Middleware)
	e.GET("/api/v1/health", (Handlers{Sessions: manager, Version: "test-version"}).Health)
	call := func(authenticated bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		request.Host = "127.0.0.1:43123"
		if authenticated { request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID}) }
		response := httptest.NewRecorder()
		e.ServeHTTP(response, request)
		return response
	}
	if got := call(false).Code; got != http.StatusUnauthorized { t.Fatalf("without cookie = %d", got) }
	response := call(true)
	if response.Code != http.StatusOK { t.Fatalf("with cookie = %d", response.Code) }
	if got := strings.TrimSpace(response.Body.String()); got != `{"status":"ok","version":"test-version"}` {
		t.Fatalf("body = %s", got)
	}
}
```

- [ ] **Step 3: Run tests to verify handlers are absent**

Run: `go test ./internal/httpserver -run 'Test(Bootstrap|Health)' -v`

Expected: FAIL because handler registration and `Server` are undefined.

- [ ] **Step 4: Implement handlers without body or secret logging**

```go
type Handlers struct {
	Sessions *session.Manager
	Version string
}

func (h Handlers) Bootstrap(c *echo.Context) error {
	credentials, err := h.Sessions.Bootstrap(c.Request().Header.Get("X-SSH-UI-Bootstrap"))
	switch {
	case errors.Is(err, session.ErrInvalidBootstrap):
		return problem(c, http.StatusUnauthorized, "invalid_bootstrap")
	case errors.Is(err, session.ErrBootstrapUsed):
		return problem(c, http.StatusConflict, "bootstrap_used")
	case err != nil:
		return problem(c, http.StatusInternalServerError, "bootstrap_failed")
	}
	c.SetCookie(&http.Cookie{
		Name: SessionCookie, Value: credentials.SessionID, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	return c.JSON(http.StatusOK, api.BootstrapResponse{CsrfToken: credentials.CSRFToken})
}

func (h Handlers) Health(c *echo.Context) error {
	return c.JSON(http.StatusOK, api.HealthResponse{Status: "ok", Version: h.Version})
}
```

- [ ] **Step 5: Implement listener-owned server lifecycle**

`New` must reject a listener whose `Addr()` is not a TCP loopback address equal to `127.0.0.1`. Register bootstrap, health, static assets, and SPA fallback behind the same `Security.Middleware`. `Serve(ctx)` must call `http.Server.Serve` in a goroutine and `Shutdown` with a five-second timeout when `ctx.Done()` fires.

Do not call `Echo.Start`, because the caller already owns the `127.0.0.1:0` listener and must know the actual port before opening the browser.

```go
type Options struct {
	Listener net.Listener
	Sessions *session.Manager
	UI fs.FS
	Version string
	Logger *slog.Logger
}

var ErrNonLoopbackListener = errors.New("listener must use 127.0.0.1")

type Server struct {
	listener net.Listener
	http *http.Server
	url string
}

func New(options Options) (*Server, error) {
	tcpAddress, ok := options.Listener.Addr().(*net.TCPAddr)
	if !ok || len(tcpAddress.IP) != net.IPv4len || tcpAddress.IP[0] != 127 || tcpAddress.IP[1] != 0 || tcpAddress.IP[2] != 0 || tcpAddress.IP[3] != 1 {
		return nil, ErrNonLoopbackListener
	}
	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpAddress.Port))
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use((Security{
		ExpectedHost: host,
		ExpectedOrigin: "http://" + host,
		Sessions: options.Sessions,
	}).Middleware)
	handlers := Handlers{Sessions: options.Sessions, Version: options.Version}
	e.POST("/api/v1/session/bootstrap", handlers.Bootstrap)
	e.GET("/api/v1/health", handlers.Health)
	e.GET("/*", echo.WrapHandler(http.FileServer(http.FS(options.UI))))
	return &Server{
		listener: options.Listener,
		http: &http.Server{Handler: e, ReadHeaderTimeout: 5 * time.Second},
		url: "http://" + host,
	}, nil
}

func (s *Server) URL() string { return s.url }

func (s *Server) Serve(ctx context.Context) error {
	shutdownComplete := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.http.Shutdown(shutdownCtx)
		case <-shutdownComplete:
		}
	}()
	err := s.http.Serve(s.listener)
	close(shutdownComplete)
	if errors.Is(err, http.ErrServerClosed) { return nil }
	return err
}
```

Task 7 replaces the basic file server with an HTML-aware SPA fallback; Task 4 keeps static serving intentionally literal so lifecycle and API behavior can be reviewed independently.

- [ ] **Step 6: Add wrong-listener and shutdown tests**

Use fake `net.Listener` addresses to prove `0.0.0.0:0` and `[::]:0` are rejected. Use a real `net.Listen("tcp4", "127.0.0.1:0")`, cancel the context, and assert `Serve` exits without leaking a listener.

- [ ] **Step 7: Run server tests and race detector**

Run:

```bash
go test ./internal/httpserver
go test -race ./internal/httpserver
```

Expected: PASS.

- [ ] **Step 8: Commit the server**

```bash
git add internal/httpserver
git commit -m "feat: serve authenticated local API"
```

## Task 5: Add macOS browser launch and CLI orchestration

**Files:**
- Create: `internal/platform/browser.go`
- Create: `internal/platform/macos/browser.go`
- Create: `internal/platform/macos/browser_test.go`
- Create: `internal/app/run.go`
- Create: `internal/app/run_test.go`

**Interfaces:**
- Produces: `platform.BrowserLauncher.Open(context.Context, string) error`.
- Produces: `platform.CommandRunner.Run(context.Context, string, ...string) error`.
- Produces: `app.Dependencies{Random io.Reader, Browser platform.BrowserLauncher, Listen func(network, address string) (net.Listener, error), UI fs.FS, Logger *slog.Logger}`.
- Produces: `app.Run(context.Context, Dependencies, version string) error`.
- Consumes: Task 4 `httpserver.New` and `Serve`.

- [ ] **Step 1: Write the shell-free browser adapter test**

```go
type fakeRunner struct{ argv []string }

func (runner *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	runner.argv = append([]string{name}, args...)
	return nil
}

func TestBrowserUsesOpenWithoutShell(t *testing.T) {
	runner := &fakeRunner{}
	browser := macos.NewBrowser(runner)
	url := "http://127.0.0.1:43123/#bootstrap=abc;$(touch%20/tmp/nope)"
	if err := browser.Open(context.Background(), url); err != nil { t.Fatal(err) }
	if !slices.Equal([]string{"open", url}, runner.argv) {
		t.Fatalf("argv = %#v", runner.argv)
	}
}
```

The fake stores argv only; it never starts a process.

- [ ] **Step 2: Run the test and verify the adapter is absent**

Run: `go test ./internal/platform/macos -v`

Expected: FAIL because the browser adapter is undefined.

- [ ] **Step 3: Implement the adapter using direct argv**

```go
var ErrUnsafeBrowserURL = errors.New("browser URL must use loopback HTTP")

type Browser struct{ runner platform.CommandRunner }

func NewBrowser(runner platform.CommandRunner) Browser { return Browser{runner: runner} }

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func NewExecRunner() platform.CommandRunner { return execRunner{} }

func (b Browser) Open(ctx context.Context, target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		return ErrUnsafeBrowserURL
	}
	return b.runner.Run(ctx, "open", target)
}
```

Do not use `sh -c`, AppleScript, string concatenation into a command, or `open` through a shell.

- [ ] **Step 4: Write orchestration tests**

Inject a listener factory that records `network` and `address`, plus a fake browser. Assert:

- `Listen` receives exactly `tcp4`, `127.0.0.1:0`;
- the browser receives `http://127.0.0.1:<assigned>/#bootstrap=<43 chars>`;
- the bootstrap value is not sent as a query parameter;
- cancelling context closes the listener and returns;
- browser failure shuts the server down and returns the error.

```go
type browserFunc func(context.Context, string) error

func (function browserFunc) Open(ctx context.Context, target string) error {
	return function(ctx, target)
}

func TestRunUsesRandomIPv4LoopbackAndReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opened := make(chan string, 1)
	var gotNetwork, gotAddress string
	dependencies := Dependencies{
		Random: bytes.NewReader(bytes.Repeat([]byte{0x81}, 96)),
		Browser: browserFunc(func(_ context.Context, target string) error { opened <- target; return nil }),
		Listen: func(network, address string) (net.Listener, error) {
			gotNetwork, gotAddress = network, address
			return net.Listen(network, address)
		},
		UI: fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, dependencies, "test") }()
	target := <-opened
	if gotNetwork != "tcp4" || gotAddress != "127.0.0.1:0" {
		t.Fatalf("listen = %s %s", gotNetwork, gotAddress)
	}
	parsed, err := url.Parse(target)
	if err != nil { t.Fatal(err) }
	if parsed.Hostname() != "127.0.0.1" || parsed.RawQuery != "" || !strings.HasPrefix(parsed.Fragment, "bootstrap=") {
		t.Fatalf("target = %q", target)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil { t.Fatalf("Run = %v", err) }
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}
```

- [ ] **Step 5: Implement `app.Run`**

```go
type ListenFunc func(network, address string) (net.Listener, error)

type Dependencies struct {
	Random io.Reader
	Browser platform.BrowserLauncher
	Listen ListenFunc
	UI fs.FS
	Logger *slog.Logger
}

func Run(ctx context.Context, dependencies Dependencies, version string) error {
	listener, err := dependencies.Listen("tcp4", "127.0.0.1:0")
	if err != nil { return fmt.Errorf("listen: %w", err) }
	sessions, bootstrap, err := session.NewManager(dependencies.Random)
	if err != nil { listener.Close(); return fmt.Errorf("session: %w", err) }
	server, err := httpserver.New(httpserver.Options{
		Listener: listener, Sessions: sessions, UI: dependencies.UI,
		Version: version, Logger: dependencies.Logger,
	})
	if err != nil { listener.Close(); return err }
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

```go
var errAccept = errors.New("accept failed")

type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errAccept }
func (failingListener) Close() error { return nil }
func (failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 43123}
}

func TestRunReturnsServerFailureWithoutWaitingForCancellation(t *testing.T) {
	dependencies := Dependencies{
		Random: bytes.NewReader(bytes.Repeat([]byte{0x91}, 96)),
		Browser: browserFunc(func(context.Context, string) error { return nil }),
		Listen: func(string, string) (net.Listener, error) { return failingListener{}, nil },
		UI: fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), dependencies, "test") }()
	select {
	case err := <-done:
		if !errors.Is(err, errAccept) { t.Fatalf("Run error = %v", err) }
	case <-time.After(time.Second):
		t.Fatal("Run waited for context after server failure")
	}
}
```

- [ ] **Step 6: Run orchestration tests**

Run:

```bash
go test ./internal/platform/... ./internal/app/...
go test -race ./internal/platform/... ./internal/app/...
```

Expected: PASS and `/tmp/nope` does not exist.

- [ ] **Step 7: Commit CLI orchestration**

```bash
git add internal/app internal/platform
git commit -m "feat: launch secure localhost UI on macOS"
```

## Task 6: Build the React bootstrap shell

**Files:**
- Create: `web/index.html`
- Create: `web/vitest.setup.ts`
- Create: `web/src/index.css`
- Create: `web/src/api/client.ts`
- Create: `web/src/session/bootstrap.ts`
- Create: `web/src/session/bootstrap.test.ts`
- Create: `web/src/App.tsx`
- Create: `web/src/App.test.tsx`
- Create: `web/src/main.tsx`

**Interfaces:**
- Consumes: generated TypeScript `paths` from Task 1.
- Produces: `bootstrapSession(location, history, fetch): Promise<SessionState>`.
- Produces: `apiClient.setCSRF(token)` and typed `apiClient.health()`.
- Produces: authenticated React shell with no persistent secret storage.

- [ ] **Step 1: Write bootstrap extraction and cleanup tests**

```ts
it("exchanges the fragment once and removes it from browser history", async () => {
  const replaceState = vi.fn();
  const fetcher = vi.fn().mockResolvedValue(new Response(
    JSON.stringify({ csrfToken: "c".repeat(43) }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  ));
  const state = await bootstrapSession(
    { hash: `#bootstrap=${"b".repeat(43)}`, pathname: "/", search: "" },
    { replaceState },
    fetcher,
  );
  expect(fetcher).toHaveBeenCalledWith("/api/v1/session/bootstrap", expect.objectContaining({
    method: "POST",
    credentials: "same-origin",
    headers: expect.objectContaining({ "X-SSH-UI-Bootstrap": "b".repeat(43) }),
  }));
  expect(replaceState).toHaveBeenCalledWith(null, "", "/");
  expect(state.csrfToken).toBe("c".repeat(43));
});
```

```ts
it.each([
  ["missing", "", "invalid_bootstrap_fragment"],
  ["short", "#bootstrap=short", "invalid_bootstrap_fragment"],
])("rejects a %s fragment before fetch", async (_name, hash, code) => {
  const fetcher = vi.fn();
  await expect(bootstrapSession(
    { hash, pathname: "/", search: "" },
    { replaceState: vi.fn() },
    fetcher,
  )).rejects.toThrow(code);
  expect(fetcher).not.toHaveBeenCalled();
});

it("rejects a non-success response", async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
  await expect(bootstrapSession(
    { hash: `#bootstrap=${"b".repeat(43)}`, pathname: "/", search: "" },
    { replaceState: vi.fn() },
    fetcher,
  )).rejects.toThrow("bootstrap_rejected");
});

it("rejects a malformed response without persistent storage", async () => {
  const localSet = vi.spyOn(Storage.prototype, "setItem");
  const fetcher = vi.fn().mockResolvedValue(new Response(
    JSON.stringify({ csrfToken: "short" }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  ));
  await expect(bootstrapSession(
    { hash: `#bootstrap=${"b".repeat(43)}`, pathname: "/", search: "" },
    { replaceState: vi.fn() },
    fetcher,
  )).rejects.toThrow("invalid_bootstrap_response");
  expect(localSet).not.toHaveBeenCalled();
  expect(window.localStorage).toHaveLength(0);
  expect(window.sessionStorage).toHaveLength(0);
});
```

- [ ] **Step 2: Run the tests and verify missing implementation**

Run: `npm test --prefix web -- src/session/bootstrap.test.ts`

Expected: FAIL because `bootstrapSession` is undefined.

- [ ] **Step 3: Implement fragment bootstrap with immediate cleanup**

```ts
export async function bootstrapSession(
  location: Pick<Location, "hash" | "pathname" | "search">,
  history: Pick<History, "replaceState">,
  fetcher: typeof fetch,
): Promise<SessionState> {
  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  const bootstrap = params.get("bootstrap") ?? "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(bootstrap)) throw new Error("invalid_bootstrap_fragment");
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  const response = await fetcher("/api/v1/session/bootstrap", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "X-SSH-UI-Bootstrap": bootstrap,
    },
  });
  if (!response.ok) throw new Error("bootstrap_rejected");
  const payload: unknown = await response.json();
  if (!isBootstrapResponse(payload)) throw new Error("invalid_bootstrap_response");
  return { csrfToken: payload.csrfToken };
}
```

Define the referenced runtime validation immediately above that function:

```ts
import type { components } from "../api/schema";

type BootstrapResponse = components["schemas"]["BootstrapResponse"];
export type SessionState = Readonly<{ csrfToken: string }>;

function isBootstrapResponse(value: unknown): value is BootstrapResponse {
  if (typeof value !== "object" || value === null) return false;
  const token = (value as Record<string, unknown>).csrfToken;
  return typeof token === "string" && /^[A-Za-z0-9_-]{43}$/.test(token);
}
```

Do not attempt to set `Sec-Fetch-Site` from browser JavaScript because it is a forbidden request header. The browser supplies it; the fetch mock verifies only the bootstrap header, method, and credentials, while Go integration tests verify server enforcement.

- [ ] **Step 4: Implement a typed same-origin client with module-memory CSRF**

```ts
import type { components } from "./schema";

export type HealthResponse = components["schemas"]["HealthResponse"];

function validateHealth(value: unknown): HealthResponse {
  if (typeof value !== "object" || value === null) throw new Error("invalid_health_response");
  const record = value as Record<string, unknown>;
  if (record.status !== "ok" || typeof record.version !== "string" || record.version.length === 0) {
    throw new Error("invalid_health_response");
  }
  return { status: "ok", version: record.version };
}

let csrfToken: string | null = null;

export const apiClient = {
  setCSRF(token: string) { csrfToken = token; },
  clear() { csrfToken = null; },
  async health(): Promise<HealthResponse> {
    const response = await fetch("/api/v1/health", { credentials: "same-origin" });
    if (!response.ok) throw new Error("health_failed");
    return validateHealth(await response.json());
  },
  async mutate<T>(path: string, init: RequestInit): Promise<T> {
    if (!csrfToken) throw new Error("csrf_unavailable");
	const headers = new Headers(init.headers);
	headers.set("X-SSH-UI-CSRF", csrfToken);
    const response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      headers,
    });
    if (!response.ok) throw new Error("api_mutation_failed");
    return response.json() as Promise<T>;
  },
};
```

Keep `csrfToken` private to the module; do not expose a getter and do not persist it.

- [ ] **Step 5: Write the application shell test**

Render `<App />` with injected bootstrap and health functions. Assert the user sees:

- an initial `Starting secure local session…` status;
- `SSH UI` heading and `Local session active` after bootstrap and health succeed;
- disabled navigation labels for Connections, Groups, Config, Keys, Known Hosts, and History;
- an actionable error screen when bootstrap fails;
- no bootstrap or CSRF token text in the DOM.

- [ ] **Step 6: Implement the accessible shell and local Tailwind theme**

Use semantic `<header>`, `<nav aria-label="Primary">`, `<main>`, and `role="status"`. Keep the foundation UI deliberately minimal: one status card and disabled navigation. Import Tailwind locally with:

```tsx
import { useEffect, useState } from "react";
import { apiClient, type HealthResponse } from "./api/client";
import type { SessionState } from "./session/bootstrap";

type AppProps = {
  bootstrap: () => Promise<SessionState>;
  health: () => Promise<HealthResponse>;
};

const sections = ["Connections", "Groups", "Config", "Keys", "Known Hosts", "History"];

export function App({ bootstrap, health }: AppProps) {
  const [state, setState] = useState<"starting" | "ready" | "error">("starting");
  const [version, setVersion] = useState("");
  useEffect(() => {
    let active = true;
    void bootstrap()
      .then((sessionState) => {
        apiClient.setCSRF(sessionState.csrfToken);
        return health();
      })
      .then((result) => {
        if (!active) return;
        setVersion(result.version);
        setState("ready");
      })
      .catch(() => { if (active) setState("error"); });
    return () => { active = false; apiClient.clear(); };
  }, [bootstrap, health]);

  if (state === "error") {
    return <main><h1>SSH UI</h1><p role="alert">Secure local session could not be started. Restart ssh-ui and use the newly opened tab.</p></main>;
  }
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-800 px-6 py-4"><h1 className="text-xl font-semibold">SSH UI</h1></header>
      <div className="grid grid-cols-[15rem_1fr]">
        <nav aria-label="Primary" className="border-r border-zinc-800 p-4">
          <ul>{sections.map((section) => <li key={section}><button disabled className="w-full px-3 py-2 text-left text-zinc-500">{section}</button></li>)}</ul>
        </nav>
        <main className="p-8">
          <section aria-labelledby="status-heading" className="max-w-xl rounded-xl border border-zinc-800 bg-zinc-900 p-6">
            <h2 id="status-heading" className="font-medium">Local process</h2>
            <p role="status" className="mt-2 text-sm text-zinc-300">
              {state === "ready" ? `Local session active · ${version}` : "Starting secure local session…"}
            </p>
          </section>
        </main>
      </div>
    </div>
  );
}
```

```css
@import "tailwindcss";

:root {
  color-scheme: dark;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #09090b;
  color: #f4f4f5;
}
```

```tsx
// web/src/main.tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { apiClient } from "./api/client";
import { App } from "./App";
import "./index.css";
import { bootstrapSession } from "./session/bootstrap";

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");
createRoot(root).render(
  <StrictMode>
    <App
      bootstrap={() => bootstrapSession(window.location, window.history, window.fetch.bind(window))}
      health={() => apiClient.health()}
    />
  </StrictMode>,
);
```

- [ ] **Step 7: Run frontend tests and type checks**

Run:

```bash
npm test --prefix web
npm run typecheck --prefix web
```

Expected: PASS; the tests find no secret values in rendered DOM.

- [ ] **Step 8: Commit the frontend shell**

```bash
git add web
git commit -m "feat: add secure React bootstrap shell"
```

## Task 7: Embed the UI and verify the single binary

**Files:**
- Create: `internal/ui/embed.go`
- Generate: `internal/ui/dist/**`
- Create: `cmd/ssh-ui/main.go`
- Modify: `internal/httpserver/server.go`
- Create: `internal/httpserver/integration_test.go`
- Create: `Makefile`
- Create: `README.md`

**Interfaces:**
- Produces: `ui.FS() (fs.FS, error)`.
- Consumes: Task 4 server static-file option.
- Produces: `make generate`, `make test`, and `make build` as the supported local commands.

- [ ] **Step 1: Write an integration test for the complete browser flow**

Start the server on a real `127.0.0.1:0` listener with deterministic random input and an in-memory UI fixture. Assert:

1. `GET /` with the exact Host returns the fixture and security headers.
2. The fragment token is absent from all server request targets and captured logs.
3. Bootstrap with exact Origin and Host returns a cookie and CSRF token.
4. Replaying bootstrap returns 409.
5. Health without the cookie returns 401.
6. Health with the cookie returns 200.
7. A POST with the cookie but no CSRF returns 403.
8. A request using `localhost:<port>` instead of `127.0.0.1:<port>` returns 403.

- [ ] **Step 2: Run the integration test and verify embedding is missing**

Run: `go test ./internal/httpserver -run TestIntegratedBootstrapFlow -v`

Expected: FAIL because the UI filesystem and SPA fallback are not complete.

- [ ] **Step 3: Build React into the Go package and embed it**

```go
// internal/ui/embed.go
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

func FS() (fs.FS, error) {
	return fs.Sub(assets, "dist")
}
```

Run: `npm run build --prefix web`

Expected: Vite writes `internal/ui/dist/index.html` and hashed local assets; no generated HTML references an HTTP(S) origin.

- [ ] **Step 4: Add static serving with safe SPA fallback**

Serve only files returned by the embedded `fs.FS`. For a path without a matching asset, return `index.html` only for GET and HEAD requests that accept HTML. Never translate a URL path into an OS filesystem path.

API paths must never fall through to the SPA.

```go
func spaHandler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/api/") {
			http.NotFound(response, request)
			return
		}
		name := strings.TrimPrefix(path.Clean(request.URL.Path), "/")
		if name == "." || name == "" { name = "index.html" }
		if !fs.ValidPath(name) {
			http.NotFound(response, request)
			return
		}
		contents, err := fs.ReadFile(assets, name)
		if err != nil {
			if !strings.Contains(request.Header.Get("Accept"), "text/html") {
				http.NotFound(response, request)
				return
			}
			name = "index.html"
			contents, err = fs.ReadFile(assets, name)
			if err != nil { http.NotFound(response, request); return }
		}
		if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
			response.Header().Set("Content-Type", contentType)
		}
		http.ServeContent(response, request, name, time.Time{}, bytes.NewReader(contents))
	})
}
```

Replace Task 4's basic `http.FileServer` route with `echo.WrapHandler(spaHandler(options.UI))`, registered for GET and HEAD.

- [ ] **Step 5: Add the signal-aware main entrypoint**

```go
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"ssh-ui/internal/app"
	"ssh-ui/internal/platform/macos"
	"ssh-ui/internal/ui"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	assets, err := ui.FS()
	if err != nil {
		logger.Error("load embedded UI", "error", err)
		os.Exit(1)
	}
	dependencies := app.Dependencies{
		Random: rand.Reader,
		Browser: macos.NewBrowser(macos.NewExecRunner()),
		Listen: net.Listen,
		UI: assets,
		Logger: logger,
	}
	if err := app.Run(ctx, dependencies, version); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("ssh-ui stopped", "error", err)
		os.Exit(1)
	}
}
```

The production logger must never receive target URLs because they contain the bootstrap fragment.

- [ ] **Step 6: Add reproducible commands**

```make
.PHONY: generate test build

generate:
	go generate ./internal/api
	npm run generate:api --prefix web

test:
	go test ./...
	go test -race ./...
	npm test --prefix web
	npm run typecheck --prefix web

build:
	npm run build --prefix web
	go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui
```

- [ ] **Step 7: Document the exact development and threat boundary**

`README.md` must state:

- prerequisites and pinned versions;
- package installation commands requiring conscious execution;
- `make generate`, `make test`, and `make build`;
- the binary binds only to `127.0.0.1` and is not safe to expose over a network;
- the foundation does not read `~/.ssh` yet;
- secrets remain vulnerable to browser extensions and local clipboard tooling in later reveal features;
- Echo v5 is intentionally pinned to v5.3.1 for a reproducible foundation build.

- [ ] **Step 8: Run the full foundation verification**

Run:

```bash
make generate
make test
make build
file bin/ssh-ui
git diff --check
git status --short
```

Expected:

- generate produces no uncommitted diff after the first committed generation;
- all Go, race, Vitest, and TypeScript checks pass;
- `bin/ssh-ui` is a Mach-O arm64 executable;
- `git diff --check` emits nothing;
- `git status --short` is empty; `bin/` remains absent from status because it is intentionally ignored.

- [ ] **Step 9: Perform a manual isolated smoke test**

Run: `./bin/ssh-ui`

Expected:

- the default browser opens a `127.0.0.1:<random>` URL;
- the fragment disappears immediately;
- UI shows `Local session active`;
- no `~/.ssh` file is read or changed;
- Ctrl-C stops the process and the URL stops responding.

- [ ] **Step 10: Commit the verified foundation**

```bash
git add Makefile README.md internal/ui internal/httpserver web/src/api/schema.d.ts internal/api/models.gen.go
git commit -m "feat: deliver embedded secure localhost foundation"
```

## Foundation Acceptance Gate

Before starting the lossless config-engine plan, verify all of the following:

- `go test ./...` passes.
- `go test -race ./...` passes.
- `npm test --prefix web` passes.
- `npm run typecheck --prefix web` passes.
- `npm run build --prefix web` references no external asset origin.
- `go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui` succeeds.
- listener tests prove only `tcp4/127.0.0.1:0` is accepted.
- integration tests prove bootstrap replay, wrong Host, wrong Origin, missing cookie and missing CSRF are rejected.
- logs contain none of the deterministic bootstrap, session, or CSRF fixtures.
- automated tests did not access the real `~/.ssh`, Keychain, Terminal, or a remote host.
