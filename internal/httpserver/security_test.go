package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/session"
)

func TestSecurityRejectsCrossSiteAndWrongHost(t *testing.T) {
	manager, _, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x42}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	security := Security{
		ExpectedHost:   "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions:       manager,
		Unlocked:       alwaysUnlocked,
	}
	tests := []struct {
		name      string
		host      string
		origin    string
		fetchSite string
		want      int
	}{
		{"valid", "127.0.0.1:43123", "http://127.0.0.1:43123", "same-origin", http.StatusNoContent},
		{"wrong host", "localhost:43123", "http://127.0.0.1:43123", "same-origin", http.StatusForbidden},
		{"cross origin", "127.0.0.1:43123", "https://evil.example", "cross-site", http.StatusForbidden},
		{"missing origin", "127.0.0.1:43123", "", "same-origin", http.StatusForbidden},
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
			if test.origin != "" {
				request.Header.Set(echo.HeaderOrigin, test.origin)
			}
			request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

// TestSecurityRefusesEveryAPIRequestFromAnotherSite drives the middleware
// alone, with a handler that would answer 204 for anything that reaches it, so
// the refusal can only come from the Fetch Metadata check under test rather
// than from a handler-level guard behind it.
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
		Unlocked:       alwaysUnlocked,
	}).Middleware)
	e.GET("/api/v1/test", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })

	tests := []struct {
		name      string
		fetchSite string
		want      int
		wantCode  string
	}{
		{"same origin", "same-origin", http.StatusNoContent, ""},
		{"cross site", "cross-site", http.StatusForbidden, "cross_site_request"},
		{"same site", "same-site", http.StatusForbidden, "cross_site_request"},
		{"user initiated", "none", http.StatusForbidden, "cross_site_request"},
		{"header absent", "", http.StatusForbidden, "cross_site_request"},
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
			// The problem code is asserted, not merely the status: a 403 from
			// the host check or from CSRF would otherwise look like a pass.
			if test.wantCode != "" && !strings.Contains(response.Body.String(), test.wantCode) {
				t.Fatalf("body = %q, want the %q problem code", response.Body.String(), test.wantCode)
			}
		})
	}
}

// TestSecurityBoundsABodyAHandlerReadsWithoutItsOwnLimit covers the half of the
// ceiling that no registered route can reach today.
//
// Every handler in the tree applies its own limit at or below
// MaxRequestBodyCeiling, and a request that declares an oversized length is
// refused before any handler runs, so the MaxBytesReader wrapper only matters
// for a route added later that reads its body without a limit of its own, over
// a chunked request that declares no length at all. That is exactly the route
// this test registers.
func TestSecurityBoundsABodyAHandlerReadsWithoutItsOwnLimit(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x44}, 96)))
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
		Unlocked:       alwaysUnlocked,
	}).Middleware)

	var read int
	var readErr error
	e.POST("/api/v1/unbounded", func(c *echo.Context) error {
		contents, err := io.ReadAll(c.Request().Body)
		read, readErr = len(contents), err
		if err != nil {
			return problem(c, http.StatusRequestEntityTooLarge, "request_body_too_large")
		}
		return c.NoContent(http.StatusNoContent)
	})

	oversized := bytes.Repeat([]byte("a"), MaxRequestBodyCeiling+(1<<10))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/unbounded", bytes.NewReader(oversized))
	request.Host = "127.0.0.1:43123"
	request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set(CSRFHeader, credentials.CSRFToken)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
	// A chunked request declares no length, so the Content-Length refusal
	// cannot fire and the reader is the only thing bounding this body.
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}

	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	if readErr == nil {
		t.Fatalf("the handler read %d bytes without error; the body was not bounded", read)
	}
	if read > MaxRequestBodyCeiling {
		t.Fatalf("the handler read %d bytes, past the %d ceiling", read, MaxRequestBodyCeiling)
	}
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestSecurityNavigationHeadersAndAPIAuthentication(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x52}, 96)))
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
		Unlocked:       alwaysUnlocked,
	}).Middleware)
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	e.GET("/api/v1/test", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	e.POST("/api/v1/test", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })

	run := func(method, path string, authenticated, csrf bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, nil)
		request.Host = "127.0.0.1:43123"
		// Every API request the frontend makes carries Fetch Metadata, a read
		// as much as a write; only Origin is specific to a state change.
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		if method != http.MethodGet {
			request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
		}
		if authenticated {
			request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
		}
		if csrf {
			request.Header.Set(CSRFHeader, credentials.CSRFToken)
		}
		response := httptest.NewRecorder()
		e.ServeHTTP(response, request)
		return response
	}

	navigation := run(http.MethodGet, "/", false, false)
	if navigation.Code != http.StatusNoContent {
		t.Fatalf("navigation status = %d", navigation.Code)
	}
	for name, value := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := navigation.Header().Get(name); got != value {
			t.Errorf("%s = %q", name, got)
		}
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

func TestSecurityRejectionDoesNotEchoRequestValues(t *testing.T) {
	manager, _, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x62}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Use((Security{
		ExpectedHost:   "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions:       manager,
		Unlocked:       alwaysUnlocked,
	}).Middleware)
	e.POST("/api/v1/session/bootstrap", func(c *echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/session/bootstrap", nil)
	request.Host = "evil.example:43123"
	request.Header.Set(echo.HeaderOrigin, "https://evil.example/request-secret")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if got := response.Header().Get(echo.HeaderContentType); got != "application/problem+json" {
		t.Fatalf("content type = %q", got)
	}
	if got, want := response.Body.String(), "{\"code\":\"invalid_host\",\"message\":\"request rejected\"}\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// runGuarded drives the middleware alone with a session that exists, so the
// only thing that can refuse is the gate under test.
func runGuarded(t *testing.T, host string, security Security, credentials session.Credentials, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	e.Use(security.Middleware)
	e.Add(method, path, func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	request := httptest.NewRequest(method, path, strings.NewReader("{}"))
	request.Host = host
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set(echo.HeaderOrigin, "http://"+host)
	request.Header.Set(echo.HeaderContentType, "application/json")
	request.Header.Set(CSRFHeader, credentials.CSRFToken)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, request)
	return recorder
}

func gatedSecurity(t *testing.T, unlocked func() bool) (Security, string, session.Credentials) {
	t.Helper()
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x51}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1:43123"
	security := Security{ExpectedHost: host, ExpectedOrigin: "http://" + host, Sessions: manager}
	if unlocked != nil {
		security.Unlocked = unlocked
	}
	return security, host, credentials
}

// The application is the thing behind the master password now, not each screen
// in turn.
//
// The exemptions are the gate itself and the two things that must work before
// there is anything to unlock. Everything else answers vault_locked.
func TestEveryRouteButTheGateRefusesWhileTheVaultIsShut(t *testing.T) {
	security, host, credentials := gatedSecurity(t, func() bool { return false })

	locked := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/config/overview"},
		{http.MethodPost, "/api/v1/config/save"},
		{http.MethodGet, "/api/v1/keys"},
		{http.MethodGet, "/api/v1/known-hosts"},
		{http.MethodGet, "/api/v1/sync"},
		{http.MethodGet, "/api/v1/history"},
		{http.MethodGet, "/api/v1/credentials"},
	}
	for _, route := range locked {
		recorder := runGuarded(t, host, security, credentials, route.method, route.path)
		if recorder.Code != http.StatusConflict {
			t.Errorf("%s %s while shut = %d, want 409", route.method, route.path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "vault_locked") {
			t.Errorf("%s %s = %s", route.method, route.path, recorder.Body.String())
		}
	}

	open := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/health"},
		{http.MethodGet, "/api/v1/passwords"},
		{http.MethodPost, "/api/v1/passwords/initialise"},
		{http.MethodPost, "/api/v1/passwords/unlock"},
		{http.MethodPost, "/api/v1/session/renew"},
	}
	for _, route := range open {
		recorder := runGuarded(t, host, security, credentials, route.method, route.path)
		if recorder.Code != http.StatusOK {
			t.Errorf("%s %s while shut = %d, want it to pass the gate: %s",
				route.method, route.path, recorder.Code, recorder.Body.String())
		}
	}
}

// A gate with nothing wired to it is shut. A forgotten wiring must not be the
// difference between a locked application and an open one.
func TestAMiddlewareWithNoVaultToAskIsShut(t *testing.T) {
	security, host, credentials := gatedSecurity(t, nil)
	if recorder := runGuarded(t, host, security, credentials, http.MethodGet, "/api/v1/keys"); recorder.Code != http.StatusConflict {
		t.Errorf("a middleware with no Unlocked = %d, want 409", recorder.Code)
	}
}

// An open vault changes nothing else: the gate is one more check, not a
// replacement for the session and the CSRF token.
func TestAnOpenVaultStillRequiresTheSessionAndTheToken(t *testing.T) {
	security, host, credentials := gatedSecurity(t, func() bool { return true })
	if recorder := runGuarded(t, host, security, credentials, http.MethodGet, "/api/v1/keys"); recorder.Code != http.StatusOK {
		t.Errorf("GET with an open vault = %d, want 200", recorder.Code)
	}
	withoutToken := session.Credentials{SessionID: credentials.SessionID}
	if recorder := runGuarded(t, host, security, withoutToken, http.MethodPost, "/api/v1/config/save"); recorder.Code != http.StatusForbidden {
		t.Errorf("POST with no CSRF token = %d, want 403", recorder.Code)
	}
}

// alwaysUnlocked opens the gate for the tests that are about something else.
// The gate has tests of its own, above.
func alwaysUnlocked() bool { return true }
