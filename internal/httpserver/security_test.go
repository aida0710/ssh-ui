package httpserver

import (
	"bytes"
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
