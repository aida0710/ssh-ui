package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/session"
)

func TestBootstrapHandlerSetsStrictSessionCookieAndRejectsReplay(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x61}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Use((Security{
		ExpectedHost:   "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions:       manager, Unlocked: alwaysUnlocked,
	}).Middleware)
	e.POST("/api/v1/session/bootstrap", (Handlers{Sessions: manager, Version: "test-version"}).Bootstrap)

	call := func(token string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/session/bootstrap", nil)
		request.Host = "127.0.0.1:43123"
		request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("X-SSHC-Bootstrap", token)
		response := httptest.NewRecorder()
		e.ServeHTTP(response, request)
		return response
	}

	response := call(bootstrap)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	result := response.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != SessionCookie || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Secure {
		t.Fatalf("cookie = %#v", cookie)
	}
	if got := result.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
	var payload api.BootstrapResponse
	if err := json.NewDecoder(result.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.CsrfToken) != 43 {
		t.Fatalf("csrf length = %d", len(payload.CsrfToken))
	}
	if got := call(bootstrap).Code; got != http.StatusConflict {
		t.Fatalf("replay = %d, want %d", got, http.StatusConflict)
	}
	invalid := call("wrong-token")
	if invalid.Code != http.StatusConflict {
		t.Fatalf("invalid after bootstrap = %d, want %d", invalid.Code, http.StatusConflict)
	}
}

func TestBootstrapHandlerRejectsWrongTokenWithoutCookie(t *testing.T) {
	manager, _, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x63}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Use((Security{
		ExpectedHost:   "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions:       manager, Unlocked: alwaysUnlocked,
	}).Middleware)
	e.POST("/api/v1/session/bootstrap", (Handlers{Sessions: manager}).Bootstrap)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/session/bootstrap", nil)
	request.Host = "127.0.0.1:43123"
	request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("X-SSHC-Bootstrap", "wrong-token")
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if cookies := response.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func TestHealthRequiresSessionCookie(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x71}, 96)))
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
		Sessions:       manager, Unlocked: alwaysUnlocked,
	}).Middleware)
	e.GET("/api/v1/health", (Handlers{Sessions: manager, Version: "test-version"}).Health)

	call := func(authenticated bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		request.Host = "127.0.0.1:43123"
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		if authenticated {
			request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
		}
		response := httptest.NewRecorder()
		e.ServeHTTP(response, request)
		return response
	}

	if got := call(false).Code; got != http.StatusUnauthorized {
		t.Fatalf("without cookie = %d, want %d", got, http.StatusUnauthorized)
	}
	response := call(true)
	if response.Code != http.StatusOK {
		t.Fatalf("with cookie = %d, want %d", response.Code, http.StatusOK)
	}
	if got := strings.TrimSpace(response.Body.String()); got != `{"status":"ok","version":"test-version"}` {
		t.Fatalf("body = %s", got)
	}
}
