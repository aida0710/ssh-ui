package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"sshc/internal/session"
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

// TestSecurityRefusesEveryAPIRequestFromAnotherSite は middleware だけを
// 動かす。届いたものには何でも 204 を返すハンドラを使うことで、
// 拒否がテスト対象の Fetch Metadata チェックからしか来得ないように
// し、その先にあるハンドラレベルの防護からは来ないようにする。
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
			// 読み取りが今トークンを運ぶので、テスト対象の拒否は欠けたトークン
			// ではなく Fetch Metadata の方によるものである。
			request.Header.Set(CSRFHeader, credentials.CSRFToken)
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
			// status だけでなく problem code もアサートする。host チェックや
			// CSRF による 403 では、そうしないと成功のように見えてしまうからだ。
			if test.wantCode != "" && !strings.Contains(response.Body.String(), test.wantCode) {
				t.Fatalf("body = %q, want the %q problem code", response.Body.String(), test.wantCode)
			}
		})
	}
}

// TestSecurityBoundsABodyAHandlerReadsWithoutItsOwnLimit は、上限のうち
// 現状どの登録済みルートも到達できない半分をカバーする。
//
// ツリー内のすべてのハンドラは MaxRequestBodyCeiling 以下の自前の
// 制限をかけており、大きすぎる長さを宣言したリクエストはどのハンドラ
// が実行される前にも拒否される。したがって MaxBytesReader wrapper が
// 意味を持つのは、後で追加され自前の制限なしに body を読むルートが、
// 長さを一切宣言しない chunked リクエストを扱う場合だけだ。それが
// まさにこのテストが登録するルートである。
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
	// chunked リクエストは長さを宣言しないため、Content-Length による
	// 拒否は発動できず、この body を制限するのは reader だけになる。
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
		// フロントエンドが送るすべての API リクエストは Fetch Metadata を運ぶ。
		// 読み取りも書き込みと同様であり、Origin だけが状態変更に固有である。
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
	// 読み取りにもトークンが要る。cookie はポートに紐づかないため、
	// 127.0.0.1 上の別のサーバーがそれを受け取ってしまうが、トークンは決してそこへ渡らない。
	if got := run(http.MethodGet, "/api/v1/test", true, false).Code; got != http.StatusForbidden {
		t.Fatalf("GET with the cookie and no token = %d", got)
	}
	if response := run(http.MethodGet, "/api/v1/test", true, true); response.Code != http.StatusNoContent || response.Header().Get("Cache-Control") != "no-store" {
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

// runGuarded は既存のセッションで middleware だけを動かす。よって
// 拒否し得るのはテスト対象のゲートだけになる。
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

// application はもはやマスターパスワードの向こう側にあるものであり、
// 各画面が個別にそうなのではない。
//
// 除外されているのはゲート自身と、そもそも解錠すべき何かが生じる
// 前に動く必要のある 2 つのものである。それ以外は vault_locked を返す。
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

// 何も配線されていないゲートは施錠されている。配線し忘れが、施錠
// された application と開いた application の違いになってはならない。
func TestAMiddlewareWithNoVaultToAskIsShut(t *testing.T) {
	security, host, credentials := gatedSecurity(t, nil)
	if recorder := runGuarded(t, host, security, credentials, http.MethodGet, "/api/v1/keys"); recorder.Code != http.StatusConflict {
		t.Errorf("a middleware with no Unlocked = %d, want 409", recorder.Code)
	}
}

// 開いた vault は他には何も変えない。ゲートは追加のチェックの 1 つで
// あり、セッションと CSRF トークンの代わりではない。
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

// alwaysUnlocked は、別の事柄を扱うテストのためにゲートを開く。
// ゲート自体のテストは上にある。
func alwaysUnlocked() bool { return true }

// cookie はポートに紐づかず、site もまたそうである。
//
// 127.0.0.1 上の別のサーバー——他のポートで動く開発用サーバー——が
// この application のセッション cookie を受け取ってしまう。SameSite は
// scheme と registrable domain を比較し、IP はそれ自体が site のすべて
// だからだ。したがって cookie だけでは何も読めてはならない。CSRF
// トークンはページのメモリに存在してその別ポートへは渡らないため、
// 書き込みだけでなく読み取りにも要求することで、漏洩した cookie を無価値にする。
func TestReadsRequireTheTokenAsWellAsTheCookie(t *testing.T) {
	security, host, credentials := gatedSecurity(t, func() bool { return true })

	withoutToken := session.Credentials{SessionID: credentials.SessionID}
	if recorder := runGuarded(t, host, security, withoutToken, http.MethodGet, "/api/v1/keys"); recorder.Code != http.StatusForbidden {
		t.Errorf("GET with the cookie and no token = %d, want 403", recorder.Code)
	}
	if recorder := runGuarded(t, host, security, credentials, http.MethodGet, "/api/v1/keys"); recorder.Code != http.StatusOK {
		t.Errorf("GET with both = %d, want 200", recorder.Code)
	}
	// 更新はトークンを失ったページがそれを得る手段であるため、まさに
	// 求めているそのトークンを求められるわけにはいかない。
	if recorder := runGuarded(t, host, security, withoutToken, http.MethodPost, "/api/v1/session/renew"); recorder.Code != http.StatusOK {
		t.Errorf("renew with no token = %d, want it to pass", recorder.Code)
	}
}
