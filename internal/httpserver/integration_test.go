package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"sshc/internal/api"
	"sshc/internal/session"
)

func TestIntegratedBootstrapFlow(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0xa7}, 96)))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	const document = "<!doctype html><title>integrated fixture</title>"
	var logs bytes.Buffer
	server, err := New(Options{
		Listener: listener,
		Sessions: manager,
		UI:       fstest.MapFS{"index.html": {Data: []byte(document)}},
		Version:  "integration-version",
		Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var targetsMu sync.Mutex
	var requestTargets []string
	serverHandler := server.http.Handler
	server.http.Handler = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		targetsMu.Lock()
		requestTargets = append(requestTargets, request.RequestURI)
		targetsMu.Unlock()
		serverHandler.ServeHTTP(response, request)
	})

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-serveDone; err != nil {
			t.Errorf("Serve error = %v", err)
		}
	})

	client := &http.Client{}
	host := strings.TrimPrefix(server.URL(), "http://")
	do := func(method, requestURL, requestHost string, headers map[string]string, cookie *http.Cookie) *http.Response {
		t.Helper()
		request, err := http.NewRequest(method, requestURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = requestHost
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	readBody := func(response *http.Response) string {
		t.Helper()
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	navigation := do(http.MethodGet, server.URL()+"/#bootstrap="+bootstrap, host, nil, nil)
	if navigation.StatusCode != http.StatusOK || readBody(navigation) != document {
		t.Fatalf("navigation = %d, want fixture", navigation.StatusCode)
	}
	for name, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := navigation.Header.Get(name); got != want {
			t.Errorf("navigation %s = %q, want %q", name, got, want)
		}
	}
	if got := navigation.Header.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Errorf("navigation CSP = %q", got)
	}

	deepLink := do(http.MethodGet, server.URL()+"/connections/primary", host, map[string]string{"Accept": "text/html"}, nil)
	if deepLink.StatusCode != http.StatusOK || readBody(deepLink) != document {
		t.Fatalf("SPA fallback = %d, want fixture", deepLink.StatusCode)
	}

	const crossOriginSecret = "cross-origin-request-secret"
	crossOriginBootstrap := do(http.MethodPost, server.URL()+"/api/v1/session/bootstrap", host, map[string]string{
		"Origin":           "https://evil.example/" + crossOriginSecret,
		"Sec-Fetch-Site":   "same-origin",
		"X-SSHC-Bootstrap": bootstrap,
	}, nil)
	if crossOriginBootstrap.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin bootstrap = %d, want %d", crossOriginBootstrap.StatusCode, http.StatusForbidden)
	}
	if cookies := crossOriginBootstrap.Cookies(); len(cookies) != 0 {
		t.Fatalf("cross-origin bootstrap cookies = %#v, want none", cookies)
	}
	readBody(crossOriginBootstrap)

	bootstrapHeaders := map[string]string{
		"Origin":           server.URL(),
		"Sec-Fetch-Site":   "same-origin",
		"X-SSHC-Bootstrap": bootstrap,
	}
	bootstrapResponse := do(http.MethodPost, server.URL()+"/api/v1/session/bootstrap", host, bootstrapHeaders, nil)
	if bootstrapResponse.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap = %d, want %d", bootstrapResponse.StatusCode, http.StatusOK)
	}
	cookies := bootstrapResponse.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("bootstrap cookies = %#v", cookies)
	}
	var payload api.BootstrapResponse
	if err := json.NewDecoder(bootstrapResponse.Body).Decode(&payload); err != nil {
		bootstrapResponse.Body.Close()
		t.Fatal(err)
	}
	bootstrapResponse.Body.Close()
	if payload.CsrfToken == "" {
		t.Fatal("bootstrap returned an empty CSRF token")
	}

	replay := do(http.MethodPost, server.URL()+"/api/v1/session/bootstrap", host, bootstrapHeaders, nil)
	if replay.StatusCode != http.StatusConflict {
		t.Fatalf("bootstrap replay = %d, want %d", replay.StatusCode, http.StatusConflict)
	}
	readBody(replay)

	// Fetch Metadata now accompanies every API request, including a read, so
	// these three carry the header the frontend's own fetch would carry.
	sameOriginRead := map[string]string{"Sec-Fetch-Site": "same-origin"}
	unauthenticatedHealth := do(http.MethodGet, server.URL()+"/api/v1/health", host, sameOriginRead, nil)
	if unauthenticatedHealth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("health without cookie = %d, want %d", unauthenticatedHealth.StatusCode, http.StatusUnauthorized)
	}
	readBody(unauthenticatedHealth)

	authenticatedHealth := do(http.MethodGet, server.URL()+"/api/v1/health", host, sameOriginRead, cookies[0])
	if authenticatedHealth.StatusCode != http.StatusOK {
		t.Fatalf("health with cookie = %d, want %d", authenticatedHealth.StatusCode, http.StatusOK)
	}
	readBody(authenticatedHealth)

	missingCSRF := do(http.MethodPost, server.URL()+"/api/v1/missing", host, map[string]string{
		"Origin":         server.URL(),
		"Sec-Fetch-Site": "same-origin",
	}, cookies[0])
	if missingCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d, want %d", missingCSRF.StatusCode, http.StatusForbidden)
	}
	readBody(missingCSRF)

	apiFallback := do(http.MethodGet, server.URL()+"/api/v1/missing", host, map[string]string{
		"Accept": "text/html", "Sec-Fetch-Site": "same-origin",
	}, cookies[0])
	if apiFallback.StatusCode != http.StatusNotFound || readBody(apiFallback) == document {
		t.Fatalf("missing API = %d, must not serve SPA", apiFallback.StatusCode)
	}

	wrongHost := do(http.MethodGet, server.URL()+"/", "localhost:"+strings.Split(host, ":")[1], nil, nil)
	if wrongHost.StatusCode != http.StatusForbidden {
		t.Fatalf("localhost Host = %d, want %d", wrongHost.StatusCode, http.StatusForbidden)
	}
	readBody(wrongHost)

	targetsMu.Lock()
	seenTargets := append([]string(nil), requestTargets...)
	targetsMu.Unlock()
	for _, target := range seenTargets {
		if strings.Contains(target, bootstrap) || strings.Contains(target, "#") {
			t.Fatalf("server request target contains fragment secret: %q", target)
		}
	}
	for name, secret := range map[string]string{
		"bootstrap":           bootstrap,
		"session":             cookies[0].Value,
		"csrf":                payload.CsrfToken,
		"cross-origin header": crossOriginSecret,
	} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("captured logs contain %s secret", name)
		}
	}
}
