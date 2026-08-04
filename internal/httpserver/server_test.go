package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"ssh-ui/internal/session"
)

type fakeListener struct{ address net.Addr }

func (listener fakeListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (listener fakeListener) Close() error              { return nil }
func (listener fakeListener) Addr() net.Addr            { return listener.address }

func TestNewRejectsNonLoopbackListeners(t *testing.T) {
	tests := []struct {
		name    string
		address net.Addr
		wantErr bool
	}{
		{name: "unmapped IPv4 loopback", address: &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 43123}},
		{name: "IPv4 mapped IPv6 loopback", address: &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1")}, wantErr: true},
		{name: "unspecified IPv4", address: &net.TCPAddr{IP: net.IPv4zero}, wantErr: true},
		{name: "unspecified IPv6", address: &net.TCPAddr{IP: net.IPv6unspecified}, wantErr: true},
		{name: "non TCP address", address: fakeAddr("unix"), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Options{Listener: fakeListener{address: test.address}})
			if test.wantErr && !errors.Is(err, ErrNonLoopbackListener) {
				t.Fatalf("New error = %v, want %v", err, ErrNonLoopbackListener)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("New error = %v", err)
			}
		})
	}
}

func TestServerServesStaticFilesAndShutsDownAfterCancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager, _, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x73}, 96)))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server, err := New(Options{
		Listener: listener,
		Sessions: manager,
		UI: fstest.MapFS{
			"asset.txt": &fstest.MapFile{Data: []byte("static asset")},
		},
		Version: "test-version",
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()

	response, err := http.Get(server.URL() + "/asset.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("static status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "static asset" {
		t.Fatalf("static body = %q", got)
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit after context cancellation")
	}
	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), 100*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("listener still accepts connections after Serve returns")
	}
}

func TestServerSPAFallbackRequiresHTMLNavigation(t *testing.T) {
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x83}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{
		Listener: fakeListener{address: &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 43123}},
		Sessions: manager,
		UI: fstest.MapFS{
			"index.html": {Data: []byte("<!doctype html><title>SPA fixture</title>")},
			"app.js":     {Data: []byte("export const ready = true;")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		accept     string
		wantStatus int
		wantBody   string
		checkBody  bool
		auth       bool
	}{
		{name: "existing asset", method: http.MethodGet, path: "/app.js", accept: "*/*", wantStatus: http.StatusOK, wantBody: "export const ready = true;", checkBody: true},
		{name: "GET HTML navigation", method: http.MethodGet, path: "/connections/primary", accept: "text/html,application/xhtml+xml", wantStatus: http.StatusOK, wantBody: "<!doctype html><title>SPA fixture</title>", checkBody: true},
		{name: "HEAD HTML navigation", method: http.MethodHead, path: "/connections/primary", accept: "text/html", wantStatus: http.StatusOK, checkBody: true},
		{name: "weighted HTML navigation", method: http.MethodGet, path: "/connections/weighted", accept: "application/json;q=0.9, text/html; q=0.4", wantStatus: http.StatusOK, wantBody: "<!doctype html><title>SPA fixture</title>", checkBody: true},
		{name: "zero quality HTML", method: http.MethodGet, path: "/connections/disabled", accept: "text/html;q=0", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n", checkBody: true},
		{name: "HTML lookalike", method: http.MethodGet, path: "/connections/lookalike", accept: "application/x-text/html-data", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n", checkBody: true},
		{name: "non HTML missing asset", method: http.MethodGet, path: "/missing.json", accept: "application/json", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n", checkBody: true},
		{name: "exact API namespace", method: http.MethodGet, path: "/api", accept: "text/html", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n", checkBody: true},
		{name: "normalized API namespace", method: http.MethodGet, path: "/public/../api/v1/missing", accept: "text/html", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n", checkBody: true},
		{name: "raw API namespace", method: http.MethodGet, path: "/api/../connections", accept: "text/html", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n", checkBody: true, auth: true},
		{name: "API lookalike navigation", method: http.MethodGet, path: "/apiary", accept: "text/html", wantStatus: http.StatusOK, wantBody: "<!doctype html><title>SPA fixture</title>", checkBody: true},
		{name: "POST navigation", method: http.MethodPost, path: "/connections/primary", accept: "text/html", wantStatus: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Host = "127.0.0.1:43123"
			request.Header.Set("Accept", test.accept)
			// A same-origin navigation carries this header. The "raw API
			// namespace" case needs it because its unnormalised path begins
			// with /api/, so the API rules apply to it; the assertion it makes
			// is still that such a path never yields the SPA document.
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			if test.auth {
				request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
			}
			response := httptest.NewRecorder()
			server.http.Handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if got := response.Body.String(); test.checkBody && got != test.wantBody {
				t.Fatalf("body = %q, want %q", got, test.wantBody)
			}
		})
	}
}

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

type fakeAddr string

func (address fakeAddr) Network() string { return string(address) }
func (address fakeAddr) String() string  { return string(address) }
