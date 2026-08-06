package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"ssh-ui/internal/platform"
)

type browserFunc func(context.Context, string) error

func (function browserFunc) Open(ctx context.Context, target string) error {
	return function(ctx, target)
}

func TestRunUsesRandomIPv4LoopbackAndReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opened := make(chan string, 1)
	var gotNetwork, gotAddress string
	dependencies := Dependencies{
		Random: bytes.NewReader(bytes.Repeat([]byte{0x81}, 96)),
		Browser: browserFunc(func(_ context.Context, target string) error {
			opened <- target
			return nil
		}),
		Listen: func(network, address string) (net.Listener, error) {
			gotNetwork, gotAddress = network, address
			return net.Listen(network, address)
		},
		UI:     fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:   t.TempDir(),
	}

	done := make(chan error, 1)
	go func() { done <- Run(ctx, dependencies, "test") }()

	target := <-opened
	if gotNetwork != "tcp4" || gotAddress != "127.0.0.1:0" {
		t.Fatalf("listen = %s %s", gotNetwork, gotAddress)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Hostname() != "127.0.0.1" || parsed.RawQuery != "" || !strings.HasPrefix(parsed.Fragment, "bootstrap=") {
		t.Fatalf("target = %q", target)
	}
	if got := strings.TrimPrefix(parsed.Fragment, "bootstrap="); len(got) != 43 {
		t.Fatalf("bootstrap length = %d, want 43", len(got))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

var errAccept = errors.New("accept failed")

type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errAccept }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 43123}
}

func TestRunReturnsServerFailureWithoutWaitingForCancellation(t *testing.T) {
	dependencies := Dependencies{
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x91}, 96)),
		Browser: browserFunc(func(context.Context, string) error { return nil }),
		Listen:  func(string, string) (net.Listener, error) { return failingListener{}, nil },
		UI:      fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:    t.TempDir(),
	}

	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), dependencies, "test") }()

	select {
	case err := <-done:
		if !errors.Is(err, errAccept) {
			t.Fatalf("Run error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run waited for context after server failure")
	}
}

func TestRunShutsServerDownWhenBrowserFails(t *testing.T) {
	browserErr := errors.New("browser unavailable")
	listener := &trackingListener{Listener: mustListen(t)}
	dependencies := Dependencies{
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x72}, 96)),
		Browser: browserFunc(func(context.Context, string) error { return browserErr }),
		Listen:  func(string, string) (net.Listener, error) { return listener, nil },
		UI:      fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:    t.TempDir(),
	}

	err := Run(context.Background(), dependencies, "test")
	if !errors.Is(err, browserErr) {
		t.Fatalf("Run error = %v", err)
	}
	if !listener.closed {
		t.Fatal("listener was not closed after browser failure")
	}
}

type stubRunner struct{}

func (stubRunner) RunOutput(context.Context, platform.Command) (platform.Output, error) {
	return platform.Output{Stdout: []byte("ssh-ed25519\n")}, nil
}

type stubToolchain struct{}

func (stubToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (stubToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }
func (stubToolchain) KeyGen() (string, error)  { return "/usr/bin/ssh-keygen", nil }
func (stubToolchain) KeyAdd() (string, error)  { return "/usr/bin/ssh-add", nil }

type stubKeyAgent struct{}

func (stubKeyAgent) Available(context.Context) bool { return false }
func (stubKeyAgent) List(context.Context) ([]platform.AgentIdentity, error) {
	return nil, platform.ErrAgentUnavailable
}
func (stubKeyAgent) Add(context.Context, platform.AgentAddRequest) error {
	return platform.ErrAgentUnavailable
}
func (stubKeyAgent) Remove(context.Context, string) error { return platform.ErrAgentUnavailable }

// keyVaultSession drives the wired process the way the browser does.
type keyVaultSession struct {
	base    string
	client  *http.Client
	cookie  *http.Cookie
	csrf    string
	testing *testing.T
}

func (call keyVaultSession) do(method, path string, body []byte, headers map[string]string) *http.Response {
	call.testing.Helper()
	request, err := http.NewRequest(method, call.base+path, bytes.NewReader(body))
	if err != nil {
		call.testing.Fatalf("build %s %s: %v", method, path, err)
	}
	request.AddCookie(call.cookie)
	request.Header.Set("Content-Type", "application/json")
	// Fetch Metadata accompanies every API request, a read as much as a write.
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	if method != http.MethodGet {
		request.Header.Set("Origin", call.base)
		request.Header.Set("X-SSH-UI-CSRF", call.csrf)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := call.client.Do(request)
	if err != nil {
		call.testing.Fatalf("%s %s: %v", method, path, err)
	}
	return response
}

// The key vault must not share the transaction manager that application.Service
// owns, because that manager carries a configuration validator which parses
// every written file as ssh_config. A trash manifest is JSON, so sharing would
// reject a soft delete as a configuration syntax error. Generating a key and
// then trashing it through the wired process proves the separation holds.
func TestRunExposesTheKeyVaultAndItsTrashThroughTheWiredProcess(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("create ssh directory: %v", err)
	}
	opened := make(chan string, 1)
	dependencies := Dependencies{
		Random: rand.Reader,
		Browser: browserFunc(func(_ context.Context, target string) error {
			opened <- target
			return nil
		}),
		Listen:    net.Listen,
		UI:        fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:      home,
		Runner:    stubRunner{},
		Toolchain: stubToolchain{},
		KeyAgent:  stubKeyAgent{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, dependencies, "test") }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run error = %v", err)
		}
	}()

	target := <-opened
	base, fragment, _ := strings.Cut(target, "/#")
	bootstrapToken := strings.TrimPrefix(fragment, "bootstrap=")

	client := &http.Client{}
	bootstrapRequest, err := http.NewRequest(http.MethodPost, base+"/api/v1/session/bootstrap", nil)
	if err != nil {
		t.Fatalf("build bootstrap request: %v", err)
	}
	bootstrapRequest.Header.Set("Origin", base)
	bootstrapRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	bootstrapRequest.Header.Set("X-SSH-UI-Bootstrap", bootstrapToken)
	bootstrapResponse, err := client.Do(bootstrapRequest)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	var bootstrapBody struct {
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(bootstrapResponse.Body).Decode(&bootstrapBody); err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	cookies := bootstrapResponse.Cookies()
	bootstrapResponse.Body.Close()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}
	call := keyVaultSession{base: base, client: client, cookie: cookies[0], csrf: bootstrapBody.CsrfToken, testing: t}

	// Every route is behind the master password, so setting one is part of
	// starting the application rather than part of a test about keys.
	unlocked := call.do(http.MethodPost, "/api/v1/passwords/initialise",
		[]byte(`{"passphrase":"a master password for this run"}`), nil)
	if unlocked.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(unlocked.Body)
		t.Fatalf("initialise the vault = %d: %s", unlocked.StatusCode, body)
	}
	unlocked.Body.Close()

	listing := call.do(http.MethodGet, "/api/v1/keys", nil, nil)
	defer listing.Body.Close()
	if listing.StatusCode != http.StatusOK {
		t.Fatalf("list keys = %d, want 200", listing.StatusCode)
	}
	if got := listing.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	generateBody := []byte(`{"algorithm":"ed25519","fileName":"id_work","comment":"aida@laptop","passphrase":"correct horse","unencrypted":false}`)
	generated := call.do(http.MethodPost, "/api/v1/keys", generateBody, nil)
	var generateResult struct {
		Id string `json:"id"`
	}
	if err := json.NewDecoder(generated.Body).Decode(&generateResult); err != nil {
		t.Fatalf("decode generate: %v", err)
	}
	generated.Body.Close()
	if generated.StatusCode != http.StatusCreated || generateResult.Id == "" {
		t.Fatalf("generate = %d %#v", generated.StatusCode, generateResult)
	}

	trashed := call.do(http.MethodPost, "/api/v1/keys/"+generateResult.Id+"/trash", nil, nil)
	body, _ := io.ReadAll(trashed.Body)
	trashed.Body.Close()
	if trashed.StatusCode != http.StatusOK {
		t.Fatalf("trash = %d, want 200: %s", trashed.StatusCode, body)
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".ssh", "id_work")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the key is still in the workspace: %v", statErr)
	}

	// The configuration surface must still work: the two subsystems share a
	// workspace, so a broken separation would show up here as well.
	overview := call.do(http.MethodGet, "/api/v1/config/overview", nil, nil)
	overview.Body.Close()
	if overview.StatusCode != http.StatusOK {
		t.Fatalf("config overview = %d, want 200", overview.StatusCode)
	}
}

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

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

type trackingListener struct {
	net.Listener
	closed bool
}

func (listener *trackingListener) Close() error {
	listener.closed = true
	return listener.Listener.Close()
}
