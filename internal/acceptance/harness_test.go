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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
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

func (t *recordingTerminal) reset() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.aliases = nil
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
	client *http.Client
	// anonymous carries no cookie jar, so a request made through it reaches the
	// server without a session.
	anonymous *http.Client
	server    *httpserver.Server
	runner    *recordingRunner
	terminal  *recordingTerminal
	clock     *testClock
	logs      *syncBuffer
	canaries  fixtureCanaries
	sessionID    string
	cachedKey    string
	trashCounter atomic.Int64
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
		client:    &http.Client{Jar: jar, Timeout: 15 * time.Second},
		anonymous: &http.Client{Timeout: 15 * time.Second},
		server:    server,
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

// doAnonymous issues the same request as do but through a client with no
// cookie jar, so the session cookie is genuinely absent.
//
// Deleting the Cookie header from inside an adjust function does not work:
// http.Client attaches the jar's cookies after the caller has finished building
// the request, so the header would reappear and a test meaning to prove the
// session requirement would silently be sending one.
func (f *fixture) doAnonymous(method, path string, body []byte, adjust ...func(*http.Request)) *http.Response {
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
	response, err := f.anonymous.Do(request)
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
	if f.cachedKey != "" {
		return f.cachedKey
	}
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
			f.cachedKey = item.ID
			return item.ID
		}
	}
	f.t.Fatal("the fixture private key is not in the inventory")
	return ""
}

// knownHostsPath returns the path the server itself reports for known_hosts.
//
// It is not filepath.Join(f.root, "known_hosts"): a token for a known_hosts
// change is bound to the workspace's own spelling of that path, and on macOS
// t.TempDir() hands back a /var symlink whose resolved form is /private/var.
func (f *fixture) knownHostsPath() string {
	f.t.Helper()
	body := readBody(f.t, f.do(http.MethodGet, "/api/v1/known-hosts", nil))
	var payload struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil || payload.Path == "" {
		f.t.Fatalf("the known_hosts listing did not report a path: %s", body)
	}
	return payload.Path
}

// newTrashEntry generates a throwaway key and trashes it, returning the trash
// entry identifier.
//
// A confirmation for a permanent delete is bound to evidence derived from the
// entry, so no token can be minted for an entry that does not exist. Each
// caller gets its own entry, which keeps the refusal cases independent of the
// positive control that spends one.
func (f *fixture) newTrashEntry(t testing.TB) string {
	t.Helper()
	name := "acceptance-" + strconv.Itoa(int(f.trashCounter.Add(1)))
	generated := f.do(http.MethodPost, "/api/v1/keys", mustJSON(t, map[string]any{
		"algorithm": "ed25519", "fileName": name, "comment": "acceptance",
		"passphrase": "", "unencrypted": true,
	}))
	generatedBody := readBody(t, generated)
	if generated.StatusCode != http.StatusCreated {
		t.Fatalf("generate %s = %d: %s", name, generated.StatusCode, generatedBody)
	}
	var key struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(generatedBody), &key); err != nil || key.ID == "" {
		t.Fatalf("generate did not report an id: %s", generatedBody)
	}

	trashed := f.do(http.MethodPost, "/api/v1/keys/"+key.ID+"/trash", nil)
	trashedBody := readBody(t, trashed)
	if trashed.StatusCode != http.StatusOK {
		t.Fatalf("trash %s = %d: %s", name, trashed.StatusCode, trashedBody)
	}
	var entry struct {
		EntryID string `json:"entryId"`
	}
	if err := json.Unmarshal([]byte(trashedBody), &entry); err != nil || entry.EntryID == "" {
		t.Fatalf("trash did not report an entry: %s", trashedBody)
	}
	return entry.EntryID
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

// actionToken asks the running server for one confirmation token, exactly as
// the frontend does, and fails the test when none is issued.
//
// The merged tree settled on a single POST /api/v1/actions endpoint that takes
// {kind, target} and answers 201, and on one delivery spelling for every
// guarded route: the X-SSH-UI-Action header. The plan was drafted while two
// endpoint spellings and a body-carried token were still in play; neither
// survived into the tree.
func (f *fixture) actionToken(t testing.TB, kind, target string) string {
	t.Helper()
	token := f.tryActionToken(kind, target)
	if token == "" {
		t.Fatalf("POST /api/v1/actions issued no %q token for %q", kind, target)
	}
	return token
}

// tryActionToken issues a token when the target is acceptable and returns an
// empty string otherwise, so a hostile target does not abort the test.
func (f *fixture) tryActionToken(kind, target string) string {
	response := f.do(http.MethodPost, "/api/v1/actions", mustJSON(f.t, map[string]any{
		"kind": kind, "target": target,
	}))
	status := response.StatusCode
	body := readBody(f.t, response)
	if status != http.StatusOK && status != http.StatusCreated {
		return ""
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return ""
	}
	return payload.Token
}

// withAction delivers a confirmation the way every guarded route expects it.
func withAction(token string) func(*http.Request) {
	return func(request *http.Request) {
		if token != "" {
			request.Header.Set("X-SSH-UI-Action", token)
		}
	}
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

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
