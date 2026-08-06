package acceptance_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssh-ui/internal/session"
)

// guardedRoute is one operation that starts a process, changes a file outside
// the ordinary edit path, or hands out key material.
//
// Every one of them takes its confirmation in the X-SSH-UI-Action header: the
// merged tree settled on one delivery spelling, so the plan's tokenInBody
// variant has no route to describe.
type guardedRoute struct {
	Method string
	// Path is the Echo path, so the router cross-check below can compare
	// against it. Target resolves the concrete path and the token target
	// together, because for a permanent delete they are the same value and it
	// has to be a trash entry that exists.
	Path string
	Kind string
	// Target returns the value the route's confirmation is bound to. It is a
	// function rather than a string so a row can mint a fresh subject per use;
	// the permanent-delete row needs one, because its positive control spends
	// the entry it was issued for.
	Target func(t testing.TB) string
	// Concrete builds the request path from a resolved target.
	Concrete func(target string) string
	Body     func(f *fixture, target string) map[string]any
}

func constantTarget(value string) func(testing.TB) string {
	return func(testing.TB) string { return value }
}

func fixedPath(path string) func(string) string {
	return func(string) string { return path }
}

func guardedRoutes(f *fixture) []guardedRoute {
	keyID := f.keyID()
	knownHostsPath := f.knownHostsPath()
	alias := func(extra map[string]any) func(*fixture, string) map[string]any {
		return func(_ *fixture, _ string) map[string]any {
			body := map[string]any{"alias": "bastion"}
			for key, value := range extra {
				body[key] = value
			}
			return body
		}
	}
	return []guardedRoute{
		{http.MethodPost, "/api/v1/diagnostics/reachability", session.ActionReachability,
			constantTarget("bastion"), fixedPath("/api/v1/diagnostics/reachability"), alias(nil)},
		{http.MethodPost, "/api/v1/diagnostics/authentication", session.ActionAuthentication,
			constantTarget("bastion"), fixedPath("/api/v1/diagnostics/authentication"),
			alias(map[string]any{"acknowledgeExecutable": true})},
		{http.MethodPost, "/api/v1/terminal/launch", session.ActionTerminalLaunch,
			constantTarget("bastion"), fixedPath("/api/v1/terminal/launch"), alias(nil)},
		{http.MethodPost, "/api/v1/known-hosts/delete", session.ActionKnownHostsDelete,
			constantTarget(knownHostsPath), fixedPath("/api/v1/known-hosts/delete"),
			func(*fixture, string) map[string]any {
				return map[string]any{"entries": []map[string]any{{"line": 2, "digest": strings.Repeat("0", 64)}}}
			}},
		{http.MethodPost, "/api/v1/known-hosts/scan", session.ActionKnownHostsScan,
			constantTarget("203.0.113.10"), fixedPath("/api/v1/known-hosts/scan"),
			func(*fixture, string) map[string]any {
				return map[string]any{"host": "203.0.113.10", "port": 22}
			}},
		{http.MethodPost, "/api/v1/known-hosts/add", session.ActionKnownHostsAdd,
			constantTarget("203.0.113.10"), fixedPath("/api/v1/known-hosts/add"),
			func(*fixture, string) map[string]any {
				return map[string]any{
					"host": "203.0.113.10", "port": 22, "keyType": "ssh-ed25519",
					"key":                 "AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl",
					"expectedFingerprint": "", "acknowledged": true,
				}
			}},
		{http.MethodPost, "/api/v1/remote-keys/register", session.ActionRemoteKeyRegister,
			constantTarget("bastion"), fixedPath("/api/v1/remote-keys/register"),
			func(f *fixture, _ string) map[string]any {
				return map[string]any{
					"alias": "bastion", "keyPath": "id_ed25519.pub",
					"publicKey":             string(bytes.TrimSpace(f.read("id_ed25519.pub"))),
					"acknowledgeExecutable": true,
				}
			}},
		{http.MethodPost, "/api/v1/keys/:keyId/reveal", session.ActionRevealPrivateKey,
			constantTarget(keyID),
			func(target string) string { return "/api/v1/keys/" + target + "/reveal" }, nil},
		{http.MethodDelete, "/api/v1/trash/:entryId", session.ActionPurgeTrashEntry,
			func(t testing.TB) string { return f.newTrashEntry(t) },
			func(target string) string { return "/api/v1/trash/" + target }, nil},
	}
}

// sendGuarded issues one guarded request with the token in the header the
// route expects, or with no header at all when presented is empty.
func (f *fixture) sendGuarded(t testing.TB, route guardedRoute, target, presented string) *http.Response {
	t.Helper()
	var body []byte
	if route.Body != nil {
		body = mustJSON(t, route.Body(f, target))
	}
	return f.do(route.Method, route.Concrete(target), body, withAction(presented))
}

func TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken(t *testing.T) {
	f := newFixture(t)
	routes := guardedRoutes(f)

	for _, route := range routes {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			// Positive control first: a correct token must reach the operation,
			// otherwise every refusal below proves nothing.
			f.runner.reset()
			controlTarget := route.Target(t)
			valid := f.actionToken(t, route.Kind, controlTarget)
			accepted := f.sendGuarded(t, route, controlTarget, valid)
			acceptedStatus := accepted.StatusCode
			acceptedBody := readBody(t, accepted)
			if acceptedStatus == http.StatusForbidden && strings.Contains(acceptedBody, "action_token") {
				t.Fatalf("a freshly issued token was refused: %d %s", acceptedStatus, acceptedBody)
			}

			refusals := []struct {
				name  string
				token func(target string) string
			}{
				{"no token", func(string) string { return "" }},
				{"token from another kind", func(target string) string {
					other := session.ActionReachability
					if route.Kind == other {
						other = session.ActionTerminalLaunch
					}
					return f.tryActionToken(other, target)
				}},
				{"token for another target", func(string) string {
					return f.tryActionToken(route.Kind, "some-other-target")
				}},
				{"token already spent", func(target string) string {
					spent := f.actionToken(t, route.Kind, target)
					readBody(t, f.sendGuarded(t, route, target, spent))
					return spent
				}},
				{"token past its lifetime", func(target string) string {
					aged := f.actionToken(t, route.Kind, target)
					f.clock.advance(session.ActionTokenTTL + time.Minute)
					return aged
				}},
				{"token invented by the caller", func(string) string { return strings.Repeat("A", 43) }},
			}

			for _, refusal := range refusals {
				t.Run(refusal.name, func(t *testing.T) {
					// Each refusal gets its own subject, so a row whose control
					// spent the one it was issued for still has a live subject
					// to be refused against.
					target := route.Target(t)
					presented := refusal.token(target)
					f.runner.reset()
					f.terminal.reset()
					before := f.read("known_hosts")

					response := f.sendGuarded(t, route, target, presented)
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
		key := route.Method + " " + route.Path
		if !requiresConfirmation(route.Path) || tabled[key] {
			continue
		}
		t.Errorf("route %s is a confirmation-guarded operation with no row in guardedRoutes", key)
	}
	// And the other way: a row naming a route the router does not register
	// would silently test nothing.
	registered := map[string]bool{}
	for _, route := range f.apiRoutes() {
		registered[route.Method+" "+route.Path] = true
	}
	for key := range tabled {
		if !registered[key] {
			t.Errorf("guardedRoutes names %s but the server registers no such route", key)
		}
	}
}

// requiresConfirmation names the route families design §8.2 puts behind an
// action token: anything that connects, launches Terminal, edits known_hosts,
// registers a key on a remote host, reveals a private key or permanently
// deletes one.
//
// POST /api/v1/diagnostics/effective is deliberately absent. Design §8.3 makes
// its confirmation conditional — evaluation runs a command only when the
// configuration carries a Match exec — so a missing token is not a refusal
// there, it is simply an unevaluated answer. That conditional gate has its own
// test below, against a configuration that does carry one.
func requiresConfirmation(path string) bool {
	switch {
	case path == "/api/v1/diagnostics/config", path == "/api/v1/diagnostics/effective":
		return false
	case strings.HasPrefix(path, "/api/v1/diagnostics/"):
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

// TestEvaluationOfAnExecutableConfigurationNeedsAConfirmation covers the gate
// the table above leaves out.
//
// A Match exec is the one directive OpenSSH runs while merely reading a
// configuration file, so `ssh -G` over such a file must not start until the
// user has confirmed the exact command they were shown.
func TestEvaluationOfAnExecutableConfigurationNeedsAConfirmation(t *testing.T) {
	f := newFixture(t)

	// The evidence a diagnostics token carries is derived from the executable
	// directives of the configuration as it stands, so the file is rewritten
	// before any token is issued.
	mustWrite(t, filepath.Join(f.root, "config"), []byte(""+
		"Match exec \"true\"\n"+
		"\tUser matched\n"+
		"\n"+
		"Host bastion\n"+
		"\tHostName 203.0.113.10\n"), 0o600)

	f.runner.reset()
	unconfirmed := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}))
	unconfirmedBody := readBody(t, unconfirmed)
	if commands := f.runner.recorded(); len(commands) != 0 {
		t.Fatalf("evaluating an executable configuration ran %#v without a confirmation", commands)
	}
	if !strings.Contains(unconfirmedBody, `"requiresConfirmation":true`) {
		t.Fatalf("the unconfirmed answer does not report that a confirmation is required: %s", unconfirmedBody)
	}
	if strings.Contains(unconfirmedBody, `"evaluated":true`) {
		t.Fatal("an executable configuration was evaluated without a confirmation")
	}

	// A wrong token is refused outright rather than quietly downgraded to the
	// unconfirmed answer.
	f.runner.reset()
	refused := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}), withAction(strings.Repeat("B", 43)))
	refusedStatus := refused.StatusCode
	readBody(t, refused)
	if refusedStatus != http.StatusForbidden {
		t.Fatalf("an invented token = %d, want 403", refusedStatus)
	}
	if commands := f.runner.recorded(); len(commands) != 0 {
		t.Fatalf("an invented token still ran %#v", commands)
	}

	// Positive control: with a confirmation the evaluation does run, so the two
	// refusals above are the gate working rather than a route that never runs.
	f.runner.reset()
	token := f.actionToken(t, session.ActionEvaluate, "bastion")
	confirmed := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}), withAction(token))
	confirmedBody := readBody(t, confirmed)
	if commands := f.runner.recorded(); len(commands) == 0 {
		t.Fatalf("a confirmed evaluation started no process: %s", confirmedBody)
	}
}

// contentBearingRoutes are the only responses allowed to contain material a
// user would recognise as the contents of a file. Each entry states why.
//
// This map is the assertion, not a convenience: a route that leaks without a
// row here fails, and a row whose route stops leaking also fails, so the
// allowlist cannot quietly widen into a blanket exemption.
var contentBearingRoutes = map[string]string{
	"GET /api/v1/config/overview":  "the overview carries the parsed text of every managed file",
	"GET /api/v1/config/file":      "the raw editor is the feature; it returns the file the user asked to edit",
	"GET /api/v1/config/host":      "the block editor returns the raw text of the block the user opened",
	"POST /api/v1/config/preview":  "a save preview is a diff of configuration text",
	"POST /api/v1/config/save":     "a save result reports the diff it wrote",
	"POST /api/v1/history/restore": "a restore reports the diff it wrote",
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

	// The reveal goes first. Phase one below drives POST /api/v1/keys/:keyId/trash
	// on the fixture key, and a trashed key can no longer have a reveal
	// confirmation minted for it, so the one response allowed to carry key
	// material has to be collected while the key is still there.
	keyID := f.keyID()
	revealToken := f.actionToken(t, session.ActionRevealPrivateKey, keyID)
	record(http.MethodPost, "/api/v1/keys/"+keyID+"/reveal", nil, withAction(revealToken))

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

	// The reveal goes first, for the same reason as in the response sweep: the
	// route walk below trashes the fixture key.
	keyID := f.keyID()
	revealToken := f.actionToken(t, session.ActionRevealPrivateKey, keyID)
	readBody(t, f.do(http.MethodPost, "/api/v1/keys/"+keyID+"/reveal", nil, withAction(revealToken)))

	// Exercise every route so the log has something in it, including refusals,
	// which are the lines most likely to echo what was rejected.
	for _, route := range f.apiRoutes() {
		readBody(t, f.do(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method)))
		readBody(t, f.do(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method), func(request *http.Request) {
			request.Header.Set("Sec-Fetch-Site", "cross-site")
		}))
	}

	logged := f.logText()
	if strings.TrimSpace(logged) == "" {
		t.Log("the server logged nothing at all, which satisfies this test trivially but is worth knowing")
	}
	for name, secret := range map[string]string{
		"the bootstrap token":      f.canaries.Bootstrap,
		"the session id":           f.canaries.SessionID,
		"the CSRF token":           f.canaries.CSRF,
		"an action token":          revealToken,
		"the key passphrase":       f.canaries.Passphrase,
		"private key material":     f.canaries.PrivateKeyLine,
		"a file outside ~/.ssh":    f.canaries.Outside,
		"configuration file bytes": "Managed by hand since 2019",
	} {
		if secret != "" && strings.Contains(logged, secret) {
			t.Errorf("the log contains %s", name)
		}
	}
	if strings.Contains(logged, f.home) {
		t.Error("the log contains the absolute home directory path")
	}
}

// TestTheLogScrapeWouldNoticeASecret is the leak sweep's own control.
//
// TestNoLogLineCarriesASecret passes trivially against a server that logs
// nothing, and this application logs very little. This proves the scrape reads
// the same stream the server writes to, so a future handler that does log a
// secret would be caught rather than silently missed.
func TestTheLogScrapeWouldNoticeASecret(t *testing.T) {
	f := newFixture(t)
	if _, err := f.logs.Write([]byte("level=INFO msg=\"planted\" token=" + f.canaries.SessionID + "\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.logText(), f.canaries.SessionID) {
		t.Fatal("logText did not observe a line written to the server's own log stream")
	}
	if _, err := os.Stat(filepath.Join(f.home, ".ssh")); err != nil {
		t.Fatal(err)
	}
}

// Nothing in the backup directory is readable without the master password.
//
// The generational backups hold the previous contents of every file this
// application replaces, which is why the writes whose previous contents could
// be a private key used to keep no backup at all and could therefore never be
// undone. This is what makes keeping them safe: the whole directory is
// ciphertext, and restoring one comes back through the vault.
func TestNothingInTheBackupDirectoryIsReadable(t *testing.T) {
	f := newFixture(t)

	base := string(f.read("config"))
	saved := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "config", "base": base,
		"raw": base + "\n# a line that makes this a change\n",
	}))
	status := saved.StatusCode
	body := readBody(t, saved)
	if status != http.StatusOK {
		t.Fatalf("save = %d (%s); there would be no backup to inspect", status, body)
	}

	backups := filepath.Join(f.root, "ssh-ui", "backups")
	found := 0
	err := filepath.WalkDir(backups, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		found++
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		// The previous configuration is what this backup is of, so finding any
		// recognisable part of it means the file was written in the clear.
		for _, secret := range []string{"Host bastion", "203.0.113.10", "IdentityFile"} {
			if bytes.Contains(contents, []byte(secret)) {
				t.Errorf("%s carries %q in the clear", path, secret)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no backup was written, so this test proved nothing")
	}

	// And it can still be restored, which is the whole point of keeping it.
	history := f.do(http.MethodGet, "/api/v1/history", nil)
	defer func() { _ = history.Body.Close() }()
	if history.StatusCode != http.StatusOK {
		t.Fatalf("history = %d", history.StatusCode)
	}
	var listed struct {
		Entries []struct {
			ID         string   `json:"id"`
			Restorable []string `json:"restorable"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(readBody(t, history)), &listed); err != nil {
		t.Fatal(err)
	}
	restored := false
	for _, entry := range listed.Entries {
		for _, path := range entry.Restorable {
			if path != "config" {
				continue
			}
			response := f.do(http.MethodPost, "/api/v1/history/restore",
				mustJSON(t, map[string]any{"transactionId": entry.ID, "path": path}))
			code := response.StatusCode
			restoreBody := readBody(t, response)
			if code != http.StatusOK {
				t.Fatalf("restore = %d (%s)", code, restoreBody)
			}
			restored = true
		}
	}
	if !restored {
		t.Fatal("nothing was offered as restorable")
	}
	if got := string(f.read("config")); got != base {
		t.Errorf("after restoring, config = %q, want the bytes from before the save", got)
	}
}
