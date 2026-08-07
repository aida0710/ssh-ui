package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/diagnostics"
	"sshc/internal/platform"
	"sshc/internal/session"
	"sshc/internal/storage"
)

// stubRunner answers without starting a process and records every argv it was
// asked to run, so a test can prove that nothing ran.
type stubRunner struct {
	commands []platform.Command
	output   platform.Output
}

func (runner *stubRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, nil
}

type stubToolchain struct{}

func (stubToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (stubToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }
func (stubToolchain) KeyGen() (string, error)  { return "/usr/bin/ssh-keygen", nil }
func (stubToolchain) KeyAdd() (string, error)  { return "/usr/bin/ssh-add", nil }

type dialerStub func(ctx context.Context, network, address string) (net.Conn, error)

func (dial dialerStub) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dial(ctx, network, address)
}

const diagnosticsConfig = "Host bastion\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 2222\n" +
	"\nHost risky\n\tProxyCommand /usr/bin/nc %h %p\n"

func newDiagnosticsServer(t *testing.T) (*echo.Echo, session.Credentials, *stubRunner, *diagnostics.Service) {
	t.Helper()

	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config"), []byte(diagnosticsConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}

	runner := &stubRunner{output: platform.Output{Stdout: []byte("hostname 203.0.113.10\nport 2222\n")}}
	service := diagnostics.NewService(workspace, runner, stubToolchain{}, nil, nil)
	service.Reachability = diagnostics.Reachability{
		Dialer: dialerStub(func(context.Context, string, string) (net.Conn, error) {
			return nil, net.UnknownNetworkError("unreachable in test")
		}),
	}

	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x3c}, 8192)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	engine := echo.New()
	engine.Use((Security{ExpectedHost: keyTestHost, ExpectedOrigin: "http://" + keyTestHost, Sessions: manager, Unlocked: alwaysUnlocked}).Middleware)
	registry := actionRegistry{}
	addDiagnosticsActions(registry, service)
	actions := ActionHandlers{Sessions: manager, Kinds: registry}
	registerActionRoutes(engine, actions)
	registerDiagnosticsRoutes(engine, DiagnosticsHandlers{Service: service, Actions: actions})
	return engine, credentials, runner, service
}

// diagnosticsToken asks the server for a confirmation exactly as the UI does,
// so the evidence the token carries is the evidence the server derived.
func diagnosticsToken(t *testing.T, engine *echo.Echo, credentials session.Credentials, kind, target string) string {
	t.Helper()
	body, err := json.Marshal(api.IssueActionRequest{Kind: kind, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/actions", body, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("issue action = %d, want 201: %s", response.Code, response.Body.String())
	}
	var issued api.IssueActionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	return issued.Token
}

// problemCode reads the stable code out of a problem+json body, so a test can
// assert which check rejected a request rather than only that one did.
func problemCode(t *testing.T, body []byte) string {
	t.Helper()
	var payload api.Problem
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode problem: %v (%s)", err, body)
	}
	return payload.Code
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEffectiveEndpointEvaluatesASafeConfigurationWithoutAConfirmation(t *testing.T) {
	engine, credentials, _, _ := newDiagnosticsServer(t)

	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/effective",
		mustMarshal(t, api.AliasRequest{Alias: "bastion"}), "")
	if response.Code != http.StatusOK {
		t.Fatalf("effective = %d: %s", response.Code, response.Body.String())
	}

	var payload api.EffectiveResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Evaluated {
		t.Fatalf("a configuration without Match exec evaluates automatically: %#v", payload)
	}
	if len(payload.ExecutableDirectives) != 1 || payload.ExecutableDirectives[0].Command != "/usr/bin/nc %h %p" {
		t.Errorf("executable directives = %#v", payload.ExecutableDirectives)
	}
	if payload.TokenWarning == "" {
		t.Error("the response must carry the token-escaping warning")
	}
	if len(payload.Sources) == 0 || payload.Sources[0].Path == "" {
		t.Errorf("sources = %#v", payload.Sources)
	}
}

func TestStateChangingDiagnosticsRequireCSRFAndAOneTimeActionToken(t *testing.T) {
	engine, credentials, _, _ := newDiagnosticsServer(t)
	body := mustMarshal(t, api.AliasRequest{Alias: "bastion"})

	noToken := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/reachability", body, "")
	if noToken.Code != http.StatusForbidden {
		t.Fatalf("missing action token = %d, want 403", noToken.Code)
	}

	wrongToken := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/reachability",
		body, strings.Repeat("a", 43))
	if wrongToken.Code != http.StatusForbidden {
		t.Fatalf("invalid action token = %d, want 403", wrongToken.Code)
	}

	token := diagnosticsToken(t, engine, credentials, session.ActionReachability, "bastion")
	accepted := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/reachability", body, token)
	if accepted.Code != http.StatusOK {
		t.Fatalf("reachability = %d: %s", accepted.Code, accepted.Body.String())
	}
	var payload api.ReachabilityResponse
	if err := json.Unmarshal(accepted.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Address != "203.0.113.10:2222" || payload.Notice == "" {
		t.Errorf("payload = %#v", payload)
	}

	replay := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/reachability", body, token)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replayed token = %d, want 403", replay.Code)
	}
}

func TestDiagnosticsRejectAMissingCSRFHeader(t *testing.T) {
	engine, credentials, _, _ := newDiagnosticsServer(t)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/reachability",
		bytes.NewReader(mustMarshal(t, api.AliasRequest{Alias: "bastion"})))
	request.Host = keyTestHost
	request.Header.Set(echo.HeaderContentType, "application/json")
	request.Header.Set(echo.HeaderOrigin, "http://"+keyTestHost)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF = %d, want 403", response.Code)
	}
}

func TestActionTokenIsUselessForAnotherOperationOrTarget(t *testing.T) {
	engine, credentials, _, _ := newDiagnosticsServer(t)

	token := diagnosticsToken(t, engine, credentials, session.ActionReachability, "bastion")
	wrongKind := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/authentication",
		mustMarshal(t, api.AuthenticationRequest{Alias: "bastion"}), token)
	if wrongKind.Code != http.StatusForbidden {
		t.Fatalf("token used for another kind = %d, want 403", wrongKind.Code)
	}

	other := diagnosticsToken(t, engine, credentials, session.ActionReachability, "risky")
	wrongTarget := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/reachability",
		mustMarshal(t, api.AliasRequest{Alias: "bastion"}), other)
	if wrongTarget.Code != http.StatusForbidden {
		t.Fatalf("token used for another target = %d, want 403", wrongTarget.Code)
	}
}

func TestDiagnosticsRejectUnsafeAliasesAndOversizedBodies(t *testing.T) {
	engine, credentials, runner, _ := newDiagnosticsServer(t)

	unsafe := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/effective",
		mustMarshal(t, api.AliasRequest{Alias: "-oProxyCommand=id"}), "")
	if unsafe.Code != http.StatusBadRequest {
		t.Fatalf("unsafe alias = %d, want 400", unsafe.Code)
	}
	if len(runner.commands) != 0 {
		t.Fatal("an unsafe alias started a process")
	}

	// A body over the ceiling is now refused by Security.Middleware before the
	// handler decodes anything, so it answers 413 rather than the handler's
	// 400. The property this case guards is unchanged: the request is refused
	// and no process starts.
	oversized := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/effective",
		mustMarshal(t, api.AliasRequest{Alias: strings.Repeat("a", maxRequestBody)}), "")
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, want %d", oversized.Code, http.StatusRequestEntityTooLarge)
	}
	if !strings.Contains(oversized.Body.String(), "request_body_too_large") {
		t.Fatalf("oversized body = %q, want the request_body_too_large problem code", oversized.Body.String())
	}
	if len(runner.commands) != 0 {
		t.Fatal("an oversized body started a process")
	}
}

func TestConfigCheckNeedsNoActionTokenAndStartsNoProcess(t *testing.T) {
	engine, credentials, runner, _ := newDiagnosticsServer(t)

	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/config", []byte(`{}`), "")
	if response.Code != http.StatusOK {
		t.Fatalf("config check = %d: %s", response.Code, response.Body.String())
	}
	var payload api.ConfigCheckResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Files) != 1 {
		t.Fatalf("files = %#v", payload.Files)
	}
	if len(runner.commands) != 0 {
		t.Fatal("the configuration check started a process")
	}
	if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

type recordingLauncher struct{ aliases []string }

func (launcher *recordingLauncher) Launch(_ context.Context, alias string) error {
	launcher.aliases = append(launcher.aliases, alias)
	return nil
}

// TestTerminalEndpointsSeparateCopyableCommandsFromLaunches proves the alias
// gate holds at the HTTP boundary: an alias carrying AppleScript quoting and a
// `do shell script` payload is described as copyable text and refused for
// launch, and never reaches the launcher in any escaped form.
func TestTerminalEndpointsSeparateCopyableCommandsFromLaunches(t *testing.T) {
	engine, credentials, _, service := newDiagnosticsServer(t)
	terminal := &recordingLauncher{}
	service.Terminal = terminal

	hostile := `bastion" & (do shell script "id") & "`
	described := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/terminal/command",
		mustMarshal(t, api.AliasRequest{Alias: hostile}), "")
	if described.Code != http.StatusOK {
		t.Fatalf("terminal command = %d: %s", described.Code, described.Body.String())
	}
	var payload api.TerminalCommandResponse
	if err := json.Unmarshal(described.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Launchable || payload.Warning == "" {
		t.Fatalf("response = %#v", payload)
	}
	if payload.Command != "ssh -- "+hostile {
		t.Errorf("command = %q, want the alias verbatim for copying", payload.Command)
	}

	refused := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/terminal/launch",
		mustMarshal(t, api.AliasRequest{Alias: hostile}), strings.Repeat("a", 43))
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("launching an unsafe alias = %d, want 400", refused.Code)
	}
	// The code is asserted, not just the status, so this proves the launch
	// handler's own gate rejected the alias rather than some later layer
	// happening to answer 400 as well.
	if code := problemCode(t, refused.Body.Bytes()); code != "alias_not_launchable" {
		t.Fatalf("problem code = %q, want alias_not_launchable from the launch gate", code)
	}
	if len(terminal.aliases) != 0 {
		t.Fatalf("an unsafe alias reached the launcher: %#v", terminal.aliases)
	}

	noToken := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/terminal/launch",
		mustMarshal(t, api.AliasRequest{Alias: "bastion"}), "")
	if noToken.Code != http.StatusForbidden {
		t.Fatalf("launch without a confirmation = %d, want 403", noToken.Code)
	}
	if len(terminal.aliases) != 0 {
		t.Fatalf("an unconfirmed launch reached the launcher: %#v", terminal.aliases)
	}

	token := diagnosticsToken(t, engine, credentials, session.ActionTerminalLaunch, "bastion")
	launched := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/terminal/launch",
		mustMarshal(t, api.AliasRequest{Alias: "bastion"}), token)
	if launched.Code != http.StatusOK {
		t.Fatalf("launch = %d: %s", launched.Code, launched.Body.String())
	}
	if len(terminal.aliases) != 1 || terminal.aliases[0] != "bastion" {
		t.Fatalf("aliases = %#v", terminal.aliases)
	}
}

func TestAuthenticationEndpointRefusesUnacknowledgedExecutableDirectives(t *testing.T) {
	engine, credentials, _, service := newDiagnosticsServer(t)
	// A ProxyCommand cannot be disabled from the command line, so connecting
	// runs it and the caller must acknowledge that exact command first.
	service.Authentication.ConfigPath = service.ConfigPath()

	token := diagnosticsToken(t, engine, credentials, session.ActionAuthentication, "risky")
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/authentication",
		mustMarshal(t, api.AuthenticationRequest{Alias: "risky"}), token)
	if response.Code != http.StatusConflict {
		t.Fatalf("unacknowledged executable directive = %d, want 409: %s", response.Code, response.Body.String())
	}

	acknowledged := diagnosticsToken(t, engine, credentials, session.ActionAuthentication, "risky")
	allowed := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/diagnostics/authentication",
		mustMarshal(t, api.AuthenticationRequest{Alias: "risky", AcknowledgeExecutable: true}), acknowledged)
	if allowed.Code != http.StatusOK {
		t.Fatalf("acknowledged test = %d: %s", allowed.Code, allowed.Body.String())
	}
}
