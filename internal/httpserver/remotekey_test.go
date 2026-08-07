package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/diagnostics"
	"sshc/internal/platform"
	"sshc/internal/remotekey"
	"sshc/internal/session"
	"sshc/internal/storage"
)

const remoteKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS fixture@example"

// sequencedRunner は呼び出しごとに用意した出力を 1 つずつ再生する。
// これにより、プロセスを起動せずに probe と registration に別々の応答をさせられる。
type sequencedRunner struct {
	commands []platform.Command
	outputs  []platform.Output
}

func (runner *sequencedRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	if len(runner.outputs) == 0 {
		return platform.Output{}, nil
	}
	next := runner.outputs[0]
	runner.outputs = runner.outputs[1:]
	return next, nil
}

func newRemoteKeyServer(t *testing.T, outputs []platform.Output) (*echo.Echo, session.Credentials, *sequencedRunner) {
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

	diagnosticsService := diagnostics.NewService(workspace, &stubRunner{}, stubToolchain{}, nil, nil)
	diagnosticsService.Reachability = diagnostics.Reachability{
		Dialer: dialerStub(func(context.Context, string, string) (net.Conn, error) {
			return nil, net.UnknownNetworkError("unreachable in test")
		}),
	}

	runner := &sequencedRunner{outputs: outputs}
	remote := &remotekey.Service{
		Runner:     runner,
		Toolchain:  stubToolchain{},
		ConfigPath: diagnosticsService.ConfigPath(),
	}

	sessions, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x77}, 8192)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := sessions.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	engine := echo.New()
	engine.Use((Security{ExpectedHost: keyTestHost, ExpectedOrigin: "http://" + keyTestHost, Sessions: sessions, Unlocked: alwaysUnlocked}).Middleware)
	registry := actionRegistry{}
	addDiagnosticsActions(registry, diagnosticsService)
	actions := ActionHandlers{Sessions: sessions, Kinds: registry}
	registerActionRoutes(engine, actions)
	registerRemoteKeyRoutes(engine, RemoteKeyHandlers{
		Service:     remote,
		Diagnostics: diagnosticsService,
		Actions:     actions,
	})
	return engine, credentials, runner
}

func TestRemoteKeyPlanDescribesTheChangeWithoutContactingAnything(t *testing.T) {
	engine, credentials, runner := newRemoteKeyServer(t, nil)

	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/remote-keys/plan",
		mustMarshal(t, api.RemoteKeyPlanRequest{
			Alias: "bastion", KeyPath: "~/.ssh/id_ed25519.pub", PublicKey: remoteKeyLine,
		}), "")
	if response.Code != http.StatusOK {
		t.Fatalf("plan = %d: %s", response.Code, response.Body.String())
	}
	var payload api.RemoteKeyPlan
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.RemotePath != "~/.ssh/authorized_keys" || !payload.Supported {
		t.Fatalf("plan = %#v", payload)
	}
	if payload.Routine != remotekey.Routine {
		t.Error("the plan must show the exact routine that will run")
	}
	if strings.Contains(payload.Routine, "fixture@example") || strings.Contains(payload.Routine, "bastion") {
		t.Fatal("the routine carried caller input")
	}
	if len(payload.Manual) == 0 {
		t.Error("the plan must offer manual instructions")
	}
	// plan は設定が持つ ProxyCommand を表示する。鍵を登録するために
	// 接続すれば、それが実行されてしまうからだ。
	if len(payload.ExecutableDirectives) != 1 {
		t.Errorf("executable directives = %#v", payload.ExecutableDirectives)
	}
	if len(runner.commands) != 0 {
		t.Fatal("planning started a process")
	}
}

func TestRemoteKeyRegisterNeedsAConfirmationAndSendsTheKeyOnStdin(t *testing.T) {
	engine, credentials, runner := newRemoteKeyServer(t, []platform.Output{
		{Stdout: []byte(remotekey.ProbeMarker + "\n")},
		{Stdout: []byte("sshc: added\n")},
	})
	body := mustMarshal(t, api.RemoteKeyRegisterRequest{
		Alias: "bastion", KeyPath: "~/.ssh/id_ed25519.pub", PublicKey: remoteKeyLine, AcknowledgeExecutable: true,
	})

	refused := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/remote-keys/register", body, "")
	if refused.Code != http.StatusForbidden {
		t.Fatalf("register without a confirmation = %d, want 403", refused.Code)
	}
	if len(runner.commands) != 0 {
		t.Fatal("an unconfirmed registration started a process")
	}

	token := diagnosticsToken(t, engine, credentials, session.ActionRemoteKeyRegister, "bastion")
	accepted := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/remote-keys/register", body, token)
	if accepted.Code != http.StatusOK {
		t.Fatalf("register = %d: %s", accepted.Code, accepted.Body.String())
	}
	var payload api.RemoteKeyRegisterResponse
	if err := json.Unmarshal(accepted.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Outcome != remotekey.RegistrationAdded {
		t.Fatalf("payload = %#v", payload)
	}

	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v", runner.commands)
	}
	register := runner.commands[1]
	if string(register.Stdin) != remoteKeyLine+"\n" {
		t.Errorf("stdin = %q, want the key line", register.Stdin)
	}
	// argv に可変のものが現れてはならない。routine は定数であり、
	// 鍵は標準入力に乗せて運ばれる。
	for _, argument := range register.Arguments {
		if argument == remotekey.Routine {
			continue
		}
		if strings.Contains(argument, "AAAAC3Nza") || strings.Contains(argument, "fixture@example") {
			t.Fatalf("argv carried key material: %q", argument)
		}
	}
}

func TestRemoteKeyRegisterRefusesAnUnacknowledgedExecutableDirective(t *testing.T) {
	engine, credentials, runner := newRemoteKeyServer(t, []platform.Output{
		{Stdout: []byte(remotekey.ProbeMarker + "\n")},
		{Stdout: []byte("sshc: added\n")},
	})

	token := diagnosticsToken(t, engine, credentials, session.ActionRemoteKeyRegister, "bastion")
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/remote-keys/register",
		mustMarshal(t, api.RemoteKeyRegisterRequest{
			Alias: "bastion", KeyPath: "x", PublicKey: remoteKeyLine, AcknowledgeExecutable: false,
		}), token)
	if response.Code != http.StatusConflict {
		t.Fatalf("unacknowledged directive = %d, want 409: %s", response.Code, response.Body.String())
	}
	if len(runner.commands) != 0 {
		t.Fatal("a refused registration started a process")
	}
}

func TestRemoteKeyRegisterRejectsAKeyItCannotParse(t *testing.T) {
	engine, credentials, runner := newRemoteKeyServer(t, nil)

	token := diagnosticsToken(t, engine, credentials, session.ActionRemoteKeyRegister, "bastion")
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/remote-keys/register",
		mustMarshal(t, api.RemoteKeyRegisterRequest{
			Alias: "bastion", KeyPath: "x", PublicKey: "rm -rf / AAAA", AcknowledgeExecutable: true,
		}), token)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid key = %d, want 400: %s", response.Code, response.Body.String())
	}
	if len(runner.commands) != 0 {
		t.Fatal("an invalid key started a process")
	}
}
