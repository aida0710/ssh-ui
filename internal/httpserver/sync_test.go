package httpserver

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/remotesync"
	"ssh-ui/internal/secret"
	"ssh-ui/internal/storage"
)

func syncEngine(t *testing.T) (*echo.Echo, *remotesync.Service) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	service := remotesync.NewService(workspace,
		storage.NewManager(workspace, time.Now, rand.Reader),
		func() ([]string, error) { return []string{"config"}, nil },
		func() string { return "2026-08-05T00:00:00Z" },
		func() (string, error) { return "origin-test", nil },
	)

	engine := echo.New()
	registerSyncRoutes(engine, SyncHandlers{Service: service})
	return engine, service
}

const syncTestPassphrase = "a master password for sync"

func syncEngineWithVault(t *testing.T) (*echo.Echo, *remotesync.Service, *secret.Service) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	manager := storage.NewManager(workspace, time.Now, rand.Reader)
	service := remotesync.NewService(workspace, manager,
		func() ([]string, error) { return []string{"config"}, nil },
		func() string { return "2026-08-05T00:00:00Z" },
		func() (string, error) { return "origin-test", nil },
	)
	secrets := secret.NewService(workspace, manager)

	engine := echo.New()
	registerSyncRoutes(engine, SyncHandlers{Service: service, Secrets: secrets})
	return engine, service, secrets
}

func sendSync(t *testing.T, engine *echo.Echo, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, engine, method, path, body, nil)
}

func settings(direction string) string {
	body := `{"endpoint":"https://example.invalid","bucket":"ssh-ui",` +
		`"accessKeyId":"AKID","secretAccessKey":"secret"`
	if direction != "" {
		body += `,"direction":"` + direction + `"`
	}
	return body + "}"
}

func TestTheDirectionIsReportedAndDefaultsToBoth(t *testing.T) {
	engine, _ := syncEngine(t)

	recorder := send(t, engine, http.MethodGet, "/api/v1/sync", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/sync = %d: %s", recorder.Code, recorder.Body.String())
	}
	var status struct {
		Direction string `json:"direction"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	// A machine that has never been configured is not in a one-way mode: it is
	// in no mode at all, and the safe reading of that is the ordinary one.
	if status.Direction != "both" {
		t.Errorf("direction = %q, want both", status.Direction)
	}
}

func TestSettingsCarryTheDirectionThroughToTheService(t *testing.T) {
	engine, service := syncEngine(t)

	for _, direction := range []string{"push", "pull", "both"} {
		recorder := send(t, engine, http.MethodPut, "/api/v1/sync/settings", settings(direction), nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("PUT with %q = %d: %s", direction, recorder.Code, recorder.Body.String())
		}
		if got := string(service.Direction()); got != direction {
			t.Errorf("after %q the service reports %q", direction, got)
		}
		var status struct {
			Direction string `json:"direction"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Direction != direction {
			t.Errorf("the response reports %q after setting %q", status.Direction, direction)
		}
	}
}

func TestSettingsWithoutADirectionMeanBoth(t *testing.T) {
	engine, service := syncEngine(t)
	if recorder := send(t, engine, http.MethodPut, "/api/v1/sync/settings", settings("pull"), nil); recorder.Code != http.StatusOK {
		t.Fatalf("PUT = %d", recorder.Code)
	}
	if recorder := send(t, engine, http.MethodPut, "/api/v1/sync/settings", settings(""), nil); recorder.Code != http.StatusOK {
		t.Fatalf("PUT = %d", recorder.Code)
	}
	// Omitting the field is not "leave it as it was". The settings form sends
	// the whole configuration, so a missing direction is a request for the
	// default, and a one-way setting that outlived the form that set it would
	// be a setting nobody can see.
	if got := service.Direction(); got != remotesync.DirectionBoth {
		t.Errorf("direction = %q after settings with no direction, want both", got)
	}
}

func TestAnUnknownDirectionIsRefusedRatherThanIgnored(t *testing.T) {
	engine, service := syncEngine(t)
	if recorder := send(t, engine, http.MethodPut, "/api/v1/sync/settings", settings("pull"), nil); recorder.Code != http.StatusOK {
		t.Fatalf("PUT = %d", recorder.Code)
	}

	recorder := send(t, engine, http.MethodPut, "/api/v1/sync/settings", settings("sideways"), nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("PUT with an unknown direction = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	// And it changed nothing: a refused request that had already applied half
	// of itself would be worse than one that applied all of it.
	if got := service.Direction(); got != remotesync.DirectionPull {
		t.Errorf("direction = %q after a refused request, want the previous pull", got)
	}
}

func TestARefusedDirectionIsAConflictAndNotAGatewayFailure(t *testing.T) {
	engine, _ := syncEngine(t)
	if recorder := send(t, engine, http.MethodPut, "/api/v1/sync/settings", settings("pull"), nil); recorder.Code != http.StatusOK {
		t.Fatalf("PUT = %d", recorder.Code)
	}

	recorder := send(t, engine, http.MethodPost, "/api/v1/sync/push", `{"passphrase":"correct horse battery staple"}`, nil)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("POST /push on a receive-only machine = %d, want 409: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// The code has to name the setting, because "sync_failed" would send the
	// user looking at their bucket for a refusal this machine made.
	if body.Code != "sync_push_refused" {
		t.Errorf("code = %q, want sync_push_refused", body.Code)
	}
}

// The settings are stored, so a second run has them. What must never travel
// back out is the access key: the status is what the screen reads, and it says
// where the bucket is and whether the vault is shut, and nothing else.
func TestSyncStatusNeverCarriesTheAccessKey(t *testing.T) {
	engine, service, secrets := syncEngineWithVault(t)
	_ = service
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}

	configure := `{"endpoint":"https://s3.example.invalid","bucket":"b","region":"auto",` +
		`"accessKeyId":"AKIAEXAMPLE","secretAccessKey":"s3cret-key"}`
	if code := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", configure).Code; code != http.StatusOK {
		t.Fatalf("configure = %d", code)
	}

	response := sendSync(t, engine, http.MethodGet, "/api/v1/sync", "")
	for _, absent := range []string{"AKIAEXAMPLE", "s3cret-key"} {
		if strings.Contains(response.Body.String(), absent) {
			t.Errorf("the status carries %q: %s", absent, response.Body.String())
		}
	}
	if !strings.Contains(response.Body.String(), "s3.example.invalid") {
		t.Errorf("the status does not say where the bucket is: %s", response.Body.String())
	}
}

// Nothing is asked at startup, so the screen has to be able to say why its form
// is empty rather than showing an empty form that looks configured-and-broken.
func TestSyncStatusSaysWhenTheVaultIsShut(t *testing.T) {
	engine, _, secrets := syncEngineWithVault(t)
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}
	secrets.Lock()

	response := sendSync(t, engine, http.MethodGet, "/api/v1/sync", "")
	if !strings.Contains(response.Body.String(), `"locked":true`) {
		t.Errorf("the status does not say the vault is shut: %s", response.Body.String())
	}
}

func TestConfiguringRefusesAShutVault(t *testing.T) {
	engine, _, secrets := syncEngineWithVault(t)
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}
	secrets.Lock()

	configure := `{"endpoint":"https://s3.example.invalid","bucket":"b","accessKeyId":"k","secretAccessKey":"s"}`
	if code := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", configure).Code; code != http.StatusConflict {
		t.Errorf("configure while locked = %d, want 409", code)
	}
}
