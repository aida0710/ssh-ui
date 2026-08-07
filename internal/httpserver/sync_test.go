package httpserver

import (
	"context"
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

	"sshc/internal/objectstore"
	"sshc/internal/remotesync"
	"sshc/internal/secret"
	"sshc/internal/storage"
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
	registerSyncRoutes(engine, SyncHandlers{Service: service, Reach: reachable})
	return engine, service
}

const syncTestPassphrase = "a master password for sync"

// reachable stands in for the bucket. The question "does this bucket answer" is
// remotesync's, and it is tested there against a real HTTP server; here it must
// never be asked of a network.
func reachable(context.Context, *objectstore.Client, string) error { return nil }

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
	secrets := secret.NewService(workspace, manager, time.Now)

	engine := echo.New()
	registerSyncRoutes(engine, SyncHandlers{Service: service, Secrets: secrets, Reach: reachable})
	return engine, service, secrets
}

func sendSync(t *testing.T, engine *echo.Echo, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, engine, method, path, body, nil)
}

func settings(direction string) string {
	body := `{"endpoint":"https://example.invalid","bucket":"sshc",` +
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

// The endpoint is stored as it will be used, not as it was typed.
//
// A trailing slash produced "https://host//bucket" wherever the screen showed
// where the snapshot goes. The request never carried it — the client replaces
// the whole path — so this is about the value the user is shown and asked to
// recognise as their bucket.
func TestATrailingSlashOnTheEndpointIsRemoved(t *testing.T) {
	engine, service, secrets := syncEngineWithVault(t)
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}
	body := `{"endpoint":"https://s3.example.invalid/","bucket":"b","accessKeyId":"k","secretAccessKey":"s"}`
	if code := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", body).Code; code != http.StatusOK {
		t.Fatalf("configure = %d", code)
	}
	endpoint, _, _ := service.Target()
	if endpoint != "https://s3.example.invalid" {
		t.Errorf("endpoint = %q, want the trailing slash gone", endpoint)
	}
}

// An endpoint with a path is refused rather than silently truncated. The client
// replaces the path with /bucket/key, so a pasted "…/my-bucket" would be
// dropped without a word and the user would be looking for their objects in a
// place this application never wrote to.
func TestAnEndpointWithAPathIsRefused(t *testing.T) {
	engine, _, secrets := syncEngineWithVault(t)
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}
	body := `{"endpoint":"https://s3.example.invalid/my-bucket","bucket":"b","accessKeyId":"k","secretAccessKey":"s"}`
	recorder := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", body)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("configure with a path = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "endpoint_must_have_no_path") {
		t.Errorf("code = %s", recorder.Body.String())
	}
}

// Settings are tried before they are kept.
//
// A bucket that will not answer is a bucket the user has mistyped, and storing
// the mistake means the failure surfaces on the first push instead of on the
// screen where it can be corrected. Nothing is stored and nothing is
// configured: a half-applied refusal would be worse than none.
func TestSettingsThatCannotReachTheBucketAreNotStored(t *testing.T) {
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
		func() (string, error) { return "origin-test", nil })
	secrets := secret.NewService(workspace, manager, time.Now)
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}
	engine := echo.New()
	registerSyncRoutes(engine, SyncHandlers{
		Service: service, Secrets: secrets,
		Reach: func(context.Context, *objectstore.Client, string) error { return objectstore.ErrRefused },
	})

	body := `{"endpoint":"https://s3.example.invalid","bucket":"b","accessKeyId":"k","secretAccessKey":"s"}`
	recorder := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", body)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("configure against an unreachable bucket = %d, want 502: %s", recorder.Code, recorder.Body.String())
	}
	if service.Configured() {
		t.Error("the service was configured with settings that do not work")
	}
	if settings, err := secrets.SyncSettings(); err != nil || settings.Bucket != "" {
		t.Errorf("the settings were stored anyway: %+v (%v)", settings, err)
	}
}

// The snapshot is sealed with the master password, not a second one.
//
// Two passwords meant two things to remember, and the second one was typed into
// a field that could not check it: a typo produced an archive nobody could ever
// open, and said so on the next machine, months later. This is the check that
// was missing.
func TestPushRefusesAPasswordThatIsNotTheMasterOne(t *testing.T) {
	engine, _, secrets := syncEngineWithVault(t)
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}
	if code := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", settings("")).Code; code != http.StatusOK {
		t.Fatalf("configure = %d", code)
	}

	recorder := sendSync(t, engine, http.MethodPost, "/api/v1/sync/push", `{"passphrase":"not the master password"}`)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("push with the wrong password = %d, want 403: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "wrong_master_password") {
		t.Errorf("code = %s", recorder.Body.String())
	}
	// And it stopped there. A handler that writes a refusal and then does the
	// thing anyway leaves both answers in the body, and the first status is all
	// the recorder reports — so the refusal is checked by what did not happen
	// after it.
	if strings.Contains(recorder.Body.String(), "sync_failed") {
		t.Errorf("the push ran after being refused: %s", recorder.Body.String())
	}
}

// A machine that has never made a vault is a machine doing its first pull. The
// password it types is the key to the archive, nothing here can check it, and
// the archive itself will.
func TestPullOnAMachineWithNoVaultIsNotRefusedForTheWrongReason(t *testing.T) {
	engine, _ := syncEngine(t)
	if code := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", settings("")).Code; code != http.StatusOK {
		t.Fatalf("configure = %d", code)
	}

	recorder := sendSync(t, engine, http.MethodPost, "/api/v1/sync/pull", `{"passphrase":"a password for a vault that is not here"}`)
	if recorder.Code == http.StatusForbidden && strings.Contains(recorder.Body.String(), "wrong_master_password") {
		t.Errorf("a machine with no vault was told its master password was wrong: %s", recorder.Body.String())
	}
}

// The path is stored and reported back, and it is as narrow as the bucket name:
// both become segments in a URL this application signs.
func TestTheObjectPathIsStoredAndRefusedWhenItCouldEscape(t *testing.T) {
	engine, service, secrets := syncEngineWithVault(t)
	if err := secrets.Initialise(syncTestPassphrase); err != nil {
		t.Fatal(err)
	}

	body := `{"endpoint":"https://s3.example.invalid","bucket":"b","path":"/laptops/","accessKeyId":"k","secretAccessKey":"s"}`
	recorder := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("configure = %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, _, path := service.Target(); path != "laptops" {
		t.Errorf("path = %q, want it trimmed to laptops", path)
	}
	if !strings.Contains(recorder.Body.String(), `"path":"laptops"`) {
		t.Errorf("the status does not report the path: %s", recorder.Body.String())
	}

	for _, unsafe := range []string{"../elsewhere", "a//b", "a b"} {
		escaping := `{"endpoint":"https://s3.example.invalid","bucket":"b","path":"` + unsafe +
			`","accessKeyId":"k","secretAccessKey":"s"}`
		if code := sendSync(t, engine, http.MethodPut, "/api/v1/sync/settings", escaping).Code; code != http.StatusBadRequest {
			t.Errorf("configure with path %q = %d, want 400", unsafe, code)
		}
	}
	// And the refusals changed nothing.
	if _, _, path := service.Target(); path != "laptops" {
		t.Errorf("path = %q after refusals, want laptops", path)
	}
}
