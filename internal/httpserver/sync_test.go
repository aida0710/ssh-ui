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

// reachable は bucket の代わりを務める。「この bucket は応答するか」
// という問いは remotesync のものであり、そちらでは実物の HTTP
// サーバーに対してテストされる。ここではネットワークに問うてはならない。
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
	// 一度も設定されたことのないマシンは、一方向モードにあるのではなく
	// どのモードにもない。その安全な解釈は、普通のモードとみなすことである。
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
	// フィールドを省略することは「今までどおりにする」ではない。設定
	// form は設定全体を送るため、direction が欠けていることは既定値の
	// 要求を意味する。それを設定した form より長生きした一方向設定は、
	// 誰にも見えない設定になってしまう。
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
	// そして何も変わらなかった。すでに半分だけ適用してしまった拒否済み
	// リクエストは、全部適用してしまうより始末が悪い。
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
	// code は設定を名指ししなければならない。"sync_failed" では、
	// このマシンが行った拒否なのに、ユーザーは自分の bucket を疑ってしまう。
	if body.Code != "sync_push_refused" {
		t.Errorf("code = %q, want sync_push_refused", body.Code)
	}
}

// 設定は保存されるため、2 回目の実行でもそれが残っている。決して
// 外へ漏れてはならないのは access key である。status は画面が読む
// ものであり、bucket の場所と vault が施錠中かどうかだけを伝える。
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

// 起動時には何も尋ねないため、画面は「設定済みなのに壊れている」
// ように見える空の form を出す代わりに、なぜ空なのかを言えなければならない。
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

// endpoint は打ち込まれたとおりではなく、使われる形で保存される。
//
// 末尾のスラッシュは、スナップショットの行き先を画面が示すところ
// どこでも "https://host//bucket" を生んでいた。リクエスト自体には
// それは含まれない——client がパス全体を置き換えるからだ——ので、
// これはユーザーに見せて自分の bucket と認識させる値についての話である。
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

// パス付きの endpoint は黙って切り詰めるのではなく拒否する。client
// はパスを /bucket/key に置き換えるため、貼り付けられた
// "…/my-bucket" は何も言わずに捨てられ、ユーザーはこの application が
// 一度も書いたことのない場所にオブジェクトを探すことになる。
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

// 設定は保持される前に試される。
//
// 応答しない bucket は、ユーザーが打ち間違えた bucket である。その
// 間違いを保存してしまうと、直せるはずのこの画面ではなく最初の
// push で失敗が表面化することになる。何も保存されず何も設定
// されない。中途半端に適用された拒否は、何もしないより始末が悪い。
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

// スナップショットは第 2 のパスワードではなくマスターパスワードで封印される。
//
// 2 つのパスワードは覚えるべきものが 2 つあることを意味し、2 つ目は
// それをチェックできないフィールドに打ち込まれていた。typo は誰も
// 二度と開けないアーカイブを作り、それが分かるのは何ヶ月も後の別の
// マシンでのことだった。これが欠けていたチェックである。
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
	// そしてそこで止まった。拒否を書き込んでからそれでも実行してしまう
	// ハンドラは、body に両方の答えを残してしまう。recorder が報告する
	// のは最初の status だけなので、この拒否は、その後に起きなかった
	// ことによって確かめられている。
	if strings.Contains(recorder.Body.String(), "sync_failed") {
		t.Errorf("the push ran after being refused: %s", recorder.Body.String())
	}
}

// vault を一度も作ったことのないマシンは、初めての pull を行う
// マシンである。打ち込まれるパスワードはアーカイブへの鍵であり、
// ここでは確認できない——確認できるのはアーカイブ自身だけだ。
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

// path は保存され、応答にも返される。そして bucket 名と同じくらい
// 狭く絞られている。どちらもこの application が署名する URL のセグメントになるからだ。
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
	// そして拒否によって何も変わらなかった。
	if _, _, path := service.Target(); path != "laptops" {
		t.Errorf("path = %q after refusals, want laptops", path)
	}
}
