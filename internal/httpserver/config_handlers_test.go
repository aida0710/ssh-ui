package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/application"
	"sshc/internal/session"
	"sshc/internal/storage"
)

const handlerConfig = "Host bastion\n\tHostName 203.0.113.10\n\tPort 22\n"

type testHarness struct {
	echo    *echo.Echo
	cookie  *http.Cookie
	csrf    string
	root    string
	service *application.Service
}

func newConfigHarness(t *testing.T) *testHarness {
	t.Helper()
	home := t.TempDir()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	if err := workspace.EnsureDirectory(workspace.Root()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(handlerConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := storage.NewManager(workspace, time.Now, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))
	service := application.NewService(workspace, manager)

	sessions, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0xa1}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := sessions.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	engine := echo.New()
	engine.Use((Security{
		ExpectedHost:   "127.0.0.1:43123",
		ExpectedOrigin: "http://127.0.0.1:43123",
		Sessions:       sessions, Unlocked: alwaysUnlocked,
	}).Middleware)
	registerConfigRoutes(engine, ConfigHandlers{Service: service})

	return &testHarness{
		echo:    engine,
		cookie:  &http.Cookie{Name: SessionCookie, Value: credentials.SessionID},
		csrf:    credentials.CSRFToken,
		root:    workspace.Root(),
		service: service,
	}
}

func (h *testHarness) call(t *testing.T, method, target string, body any, authenticated, withCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(encoded))
	} else {
		reader = strings.NewReader("")
	}
	request := httptest.NewRequest(method, target, reader)
	request.Host = "127.0.0.1:43123"
	request.Header.Set(echo.HeaderContentType, "application/json")
	// Fetch Metadata はすべての API リクエストで検証されるので、フロントエンドは
	// 書き込みだけでなく読み取りでもこのヘッダーを送る。
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	if method != http.MethodGet {
		request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
	}
	if authenticated {
		request.AddCookie(h.cookie)
	}
	if withCSRF {
		request.Header.Set(CSRFHeader, h.csrf)
	}
	response := httptest.NewRecorder()
	h.echo.ServeHTTP(response, request)
	return response
}

func TestConfigEndpointsRequireASessionAndCSRF(t *testing.T) {
	harness := newConfigHarness(t)

	if got := harness.call(t, http.MethodGet, "/api/v1/config/overview", nil, false, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("overview without a session = %d", got)
	}
	save := application.EditRequest{Kind: application.EditFileRaw, Path: "config", Base: handlerConfig, Raw: handlerConfig}
	if got := harness.call(t, http.MethodPost, "/api/v1/config/save", save, true, false).Code; got != http.StatusForbidden {
		t.Fatalf("save without CSRF = %d", got)
	}
	// トークンのない読み取りも拒否される。cookie はポートにスコープされないが、
	// トークンはスコープされるからだ。
	if got := harness.call(t, http.MethodGet, "/api/v1/config/overview", nil, true, false).Code; got != http.StatusForbidden {
		t.Fatalf("overview without CSRF = %d", got)
	}
	response := harness.call(t, http.MethodGet, "/api/v1/config/overview", nil, true, true)
	if response.Code != http.StatusOK {
		t.Fatalf("overview = %d, body %s", response.Code, response.Body.String())
	}
	if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
}

// TestEveryConfigMutationRequiresCSRFAndEveryResponseIsUncacheable は、
// 代表的な 1 ルートだけでなく全面を走査する。あとからヘッダーチェックなしで
// 追加されたルートこそ、このテストが検出すべき退行そのものだからだ。
func TestEveryConfigMutationRequiresCSRFAndEveryResponseIsUncacheable(t *testing.T) {
	harness := newConfigHarness(t)

	mutations := []struct {
		target string
		body   any
	}{
		{"/api/v1/config/preview", application.EditRequest{Kind: application.EditFileRaw, Path: "config", Base: handlerConfig, Raw: handlerConfig}},
		{"/api/v1/config/save", application.EditRequest{Kind: application.EditFileRaw, Path: "config", Base: handlerConfig, Raw: handlerConfig}},
		{"/api/v1/history/restore", restoreRequest{TransactionID: "x", Path: "config"}},
		{"/api/v1/history/recover", recoverRequest{TransactionID: "x", Action: "rollback"}},
	}
	for _, mutation := range mutations {
		response := harness.call(t, http.MethodPost, mutation.target, mutation.body, true, false)
		if response.Code != http.StatusForbidden {
			t.Errorf("POST %s without CSRF = %d, want 403", mutation.target, response.Code)
		}
		if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("POST %s cache control = %q", mutation.target, got)
		}
	}

	reads := []string{
		"/api/v1/config/overview",
		"/api/v1/config/host?path=config&alias=bastion",
		"/api/v1/config/file?path=config",
		"/api/v1/metadata",
		"/api/v1/history",
	}
	for _, target := range reads {
		response := harness.call(t, http.MethodGet, target, nil, true, true)
		if response.Code != http.StatusOK {
			t.Errorf("GET %s = %d, body %s", target, response.Code, response.Body.String())
		}
		if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s cache control = %q", target, got)
		}
		if got := harness.call(t, http.MethodGet, target, nil, false, false).Code; got != http.StatusUnauthorized {
			t.Errorf("GET %s without a session = %d, want 401", target, got)
		}
	}
}

func TestOverviewAndHostResponsesMatchTheGeneratedContract(t *testing.T) {
	harness := newConfigHarness(t)

	overview := harness.call(t, http.MethodGet, "/api/v1/config/overview", nil, true, true)
	var generatedOverview api.Overview
	decoder := json.NewDecoder(bytes.NewReader(overview.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&generatedOverview); err != nil {
		t.Fatalf("overview does not match the contract: %v", err)
	}
	if len(generatedOverview.Hosts) != 1 {
		t.Fatalf("hosts = %#v", generatedOverview.Hosts)
	}

	host := harness.call(t, http.MethodGet, "/api/v1/config/host?path=config&alias=bastion", nil, true, true)
	if host.Code != http.StatusOK {
		t.Fatalf("host = %d, body %s", host.Code, host.Body.String())
	}
	var generatedHost api.HostDetail
	hostDecoder := json.NewDecoder(bytes.NewReader(host.Body.Bytes()))
	hostDecoder.DisallowUnknownFields()
	if err := hostDecoder.Decode(&generatedHost); err != nil {
		t.Fatalf("host detail does not match the contract: %v", err)
	}
}

func TestHostEndpointRejectsTraversalAndUnknownAliases(t *testing.T) {
	harness := newConfigHarness(t)

	if got := harness.call(t, http.MethodGet, "/api/v1/config/host?path=../.bashrc&alias=x", nil, true, true).Code; got != http.StatusBadRequest {
		t.Fatalf("traversal path = %d", got)
	}
	if got := harness.call(t, http.MethodGet, "/api/v1/config/host?path=config&alias=absent", nil, true, true).Code; got != http.StatusNotFound {
		t.Fatalf("unknown alias = %d", got)
	}
}

func TestSaveReportsSyntaxErrorsWithoutLeakingFileContents(t *testing.T) {
	harness := newConfigHarness(t)

	response := harness.call(t, http.MethodPost, "/api/v1/config/save", application.EditRequest{
		Kind: application.EditFileRaw,
		Path: "config",
		Base: handlerConfig,
		Raw:  "Host bastion\n\tHostName \"unbalanced\n",
	}, true, true)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body %s", response.Code, response.Body.String())
	}
	var payload problemPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "config_syntax_error" || payload.Path != "config" || payload.Line != 2 {
		t.Fatalf("payload = %#v", payload)
	}
	if strings.Contains(response.Body.String(), "203.0.113.10") {
		t.Fatal("problem response leaked file contents")
	}
	if got := response.Result().Header.Get(echo.HeaderContentType); !strings.HasPrefix(got, "application/problem+json") {
		t.Fatalf("content type = %q", got)
	}
}

// TestErrorBodiesCarryLocationsNeverConfigurationText は、構文エラーの
// ケースだけでなくエラー面全体を検査する。problem レスポンスはファイル名・
// 行番号・安定した code を含んでよいが、ファイルの中身を書き戻してはならない。
func TestErrorBodiesCarryLocationsNeverConfigurationText(t *testing.T) {
	harness := newConfigHarness(t)
	const secret = "203.0.113.10"

	responses := []*httptest.ResponseRecorder{
		// 新たにパース不能になった行。
		harness.call(t, http.MethodPost, "/api/v1/config/save", application.EditRequest{
			Kind: application.EditFileRaw, Path: "config", Base: handlerConfig,
			Raw: "Host bastion\n\tHostName \"unbalanced\n",
		}, true, true),
		// lossless edit のルールにより拒否された編集。
		harness.call(t, http.MethodPost, "/api/v1/config/save", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: handlerConfig, Alias: "bastion",
			Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 2, Values: []string{`echo "hi"`}}},
		}, true, true),
		// 未知の host。
		harness.call(t, http.MethodGet, "/api/v1/config/host?path=config&alias=absent", nil, true, true),
		// 未知の transaction。
		harness.call(t, http.MethodPost, "/api/v1/history/restore", restoreRequest{
			TransactionID: "20260101T000000.000-aabbccdd", Path: "config",
		}, true, true),
	}
	for index, response := range responses {
		if response.Code < 400 {
			t.Errorf("response[%d] = %d, want an error status", index, response.Code)
		}
		if strings.Contains(response.Body.String(), secret) {
			t.Errorf("response[%d] leaked configuration text: %s", index, response.Body.String())
		}
		var payload problemPayload
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Errorf("response[%d] is not a problem document: %v", index, err)
			continue
		}
		if payload.Code == "" {
			t.Errorf("response[%d] has no stable code: %#v", index, payload)
		}
	}

	// 衝突は diff の行を伴うが、これは本質的に設定テキストであるため、
	// ファイルの中身を書き戻してよい唯一の形である——ただしユーザーに解決を
	// 求めている衝突レポートの中に限る。
	if err := os.WriteFile(filepath.Join(harness.root, "config"), []byte(handlerConfig+"Host later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conflict := harness.call(t, http.MethodPost, "/api/v1/config/save", application.EditRequest{
		Kind: application.EditHostFields, Path: "config", Base: handlerConfig, Alias: "bastion",
		Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 3, Values: []string{"2222"}}},
	}, true, true)
	var payload problemPayload
	if err := json.Unmarshal(conflict.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Conflict == nil {
		t.Fatalf("conflict payload = %#v", payload)
	}
	if payload.Detail != "" {
		t.Fatalf("a conflict must not carry a free-text detail: %q", payload.Detail)
	}
}

func TestSaveReportsAConflictWithBothSides(t *testing.T) {
	harness := newConfigHarness(t)
	if err := os.WriteFile(filepath.Join(harness.root, "config"), []byte(handlerConfig+"Host later\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	response := harness.call(t, http.MethodPost, "/api/v1/config/save", application.EditRequest{
		Kind:   application.EditHostFields,
		Path:   "config",
		Base:   handlerConfig,
		Alias:  "bastion",
		Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 3, Values: []string{"2222"}}},
	}, true, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body %s", response.Code, response.Body.String())
	}
	var payload problemPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "config_conflict" || payload.Conflict == nil || len(payload.Conflict.ExternalChange) == 0 {
		t.Fatalf("payload = %#v", payload)
	}
	// このサブシステムで最も重要なふるまい: ディスク上のファイルは、
	// 別の書き手が置いたものをそのまま保持し続ける。
	contents, err := os.ReadFile(filepath.Join(harness.root, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != handlerConfig+"Host later\n" {
		t.Fatalf("a stale base overwrote the external change: %q", contents)
	}
	if len(payload.Conflict.LocalChange) == 0 {
		t.Fatalf("conflict must show the user's own pending change too: %#v", payload.Conflict)
	}
}

func TestPreviewAndSaveRoundTripThroughTheContract(t *testing.T) {
	harness := newConfigHarness(t)
	request := application.EditRequest{
		Kind:   application.EditHostFields,
		Path:   "config",
		Base:   handlerConfig,
		Alias:  "bastion",
		Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 3, Values: []string{"2222"}}},
	}

	preview := harness.call(t, http.MethodPost, "/api/v1/config/preview", request, true, true)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview = %d, body %s", preview.Code, preview.Body.String())
	}
	var generatedPreview api.SavePreview
	previewDecoder := json.NewDecoder(bytes.NewReader(preview.Body.Bytes()))
	previewDecoder.DisallowUnknownFields()
	if err := previewDecoder.Decode(&generatedPreview); err != nil {
		t.Fatalf("preview does not match the contract: %v", err)
	}

	save := harness.call(t, http.MethodPost, "/api/v1/config/save", request, true, true)
	if save.Code != http.StatusOK {
		t.Fatalf("save = %d, body %s", save.Code, save.Body.String())
	}
	contents, err := os.ReadFile(filepath.Join(harness.root, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "Host bastion\n\tHostName 203.0.113.10\n\tPort 2222\n" {
		t.Fatalf("config = %q", contents)
	}

	history := harness.call(t, http.MethodGet, "/api/v1/history", nil, true, true)
	var generatedHistory api.HistoryList
	historyDecoder := json.NewDecoder(bytes.NewReader(history.Body.Bytes()))
	historyDecoder.DisallowUnknownFields()
	if err := historyDecoder.Decode(&generatedHistory); err != nil {
		t.Fatalf("history does not match the contract: %v", err)
	}
	if len(generatedHistory.Entries) != 1 {
		t.Fatalf("history entries = %#v", generatedHistory.Entries)
	}
}

func TestSaveRejectsAnUnknownJSONFieldAndAnOversizedBody(t *testing.T) {
	harness := newConfigHarness(t)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/config/save",
		strings.NewReader(`{"kind":"file_raw","path":"config","raw":"Host a\n","surprise":true}`))
	request.Host = "127.0.0.1:43123"
	request.Header.Set(echo.HeaderOrigin, "http://127.0.0.1:43123")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set(echo.HeaderContentType, "application/json")
	request.Header.Set(CSRFHeader, harness.csrf)
	request.AddCookie(harness.cookie)
	response := httptest.NewRecorder()
	harness.echo.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, body %s", response.Code, response.Body.String())
	}

	oversized := application.EditRequest{
		Kind: application.EditFileRaw,
		Path: "config",
		Raw:  strings.Repeat("a", maxRawLength+1),
	}
	if got := harness.call(t, http.MethodPost, "/api/v1/config/save", oversized, true, true).Code; got != http.StatusBadRequest {
		t.Fatalf("oversized raw = %d", got)
	}
}

// アプリケーションが理解し、かつこのファイルが拒否する kind は、
// 誰にも到達できない kind である。
//
// directory の操作は書かれ、サービスに対してテストされ、ここでは
// invalid_request で拒否される。kind ごとの validation は第二の関門であり、
// サービスレベルのテストはそれをそのまま素通りしてしまうからだ。
func TestEveryEditKindTheApplicationAcceptsPassesValidation(t *testing.T) {
	for _, kind := range []application.EditKind{
		application.EditHostFields, application.EditBlockRaw, application.EditFileRaw,
		application.EditRename, application.EditMove, application.EditComment,
		application.EditFileRename, application.EditFileDelete,
		application.EditDirectoryCreate, application.EditDirectoryDelete,
		application.EditGroups, application.EditMetadata,
	} {
		request := application.EditRequest{Kind: kind, Path: "conf.d/10-home.conf"}
		// 各 kind が path 以外に必要とする形だけを見る。したがって以下の失敗は、
		// フィールドの欠落についてではなく、kind が既知かどうかについてのものである。
		switch kind {
		case application.EditHostFields:
			request.Alias = "nas"
			request.Fields = []application.FieldEdit{{
				Action: application.ActionAdd, Keyword: "Port", Values: []string{"22"},
			}}
		case application.EditBlockRaw, application.EditFileRaw:
			request.Alias, request.Raw = "nas", "Host nas\n"
		case application.EditRename:
			request.Alias, request.NewAlias = "nas", "nas2"
		case application.EditMove:
			request.Alias, request.DestinationGroup = "nas", "work"
		case application.EditComment:
			request.Alias = "nas"
		case application.EditFileRename:
			request.DestinationPath = "conf.d/20-home.conf"
		case application.EditGroups, application.EditMetadata:
			metadata := application.NewMetadata()
			request.Metadata, request.Path = &metadata, ""
		}
		if err := validateEditRequest(request); err != nil {
			t.Errorf("validateEditRequest(%q) = %v, so no request of that kind can reach the application", kind, err)
		}
	}
}
