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

	"sshc/internal/api"
	"sshc/internal/application"
	"sshc/internal/secret"
	"sshc/internal/storage"
)

const testPassphrase = "correct horse battery staple"

func passwordEngine(t *testing.T) (*echo.Echo, *secret.Service) {
	engine, service, _ := passwordEngineIn(t)
	return engine, service
}

// passwordEngineIn は home も返す。API の返答ではなく実際に書かれた
// ものを読むテストのためである。
func passwordEngineIn(t *testing.T) (*echo.Echo, *secret.Service, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	service := secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now)

	engine := echo.New()
	registerPasswordRoutes(engine, PasswordHandlers{
		Service:    service,
		Answerable: func(_ string, prompt string) bool { return strings.HasSuffix(prompt, "password: ") },
	})
	return engine, service, home
}

func send(t *testing.T, engine *echo.Echo, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set(echo.HeaderContentType, "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	return recorder
}

func TestNoPasswordRouteEverReturnsAPassword(t *testing.T) {
	// 腐らせてはならないアサーションである。このファイルの全ルートが
	// 走査対象であり、書き込みを行うものも含め、どの body にも
	// 保存された値が含まれてはならない。
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	responses := []*httptest.ResponseRecorder{
		send(t, engine, http.MethodGet, "/api/v1/passwords", "", nil),
		send(t, engine, http.MethodPut, "/api/v1/passwords/bastion", `{"password":"hunter2"}`, nil),
		send(t, engine, http.MethodPost, "/api/v1/passwords/unlock", `{"passphrase":"`+testPassphrase+`"}`, nil),
		send(t, engine, http.MethodPost, "/api/v1/passwords/lock", "", nil),
		send(t, engine, http.MethodDelete, "/api/v1/passwords/bastion", "", nil),
	}
	for index, response := range responses {
		if strings.Contains(response.Body.String(), "hunter2") {
			t.Errorf("response %d contains the stored password: %s", index, response.Body.String())
		}
		if strings.Contains(response.Body.String(), testPassphrase) {
			t.Errorf("response %d contains the vault passphrase", index)
		}
	}
}

func TestStatusReportsWhichHostsHaveAPasswordAndNothingElse(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	response := send(t, engine, http.MethodGet, "/api/v1/passwords", "", nil)
	var status struct {
		Exists   bool     `json:"exists"`
		Unlocked bool     `json:"unlocked"`
		Aliases  []string `json:"aliases"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode: %v (%s)", err, response.Body.String())
	}
	if !status.Exists || !status.Unlocked || len(status.Aliases) != 1 || status.Aliases[0] != "bastion" {
		t.Errorf("status = %#v", status)
	}
}

func TestStoringRefusesWhileTheVaultIsLocked(t *testing.T) {
	engine, _ := passwordEngine(t)

	response := send(t, engine, http.MethodPut, "/api/v1/passwords/bastion", `{"password":"hunter2"}`, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", response.Code)
	}
}

func TestInitialiseRefusesAShortPassphraseAndDoesNotCreateAVault(t *testing.T) {
	engine, service := passwordEngine(t)

	response := send(t, engine, http.MethodPost, "/api/v1/passwords/initialise", `{"passphrase":"short"}`, nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", response.Code)
	}
	exists, err := service.Exists()
	if err != nil || exists {
		t.Errorf("a vault was created: %v, %v", exists, err)
	}
}

func askpassHeaders(token string) map[string]string {
	return map[string]string{
		echo.HeaderContentType: "application/json",
		AskpassTokenHeader:     token,
	}
}

func TestAskpassAnswersOnceWithAValidToken(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"alias":"bastion","prompt":"ops@203.0.113.10's password: "}`
	first := send(t, engine, http.MethodPost, AskpassPath, body, askpassHeaders(token))
	if first.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", first.Code, first.Body.String())
	}
	var answer struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &answer); err != nil || answer.Password != "hunter2" {
		t.Fatalf("answer = %#v, err = %v", answer, err)
	}

	second := send(t, engine, http.MethodPost, AskpassPath, body, askpassHeaders(token))
	if second.Code == http.StatusOK {
		t.Fatal("the token was accepted a second time")
	}
}

func TestAskpassRefusesWithoutAValidRequest(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"alias":"bastion","prompt":"ops@h's password: "}`

	cases := map[string]struct {
		headers map[string]string
		body    string
	}{
		"no token":    {map[string]string{echo.HeaderContentType: "application/json"}, body},
		"wrong token": {askpassHeaders("not-the-token"), body},
		// form の content type は、クロスオリジンのページがプリフライトなしに
		// 送れるものなので、侵入経路になってはならない。
		"form content type": {map[string]string{
			echo.HeaderContentType: "application/x-www-form-urlencoded",
			AskpassTokenHeader:     token,
		}, body},
		"host key prompt": {askpassHeaders(token),
			`{"alias":"bastion","prompt":"Are you sure you want to continue connecting (yes/no)? "}`},
		"unsafe alias": {askpassHeaders(token), `{"alias":"bad alias","prompt":"x's password: "}`},
		"not json":     {askpassHeaders(token), `not json at all`},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			response := send(t, engine, http.MethodPost, AskpassPath, test.body, test.headers)
			if response.Code == http.StatusOK {
				t.Fatalf("the request was answered: %s", response.Body.String())
			}
			if strings.Contains(response.Body.String(), "hunter2") {
				t.Error("a refusal carried the password")
			}
		})
	}
}

func TestAskpassNeverAnswersWithoutAPromptRule(t *testing.T) {
	// nil の predicate は「何も答えない」を意味し、決して「何でも答える」ではない。
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	service := secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}

	engine := echo.New()
	registerPasswordRoutes(engine, PasswordHandlers{Service: service, Answerable: nil})

	response := send(t, engine, http.MethodPost, AskpassPath,
		`{"alias":"bastion","prompt":"ops@h's password: "}`, askpassHeaders(token))
	if response.Code == http.StatusOK {
		t.Fatalf("a handler with no prompt rule answered: %s", response.Body.String())
	}
}

func TestStoreRefusesAPasswordTheHostWouldNeverBeOffered(t *testing.T) {
	// interface はこのフィールドを無効化するが、interface は差し替え
	// 可能でもこちら側はそうではない。blocker があれば保存された
	// パスワードは決して使われず、保存しても無駄に secret をディスクに置くだけになる。
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	registerPasswordRoutes(engine, PasswordHandlers{
		Service:    service,
		Answerable: func(_ string, prompt string) bool { return strings.HasSuffix(prompt, "password: ") },
		Eligibility: func(alias string) (application.PasswordEligibility, error) {
			return application.PasswordEligibility{
				Alias:    alias,
				Storable: false,
				Blockers: []application.Notice{{Code: application.BlockerPasswordAuthenticationOff}},
			}, nil
		},
	})

	recorder := send(t, engine, http.MethodPut, "/api/v1/passwords/bastion",
		`{"password":"hunter2"}`, nil)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("PUT = %d, want 409: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code     string   `json:"code"`
		Blockers []string `json:"blockers"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "password_not_storable" {
		t.Errorf("code = %q", body.Code)
	}
	// 理由は拒否と共に運ばれる。理由のない 409 だけでは、ユーザーは
	// 設定が下した判断を vault のせいだと思って探してしまう。
	if len(body.Blockers) != 1 || body.Blockers[0] != application.BlockerPasswordAuthenticationOff {
		t.Errorf("blockers = %#v", body.Blockers)
	}
	// そして何も保存されなかった。
	if service.Has("bastion") {
		t.Error("the vault holds a password for a host that refused one")
	}
}

func TestEligibilityIsReadableAndCarriesTheWarnings(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	registerPasswordRoutes(engine, PasswordHandlers{
		Service: service,
		Eligibility: func(alias string) (application.PasswordEligibility, error) {
			return application.PasswordEligibility{
				Alias: alias, Storable: true,
				Warnings: []application.Notice{{Code: application.WarnHostKeyUnknown, Detail: "203.0.113.10"}},
			}, nil
		},
	})

	recorder := send(t, engine, http.MethodGet, "/api/v1/passwords/bastion/eligibility", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", recorder.Code, recorder.Body.String())
	}
	var report api.PasswordEligibility
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Storable || len(report.Warnings) != 1 {
		t.Fatalf("report = %#v", report)
	}
	if report.Warnings[0].Code != application.WarnHostKeyUnknown {
		t.Errorf("warning = %#v", report.Warnings[0])
	}
}

func credentialPath(kind, rest string) string {
	return "/api/v1/credentials/" + kind + rest
}

// 腐らせてはならない走査を、credential を運ぶルートにも広げたもの
// である。書き込みを行うものも含め、すべてに問い合わせ、
// どの body にも値が含まれてはならない。
func TestNoCredentialRouteEverReturnsASecret(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}

	responses := []*httptest.ResponseRecorder{
		send(t, engine, http.MethodPut, credentialPath("password", "/office"), `{"secret":"hunter2"}`, nil),
		send(t, engine, http.MethodPut, credentialPath("key_passphrase", "/build"), `{"secret":"phrase-2"}`, nil),
		send(t, engine, http.MethodGet, "/api/v1/credentials", "", nil),
		send(t, engine, http.MethodPut, credentialPath("password", "/assign"), `{"subject":"web-1","name":"office"}`, nil),
		send(t, engine, http.MethodGet, "/api/v1/credentials", "", nil),
		send(t, engine, http.MethodDelete, credentialPath("password", "/assign/web-1"), "", nil),
		send(t, engine, http.MethodDelete, credentialPath("password", "/office"), "", nil),
	}
	for index, response := range responses {
		for _, absent := range []string{"hunter2", "phrase-2", testPassphrase} {
			if strings.Contains(response.Body.String(), absent) {
				t.Errorf("response %d carries %q: %s", index, absent, response.Body.String())
			}
		}
	}
}

func TestCredentialsListNamesAndUses(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	send(t, engine, http.MethodPut, credentialPath("password", "/office"), `{"secret":"hunter2"}`, nil)
	send(t, engine, http.MethodPut, credentialPath("password", "/assign"), `{"subject":"web-1","name":"office"}`, nil)
	send(t, engine, http.MethodPut, credentialPath("password", "/assign"), `{"subject":"web-2","name":"office"}`, nil)

	response := send(t, engine, http.MethodGet, "/api/v1/credentials", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"office", "web-1", "web-2"} {
		if !strings.Contains(body, want) {
			t.Errorf("list does not carry %q: %s", want, body)
		}
	}
}

// 2 台のマシンがまだ指している名前を削除すれば、後でどこか別の
// 場所で両方が壊れる。拒否はどれが使っているかを教える。
func TestDeletingACredentialInUseIsRefusedWithItsUses(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	send(t, engine, http.MethodPut, credentialPath("password", "/office"), `{"secret":"hunter2"}`, nil)
	send(t, engine, http.MethodPut, credentialPath("password", "/assign"), `{"subject":"web-1","name":"office"}`, nil)

	response := send(t, engine, http.MethodDelete, credentialPath("password", "/office"), "", nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("delete of a used credential = %d, want 409: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "web-1") {
		t.Errorf("the refusal does not say what uses it: %s", response.Body.String())
	}
}

// ブラウザが実際に到達する境界における、その分離である。
func TestAHostCannotBePointedAtAKeyPassphraseThroughTheAPI(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	send(t, engine, http.MethodPut, credentialPath("key_passphrase", "/build"), `{"secret":"phrase"}`, nil)

	response := send(t, engine, http.MethodPut, credentialPath("password", "/assign"), `{"subject":"web-1","name":"build"}`, nil)
	if response.Code == http.StatusOK {
		t.Error("a host was pointed at a key passphrase through the API")
	}
}

func TestAnUnknownCredentialKindIsRefused(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}

	if code := send(t, engine, http.MethodPut, credentialPath("wallet", "/x"), `{"secret":"y"}`, nil).Code; code != http.StatusBadRequest {
		t.Errorf("an unknown kind = %d, want 400", code)
	}
}

func TestEveryCredentialRouteRefusesALockedVault(t *testing.T) {
	engine, service := passwordEngine(t)
	if err := service.Initialise(testPassphrase); err != nil {
		t.Fatal(err)
	}
	service.Lock()

	for _, call := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/credentials", ""},
		{http.MethodPut, credentialPath("password", "/office"), `{"secret":"x"}`},
		{http.MethodDelete, credentialPath("password", "/office"), ""},
		{http.MethodPut, credentialPath("password", "/assign"), `{"subject":"web-1","name":"office"}`},
		{http.MethodDelete, credentialPath("password", "/assign/web-1"), ""},
	} {
		if code := send(t, engine, call.method, call.path, call.body, nil).Code; code != http.StatusConflict {
			t.Errorf("%s %s while locked = %d, want 409", call.method, call.path, code)
		}
	}
}

// 端から端までの、仕組み全体である。
//
// 1 つの名前の下に secret が 1 つ、それを指すホストが 2 つ、そして
// ホストも secret も名指ししないディスク上のファイルがある。これが
// secret に名前を付けて得たものだ——以前は 2 台の同じパスワードは
// 2 つのコピーであり、変更は 2 箇所の編集で、同じものと分かる術がなかった。
func TestOneNamedSecretServesTwoHostsAndTheFileNamesNeither(t *testing.T) {
	engine, _, home := passwordEngineIn(t)

	if code := send(t, engine, http.MethodPost, "/api/v1/passwords/initialise",
		`{"passphrase":"`+testPassphrase+`"}`, nil).Code; code != http.StatusOK {
		t.Fatalf("initialise = %d", code)
	}
	if code := send(t, engine, http.MethodPut, "/api/v1/credentials/password/office-vm",
		`{"secret":"hunter2"}`, nil).Code; code != http.StatusOK {
		t.Fatalf("store = %d", code)
	}
	for _, alias := range []string{"web-1", "web-2"} {
		body := `{"subject":"` + alias + `","name":"office-vm"}`
		if code := send(t, engine, http.MethodPut, "/api/v1/credentials/password/assign", body, nil).Code; code != http.StatusOK {
			t.Fatalf("assign %s = %d", alias, code)
		}
	}

	listed := send(t, engine, http.MethodGet, "/api/v1/credentials", "", nil)
	var answer api.CredentialList
	if err := json.Unmarshal(listed.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if len(answer.Credentials) != 1 || len(answer.Credentials[0].Uses) != 2 {
		t.Fatalf("the list does not say one name serves two hosts: %s", listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), "hunter2") {
		t.Error("the list carries the secret itself")
	}

	sealed, err := os.ReadFile(filepath.Join(home, ".ssh", filepath.FromSlash(secret.WorkspacePath)))
	if err != nil {
		t.Fatalf("the vault was not written: %v", err)
	}
	for _, absent := range []string{"hunter2", "office-vm", "web-1", "web-2"} {
		if strings.Contains(string(sealed), absent) {
			t.Errorf("the sealed file contains %q in clear", absent)
		}
	}

	// 同じワークスペースに対する 2 つ目の service は、このファイル形式が
	// 存在する理由そのものである、application の次回の実行である。
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	reopened := secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now)
	if err := reopened.Unlock(testPassphrase); err != nil {
		t.Fatalf("Unlock = %v", err)
	}
	for _, alias := range []string{"web-1", "web-2"} {
		if got := reopened.PasswordFor(alias); got != "hunter2" {
			t.Errorf("PasswordFor(%q) = %q, want the one secret both point at", alias, got)
		}
	}
}

// マスターパスワードの変更は bucket の最新スナップショットも再封印し、
// できなかった場合はそう伝える。
func TestChangingTheMasterPasswordReportsWhetherTheBucketFollowed(t *testing.T) {
	engine, service, _ := passwordEngineIn(t)
	if code := send(t, engine, http.MethodPost, "/api/v1/passwords/initialise",
		`{"passphrase":"`+testPassphrase+`"}`, nil).Code; code != http.StatusOK {
		t.Fatal("initialise")
	}
	_ = service

	// bucket が配線されていない場合、ローカル側は完了しており、応答は
	// リモート側も完了したとは主張しない。
	recorder := send(t, engine, http.MethodPost, "/api/v1/passwords/change",
		`{"current":"`+testPassphrase+`","next":"a different master password"}`, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", recorder.Code, recorder.Body.String())
	}
	var answer api.ChangeMasterPasswordResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.SnapshotResealed {
		t.Error("it claims the bucket was updated when no bucket is configured")
	}

	// そして今動くのは新しい方である。
	if code := send(t, engine, http.MethodPost, "/api/v1/passwords/unlock",
		`{"passphrase":"`+testPassphrase+`"}`, nil).Code; code != http.StatusForbidden {
		t.Error("the old master password still unlocks")
	}
	if code := send(t, engine, http.MethodPost, "/api/v1/passwords/unlock",
		`{"passphrase":"a different master password"}`, nil).Code; code != http.StatusOK {
		t.Error("the new master password does not unlock")
	}
}
