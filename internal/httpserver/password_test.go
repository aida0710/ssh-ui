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

	"ssh-ui/internal/secret"
	"ssh-ui/internal/storage"
)

const testPassphrase = "correct horse battery staple"

func passwordEngine(t *testing.T) (*echo.Echo, *secret.Service) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	service := secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader))

	engine := echo.New()
	registerPasswordRoutes(engine, PasswordHandlers{
		Service:    service,
		Answerable: func(prompt string) bool { return strings.HasSuffix(prompt, "password: ") },
	})
	return engine, service
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
	// The assertion that must not be allowed to rot. Every route in this file
	// is swept, including the ones that write, and none of their bodies may
	// contain the stored value.
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
		// A form content type is what a cross-origin page could send without a
		// preflight, so it must not be a way in.
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
	// A nil predicate must mean "answer nothing", never "answer everything".
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	service := secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader))
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
