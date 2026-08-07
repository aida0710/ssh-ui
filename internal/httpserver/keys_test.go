package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/keys"
	"sshc/internal/platform"
	"sshc/internal/session"
)

// stubKeyService は、filesystem にも agent にもプロセスにも触れずに応答する。
//
// evidence は mutable である。これにより、ユーザーが確認した瞬間と
// リクエストが届く瞬間の間にディスク上で鍵が変化する様子をテストで再現できる。
type stubKeyService struct {
	inventory     *keys.Inventory
	reveal        keys.RevealResult
	evidence      string
	evidenceErr   error
	revealCalls   int
	purgeCalls    int
	registerErr   error
	deregistered  []string
	deregisterErr error
}

func (stub *stubKeyService) Inventory() (*keys.Inventory, error) { return stub.inventory, nil }

func (stub *stubKeyService) ConfirmationEvidence(keys.ConfirmationSubject, string) (string, error) {
	if stub.evidenceErr != nil {
		return "", stub.evidenceErr
	}
	return stub.evidence, nil
}

func (stub *stubKeyService) AgentIdentities(context.Context) ([]platform.AgentIdentity, bool) {
	return []platform.AgentIdentity{{Bits: 256, Fingerprint: "SHA256:abcdef", Comment: "aida@laptop", Algorithm: "ED25519"}}, true
}

func (stub *stubKeyService) Algorithms(context.Context) keys.Catalogue {
	return keys.Catalogue{Source: "ssh -Q key", Variants: []keys.Variant{{Algorithm: keys.AlgorithmEd25519, Bits: 256, Label: "Ed25519", InProcess: true}}}
}

func (stub *stubKeyService) Generate(keys.GenerateRequest) (keys.GenerateResult, error) {
	return keys.GenerateResult{ID: "key-one", RelativePath: "id_work", PublicRelativePath: "id_work.pub", Encrypted: true, TransactionID: "tx"}, nil
}

func (stub *stubKeyService) HardwareCommand(keys.Algorithm, string, string, string) ([]string, error) {
	return []string{"ssh-keygen", "-t", "ed25519-sk", "-f", "/Users/example/.ssh/id_yubikey"}, nil
}

func (stub *stubKeyService) ChangePassphrase(keys.PassphraseChange) (keys.PassphraseResult, error) {
	return keys.PassphraseResult{ID: "key-one", RelativePath: "id_work", Encrypted: true, TransactionID: "tx"}, nil
}

func (stub *stubKeyService) Reveal(keyID string) (keys.RevealResult, error) {
	if keyID != "key-one" {
		return keys.RevealResult{}, keys.ErrUnknownKey
	}
	stub.revealCalls++
	return stub.reveal, nil
}

// PublicKey は公開の半分だけに応答する。この stub は、本物のサービスと
// 同じ方法で秘密鍵の identifier を拒否する。したがって、秘密鍵をこの
// ルートに通してしまうハンドラのテストは、黙って通るのではなくここで失敗する。
func (stub *stubKeyService) PublicKey(keyID string) (keys.PublicKeyResult, error) {
	if keyID != "key-two" {
		return keys.PublicKeyResult{}, keys.ErrUnknownKey
	}
	return keys.PublicKeyResult{
		ID:           "key-two",
		RelativePath: "id_work.pub",
		Contents:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl aida@laptop\n",
		Fingerprint:  "SHA256:abcdef",
		Comment:      "aida@laptop",
	}, nil
}

func (stub *stubKeyService) Deregister(_ context.Context, keyID string) error {
	stub.deregistered = append(stub.deregistered, keyID)
	return stub.deregisterErr
}

func (stub *stubKeyService) Register(context.Context, keys.RegisterRequest) (keys.RegisterResult, error) {
	if stub.registerErr != nil {
		return keys.RegisterResult{}, stub.registerErr
	}
	return keys.RegisterResult{ID: "key-one", RelativePath: "id_work"}, nil
}

func (stub *stubKeyService) Trash(string) (keys.TrashResult, error) {
	return keys.TrashResult{EntryID: trashEntryID, TransactionID: "tx"}, nil
}

func (stub *stubKeyService) ListTrash() ([]keys.TrashEntry, error) {
	return []keys.TrashEntry{{ID: trashEntryID, DeletedAt: time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC), AgeDays: 40, Stale: true}}, nil
}

func (stub *stubKeyService) Restore(string) (keys.RestoreResult, error) {
	return keys.RestoreResult{EntryID: trashEntryID, Restored: []string{"id_work"}, TransactionID: "tx"}, nil
}

func (stub *stubKeyService) Purge(string) (keys.PurgeResult, error) {
	stub.purgeCalls++
	return keys.PurgeResult{EntryID: trashEntryID, Removed: []string{"id_work"}, TransactionID: "tx"}, nil
}

const (
	keyTestHost  = "127.0.0.1:43123"
	trashEntryID = "20260805T090000.000-aabbccdd"
)

func newKeyServer(t *testing.T, service KeyService) (*echo.Echo, *session.Manager, session.Credentials) {
	t.Helper()
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x51}, 4096)))
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatalf("Bootstrap error = %v", err)
	}
	engine := echo.New()
	engine.Use((Security{ExpectedHost: keyTestHost, ExpectedOrigin: "http://" + keyTestHost, Sessions: manager, Unlocked: alwaysUnlocked}).Middleware)
	// 確認のエンドポイントは他のすべてのサブシステムと共有されるので、この
	// harness は New と全く同じ方法でそれを組み立てる: 鍵 vault の kind だけを
	// 保持する registry である。だからこそ diagnostics の kind はここでは未知のままである。
	registry := actionRegistry{}
	addKeyActions(registry, service)
	actions := ActionHandlers{Sessions: manager, Kinds: registry}
	registerActionRoutes(engine, actions)
	registerKeyRoutes(engine, KeyHandlers{Keys: service, Sessions: manager, Actions: actions})
	return engine, manager, credentials
}

func sendKeyRequest(t *testing.T, engine *echo.Echo, credentials session.Credentials, method, target string, body []byte, actionToken string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Host = keyTestHost
	request.Header.Set(echo.HeaderContentType, "application/json")
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
	// Fetch Metadata と CSRF トークンは、書き込みと同じく読み取りでも、すべての API
	// リクエストに伴う。cookie はポートで区切られないが、トークンは区切られるからだ。
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set(CSRFHeader, credentials.CSRFToken)
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set(echo.HeaderOrigin, "http://"+keyTestHost)
	}
	if actionToken != "" {
		request.Header.Set(ActionHeader, actionToken)
	}
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	return response
}

// issueToken は、UI と全く同じ方法でサーバーに確認を求める。
// したがって、トークンが運ぶ evidence はサーバーが導出した evidence である。
func issueToken(t *testing.T, engine *echo.Echo, credentials session.Credentials, kind, target string) string {
	t.Helper()
	body, err := json.Marshal(api.IssueActionRequest{Kind: kind, Target: target})
	if err != nil {
		t.Fatalf("marshal action request: %v", err)
	}
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/actions", body, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("issue action = %d, want 201: %s", response.Code, response.Body.String())
	}
	var issued api.IssueActionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode action response: %v", err)
	}
	if issued.Token == "" || issued.ExpiresAt == "" {
		t.Fatalf("issued = %#v", issued)
	}
	return issued.Token
}

func newRevealService() *stubKeyService {
	return &stubKeyService{
		inventory: &keys.Inventory{Items: []keys.Item{{ID: "key-one", RelativePath: "id_work", Kind: keys.KindPrivateKey}}},
		reveal:    keys.RevealResult{ID: "key-one", RelativePath: "id_work", Contents: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), Encrypted: true, TransactionID: "tx"},
		evidence:  "evidence-for-key-one",
	}
}

func TestRevealRequiresAFreshActionTokenForThatExactKey(t *testing.T) {
	service := newRevealService()
	engine, _, credentials := newKeyServer(t, service)

	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, "").Code; got != http.StatusForbidden {
		t.Fatalf("reveal without a token = %d, want 403", got)
	}
	if service.revealCalls != 0 {
		t.Fatalf("the service was called without an action token")
	}

	otherKeyToken := issueToken(t, engine, credentials, session.ActionRevealPrivateKey, "key-two")
	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, otherKeyToken).Code; got != http.StatusForbidden {
		t.Fatalf("reveal with another key's token = %d, want 403", got)
	}

	purgeToken := issueToken(t, engine, credentials, session.ActionPurgeTrashEntry, "key-one")
	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, purgeToken).Code; got != http.StatusForbidden {
		t.Fatalf("reveal with a purge token = %d, want 403", got)
	}

	revealToken := issueToken(t, engine, credentials, session.ActionRevealPrivateKey, "key-one")
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, revealToken)
	if response.Code != http.StatusOK {
		t.Fatalf("reveal = %d, want 200: %s", response.Code, response.Body.String())
	}
	if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var payload api.RevealPrivateKeyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode reveal: %v", err)
	}
	if payload.PrivateKey != "-----BEGIN OPENSSH PRIVATE KEY-----\n" {
		t.Fatalf("PrivateKey = %q", payload.PrivateKey)
	}

	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, revealToken).Code; got != http.StatusForbidden {
		t.Fatalf("replaying an action token = %d, want 403", got)
	}
	if service.revealCalls != 1 {
		t.Fatalf("revealCalls = %d, want exactly one", service.revealCalls)
	}
}

// トークンは、確認ダイアログが表示した内容のダイジェストに結び付く。
// 確認からクリックまでの間に鍵が変化していれば、ユーザーは別の鍵を
// 確認したことになり、reveal は拒否されなければならない。
func TestRevealIsRefusedWhenTheKeyChangedAfterTheConfirmation(t *testing.T) {
	service := newRevealService()
	engine, _, credentials := newKeyServer(t, service)

	token := issueToken(t, engine, credentials, session.ActionRevealPrivateKey, "key-one")
	service.evidence = "evidence-after-the-key-was-replaced"

	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, token)
	if response.Code != http.StatusForbidden {
		t.Fatalf("reveal after the key changed = %d, want 403: %s", response.Code, response.Body.String())
	}
	if service.revealCalls != 0 {
		t.Fatalf("the key was revealed against evidence the user never saw")
	}
}

func TestRevealIsRefusedWhenTheConfirmationHasExpired(t *testing.T) {
	service := newRevealService()
	engine, manager, credentials := newKeyServer(t, service)

	// 進められるのは session manager の時計だけであり、何も sleep しない。
	// そのためテストは高速かつ決定的なままである。
	moment := time.Now()
	manager.Now = func() time.Time { return moment }
	token := issueToken(t, engine, credentials, session.ActionRevealPrivateKey, "key-one")
	moment = moment.Add(session.ActionTokenTTL + time.Second)

	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, token)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expired reveal = %d, want 403", response.Code)
	}
	var problemBody api.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problemBody); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problemBody.Code != "action_token_expired" {
		t.Fatalf("code = %q, want action_token_expired", problemBody.Code)
	}
	if service.revealCalls != 0 {
		t.Fatalf("an expired confirmation revealed the key")
	}
}

// reveal のレスポンスは、この tab によってちょうど 1 回だけ読めなければ
// ならず、共有のログやエラーボディに書き込まれてはならない。
func TestRevealResponseIsUncacheableAndNeverEchoedInAnError(t *testing.T) {
	service := newRevealService()
	engine, _, credentials := newKeyServer(t, service)

	token := issueToken(t, engine, credentials, session.ActionRevealPrivateKey, "key-one")
	ok := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, token)
	if ok.Code != http.StatusOK {
		t.Fatalf("reveal = %d", ok.Code)
	}
	header := ok.Result().Header
	if header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", header.Get("Cache-Control"))
	}

	// 未知の鍵は reveal の経路に一切到達してはならず、その拒否は
	// 鍵の材料を一切運んではならない。
	missing := issueToken(t, engine, credentials, session.ActionRevealPrivateKey, "key-missing")
	rejected := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-missing/reveal", nil, missing)
	if rejected.Code != http.StatusNotFound {
		t.Fatalf("unknown key = %d, want 404", rejected.Code)
	}
	if bytes.Contains(rejected.Body.Bytes(), []byte("OPENSSH PRIVATE KEY")) {
		t.Fatalf("an error body carried key material")
	}
}

// security middleware はすべての /api/ レスポンスに no-store を付ける。
// そのため middleware を通したテストでは、reveal ハンドラ自身が自分の役割を
// 果たしているかを判別できない。秘密鍵のボディは、どこか別の場所で設定された
// ヘッダーに依存してはならない唯一のレスポンスなので、middleware なしで検査する。
func TestRevealHandlerSetsNoStoreWithoutRelyingOnTheMiddleware(t *testing.T) {
	service := newRevealService()
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x62}, 4096)))
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatalf("Bootstrap error = %v", err)
	}

	engine := echo.New()
	engine.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Set(SessionContextKey, credentials.SessionID)
			return next(c)
		}
	})
	keyActions := actionRegistry{}
	addKeyActions(keyActions, service)
	registerKeyRoutes(engine, KeyHandlers{
		Keys:     service,
		Sessions: manager,
		Actions:  ActionHandlers{Sessions: manager, Kinds: keyActions},
	})

	evidence, err := service.ConfirmationEvidence(keys.ConfirmRevealKey, "key-one")
	if err != nil {
		t.Fatalf("ConfirmationEvidence error = %v", err)
	}
	token, err := manager.IssueAction(credentials.SessionID, session.ActionRequest{
		Kind: session.ActionRevealPrivateKey, Target: "key-one", Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key-one/reveal", bytes.NewReader(nil))
	request.Header.Set(ActionHeader, token)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("reveal = %d, want 200: %s", response.Code, response.Body.String())
	}
	if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store from the handler itself", got)
	}
}

func TestPermanentDeleteNeedsItsOwnActionToken(t *testing.T) {
	service := &stubKeyService{inventory: &keys.Inventory{}, evidence: "evidence-for-the-entry"}
	engine, _, credentials := newKeyServer(t, service)

	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/"+trashEntryID, nil, "").Code; got != http.StatusForbidden {
		t.Fatalf("purge without a token = %d, want 403", got)
	}
	revealToken := issueToken(t, engine, credentials, session.ActionRevealPrivateKey, trashEntryID)
	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/"+trashEntryID, nil, revealToken).Code; got != http.StatusForbidden {
		t.Fatalf("purge with a reveal token = %d, want 403", got)
	}
	if service.purgeCalls != 0 {
		t.Fatalf("the service purged without a valid token")
	}

	// 別の entry に対する確認は、この entry を認可してはならない。
	otherToken := issueToken(t, engine, credentials, session.ActionPurgeTrashEntry, "20260805T100000.000-ffffffff")
	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/"+trashEntryID, nil, otherToken).Code; got != http.StatusForbidden {
		t.Fatalf("purge with another entry's token = %d, want 403", got)
	}
	if service.purgeCalls != 0 {
		t.Fatalf("the service purged against another entry's confirmation")
	}

	purgeToken := issueToken(t, engine, credentials, session.ActionPurgeTrashEntry, trashEntryID)
	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/"+trashEntryID, nil, purgeToken).Code; got != http.StatusOK {
		t.Fatalf("purge = %d, want 200", got)
	}
	if service.purgeCalls != 1 {
		t.Fatalf("purgeCalls = %d, want 1", service.purgeCalls)
	}

	// ごみ箱の entry は、拒否された purge を生き延びる。上記の拒否によって
	// 何も消費されていないので、2 回目の有効な確認が改めて必要である。
	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/"+trashEntryID, nil, purgeToken).Code; got != http.StatusForbidden {
		t.Fatalf("replayed purge token = %d, want 403", got)
	}
	if service.purgeCalls != 1 {
		t.Fatalf("purgeCalls = %d, want 1 after a replay", service.purgeCalls)
	}
}

func TestIssueActionRejectsAnUnknownKindAndAnAbsentTarget(t *testing.T) {
	service := newRevealService()
	engine, _, credentials := newKeyServer(t, service)

	for _, body := range []string{
		`{"kind":"terminal.launch","target":"key-one"}`,
		`{"kind":"reveal_private_key","target":"key-one"}`,
		`{"kind":"private_key.reveal","target":""}`,
	} {
		response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/actions", []byte(body), "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("issue %s = %d, want 400", body, response.Code)
		}
	}

	service.evidenceErr = keys.ErrUnknownKey
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/actions",
		[]byte(`{"kind":"private_key.reveal","target":"key-one"}`), "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("issue for a missing key = %d, want 404", response.Code)
	}
}

func TestKeyRoutesRejectMissingCSRFAndUnknownFields(t *testing.T) {
	service := &stubKeyService{inventory: &keys.Inventory{}}
	engine, _, credentials := newKeyServer(t, service)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader([]byte(`{}`)))
	request.Host = keyTestHost
	request.Header.Set(echo.HeaderOrigin, "http://"+keyTestHost)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("generate without CSRF = %d, want 403", response.Code)
	}

	body := []byte(`{"algorithm":"ed25519","fileName":"id_work","comment":"aida@laptop","passphrase":"x","unencrypted":false,"surprise":1}`)
	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys", body, "").Code; got != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", got)
	}
}

func TestAgentRejectionIsReportedWithASanitisedDetail(t *testing.T) {
	service := &stubKeyService{
		inventory:   &keys.Inventory{},
		registerErr: fmt.Errorf("%w: Bad passphrase for ~/.ssh/id_work", platform.ErrAgentRejected),
	}
	engine, _, credentials := newKeyServer(t, service)

	body := []byte(`{"passphrase":"wrong","lifetimeSeconds":0,"storeInKeychain":false}`)
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/agent", body, "")
	if response.Code != http.StatusBadGateway {
		t.Fatalf("register = %d, want 502: %s", response.Code, response.Body.String())
	}
	var problemBody api.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problemBody); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problemBody.Code != "agent_rejected" || problemBody.Detail == nil {
		t.Fatalf("problem = %#v", problemBody)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("wrong")) {
		t.Fatalf("the response echoed the passphrase")
	}
}

func TestInventoryAndTrashListingsMatchTheGeneratedContract(t *testing.T) {
	service := newRevealService()
	engine, _, credentials := newKeyServer(t, service)

	response := sendKeyRequest(t, engine, credentials, http.MethodGet, "/api/v1/keys", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("list keys = %d", response.Code)
	}
	var inventory api.KeyInventoryResponse
	if err := json.Unmarshal(response.Body.Bytes(), &inventory); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if len(inventory.Items) != 1 || inventory.Items[0].Id != "key-one" || !inventory.AgentAvailable {
		t.Fatalf("inventory = %#v", inventory)
	}
	if inventory.Items[0].References == nil || inventory.Items[0].Notes == nil {
		t.Fatalf("empty arrays must serialise as arrays, not null: %#v", inventory.Items[0])
	}

	trashResponse := sendKeyRequest(t, engine, credentials, http.MethodGet, "/api/v1/trash", nil, "")
	if trashResponse.Code != http.StatusOK {
		t.Fatalf("list trash = %d", trashResponse.Code)
	}
	var trash api.TrashListResponse
	if err := json.Unmarshal(trashResponse.Body.Bytes(), &trash); err != nil {
		t.Fatalf("decode trash: %v", err)
	}
	if trash.RetentionDays != keys.TrashRetentionDays || len(trash.Entries) != 1 {
		t.Fatalf("trash = %#v", trash)
	}
	if trash.Entries[0].DeletedAt != "2026-08-05T09:00:00Z" || !trash.Entries[0].Stale {
		t.Fatalf("entry = %#v", trash.Entries[0])
	}
}

// public key のルートは reveal の対極にある: 何も開示しない唯一の鍵の
// エンドポイントであり、だからこそ確認も不要な唯一のエンドポイントでもある。
// これらのテストはその両面を固定する——トークンなしで動作すること、そして
// 公開鍵でないものはすべて拒否することの両方である。
func TestPublicKeyIsServedWithoutAConfirmation(t *testing.T) {
	service := newRevealService()
	engine, _, credentials := newKeyServer(t, service)

	response := sendKeyRequest(t, engine, credentials, http.MethodGet, "/api/v1/keys/key-two/public", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("public key = %d, want 200: %s", response.Code, response.Body.String())
	}
	var body api.PublicKeyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode public key response: %v", err)
	}
	if !strings.HasPrefix(body.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("public key = %q, want the key line", body.PublicKey)
	}
	if body.RelativePath != "id_work.pub" || body.Fingerprint != "SHA256:abcdef" {
		t.Fatalf("body = %#v", body)
	}
	// このルートには監査イベントに当たるものが何もないので、
	// reveal を消費してもいないはずである。
	if service.revealCalls != 0 {
		t.Fatalf("the public key route reached the reveal path")
	}
}

func TestPublicKeyRefusesAnEntryThatIsNotAPublicKey(t *testing.T) {
	engine, _, credentials := newKeyServer(t, newRevealService())

	// key-one はこのフィクスチャにおける秘密鍵である。未確認のルートを通じて
	// そのテキストを求めても、呼び出し側の意図がどうであれ機能してはならない。
	response := sendKeyRequest(t, engine, credentials, http.MethodGet, "/api/v1/keys/key-one/public", nil, "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("public key for a private key = %d, want 404: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "PRIVATE KEY") {
		t.Fatalf("the refusal carried key material: %s", response.Body.String())
	}
}

// agent に鍵を渡したまま返却を求めないことがあり得るので、purge された
// 鍵が読み込まれたまま使用可能であり続けることがあった。削除には確認
// トークンは不要である。これは何も破壊しないからだ。
func TestDeregisterRemovesTheKeyFromTheAgentWithoutAToken(t *testing.T) {
	service := newRevealService()
	engine, _, credentials := newKeyServer(t, service)

	response := sendKeyRequest(t, engine, credentials, http.MethodDelete,
		"/api/v1/keys/key-one/agent", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("deregister = %d, want 200: %s", response.Code, response.Body.String())
	}
	if len(service.deregistered) != 1 || service.deregistered[0] != "key-one" {
		t.Errorf("deregistered = %#v, want the key from the path", service.deregistered)
	}
	var answer api.AgentIdentitiesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !answer.AgentAvailable || answer.Id != "key-one" {
		t.Errorf("answer = %#v, want what the agent holds afterwards", answer)
	}
}

func TestDeregisterReportsAnAgentThatIsNotThere(t *testing.T) {
	service := newRevealService()
	service.deregisterErr = platform.ErrAgentUnavailable
	engine, _, credentials := newKeyServer(t, service)

	response := sendKeyRequest(t, engine, credentials, http.MethodDelete,
		"/api/v1/keys/key-one/agent", nil, "")
	if response.Code == http.StatusOK {
		t.Fatalf("deregister with no agent = 200, want a refusal: %s", response.Body.String())
	}
}
