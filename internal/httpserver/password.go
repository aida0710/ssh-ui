package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/application"
	"sshc/internal/platform"
	"sshc/internal/remotesync"
	"sshc/internal/secret"
)

// AskpassPath はヘルパーがパスワードを尋ねる先である。
//
// これはわざと /api/ の配下に置いていない。API 表面はブラウザ向けで、
// セッション cookie と CSRF ヘッダ、Fetch Metadata で守られているが、
// ヘルパーはブラウザではなく、そのいずれも持たない。このエンドポイントは
// 代わりに使い捨てトークンで認証しており、/api/ パスしか調べない
// ルート表のテストは、この存在によって弱まることはない。
const AskpassPath = "/askpass"

// AskpassTokenHeader はワンタイムトークンを運ぶ。
//
// 独自ヘッダと JSON の content type の両方により、このリクエストは
// プリフライトなしにはどのブラウザもクロスオリジンで送れず、この
// サーバーはプリフライトに応えないので、どんな Web ページもこの
// エンドポイントについてどれほど知っていても到達できない。
const AskpassTokenHeader = "X-SSHC-Askpass"

// maxAskpassBody はヘルパーのリクエストの上限を定める。プロンプトは 1 行のテキストである。
const maxAskpassBody = 8 << 10

// PasswordHandlers は vault とヘルパーを提供する。
type PasswordHandlers struct {
	Service *secret.Service
	// Eligibility は alias と保存されたパスワードの間に何があるかを答える。
	// これが注入されているのは、答えが設定グラフと known_hosts から
	// 来るためで、そのどちらについても vault は何も知らない。nil の
	// 関数は何もチェックしないことを意味し、これはこの仕組みができる
	// 前に vault がしていたことである。
	Eligibility func(alias string) (application.PasswordEligibility, error)
	// Answerable はプロンプトの規則である。import ではなく注入している
	// のは、その規則とそれを適用するヘルパーとが、テストに気づかれず
	// 別々の規則へとずれてしまうことがないようにするためだ。
	Answerable func(alias, prompt string) bool
	// ResealSnapshot は新しいマスターパスワードでワークスペースを再度 push し、
	// bucket の最新スナップショットが古いパスワードでしか開けないままにはしない。
	// これが注入されているのは、スナップショットの行き先が object store に
	// 属する事柄だからで、nil はこのマシンに更新すべき bucket がないことを意味する。
	ResealSnapshot func(ctx context.Context, passphrase string) error
}

// snapshotProblemCode は bucket が更新されなかった理由を、sync 画面が
// すでに使っている語彙と同じ言葉で名付ける。
func snapshotProblemCode(err error) string {
	switch {
	case errors.Is(err, remotesync.ErrNotConfigured):
		return "sync_not_configured"
	case errors.Is(err, remotesync.ErrRemoteMoved):
		return "sync_remote_moved"
	case errors.Is(err, remotesync.ErrPushRefused):
		return "sync_push_refused"
	default:
		return "sync_failed"
	}
}

func registerPasswordRoutes(engine *echo.Echo, handlers PasswordHandlers) {
	engine.GET("/api/v1/passwords", handlers.Status)
	engine.POST("/api/v1/passwords/initialise", handlers.Initialise)
	engine.POST("/api/v1/passwords/unlock", handlers.Unlock)
	engine.POST("/api/v1/passwords/change", handlers.Change)
	engine.POST("/api/v1/passwords/lock", handlers.Lock)
	engine.GET("/api/v1/passwords/:alias/eligibility", handlers.Eligible)
	engine.PUT("/api/v1/passwords/:alias", handlers.Store)
	engine.DELETE("/api/v1/passwords/:alias", handlers.Forget)
	engine.GET("/api/v1/credentials", handlers.ListCredentials)
	engine.PUT("/api/v1/credentials/:kind/assign", handlers.AssignCredential)
	engine.DELETE("/api/v1/credentials/:kind/assign/:subject", handlers.UnassignCredential)
	engine.PUT("/api/v1/credentials/:kind/:name", handlers.SetCredential)
	engine.DELETE("/api/v1/credentials/:kind/:name", handlers.DeleteCredential)
	engine.POST(AskpassPath, handlers.Askpass)
}

// status はこのファイルの全ルートが返す唯一のレスポンスである。
// どのホストがパスワードを持つかを運び、パスワードそのものは運ばない。
func (h PasswordHandlers) status(c *echo.Context) error {
	exists, err := h.Service.Exists()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "vault_unreadable")
	}
	minimum := secret.MinPassphraseLength
	aliases := h.Service.Aliases()
	if aliases == nil {
		aliases = []string{}
	}
	return c.JSON(http.StatusOK, api.PasswordVaultStatus{
		Exists:              exists,
		Unlocked:            h.Service.Unlocked(),
		Aliases:             aliases,
		MinPassphraseLength: &minimum,
	})
}

func (h PasswordHandlers) Status(c *echo.Context) error { return h.status(c) }

func (h PasswordHandlers) Initialise(c *echo.Context) error {
	var request api.PassphraseRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := h.Service.Initialise(request.Passphrase); err != nil {
		return passwordProblem(c, err)
	}
	return h.status(c)
}

func (h PasswordHandlers) Unlock(c *echo.Context) error {
	var request api.PassphraseRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := h.Service.Unlock(request.Passphrase); err != nil {
		return passwordProblem(c, err)
	}
	return h.status(c)
}

// Change はマスターパスワードを置き換え、それが保持していたものを再封印する。
//
// bucket の最新スナップショットは同じパスワードで封印されているため、
// ここで再び push する — vault にはできない。スナップショットの行き先は
// object store に属する事柄であり、secret パッケージはそれを import
// していないからだ。その脇の日付付きコピーはわざと手を付けず残してある。それらは
// 履歴であり、全部の再封印は bucket 全体のダウンロードと再アップロードを意味する。
//
// push が失敗しても変更は元に戻らない。ローカル側はすでに完了して
// おり、そう伝える方が取り繕うより役に立つ。応答には bucket が
// 更新されたかどうかと、されなかった理由が含まれる。
func (h PasswordHandlers) Change(c *echo.Context) error {
	var request api.ChangeMasterPasswordRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := h.Service.ChangeMasterPassword(request.Current, request.Next); err != nil {
		return passwordProblem(c, err)
	}

	answer := api.ChangeMasterPasswordResult{SnapshotResealed: true}
	if h.ResealSnapshot != nil {
		if err := h.ResealSnapshot(c.Request().Context(), request.Next); err != nil {
			reason := snapshotProblemCode(err)
			answer.SnapshotResealed, answer.SnapshotProblem = false, &reason
		}
	} else {
		answer.SnapshotResealed = false
	}

	exists, err := h.Service.Exists()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "vault_unreadable")
	}
	minimum := secret.MinPassphraseLength
	aliases := h.Service.Aliases()
	if aliases == nil {
		aliases = []string{}
	}
	answer.Vault = api.PasswordVaultStatus{
		Exists: exists, Unlocked: h.Service.Unlocked(), Aliases: aliases, MinPassphraseLength: &minimum,
	}
	return c.JSON(http.StatusOK, answer)
}

func (h PasswordHandlers) Lock(c *echo.Context) error {
	h.Service.Lock()
	return h.status(c)
}

// Eligible は alias と保存されたパスワードの間に何があるかを報告する。
func (h PasswordHandlers) Eligible(c *echo.Context) error {
	alias := c.Param("alias")
	if err := platform.ValidateAlias(alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	if h.Eligibility == nil {
		return c.JSON(http.StatusOK, api.PasswordEligibility{
			Alias: alias, Storable: true,
			Blockers: []api.Notice{}, Warnings: []api.Notice{},
		})
	}
	report, err := h.Eligibility(alias)
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}
	return c.JSON(http.StatusOK, describeEligibility(report))
}

func describeEligibility(report application.PasswordEligibility) api.PasswordEligibility {
	described := api.PasswordEligibility{
		Alias:    report.Alias,
		Storable: report.Storable,
		Blockers: make([]api.Notice, 0, len(report.Blockers)),
		Warnings: make([]api.Notice, 0, len(report.Warnings)),
	}
	for _, notice := range report.Blockers {
		described.Blockers = append(described.Blockers, eligibilityNotice(notice))
	}
	for _, notice := range report.Warnings {
		described.Warnings = append(described.Warnings, eligibilityNotice(notice))
	}
	if report.HostName != "" {
		host := report.HostName
		described.HostName = &host
	}
	if report.Port != "" {
		port := report.Port
		described.Port = &port
	}
	return described
}

func eligibilityNotice(notice application.Notice) api.Notice {
	described := api.Notice{Code: notice.Code}
	if notice.Path != "" {
		path := notice.Path
		described.Path = &path
	}
	if notice.Line != 0 {
		line := notice.Line
		described.Line = &line
	}
	if notice.Detail != "" {
		detail := notice.Detail
		described.Detail = &detail
	}
	return described
}

// kindOf はパスから namespace を読み取る。namespace は 2 つあり、
// 黙って 3 つ目が増えることはない。未知の namespace は既定値にせず
// ここで拒否する。既定値にすると、typo が黙って namespace を選ぶことになるからだ。
func kindOf(c *echo.Context) (secret.Kind, bool) {
	kind := secret.Kind(c.Param("kind"))
	return kind, secret.ValidKind(kind)
}

// credentialProblem は vault の拒否を画面が扱える応答に変換する。
func credentialProblem(c *echo.Context, err error, uses []string) error {
	switch {
	case errors.Is(err, secret.ErrLocked):
		return problem(c, http.StatusConflict, "vault_locked")
	case errors.Is(err, secret.ErrCredentialInUse):
		return problemWith(c, http.StatusConflict, problemPayload{Code: "credential_in_use", Blockers: uses})
	case errors.Is(err, secret.ErrUnknownCredential):
		return problem(c, http.StatusNotFound, "unknown_credential")
	case errors.Is(err, secret.ErrUnsafeName), errors.Is(err, secret.ErrEmptySecret),
		errors.Is(err, secret.ErrUnknownKind):
		return problem(c, http.StatusBadRequest, "invalid_request")
	default:
		return problem(c, http.StatusInternalServerError, "vault_failed")
	}
}

// listCredentials は名前とそれを使うものを答える。値は決して返さ
// ない。secret を読める画面は、乗っ取られたブラウザがそこから
// 読み取れる画面でもあり、選択には名前だけあれば十分だからだ。
func (h PasswordHandlers) listCredentials(c *echo.Context) error {
	listed, err := h.Service.Credentials()
	if err != nil {
		return credentialProblem(c, err, nil)
	}
	answer := api.CredentialList{Credentials: []api.Credential{}}
	for _, kind := range []secret.Kind{secret.KindPassword, secret.KindKeyPassphrase} {
		names := make([]string, 0, len(listed[kind]))
		for name := range listed[kind] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			answer.Credentials = append(answer.Credentials, api.Credential{
				Kind: string(kind), Name: name, Uses: listed[kind][name],
			})
		}
	}
	return c.JSON(http.StatusOK, answer)
}

func (h PasswordHandlers) ListCredentials(c *echo.Context) error {
	return h.listCredentials(c)
}

func (h PasswordHandlers) SetCredential(c *echo.Context) error {
	kind, ok := kindOf(c)
	if !ok {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	var request api.StoreCredentialRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := h.Service.SetCredential(kind, c.Param("name"), request.Secret); err != nil {
		return credentialProblem(c, err, nil)
	}
	return h.listCredentials(c)
}

func (h PasswordHandlers) DeleteCredential(c *echo.Context) error {
	kind, ok := kindOf(c)
	if !ok {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	name := c.Param("name")
	if err := h.Service.DeleteCredential(kind, name); err != nil {
		uses, _ := h.Service.Credentials()
		return credentialProblem(c, err, uses[kind][name])
	}
	return h.listCredentials(c)
}

func (h PasswordHandlers) AssignCredential(c *echo.Context) error {
	kind, ok := kindOf(c)
	if !ok {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	var request api.AssignCredentialRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := h.Service.AssignCredential(kind, request.Subject, request.Name); err != nil {
		return credentialProblem(c, err, nil)
	}
	return h.listCredentials(c)
}

func (h PasswordHandlers) UnassignCredential(c *echo.Context) error {
	kind, ok := kindOf(c)
	if !ok {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := h.Service.UnassignCredential(kind, c.Param("subject")); err != nil {
		return credentialProblem(c, err, nil)
	}
	return h.listCredentials(c)
}

func (h PasswordHandlers) Store(c *echo.Context) error {
	alias := c.Param("alias")
	if err := platform.ValidateAlias(alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	var request api.StorePasswordRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	// blocker があるということは、保存したパスワードが決して提示され
	// ないことを意味し、保存すれば使い道のない secret をディスクに
	// 置くことになる。interface だけでなくここでも拒否を確認するのは、
	// interface は差し替え可能でも、こちら側はそうではないからだ。
	if h.Eligibility != nil {
		report, err := h.Eligibility(alias)
		if err != nil {
			return problem(c, http.StatusInternalServerError, "config_unreadable")
		}
		if !report.Storable {
			blockers := make([]string, 0, len(report.Blockers))
			for _, notice := range report.Blockers {
				blockers = append(blockers, notice.Code)
			}
			return problemWith(c, http.StatusConflict, problemPayload{
				Code: "password_not_storable", Blockers: blockers,
			})
		}
	}
	if err := h.Service.Set(alias, request.Password); err != nil {
		return passwordProblem(c, err)
	}
	return h.status(c)
}

func (h PasswordHandlers) Forget(c *echo.Context) error {
	alias := c.Param("alias")
	if err := platform.ValidateAlias(alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	if err := h.Service.Remove(alias); err != nil {
		return passwordProblem(c, err)
	}
	return h.status(c)
}

type askpassRequest struct {
	Alias  string `json:"alias"`
	Prompt string `json:"prompt"`
}

type askpassResponse struct {
	Password string `json:"password"`
}

// Askpass はヘルパーに応答する。
//
// すべての拒否は外から見て同じ形——status のみで body がない——
// なので、このエンドポイントはどの alias にパスワードがあるかを
// 列挙する手段にはならない。ヘルパーは「何も保存されていないか施錠中」と
// 「拒否された」しか区別しない。Terminal を見つめる人に伝える内容としては
// この 2 つが別物であり、有効なトークンを持たない呼び出し元には何も明かさない。
func (h PasswordHandlers) Askpass(c *echo.Context) error {
	request := c.Request()
	if request.Header.Get(echo.HeaderContentType) != "application/json" {
		return c.NoContent(http.StatusUnsupportedMediaType)
	}
	token := request.Header.Get(AskpassTokenHeader)
	if token == "" {
		return c.NoContent(http.StatusForbidden)
	}

	var decoded askpassRequest
	if err := json.NewDecoder(io.LimitReader(request.Body, maxAskpassBody)).Decode(&decoded); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	if err := platform.ValidateAlias(decoded.Alias); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}

	answerable := h.Answerable
	if answerable == nil {
		// 規則がなければ応答もない。nil の predicate が「許可」を意味してはならない。
		return c.NoContent(http.StatusForbidden)
	}

	password, err := h.Service.Redeem(token, decoded.Alias, decoded.Prompt, answerable)
	switch {
	case err == nil:
	case errors.Is(err, secret.ErrLocked), errors.Is(err, secret.ErrNoPassword):
		return c.NoContent(http.StatusNotFound)
	default:
		return c.NoContent(http.StatusForbidden)
	}
	return c.JSON(http.StatusOK, askpassResponse{Password: password})
}

func passwordProblem(c *echo.Context, err error) error {
	switch {
	case errors.Is(err, secret.ErrLocked):
		return problem(c, http.StatusConflict, "vault_locked")
	case errors.Is(err, secret.ErrAlreadyExists):
		return problem(c, http.StatusConflict, "vault_already_exists")
	case errors.Is(err, secret.ErrNoVault):
		return problem(c, http.StatusNotFound, "vault_missing")
	case errors.Is(err, secret.ErrWrongPassphrase):
		return problem(c, http.StatusForbidden, "wrong_passphrase")
	case errors.Is(err, secret.ErrUnsupportedVersion):
		return problem(c, http.StatusConflict, "vault_too_new")
	case errors.Is(err, secret.ErrCostRefused):
		return problem(c, http.StatusConflict, "vault_cost_refused")
	case errors.Is(err, secret.ErrWeakPassphrase):
		return problem(c, http.StatusBadRequest, "passphrase_too_short")
	case errors.Is(err, secret.ErrEmptySecret):
		return problem(c, http.StatusBadRequest, "password_empty")
	case errors.Is(err, secret.ErrUnsafeName):
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	default:
		return problem(c, http.StatusInternalServerError, "vault_write_failed")
	}
}
