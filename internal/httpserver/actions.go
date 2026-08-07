package httpserver

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/session"
)

// actionKind は、確認可能な操作 1 個をそれを所有するサブシステムに結び付ける。
//
// evidence は確認ダイアログが実際に表示した内容そのもののダイジェストを導出する。
// fail は導出エラーをそのサブシステムの problem レスポンスへ変換するので、
// 鍵が見つからない場合は 404 を、
// 設定が読めない場合は 500 を、両者が共有するエンドポイントを通じて返す。
type actionKind struct {
	evidence func(target string) (string, error)
	fail     func(c *echo.Context, err error) error
}

// actionRegistry は、session パッケージが共有する action の語彙を、
// 各 kind を所有する evidence source へ対応付ける。
//
// 存在しない kind は決して確認可能にならない。このプロセスに組み込まれていない
// サブシステムには、そのためのトークンを発行できない。鍵 vault だけを持つ
// サーバーが terminal.launch の確認発行を拒否し続けるのはこのためである。
type actionRegistry map[string]actionKind

// ActionHandlers は、外部から見えるすべての操作が必要とする
// 一度限りの確認を発行し、消費する。
//
// 通信路上のエンドポイントは 1 個だが、各 kind の背後にある evidence は
// その操作を実行するサブシステムに属する。このファイルがすべてのサービスに
// 手を伸ばすのではなく、各サブシステムが resolver を提供する。
type ActionHandlers struct {
	Sessions *session.Manager
	Kinds    actionRegistry
}

func registerActionRoutes(engine *echo.Echo, handlers ActionHandlers) {
	engine.POST("/api/v1/actions", handlers.IssueAction)
}

func (h ActionHandlers) sessionID(c *echo.Context) string {
	value, _ := c.Get(SessionContextKey).(string)
	return value
}

// IssueAction は、1 個の操作が必要とする確認を発行する。
//
// 呼び出し側が指定するのは操作とその対象だけである。トークンが何に結び付くか
// はここで現在の状態から導出される。呼び出し側が自前の evidence を渡せてしまう
// と、ユーザーが見ていないものにトークンを結び付けられてしまうからだ。
func (h ActionHandlers) IssueAction(c *echo.Context) error {
	var body api.IssueActionRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	kind, known := h.Kinds[body.Kind]
	if !known || body.Target == "" {
		return problem(c, http.StatusBadRequest, "unknown_action_kind")
	}
	sessionID := h.sessionID(c)
	if sessionID == "" {
		return problem(c, http.StatusUnauthorized, "session_required")
	}
	evidence, err := kind.evidence(body.Target)
	if err != nil {
		return kind.fail(c, err)
	}

	value, err := h.Sessions.IssueAction(sessionID, session.ActionRequest{
		Kind: body.Kind, Target: body.Target, Evidence: evidence,
	})
	switch {
	case err == nil:
	case errors.Is(err, session.ErrTooManyActions):
		return problem(c, http.StatusTooManyRequests, "too_many_confirmations")
	case errors.Is(err, session.ErrUnknownSession):
		return problem(c, http.StatusUnauthorized, "session_required")
	default:
		return problem(c, http.StatusForbidden, "action_token_refused")
	}
	return c.JSON(http.StatusCreated, api.IssueActionResponse{
		Token:     value,
		ExpiresAt: time.Now().UTC().Add(session.ActionTokenTTL).Format(time.RFC3339),
	})
}

// consume は、この操作が必要とする一度限りのトークンを消費する。
//
// evidence はリクエストから受け取るのではなく、ここで再計算される。そのため
// 確認は、ダイアログが実際に表示した状態だけを認可する。真偽値は呼び出し側が
// 続行してよいかを報告し、
// false のときはすでにレスポンスが書き込まれている。
func (h ActionHandlers) consume(c *echo.Context, kind, target string) (bool, error) {
	if h.Sessions == nil {
		return false, problem(c, http.StatusForbidden, "action_token_required")
	}
	sessionID := h.sessionID(c)
	if sessionID == "" {
		return false, problem(c, http.StatusUnauthorized, "session_required")
	}
	presented := c.Request().Header.Get(ActionHeader)
	if presented == "" {
		return false, problem(c, http.StatusForbidden, "action_token_required")
	}
	registered, known := h.Kinds[kind]
	if !known {
		return false, problem(c, http.StatusForbidden, "action_token_invalid")
	}
	evidence, err := registered.evidence(target)
	if err != nil {
		return false, registered.fail(c, err)
	}

	err = h.Sessions.ConsumeAction(sessionID, presented, session.ActionRequest{
		Kind: kind, Target: target, Evidence: evidence,
	})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, session.ErrActionExpired):
		return false, problem(c, http.StatusForbidden, "action_token_expired")
	case errors.Is(err, session.ErrUnknownSession):
		return false, problem(c, http.StatusUnauthorized, "session_required")
	default:
		return false, problem(c, http.StatusForbidden, "action_token_invalid")
	}
}

// addKeyActions は、鍵 vault の確認可能な 2 個の操作を登録する。
func addKeyActions(registry actionRegistry, service KeyService) {
	for wireKind, subject := range confirmationSubjects {
		registry[wireKind] = actionKind{
			evidence: func(target string) (string, error) {
				return service.ConfirmationEvidence(subject, target)
			},
			fail: keyProblem,
		}
	}
}
