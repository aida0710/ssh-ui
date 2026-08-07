package httpserver

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/session"
)

// actionKind binds one confirmable operation to the subsystem that owns it.
//
// evidence derives a digest of exactly what the confirmation dialog displayed;
// fail turns a derivation error into that subsystem's problem response, so a
// missing key still answers 404 and an unreadable configuration still answers
// 500 through the endpoint they share.
type actionKind struct {
	evidence func(target string) (string, error)
	fail     func(c *echo.Context, err error) error
}

// actionRegistry maps the session package's shared action vocabulary onto the
// evidence source that owns each kind.
//
// A kind that is absent is never confirmable: a subsystem that was not wired
// into this process cannot have tokens minted for it, which is why a key-vault
// only server still refuses to issue a terminal.launch confirmation.
type actionRegistry map[string]actionKind

// ActionHandlers issues and spends the one-time confirmations that every
// externally visible operation requires.
//
// There is one endpoint on the wire, but the evidence behind each kind belongs
// to the subsystem that will perform the operation. Each contributes a
// resolver rather than this file reaching into every service.
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

// IssueAction mints the confirmation one operation requires.
//
// The caller names only the operation and its target. What the token is bound
// to is derived here from the current state, because a caller able to supply
// its own evidence could bind a token to something the user never saw.
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

// consume spends the one-time token this operation requires.
//
// The evidence is recomputed here rather than taken from the request, so a
// confirmation only authorises the state the dialog actually displayed. The
// boolean reports whether the caller may continue; when it is false the
// response has already been written.
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

// addKeyActions registers the key vault's two confirmable operations.
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
