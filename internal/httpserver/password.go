package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/api"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/secret"
)

// AskpassPath is where the helper asks for a password.
//
// It is deliberately not under /api/. The API surface is for the browser and
// is guarded by a session cookie, a CSRF header and Fetch Metadata; the helper
// is not a browser and has none of those. This endpoint authenticates by a
// single-use token instead, and the route table test — which only inspects
// /api/ paths — is therefore not weakened by its existence.
const AskpassPath = "/askpass"

// AskpassTokenHeader carries the one-time token.
//
// A custom header and a JSON content type both make this a request no browser
// will send cross-origin without a preflight, and this server answers no
// preflight, so no web page can reach the endpoint however much it knows about
// it.
const AskpassTokenHeader = "X-SSH-UI-Askpass"

// maxAskpassBody bounds the helper's request. A prompt is a line of text.
const maxAskpassBody = 8 << 10

// PasswordHandlers serves the vault and the helper.
type PasswordHandlers struct {
	Service *secret.Service
	// Answerable is the prompt rule. It is injected rather than imported so
	// that the rule and the helper that also applies it cannot drift into two
	// different rules without a test noticing.
	Answerable func(prompt string) bool
}

func registerPasswordRoutes(engine *echo.Echo, handlers PasswordHandlers) {
	engine.GET("/api/v1/passwords", handlers.Status)
	engine.POST("/api/v1/passwords/initialise", handlers.Initialise)
	engine.POST("/api/v1/passwords/unlock", handlers.Unlock)
	engine.POST("/api/v1/passwords/lock", handlers.Lock)
	engine.PUT("/api/v1/passwords/:alias", handlers.Store)
	engine.DELETE("/api/v1/passwords/:alias", handlers.Forget)
	engine.POST(AskpassPath, handlers.Askpass)
}

// status is the one response every route in this file returns. It carries
// which hosts have a password and never a password.
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

func (h PasswordHandlers) Lock(c *echo.Context) error {
	h.Service.Lock()
	return h.status(c)
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

// Askpass answers the helper.
//
// Every refusal is the same shape from outside — a status and no body — so
// this endpoint cannot be used to enumerate which aliases have a password. The
// helper distinguishes only "nothing stored or locked" from "refused", because
// those are different things to tell someone staring at a Terminal window, and
// neither reveals anything to a caller without a valid token.
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
		// No rule means no answer. A nil predicate must never mean "allow".
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
