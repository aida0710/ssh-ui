package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/api"
	"ssh-ui/internal/application"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/remotesync"
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
	// Eligibility answers what stands between an alias and a stored password.
	// It is injected because the answer comes from the configuration graph and
	// known_hosts, neither of which the vault knows anything about. A nil
	// function means nothing is checked, which is what the vault did before
	// this existed.
	Eligibility func(alias string) (application.PasswordEligibility, error)
	// Answerable is the prompt rule. It is injected rather than imported so
	// that the rule and the helper that also applies it cannot drift into two
	// different rules without a test noticing.
	Answerable func(alias, prompt string) bool
	// ResealSnapshot pushes the workspace again under a new master password, so
	// the bucket's live snapshot stops being one only the old password opens.
	// It is injected because where a snapshot goes belongs to the object store,
	// and a nil one means this machine has no bucket to update.
	ResealSnapshot func(ctx context.Context, passphrase string) error
}

// snapshotProblemCode names why the bucket was not updated, in the same
// vocabulary the sync screen already uses.
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

// Change replaces the master password and re-seals what it held.
//
// The bucket's live snapshot is sealed with the same password, so it is pushed
// again here — the vault cannot do it, because where a snapshot goes belongs to
// the object store and the secret package does not import it. The dated copies
// beside it are deliberately left alone: they are history, and re-sealing every
// one of them would mean downloading and re-uploading the whole bucket.
//
// A push that fails does not undo the change. The local half is done, and
// saying so is more use than pretending it is not: the answer carries whether
// the bucket was updated and why not.
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

// Eligible reports what stands between an alias and a stored password.
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

// kindOf reads the namespace out of the path. There are two and there will not
// quietly be a third: an unknown one is refused here rather than defaulted,
// because defaulting would mean a typo silently chose a namespace.
func kindOf(c *echo.Context) (secret.Kind, bool) {
	kind := secret.Kind(c.Param("kind"))
	return kind, secret.ValidKind(kind)
}

// credentialProblem maps the vault's refusals onto answers a screen can act on.
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

// listCredentials answers names and what uses them. Never a value: a screen
// that could read a secret would be a screen a compromised browser could read
// it from, and choosing needs only the name.
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
	// A blocker means the stored password could never be offered, so storing
	// it would put a secret on disk that has no use. Refusing is checked here
	// rather than only in the interface, because the interface is replaceable
	// and this side is not.
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
