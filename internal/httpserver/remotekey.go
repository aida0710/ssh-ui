package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/diagnostics"
	"sshc/internal/platform"
	"sshc/internal/remotekey"
	"sshc/internal/session"
)

// RemoteKeyHandlers registers a public key on a remote host.
//
// Diagnostics supplies the destination the confirmation displays and the
// executable directives that connecting would run; the registration itself
// never reads the configuration a second time.
type RemoteKeyHandlers struct {
	Service     *remotekey.Service
	Diagnostics *diagnostics.Service
	Actions     ActionHandlers
}

func registerRemoteKeyRoutes(engine *echo.Echo, handlers RemoteKeyHandlers) {
	engine.POST("/api/v1/remote-keys/plan", handlers.Plan)
	engine.POST("/api/v1/remote-keys/register", handlers.Register)
}

func remoteKeyProblem(c *echo.Context, err error) error {
	switch {
	case errors.Is(err, remotekey.ErrInvalidPublicKey):
		return problem(c, http.StatusBadRequest, "invalid_public_key")
	case errors.Is(err, remotekey.ErrNotAcknowledged):
		return problem(c, http.StatusConflict, "executable_directive_not_acknowledged")
	case errors.Is(err, remotekey.ErrUnsupportedRemote):
		return problem(c, http.StatusUnprocessableEntity, "unsupported_remote")
	case errors.Is(err, platform.ErrUnsafeAlias):
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	return problem(c, http.StatusInternalServerError, "registration_failed")
}

// Plan describes the change without contacting the remote host.
func (h RemoteKeyHandlers) Plan(c *echo.Context) error {
	var request api.RemoteKeyPlanRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	key, fingerprint, err := remotekey.ParsePublicKey(request.PublicKey)
	if err != nil {
		return remoteKeyProblem(c, err)
	}
	key.Path = request.KeyPath

	// The destination comes from this application's own reading of the
	// configuration, which needs no process; ssh -G is not run behind a plan.
	hostname, port, err := h.Diagnostics.Destination(request.Alias)
	if err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_destination")
	}
	user := ""
	if projected, ok := h.Diagnostics.ProjectedValue(request.Alias, "user"); ok {
		user = projected
	}
	report, err := h.Diagnostics.Safety()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}

	plan := h.Service.Plan(request.Alias, key, fingerprint, user, hostname, port, "engine")
	return c.JSON(http.StatusOK, api.RemoteKeyPlan{
		Alias:                plan.Alias,
		User:                 plan.User,
		Hostname:             plan.Hostname,
		Port:                 plan.Port,
		ValuesFrom:           plan.ValuesFrom,
		Fingerprint:          plan.Fingerprint,
		KeyPath:              plan.KeyPath,
		KeyLine:              plan.KeyLine,
		RemotePath:           plan.RemotePath,
		Routine:              plan.Routine,
		Supported:            plan.Supported,
		Manual:               plan.Manual,
		ExecutableDirectives: describeDirectives(report.Directives),
	})
}

// Register installs the key after the confirmation is spent.
func (h RemoteKeyHandlers) Register(c *echo.Context) error {
	var request api.RemoteKeyRegisterRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	key, _, err := remotekey.ParsePublicKey(request.PublicKey)
	if err != nil {
		return remoteKeyProblem(c, err)
	}
	key.Path = request.KeyPath

	if allowed, response := h.Actions.consume(c, session.ActionRemoteKeyRegister, request.Alias); !allowed {
		return response
	}
	report, err := h.Diagnostics.Safety()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}

	result, err := h.Service.Register(c.Request().Context(), report, request.Alias, key, request.AcknowledgeExecutable)
	if err != nil {
		return remoteKeyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.RemoteKeyRegisterResponse{
		Outcome:  result.Outcome,
		ExitCode: result.ExitCode,
		// ssh names the files it read by absolute path; the account name is
		// removed before the output leaves this process.
		Stderr:    platform.SanitiseHomePaths(result.Stderr, h.Diagnostics.Home()),
		Truncated: result.Truncated,
	})
}
