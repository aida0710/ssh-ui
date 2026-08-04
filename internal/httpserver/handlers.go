package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/api"
	"ssh-ui/internal/session"
)

type Handlers struct {
	Sessions *session.Manager
	Version  string
}

func (h Handlers) Bootstrap(c *echo.Context) error {
	if h.Sessions == nil {
		return problem(c, http.StatusInternalServerError, "bootstrap_failed")
	}

	credentials, err := h.Sessions.Bootstrap(c.Request().Header.Get("X-SSH-UI-Bootstrap"))
	switch {
	case errors.Is(err, session.ErrInvalidBootstrap):
		return problem(c, http.StatusUnauthorized, "invalid_bootstrap")
	case errors.Is(err, session.ErrBootstrapUsed):
		return problem(c, http.StatusConflict, "bootstrap_used")
	case err != nil:
		return problem(c, http.StatusInternalServerError, "bootstrap_failed")
	}

	c.SetCookie(&http.Cookie{
		Name:     SessionCookie,
		Value:    credentials.SessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return c.JSON(http.StatusOK, api.BootstrapResponse{CsrfToken: credentials.CSRFToken})
}

func (h Handlers) Health(c *echo.Context) error {
	return c.JSON(http.StatusOK, api.HealthResponse{Status: "ok", Version: h.Version})
}
