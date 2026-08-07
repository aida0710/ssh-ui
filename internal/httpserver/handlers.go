package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/session"
)

type Handlers struct {
	Sessions *session.Manager
	Version  string
}

// Renew mints a fresh CSRF token for the session the cookie already names.
//
// A reload loses the token, because it lived in the page, and the bootstrap
// fragment that would have produced another is spent on first use. Without this
// the application was dead after a reload until the binary was started again.
//
// It presents no CSRF token, because a reload has none — the same exemption the
// bootstrap has, and guarded by the same things: the Host, the Origin, Fetch
// Metadata and, unlike the bootstrap, a session that already exists. A
// cross-site page can produce none of them: SameSite=Strict withholds the
// cookie and Sec-Fetch-Site cannot be forged.
func (h Handlers) Renew(c *echo.Context) error {
	if h.Sessions == nil {
		return problem(c, http.StatusInternalServerError, "bootstrap_failed")
	}
	cookie, err := c.Request().Cookie(SessionCookie)
	if err != nil {
		return problem(c, http.StatusUnauthorized, "session_required")
	}
	csrf, ok := h.Sessions.RenewCSRF(cookie.Value)
	if !ok {
		return problem(c, http.StatusUnauthorized, "invalid_session")
	}
	return c.JSON(http.StatusOK, api.BootstrapResponse{CsrfToken: csrf})
}

func (h Handlers) Bootstrap(c *echo.Context) error {
	if h.Sessions == nil {
		return problem(c, http.StatusInternalServerError, "bootstrap_failed")
	}

	credentials, err := h.Sessions.Bootstrap(c.Request().Header.Get("X-SSHC-Bootstrap"))
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
