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

// Renew は、cookie がすでに指しているセッションに対して新しい CSRF トークンを発行する。
//
// reload するとトークンは失われる。トークンはページの中にあり、別のトークンを
// 生成したはずの bootstrap フラグメントは初回使用時に消費済みだからだ。これが
// なければ、バイナリを再起動するまで reload 後のアプリケーションは死んでいた。
//
// これは CSRF トークンを提示しない。reload にはトークンがないからで、
// bootstrap と同じ免除であり、同じもの——Host、Origin、Fetch Metadata、
// そして bootstrap とは異なりすでに存在するセッション——によって守られている。
// クロスサイトのページはそのいずれも作り出せない。SameSite=Strict が
// cookie を差し止め、Sec-Fetch-Site は偽造できないからである。
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
