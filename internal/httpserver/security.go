package httpserver

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/api"
	"ssh-ui/internal/session"
)

const (
	SessionCookie     = "ssh_ui_session"
	CSRFHeader        = "X-SSH-UI-CSRF"
	SessionContextKey = "ssh-ui-session"

	contentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
)

type Security struct {
	ExpectedHost   string
	ExpectedOrigin string
	Sessions       *session.Manager
}

func (s Security) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		request := c.Request()
		isAPI := strings.HasPrefix(request.URL.Path, "/api/")
		setSecurityHeaders(c.Response().Header(), isAPI)

		if request.Host != s.ExpectedHost {
			return problem(c, http.StatusForbidden, "invalid_host")
		}

		if !isAPI {
			return next(c)
		}

		isBootstrap := request.Method == http.MethodPost && request.URL.Path == "/api/v1/session/bootstrap"
		isStateChanging := request.Method != http.MethodGet && request.Method != http.MethodHead
		if isStateChanging || isBootstrap {
			if request.Header.Get(echo.HeaderOrigin) != s.ExpectedOrigin || request.Header.Get("Sec-Fetch-Site") != "same-origin" {
				return problem(c, http.StatusForbidden, "cross_site_request")
			}
		}
		if isBootstrap {
			return next(c)
		}

		cookie, err := request.Cookie(SessionCookie)
		if err != nil {
			return problem(c, http.StatusUnauthorized, "session_required")
		}
		if s.Sessions == nil {
			return problem(c, http.StatusUnauthorized, "invalid_session")
		}
		if _, ok := s.Sessions.Authenticate(cookie.Value); !ok {
			return problem(c, http.StatusUnauthorized, "invalid_session")
		}
		if isStateChanging && !s.Sessions.VerifyCSRF(cookie.Value, request.Header.Get(CSRFHeader)) {
			return problem(c, http.StatusForbidden, "invalid_csrf")
		}

		c.Set(SessionContextKey, cookie.Value)
		return next(c)
	}
}

func setSecurityHeaders(header http.Header, apiResponse bool) {
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	if apiResponse {
		header.Set("Cache-Control", "no-store")
	}
}

func problem(c *echo.Context, status int, code string) error {
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, api.Problem{Code: code, Message: "request rejected"})
}
