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

	// MaxRequestBodyCeiling is the hard ceiling every /api/ request body is read
	// through. Handlers apply their own, smaller limits; this one exists so a
	// route added later cannot read an unbounded body by forgetting to.
	MaxRequestBodyCeiling = 2 << 20
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

		// Fetch Metadata is checked on every API request, not only on the ones
		// that change state. A cross-site GET is already starved of its cookie
		// by SameSite=Strict, but design §8.1 asks for the header to be verified
		// by exact match, and a browser that mishandles SameSite must not be the
		// only thing standing between another site and this API.
		if request.Header.Get("Sec-Fetch-Site") != "same-origin" {
			return problem(c, http.StatusForbidden, "cross_site_request")
		}
		// The ceiling is a limit on the request, not merely on what a handler
		// happens to read. A declared length over the ceiling is refused before
		// the handler runs, so a route that ignores its body — /diagnostics/config
		// and /keys/:keyId/trash today, and any route added later that takes its
		// input from the path alone — cannot be handed an unbounded one either.
		if request.ContentLength > MaxRequestBodyCeiling {
			return problem(c, http.StatusRequestEntityTooLarge, "request_body_too_large")
		}
		// A chunked request declares no length, so the reader still has to be
		// bounded for the handlers that do read.
		if request.Body != nil {
			request.Body = http.MaxBytesReader(c.Response(), request.Body, MaxRequestBodyCeiling)
		}

		isBootstrap := request.Method == http.MethodPost && request.URL.Path == "/api/v1/session/bootstrap"
		isStateChanging := request.Method != http.MethodGet && request.Method != http.MethodHead
		if (isStateChanging || isBootstrap) && request.Header.Get(echo.HeaderOrigin) != s.ExpectedOrigin {
			return problem(c, http.StatusForbidden, "cross_site_request")
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

// problemDetail returns a rejection with a bounded explanation.
//
// Callers must pass either a fixed string or a message the platform layer has
// already sanitised. A detail must never carry key material, a passphrase, a
// session or action token, or an absolute path.
func problemDetail(c *echo.Context, status int, code, detail string) error {
	const detailLimit = 512
	if len(detail) > detailLimit {
		detail = detail[:detailLimit]
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, api.Problem{Code: code, Message: "request rejected", Detail: &detail})
}
