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

	// spaFallbackRoute is the pattern the single-page application is served
	// under. A request that matched only this one matched no API route.
	spaFallbackRoute = "/*"

	// MaxRequestBodyCeiling is the hard ceiling every /api/ request body is read
	// through. Handlers apply their own, smaller limits; this one exists so a
	// route added later cannot read an unbounded body by forgetting to.
	MaxRequestBodyCeiling = 2 << 20
)

type Security struct {
	ExpectedHost   string
	ExpectedOrigin string
	Sessions       *session.Manager
	// Unlocked reports whether the master password has been given. It is a
	// function rather than the vault itself, so this file goes on knowing
	// nothing about secrets, and a nil one is shut: a forgotten wiring must not
	// be the difference between a locked application and an open one.
	Unlocked func() bool
}

// gateExempt names the routes that answer while the vault is shut.
//
// They are the gate itself and the two things that must work before there is
// anything to unlock. Everything else is behind the master password, which is
// what "the application is locked" means — not "each screen asks when it needs
// a secret", which is what this used to be.
func gateExempt(method, path string) bool {
	switch path {
	case "/api/v1/health":
		return method == http.MethodGet
	case "/api/v1/session/bootstrap", "/api/v1/session/renew":
		return method == http.MethodPost
	case "/api/v1/passwords":
		return method == http.MethodGet
	case "/api/v1/passwords/initialise", "/api/v1/passwords/unlock":
		return method == http.MethodPost
	}
	return false
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
		// Renewing a CSRF token cannot present one: a reload has the cookie and
		// nothing else. It is exempt from that check and from nothing else —
		// the session below is still required, which the bootstrap's exemption
		// cannot be.
		isRenew := request.Method == http.MethodPost && request.URL.Path == "/api/v1/session/renew"
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
		// The token is required on reads as well as writes. A cookie is not
		// scoped to a port and neither is a site, so another server on
		// 127.0.0.1 receives this one — SameSite compares scheme and
		// registrable domain, and an IP is the whole site. The token lives in
		// the page's memory and never travels there, so requiring it is what
		// makes a leaked cookie worth nothing on its own.
		//
		// Renewing is exempt because it is how a page that lost its token gets
		// one: a reload has the cookie and nothing else.
		claimed := c.Path() != "" && c.Path() != spaFallbackRoute
		// Health is exempt from the token as well as from the gate. It carries
		// a version string and nothing else, and it is the one request made
		// before a page has settled, so requiring a token there would be a
		// bootstrap ordering trap for no gain.
		isHealth := request.Method == http.MethodGet && request.URL.Path == "/api/v1/health"
		if (isStateChanging || claimed) && !isRenew && !isHealth &&
			!s.Sessions.VerifyCSRF(cookie.Value, request.Header.Get(CSRFHeader)) {
			return problem(c, http.StatusForbidden, "invalid_csrf")
		}

		// A path no API route claims is answered by the router, not by the
		// gate. "There is no such route" and "the vault is shut" are different
		// facts, and answering the second to both would make a typo in a URL
		// look like a state the user could unlock their way out of. Middleware
		// runs after the route lookup, so an empty pattern means nothing
		// matched, and the SPA catch-all means nothing in the API matched — it
		// 404s everything under /api/ itself.
		if claimed && !gateExempt(request.Method, request.URL.Path) && (s.Unlocked == nil || !s.Unlocked()) {
			return problem(c, http.StatusConflict, "vault_locked")
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
