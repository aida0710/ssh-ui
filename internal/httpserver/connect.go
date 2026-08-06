package httpserver

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/handoff"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/secret"
	"ssh-ui/internal/session"
)

// ConnectPath is where the command line asks what it needs to connect.
//
// It is deliberately not under /api/. That surface is for the browser and is
// guarded by a session cookie, a CSRF header and Fetch Metadata; a shell is
// none of those and has none of them. This route authenticates by the secret
// the running application left in its state directory instead, which is the
// same reasoning that puts the askpass endpoint outside /api/ as well.
const ConnectPath = "/cli/connect"

// maxConnectBody bounds the request. An alias is a word.
const maxConnectBody = 4 << 10

// ConnectHandlers answer `ssh-ui <alias>`.
type ConnectHandlers struct {
	// Secret is what the caller must present. An empty one refuses every
	// request: a server that could not write its handoff must not accept one.
	Secret string
	// Passwords mints the one-time askpass token. A nil one means no stored
	// password is ever offered, which is a working connection with a prompt.
	Passwords *secret.Service
	// AskpassURL is where the helper redeems that token.
	AskpassURL string
	// Warnings reports the directives OpenSSH will run for this host, so they
	// are said before the connection rather than discovered during it.
	Warnings func(alias string) []string
	// Sessions mints the way into the browser, and BaseURL is where that way
	// leads. Both nil means this application cannot be opened from the command
	// line, which is the state of a build with no session manager.
	Sessions *session.Manager
	BaseURL  string
}

type connectRequest struct {
	Alias string `json:"alias"`
}

type connectResponse struct {
	Alias        string   `json:"alias"`
	AskpassToken string   `json:"askpassToken,omitempty"`
	AskpassURL   string   `json:"askpassUrl"`
	Warnings     []string `json:"warnings"`
}

// OpenPath is where the command line asks for a way into the browser.
//
// A bootstrap token is spent on first use and only a new process printed
// another, which is fine when the user starts the application and it prints a
// URL, and useless when it runs as a background agent whose standard output
// goes nowhere. Rather than write that URL to a log file — a live credential in
// a place nothing protects — it is minted here, when somebody asks.
const OpenPath = "/cli/open"

type openResponse struct {
	URL string `json:"url"`
}

func registerConnectRoutes(engine *echo.Echo, handlers ConnectHandlers) {
	engine.POST(ConnectPath, handlers.Connect)
	engine.POST(OpenPath, handlers.Open)
}

// Open answers with a URL that will establish a session.
func (h ConnectHandlers) Open(c *echo.Context) error {
	if !h.authorised(c.Request()) {
		return c.NoContent(http.StatusForbidden)
	}
	if h.Sessions == nil || h.BaseURL == "" {
		return c.NoContent(http.StatusServiceUnavailable)
	}
	bootstrap, err := h.Sessions.Reissue()
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, openResponse{URL: h.BaseURL + "/#bootstrap=" + bootstrap})
}

// authorised reports whether the caller read the handoff rather than guessed
// at it. Every refusal is the same shape from outside, so a caller without the
// secret learns nothing at all.
func (h ConnectHandlers) authorised(request *http.Request) bool {
	presented := request.Header.Get(handoff.HeaderName)
	return h.Secret != "" && len(presented) == len(h.Secret) &&
		subtle.ConstantTimeCompare([]byte(presented), []byte(h.Secret)) == 1
}

// Connect answers with what one connection needs, and nothing that outlives it.
//
// Every refusal is the same shape from outside, so this endpoint cannot be used
// to find out which aliases exist or which have a password: a caller without
// the secret learns nothing at all.
func (h ConnectHandlers) Connect(c *echo.Context) error {
	request := c.Request()
	if request.Header.Get(echo.HeaderContentType) != "application/json" {
		return c.NoContent(http.StatusUnsupportedMediaType)
	}
	if !h.authorised(request) {
		return c.NoContent(http.StatusForbidden)
	}

	var decoded connectRequest
	if err := json.NewDecoder(io.LimitReader(request.Body, maxConnectBody)).Decode(&decoded); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	if err := platform.ValidateAlias(decoded.Alias); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}

	answer := connectResponse{Alias: decoded.Alias, AskpassURL: h.AskpassURL, Warnings: []string{}}
	if h.Warnings != nil {
		if warnings := h.Warnings(decoded.Alias); len(warnings) > 0 {
			answer.Warnings = warnings
		}
	}
	// A token only where there is something to redeem it for. Everything else —
	// a shut vault, no stored password, no endpoint — is a connection where
	// OpenSSH asks for the password itself, which is a working connection.
	if h.Passwords != nil && h.AskpassURL != "" {
		if token, err := h.Passwords.IssueToken(decoded.Alias); err == nil {
			answer.AskpassToken = token
		}
	}
	return c.JSON(http.StatusOK, answer)
}
