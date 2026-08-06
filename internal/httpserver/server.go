package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/application"
	"ssh-ui/internal/diagnostics"
	"ssh-ui/internal/knownhosts"
	"ssh-ui/internal/remotekey"
	"ssh-ui/internal/remotesync"
	"ssh-ui/internal/secret"
	"ssh-ui/internal/session"
)

type Options struct {
	// CLISecret is what `ssh-ui <alias>` must present. It is minted per run and
	// written to the state directory, so a handoff left behind by a process
	// that was killed carries a secret nothing accepts.
	CLISecret string
	// ConnectWarnings names the directives OpenSSH will run for a host, so the
	// command line can say them before the connection rather than during it.
	ConnectWarnings func(alias string) []string
	Listener        net.Listener
	Sessions        *session.Manager
	UI              fs.FS
	Version         string
	Logger          *slog.Logger
	Config          *application.Service
	Keys            KeyService
	Diagnostics     *diagnostics.Service
	KnownHosts      *knownhosts.Service
	RemoteKeys      *remotekey.Service
	// Passwords is the stored-password vault. A nil service leaves every
	// password route and the askpass endpoint unregistered, which is what the
	// tests that do not wire it rely on.
	Passwords *secret.Service
	// AskpassHelper is the absolute path of this binary, which is the program
	// OpenSSH runs to obtain a password. Only cmd/ssh-ui can know it.
	AskpassHelper string
	// Answerable is the prompt rule, injected so the server and the helper
	// cannot drift into two different rules.
	Answerable func(prompt string) bool
	// Sync carries the workspace to an object store. A nil service leaves
	// every sync route unregistered.
	Sync *remotesync.Service
}

var ErrNonLoopbackListener = errors.New("listener must use 127.0.0.1")

type Server struct {
	listener net.Listener
	http     *http.Server
	url      string
	engine   *echo.Echo
	// cliSecret is what `ssh-ui <alias>` must present. It is held so the caller
	// that knows where the handoff belongs can read it back rather than
	// carrying it alongside.
	cliSecret string
}

// Route is one route this server registered.
type Route struct {
	Method string
	Path   string
}

// Routes reports every registered route in registration order.
//
// The hardening suite enumerates this instead of keeping its own list, so a
// route added by a later change inherits the transport, cache, session and leak
// assertions without anyone remembering to add it anywhere.
func (s *Server) Routes() []Route {
	registered := s.engine.Router().Routes()
	routes := make([]Route, 0, len(registered))
	for _, info := range registered {
		routes = append(routes, Route{Method: info.Method, Path: info.Path})
	}
	return routes
}

func New(options Options) (*Server, error) {
	if options.Listener == nil {
		return nil, ErrNonLoopbackListener
	}
	tcpAddress, ok := options.Listener.Addr().(*net.TCPAddr)
	if !ok || len(tcpAddress.IP) != net.IPv4len || tcpAddress.IP[0] != 127 || tcpAddress.IP[1] != 0 || tcpAddress.IP[2] != 0 || tcpAddress.IP[3] != 1 {
		return nil, ErrNonLoopbackListener
	}

	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpAddress.Port))
	e := echo.New()
	if options.Logger != nil {
		e.Logger = options.Logger
	}
	e.Use((Security{
		ExpectedHost:   host,
		ExpectedOrigin: "http://" + host,
		Sessions:       options.Sessions,
		// The application is behind the master password, not each screen in
		// turn. A server built without a vault has no way to be unlocked and is
		// therefore shut, which is the safe direction for a missing wiring.
		Unlocked: func() bool { return options.Passwords != nil && options.Passwords.Unlocked() },
	}).Middleware)

	handlers := Handlers{Sessions: options.Sessions, Version: options.Version}
	e.POST("/api/v1/session/bootstrap", handlers.Bootstrap)
	e.POST("/api/v1/session/renew", handlers.Renew)
	e.GET("/api/v1/health", handlers.Health)
	if options.Config != nil {
		registerConfigRoutes(e, ConfigHandlers{Service: options.Config, Keys: options.Keys})
	}

	// Every subsystem that confirms an operation contributes its evidence
	// resolver to one registry, so the single POST /api/v1/actions endpoint can
	// mint a token for any of them without reaching into their services.
	registry := actionRegistry{}
	if options.Keys != nil {
		addKeyActions(registry, options.Keys)
	}
	if options.Diagnostics != nil {
		addDiagnosticsActions(registry, options.Diagnostics)
	}
	if options.KnownHosts != nil {
		addKnownHostsActions(registry, options.KnownHosts)
	}
	actions := ActionHandlers{Sessions: options.Sessions, Kinds: registry}

	if options.Keys != nil {
		registerKeyRoutes(e, KeyHandlers{
			Keys: options.Keys, Config: options.Config, Sessions: options.Sessions, Actions: actions,
		})
	}
	if options.Diagnostics != nil {
		registerDiagnosticsRoutes(e, DiagnosticsHandlers{
			Service:       options.Diagnostics,
			Actions:       actions,
			Passwords:     options.Passwords,
			AskpassHelper: options.AskpassHelper,
			AskpassURL:    "http://" + host + AskpassPath,
		})
	}
	if options.KnownHosts != nil {
		registerKnownHostsRoutes(e, KnownHostsHandlers{Service: options.KnownHosts, Actions: actions})
	}
	if options.RemoteKeys != nil && options.Diagnostics != nil {
		registerRemoteKeyRoutes(e, RemoteKeyHandlers{
			Service: options.RemoteKeys, Diagnostics: options.Diagnostics, Actions: actions,
		})
	}
	if options.Passwords != nil {
		// The eligibility check reads the configuration graph and known_hosts,
		// so it comes from the configuration service rather than from the
		// vault, which knows nothing about either. Without a configuration
		// service nothing is checked, which is what the vault did before this
		// existed and what the tests that wire only a vault rely on.
		var eligibility func(string) (application.PasswordEligibility, error)
		if options.Config != nil {
			eligibility = options.Config.PasswordEligibility
		}
		// The bucket's live snapshot is sealed with the master password too, so
		// changing it pushes again. A machine with no bucket has nothing to
		// update and the answer says so.
		var reseal func(context.Context, string) error
		if options.Sync != nil {
			reseal = options.Sync.Push
		}
		registerPasswordRoutes(e, PasswordHandlers{
			Service:        options.Passwords,
			Answerable:     options.Answerable,
			Eligibility:    eligibility,
			ResealSnapshot: reseal,
		})
	}
	// `ssh-ui <alias>` asks here for what one connection needs. The secret is
	// what the caller must have read out of the state directory; without one
	// this route refuses everything.
	registerConnectRoutes(e, ConnectHandlers{
		Secret:     options.CLISecret,
		Passwords:  options.Passwords,
		AskpassURL: "http://" + host + AskpassPath,
		Warnings:   options.ConnectWarnings,
	})
	if options.Sync != nil {
		registerSyncRoutes(e, SyncHandlers{Service: options.Sync, Secrets: options.Passwords})
	}
	if len(registry) > 0 {
		registerActionRoutes(e, actions)
	}
	static := echo.WrapHandler(spaHandler(options.UI))
	e.GET("/*", static)
	e.HEAD("/*", static)

	return &Server{
		listener: options.Listener,
		http: &http.Server{
			Handler:           e,
			ReadHeaderTimeout: 5 * time.Second,
		},
		url:       "http://" + host,
		cliSecret: options.CLISecret,
		engine:    e,
	}, nil
}

func spaHandler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean(request.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) {
			http.NotFound(response, request)
			return
		}
		if name == "api" || strings.HasPrefix(name, "api/") || request.URL.Path == "/api" || strings.HasPrefix(request.URL.Path, "/api/") {
			http.NotFound(response, request)
			return
		}

		contents, err := fs.ReadFile(assets, name)
		if err != nil {
			if !acceptsHTML(request.Header.Get("Accept")) {
				http.NotFound(response, request)
				return
			}
			name = "index.html"
			contents, err = fs.ReadFile(assets, name)
			if err != nil {
				http.NotFound(response, request)
				return
			}
		}

		if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
			response.Header().Set("Content-Type", contentType)
		}
		http.ServeContent(response, request, name, time.Time{}, bytes.NewReader(contents))
	})
}

func acceptsHTML(header string) bool {
	for _, value := range strings.Split(header, ",") {
		mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(value))
		if err != nil || mediaType != "text/html" {
			continue
		}

		quality := 1.0
		if raw, ok := parameters["q"]; ok {
			quality, err = strconv.ParseFloat(raw, 64)
			if err != nil {
				continue
			}
		}
		if quality > 0 && quality <= 1 {
			return true
		}
	}
	return false
}

// CLISecret is what `ssh-ui <alias>` must present, so the caller that knows
// where to write the handoff can read it back without holding it separately.
func (s *Server) CLISecret() string { return s.cliSecret }

func (s *Server) URL() string {
	return s.url
}

func (s *Server) Serve(ctx context.Context) error {
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- s.http.Serve(s.listener)
	}()

	select {
	case err := <-serveDone:
		return serveResult(err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return serveResult(<-serveDone)
	}
}

func serveResult(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
