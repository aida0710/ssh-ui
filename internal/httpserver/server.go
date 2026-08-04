package httpserver

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/session"
)

type Options struct {
	Listener net.Listener
	Sessions *session.Manager
	UI       fs.FS
	Version  string
	Logger   *slog.Logger
}

var ErrNonLoopbackListener = errors.New("listener must use 127.0.0.1")

type Server struct {
	listener net.Listener
	http     *http.Server
	url      string
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
	}).Middleware)

	handlers := Handlers{Sessions: options.Sessions, Version: options.Version}
	e.POST("/api/v1/session/bootstrap", handlers.Bootstrap)
	e.GET("/api/v1/health", handlers.Health)
	e.GET("/*", echo.WrapHandler(http.FileServer(http.FS(options.UI))))

	return &Server{
		listener: options.Listener,
		http: &http.Server{
			Handler:           e,
			ReadHeaderTimeout: 5 * time.Second,
		},
		url: "http://" + host,
	}, nil
}

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
