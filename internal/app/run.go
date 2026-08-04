package app

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"

	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/session"
)

type ListenFunc func(network, address string) (net.Listener, error)

type Dependencies struct {
	Random  io.Reader
	Browser platform.BrowserLauncher
	Listen  ListenFunc
	UI      fs.FS
	Logger  *slog.Logger
}

func Run(ctx context.Context, dependencies Dependencies, version string) error {
	listener, err := dependencies.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	sessions, bootstrap, err := session.NewManager(dependencies.Random)
	if err != nil {
		listener.Close()
		return fmt.Errorf("session: %w", err)
	}

	server, err := httpserver.New(httpserver.Options{
		Listener: listener,
		Sessions: sessions,
		UI:       dependencies.UI,
		Version:  version,
		Logger:   dependencies.Logger,
	})
	if err != nil {
		listener.Close()
		return err
	}

	target := server.URL() + "/#bootstrap=" + bootstrap
	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()

	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(serverCtx) }()

	if err := dependencies.Browser.Open(ctx, target); err != nil {
		stopServer()
		<-serveErrors
		return fmt.Errorf("open browser: %w", err)
	}

	select {
	case err := <-serveErrors:
		return err
	case <-ctx.Done():
		stopServer()
		return <-serveErrors
	}
}
