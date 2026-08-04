package app

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"time"

	"ssh-ui/internal/application"
	"ssh-ui/internal/diagnostics"
	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/keys"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/session"
	"ssh-ui/internal/storage"
)

type ListenFunc func(network, address string) (net.Listener, error)

type Dependencies struct {
	Random  io.Reader
	Browser platform.BrowserLauncher
	Listen  ListenFunc
	UI      fs.FS
	Logger  *slog.Logger
	// Home is the user's home directory. Only cmd/ssh-ui may read it from the
	// operating system; every test injects a temporary directory.
	Home string
	// Runner, Toolchain and KeyAgent are the key vault's boundary with the
	// operating system. A nil Runner or Toolchain leaves the algorithm
	// catalogue on its Ed25519 fallback; a nil KeyAgent makes agent
	// registration report that no agent is reachable. Neither is fatal, so the
	// process still serves every other surface.
	Runner    platform.OutputRunner
	Toolchain platform.Toolchain
	KeyAgent  platform.KeyAgent
	// Terminal opens an interactive session. A nil launcher is valid: the
	// diagnostics service then reports that no terminal is configured rather
	// than panicking, which is what the tests here rely on.
	Terminal platform.TerminalLauncher
	// Lookup reads the parent environment so the OpenSSH programs this process
	// starts receive platform.MinimalEnvironment. Only cmd/ssh-ui may supply
	// os.LookupEnv; a nil value lets children inherit, which suits a test.
	Lookup func(string) (string, bool)
}

// buildKeyService prepares the key vault over the same workspace the
// configuration engine uses.
//
// It deliberately takes its own storage.Manager. application.NewService
// installs a configuration validator on the manager it is given, and that
// validator parses every file a transaction writes as ssh_config. The key vault
// writes private keys, public keys and a JSON trash manifest, none of which is
// configuration, and a manifest would be rejected outright as a syntax error.
// Two managers over one workspace is safe: a Manager holds no mutable state
// between calls, and every transaction is identified by its own timestamp and
// random suffix, so the journal and the history remain one consistent stream.
func buildKeyService(workspace *storage.Workspace, dependencies Dependencies) httpserver.KeyService {
	transactions := storage.NewManager(workspace, time.Now, dependencies.Random)
	return keys.NewService(keys.ServiceOptions{
		Workspace:    workspace,
		Transactions: transactions,
		Resolver:     storage.NewResolver(workspace),
		Catalogue: keys.CatalogueReader{
			Runner:    dependencies.Runner,
			Toolchain: dependencies.Toolchain,
		},
		Agent:  dependencies.KeyAgent,
		Now:    time.Now,
		Random: dependencies.Random,
	})
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

	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, dependencies.Home)
	if err != nil {
		listener.Close()
		return fmt.Errorf("workspace: %w", err)
	}
	// Random must be safe for concurrent use: the session manager and both
	// transaction managers read from it. Production passes crypto/rand.
	transactions := storage.NewManager(workspace, time.Now, dependencies.Random)
	configService := application.NewService(workspace, transactions)
	keyService := buildKeyService(workspace, dependencies)
	diagnosticsService := diagnostics.NewService(
		workspace, dependencies.Runner, dependencies.Toolchain, dependencies.Terminal, dependencies.Lookup)

	server, err := httpserver.New(httpserver.Options{
		Listener:    listener,
		Sessions:    sessions,
		UI:          dependencies.UI,
		Version:     version,
		Logger:      dependencies.Logger,
		Config:      configService,
		Keys:        keyService,
		Diagnostics: diagnosticsService,
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
