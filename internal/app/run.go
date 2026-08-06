package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"ssh-ui/internal/application"
	"ssh-ui/internal/diagnostics"
	"ssh-ui/internal/handoff"
	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/keys"
	"ssh-ui/internal/knownhosts"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/remotekey"
	"ssh-ui/internal/remotesync"
	"ssh-ui/internal/secret"
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
	// AskpassHelper is the absolute path of the running binary, which is the
	// program OpenSSH executes to obtain a stored password. Only cmd/ssh-ui can
	// know it; an empty path leaves every terminal launch on the plain path.
	AskpassHelper string
	// Answerable is the prompt rule the askpass endpoint applies. A nil rule
	// means no prompt is ever answered, which is the safe default.
	Answerable func(prompt string) bool
	// Lookup reads the parent environment so the OpenSSH programs this process
	// starts receive platform.MinimalEnvironment. Only cmd/ssh-ui may supply
	// os.LookupEnv; a nil value lets children inherit, which suits a test.
	Lookup func(string) (string, bool)
	// SessionNow is the clock the session manager uses for action-token expiry.
	// It is nil in production, where time.Now is used. The hardening suite sets
	// it so a token can be aged without sleeping.
	SessionNow func() time.Time
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
// The concrete type rather than the interface, because the wiring installs the
// stored-passphrase lookup on it after the vault exists. It still satisfies
// httpserver.KeyService where that is what is wanted.
func buildKeyService(workspace *storage.Workspace, dependencies Dependencies, configuration *application.Service) *keys.Service {
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
		// What a group is belongs to the configuration engine, which reads the
		// declaration out of ~/.ssh/config. The key vault asks rather than
		// deciding, so a key can only be generated into a group that exists.
		ValidateGroup: configuration.ValidateDeclaredGroup,
	})
}

// Build wires every dependency into an HTTP server without serving it, and
// returns the one-time bootstrap token the UI must present.
//
// Run calls Build and then serves. The hardening suite calls Build directly, so
// its assertions run against the same route table, the same middleware and the
// same handler construction the shipped binary uses, instead of a hand-built
// subset that can drift.
func Build(dependencies Dependencies, version string) (*httpserver.Server, string, error) {
	listener, err := dependencies.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}

	sessions, bootstrap, err := session.NewManager(dependencies.Random)
	if err != nil {
		listener.Close()
		return nil, "", fmt.Errorf("session: %w", err)
	}
	if dependencies.SessionNow != nil {
		sessions.Now = dependencies.SessionNow
	}

	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, dependencies.Home)
	if err != nil {
		listener.Close()
		return nil, "", fmt.Errorf("workspace: %w", err)
	}
	// Random must be safe for concurrent use: the session manager and both
	// transaction managers read from it. Production passes crypto/rand.
	transactions := storage.NewManager(workspace, time.Now, dependencies.Random)
	configService := application.NewService(workspace, transactions)
	keyService := buildKeyService(workspace, dependencies, configService)
	diagnosticsService := diagnostics.NewService(
		workspace, dependencies.Runner, dependencies.Toolchain, dependencies.Terminal, dependencies.Lookup)
	// The command shown to the user is this binary and an alias, so it has to
	// know where this binary is. Nothing inside the application can work that
	// out; the entry point resolves it once and passes it in.
	diagnosticsService.Self = dependencies.AskpassHelper
	// known_hosts shares the config transaction manager: both write ordinary
	// managed files under ~/.ssh, so one journal covers them.
	var scanEnvironment []string
	if dependencies.Lookup != nil {
		scanEnvironment = platform.MinimalEnvironment(dependencies.Lookup)
	}
	knownHostsService := knownhosts.NewService(workspace, transactions, knownhosts.Scanner{
		Runner:      dependencies.Runner,
		Toolchain:   dependencies.Toolchain,
		Environment: scanEnvironment,
	})
	remoteKeyService := &remotekey.Service{
		Runner:      dependencies.Runner,
		Toolchain:   dependencies.Toolchain,
		ConfigPath:  diagnosticsService.ConfigPath(),
		Environment: scanEnvironment,
	}

	// The stored-password vault shares the configuration transaction manager:
	// it is one more ordinary managed file under ~/.ssh, so one journal covers
	// it, and it travels with everything else the workspace holds.
	passwordService := secret.NewService(workspace, transactions, time.Now)

	// A key whose passphrase is stored is added to the agent in one action
	// rather than two. The lookup is installed here rather than imported by
	// internal/keys, which must no more ask the secret package where a secret
	// lives than it asks the configuration engine what a group is.
	keyService.SetStoredPassphrase(passwordService.KeyPassphraseFor)

	// Every generational backup is ciphertext. The previous contents of a file
	// this application replaces may be a private key, which is why the writes
	// that could produce one used to ask for no backup at all and could
	// therefore never be undone. Sealing them buys the undo back. The manager
	// is handed the two functions rather than the vault, so the storage layer
	// goes on knowing nothing about secrets, and the application being behind
	// the master password is what makes them always available.
	transactions.Seal = passwordService.SealBackup
	transactions.Unseal = passwordService.OpenBackup

	// The snapshot needs to know which files are configuration, and that is a
	// question the Include graph answers. Passing the answer in keeps the
	// dependency pointing the right way: internal/remotesync imports nothing
	// of the configuration service.
	syncService := remotesync.NewService(workspace, transactions,
		func() ([]string, error) { return configService.WorkspaceFiles() },
		func() string { return time.Now().UTC().Format(time.RFC3339) },
		newOrigin(dependencies.Random),
	)

	// `ssh-ui <alias>` reads this to find the running application. The secret
	// is minted here, per run, and written after the listener is up so the URL
	// in it is the one that answers.
	cliSecret, err := handoff.Mint(dependencies.Random)
	if err != nil {
		listener.Close()
		return nil, "", err
	}

	server, err := httpserver.New(httpserver.Options{
		Listener:  listener,
		CLISecret: cliSecret,
		// The alias is checked here as well as on the command line, so what a
		// terminal is told about a host this will not launch is the same
		// sentence the screen shows.
		ConnectWarnings: func(alias string) []string {
			if _, _, warning := diagnosticsService.TerminalCommand(alias); warning != "" {
				return []string{warning}
			}
			return nil
		},
		Sessions:      sessions,
		UI:            dependencies.UI,
		Version:       version,
		Logger:        dependencies.Logger,
		Config:        configService,
		Keys:          keyService,
		Diagnostics:   diagnosticsService,
		KnownHosts:    knownHostsService,
		RemoteKeys:    remoteKeyService,
		Passwords:     passwordService,
		Sync:          syncService,
		AskpassHelper: dependencies.AskpassHelper,
		Answerable:    dependencies.Answerable,
	})
	if err != nil {
		listener.Close()
		return nil, "", err
	}

	// Written here rather than where the process starts serving, because this
	// is where the URL becomes known and because a server that is built is a
	// server something can connect through. A copy left behind by a process
	// that was killed points at a port nothing is listening on with a secret
	// nothing accepts, so removing it is tidiness rather than a guarantee.
	if _, err := handoff.Write(HandoffDir(dependencies.Home), server.URL(), cliSecret); err != nil {
		dependencies.Logger.Warn(
			"write the command-line handoff; ssh-ui <alias> will connect without a stored password",
			"error", err)
	}
	return server, bootstrap, nil
}

// HandoffDir is where the running application leaves the file `ssh-ui <alias>`
// reads. It is the same state directory everything else of this application's
// own lives in.
func HandoffDir(home string) string {
	return filepath.Join(home, ".ssh", "ssh-ui")
}

func Run(ctx context.Context, dependencies Dependencies, version string) error {
	server, bootstrap, err := Build(dependencies, version)
	if err != nil {
		return err
	}

	target := server.URL() + "/#bootstrap=" + bootstrap
	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()

	// The handoff is written once the URL is known and taken away on the way
	// out. A copy left behind by a process that was killed points at a port
	// nothing is listening on with a secret nothing accepts, so the removal is
	// tidiness rather than a guarantee anything rests on.
	defer func() {
		if err := handoff.Remove(HandoffDir(dependencies.Home)); err != nil {
			dependencies.Logger.Warn("remove the command-line handoff", "error", err)
		}
	}()

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

// newOrigin mints this installation's opaque identifier.
//
// It is random and is derived from nothing about the machine. An identifier
// built from a hostname would put that hostname in an object anyone with the
// bucket can read, for no benefit beyond what a random string gives.
func newOrigin(random io.Reader) func() (string, error) {
	return func() (string, error) {
		if random == nil {
			random = rand.Reader
		}
		raw := make([]byte, 16)
		if _, err := io.ReadFull(random, raw); err != nil {
			return "", err
		}
		return hex.EncodeToString(raw), nil
	}
}
