package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ssh-ui/internal/app"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/platform/macos"
	"ssh-ui/internal/ui"
)

var version = "dev"

// urlPrinter satisfies platform.BrowserLauncher by writing the URL instead of
// opening it. It exists for automation — the end-to-end suite and the packaging
// smoke test — which must not hand a live bootstrap token to the user's own
// browser. The token is no more exposed than it already is in the argv of
// `open`, and the flag has to be asked for.
type urlPrinter struct{ out io.Writer }

func (p urlPrinter) Open(_ context.Context, target string) error {
	_, err := fmt.Fprintln(p.out, target)
	return err
}

// AskpassSubcommand is the argv word that turns this binary into the program
// OpenSSH asks for a password. It is a subcommand rather than a second binary
// so that there is nothing extra to install, sign, notarise or keep in step
// with the application that armed it.
const AskpassSubcommand = "askpass"

func main() {
	// The branch is before flag.Parse because the prompt OpenSSH passes is an
	// arbitrary string and would otherwise be read as a flag.
	if len(os.Args) > 1 && os.Args[1] == AskpassSubcommand {
		os.Exit(runAskpass(
			context.Background(),
			os.Args[2:],
			os.Getenv,
			&http.Client{Timeout: 15 * time.Second},
			os.Stdout,
			os.Stderr,
		))
	}

	openBrowser := flag.Bool("open", true,
		"open the UI in the default browser; -open=false prints the URL on standard output instead")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	assets, err := ui.FS()
	if err != nil {
		logger.Error("load embedded UI", "error", err)
		os.Exit(1)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("resolve home directory", "error", err)
		os.Exit(1)
	}

	// One process runner and one toolchain are shared by every subsystem that
	// starts an OpenSSH program, so there is a single place where the argv, the
	// child environment and the output bound are decided.
	runner := macos.NewOutputRunner()
	toolchain := macos.NewToolchain()

	var browser platform.BrowserLauncher = macos.NewBrowser(macos.NewExecRunner())
	if !*openBrowser {
		browser = urlPrinter{out: os.Stdout}
	}

	dependencies := app.Dependencies{
		Random:    rand.Reader,
		Browser:   browser,
		Listen:    net.Listen,
		UI:        assets,
		Logger:    logger,
		Home:      home,
		Runner:    runner,
		Toolchain: toolchain,
		KeyAgent:  macos.NewKeyAgent(runner, toolchain, os.LookupEnv),
		Terminal:  macos.NewTerminal(runner),
		Lookup:    os.LookupEnv,
	}
	if err := app.Run(ctx, dependencies, version); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("ssh-ui stopped", "error", err)
		os.Exit(1)
	}
}
