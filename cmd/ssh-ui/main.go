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
	"runtime"
	"syscall"
	"time"

	"ssh-ui/internal/app"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/platform/macos"
	"ssh-ui/internal/selfupdate"
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

// askpassInvocation reports whether this process was started to answer an
// OpenSSH prompt, and returns the arguments the helper should read.
//
// The subcommand word is the way to run it by hand. It is not the way OpenSSH
// runs it: SSH_ASKPASS names a program, and OpenSSH execs that program with the
// prompt as its only argument — there is no shell, so there is nowhere for a
// subcommand word to go. Without this the shipped feature started a second copy
// of the whole application, browser and all, and ssh got a password that was
// never sent. The integration suite against a real sshd is what found it.
//
// The token is the marker because it exists for exactly one connection and
// nothing but this application ever sets it. The endpoint is required with it so
// that a stale variable alone cannot silently turn the application into a helper.
func askpassInvocation(argv []string, lookup func(string) string) ([]string, bool) {
	if len(argv) > 1 && argv[1] == AskpassSubcommand {
		return argv[2:], true
	}
	if lookup(TokenVariable) != "" && lookup(URLVariable) != "" {
		return argv[1:], true
	}
	return nil, false
}

func main() {
	// The branch is before flag.Parse because the prompt OpenSSH passes is an
	// arbitrary string and would otherwise be read as a flag.
	if arguments, ok := askpassInvocation(os.Args, os.Getenv); ok {
		os.Exit(runAskpass(
			context.Background(),
			arguments,
			os.Getenv,
			&http.Client{Timeout: 15 * time.Second},
			os.Stdout,
			os.Stderr,
		))
	}

	if len(os.Args) == 2 && os.Args[1] == OpenSubcommand {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-ui: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runOpen(
			context.Background(), app.HandoffDir(home),
			&http.Client{Timeout: connectTimeout},
			func(target string) error {
				return macos.NewBrowser(macos.NewExecRunner()).Open(context.Background(), target)
			},
			os.Stderr,
		))
	}

	// `ssh-ui <alias>` connects. It is checked after the askpass branch and
	// before flag parsing, because an alias is a bare word and flag.Parse would
	// stop at it and then the application would start instead of connecting.
	if alias, ok := connectInvocation(os.Args); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-ui: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runConnect(
			context.Background(), alias, app.HandoffDir(home),
			&http.Client{Timeout: connectTimeout}, os.Stderr,
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

	// The askpass helper is this binary. Resolving it once, here, is the only
	// place that can: nothing inside the application knows where it was
	// installed. A path that cannot be resolved leaves every terminal launch
	// on the plain path rather than arming a helper that may not be there.
	helperPath, err := os.Executable()
	if err != nil {
		logger.Warn("resolve this binary; stored passwords will not be offered", "error", err)
		helperPath = ""
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
		Random:  rand.Reader,
		Browser: browser,
		// Off unless the user turns it on, from the interface. Nothing here
		// registers anything; this only makes the switch reachable.
		LoginItem: macos.LoginItem{Runner: runner, Home: home},
		// The one place this application contacts a host other than itself,
		// and only when somebody presses the button.
		Updates: &selfupdate.Checker{
			API:          "https://api.github.com/repos/aida0710/ssh-ui/releases/latest",
			AssetName:    "ssh-ui-" + runtime.GOOS + "-" + runtime.GOARCH,
			ChecksumName: "checksums.txt",
			HTTP:         &http.Client{Timeout: 5 * time.Minute},
		},
		Listen:    net.Listen,
		UI:        assets,
		Logger:    logger,
		Home:      home,
		Runner:    runner,
		Toolchain: toolchain,
		KeyAgent:  macos.NewKeyAgent(runner, toolchain, os.LookupEnv),
		Terminal:  macos.NewTerminal(runner),
		Lookup:    os.LookupEnv,
		// The helper and the server apply the same rule, from the same
		// function, so the two can never drift into two different answers to
		// "is this prompt one we will answer".
		AskpassHelper: helperPath,
		Answerable:    AnswerablePrompt,
	}
	if err := app.Run(ctx, dependencies, version); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("ssh-ui stopped", "error", err)
		os.Exit(1)
	}
}
