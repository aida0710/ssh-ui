package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"ssh-ui/internal/app"
	"ssh-ui/internal/platform/macos"
	"ssh-ui/internal/ui"
)

var version = "dev"

func main() {
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

	dependencies := app.Dependencies{
		Random:  rand.Reader,
		Browser: macos.NewBrowser(macos.NewExecRunner()),
		Listen:  net.Listen,
		UI:      assets,
		Logger:  logger,
		Home:    home,
	}
	if err := app.Run(ctx, dependencies, version); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("ssh-ui stopped", "error", err)
		os.Exit(1)
	}
}
