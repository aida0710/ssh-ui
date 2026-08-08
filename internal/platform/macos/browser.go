package macos

import (
	"context"
	"errors"
	"net/url"
	"os/exec"

	"sshc/internal/platform"
)

var ErrUnsafeBrowserURL = errors.New("browser URL must use loopback HTTP")

type Browser struct {
	runner platform.CommandRunner
}

func NewBrowser(runner platform.CommandRunner) Browser {
	return Browser{runner: runner}
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func NewExecRunner() platform.CommandRunner {
	return execRunner{}
}

type execStarter struct{}

func (execStarter) Start(name string, args ...string) error {
	command := exec.Command(name, args...)
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func NewExecStarter() platform.CommandStarter { return execStarter{} }

func (browser Browser) Open(ctx context.Context, target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		return ErrUnsafeBrowserURL
	}
	return browser.runner.Run(ctx, "open", target)
}
