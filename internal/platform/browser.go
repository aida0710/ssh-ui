package platform

import "context"

type BrowserLauncher interface {
	Open(context.Context, string) error
}

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}
