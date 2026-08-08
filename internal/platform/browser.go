package platform

import "context"

type BrowserLauncher interface {
	Open(context.Context, string) error
}
