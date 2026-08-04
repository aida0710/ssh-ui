package platform

import "context"

// TerminalLauncher opens an interactive SSH session in the user's terminal.
// Only an alias that passes ValidateAlias is ever handed to it.
type TerminalLauncher interface {
	Launch(ctx context.Context, alias string) error
}
