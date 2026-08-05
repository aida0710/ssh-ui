package platform

import "context"

// TerminalLauncher opens an interactive SSH session in the user's terminal.
// Only an alias that passes ValidateAlias is ever handed to it.
type TerminalLauncher interface {
	Launch(ctx context.Context, alias string) error
}

// PasswordTerminalLauncher opens a session with the askpass helper armed.
//
// It is a separate interface rather than a second method on TerminalLauncher
// because a launcher that cannot do this is still a valid launcher: the
// feature is optional, and a platform without it should fail to type-assert
// rather than be forced to implement a method that returns an error.
type PasswordTerminalLauncher interface {
	LaunchWithPassword(ctx context.Context, alias, helperPath, endpoint, token string) error
}
