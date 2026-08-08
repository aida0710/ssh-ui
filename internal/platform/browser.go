package platform

import "context"

type BrowserLauncher interface {
	Open(context.Context, string) error
}

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

// CommandStarter は対話アプリケーションを起動し、終了を待たずに所有権を渡す。
// 引数はシェル文字列ではなく argv で渡される。
type CommandStarter interface {
	Start(string, ...string) error
}
