package platform

import "context"

type TerminalID string

const (
	TerminalApple  TerminalID = "terminal"
	TerminalITerm2 TerminalID = "iterm2"
	TerminalKitty  TerminalID = "kitty"
)

func ValidTerminalID(id TerminalID) bool {
	return id == TerminalApple || id == TerminalITerm2 || id == TerminalKitty
}

// TerminalLauncher は、ユーザーの端末で対話的な SSH セッションを開く。
// ValidateAlias を通った alias だけが渡される。
type TerminalLauncher interface {
	Launch(ctx context.Context, alias string) error
}

// PasswordTerminalLauncher は、askpass ヘルパーを武装させてセッションを開く。
//
// TerminalLauncher の二つ目のメソッドではなく別インターフェースにしてあるのは、
// これができないランチャーも依然として妥当なランチャーだからだ。この機能は
// 省略可能であり、それを持たないプラットフォームは、エラーを返すメソッドの実装を
// 強いられるより、型アサーションに失敗する方がよい。
type PasswordTerminalLauncher interface {
	LaunchWithPassword(ctx context.Context, alias, helperPath, endpoint, token string) error
}

// SelectableTerminalLauncher は定義済みの端末を選んで開く。任意のコマンド文字列を
// 受け付けないことが、設定ファイルの値をシェルへ変える経路を作らない境界である。
type SelectableTerminalLauncher interface {
	TerminalLauncher
	LaunchIn(ctx context.Context, terminal TerminalID, alias string) error
}

type SelectablePasswordTerminalLauncher interface {
	PasswordTerminalLauncher
	LaunchWithPasswordIn(ctx context.Context, terminal TerminalID, alias, helperPath, endpoint, token string) error
}
