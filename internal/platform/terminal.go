package platform

import "context"

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
