package macos

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"sshc/internal/platform"
)

// ErrTerminalUnavailable は、自動化プログラムが見つからないことを報告する。
var ErrTerminalUnavailable = errors.New("osascript is not available")

// TerminalScript は自動化のペイロード全体であり、定数である。
//
// alias は `on run argv` の引数として渡され、このテキストに連結されることは
// 決してない。したがって alias が抜け出すべき AppleScript の文字列はそもそも
// 存在しない。続いて `quoted form of` が、Terminal の実行するシェル向けに POSIX
// 引用されたトークンを作る。さらに呼び出し側は、シェルのメタ文字をまったく含まない
// 文字集合に alias をすでに制限している。したがって alias と、いずれの解釈系との
// あいだにも、独立した二重の壁が立っている。
const TerminalScript = `on run argv
	set targetAlias to item 1 of argv
	set sshCommand to "ssh -- " & quoted form of targetAlias
	tell application "Terminal"
		activate
		do script sshCommand
	end tell
end run
`

// TerminalPasswordScript は、このアプリケーション自身のコマンドラインを通して
// 接続を開く。
//
// これは `sshc <alias>` を実行する。動作中のアプリケーションにワンタイムトークンを
// 求め、環境を整えたうえで ssh を exec するコマンドだ。以前はその環境 — 五つの
// 変数とトークン — をウィンドウに直接与えており、そのせいで資格情報を運ぶ有効な
// トークンが Terminal のスクロールバックと、シェルが保持する履歴ファイルに入って
// いた。いまはそのどれも表示されない。
//
// 重要な性質は保たれている。このテキストには何も連結されない。alias とこの
// バイナリへのパスは `on run argv` を通って届き、個別に引用される。したがって
// どちらにも抜け出すべき AppleScript の文字列はなく、シェルの語として分割される
// こともない。
const TerminalPasswordScript = `on run argv
	set targetAlias to item 1 of argv
	set helperPath to item 2 of argv
	set sshCommand to quoted form of helperPath & " " & quoted form of targetAlias
	tell application "Terminal"
		activate
		do script sshCommand
	end tell
end run
`

// ErrHelperPathNotAbsolute は、このアプリケーションが PATH 経由で探さなければ
// ならないヘルパー、つまり他人が供給しうるヘルパーを拒否する。
var ErrHelperPathNotAbsolute = errors.New("askpass helper path must be absolute")

// LaunchError は、自動化プログラムがリクエストを拒否したことを報告する。
type LaunchError struct {
	ExitCode int
	Stderr   string
}

func (e *LaunchError) Error() string {
	return fmt.Sprintf("terminal launch failed with status %d", e.ExitCode)
}

// Terminal は osascript を通して Terminal.app を開く。
type Terminal struct {
	Runner  platform.OutputRunner
	Program string
	Timeout time.Duration
}

// NewTerminal は macOS の Terminal ランチャーを返す。
func NewTerminal(runner platform.OutputRunner) Terminal {
	return Terminal{Runner: runner, Program: "/usr/bin/osascript", Timeout: 10 * time.Second}
}

// LaunchWithPassword は、askpass ヘルパーを武装させた状態で Terminal に ssh を開く。
//
// ヘルパーのパスは、PATH 経由で解決されないよう絶対でなければならない。トークンは
// 単回使用でこの alias に属する。Terminal ウィンドウのスクロールバックとプロセス
// テーブルからは見えるが、そこから分かるのは接続が行われているということだけで、
// パスワードそのものについては何も分からない。
func (t Terminal) LaunchWithPassword(ctx context.Context, alias, helperPath, endpoint, token string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	if !filepath.IsAbs(helperPath) {
		return ErrHelperPathNotAbsolute
	}
	return t.run(ctx, TerminalPasswordScript, []string{"-", alias, helperPath})
}

// Launch は、新しい Terminal ウィンドウで `ssh -- <alias>` を開く。
func (t Terminal) Launch(ctx context.Context, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	return t.run(ctx, TerminalScript, []string{"-", alias})
}

func (t Terminal) run(ctx context.Context, script string, arguments []string) error {
	program := t.Program
	if program == "" {
		program = "/usr/bin/osascript"
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	output, err := t.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: arguments,
		Stdin:     []byte(script),
		Timeout:   timeout,
	})
	if err != nil {
		return err
	}
	if output.ExitCode != 0 {
		return &LaunchError{ExitCode: output.ExitCode, Stderr: string(output.Stderr)}
	}
	return nil
}
