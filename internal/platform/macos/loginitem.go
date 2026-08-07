package macos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"sshc/internal/platform"
)

// LoginItemLabel は、このアプリケーションが登録する launchd のラベル。
const LoginItemLabel = "com.github.aida0710.sshc"

// ErrLoginItemPathNotAbsolute は、launchd が PATH 経由で探さなければならない
// プログラム、つまり他人が供給しうるプログラムの登録を拒否する。
var ErrLoginItemPathNotAbsolute = errors.New("login item program path must be absolute")

// LoginItem は「ログイン時に sshc を起動する」を切り替える。
//
// ユーザーが求めない限りオフである。保存済みのあらゆる秘密の鍵を握る
// バックグラウンドプロセスは、他人に代わって勝手に用意してよいものではないし、
// これがなくてもアプリケーションは十分に使える。何も動いていなければ
// `sshc <alias>` は素の ssh にフォールバックする。
//
// エージェントは -open=false で起動されるので、ログイン時にブラウザが開くことは
// ない。標準出力を意図的にどこにもリダイレクトしていないのは、それが有効な
// ブートストラップトークン付きの URL を運ぶからであり、ログファイルはそれを
// 置く場所ではない。誰かが見たくなったときは `sshc open` が新しいものを発行する。
type LoginItem struct {
	// Runner は launchctl を実行する。テストがエージェントを読み込まないよう注入する。
	Runner platform.OutputRunner
	// Home はユーザーのホームディレクトリ。LaunchAgents が置かれる場所である。
	Home string
	// Launchctl はそのプログラム。argv を見たいテストのためにある。
	Launchctl string
}

func (l LoginItem) plistPath() string {
	return filepath.Join(l.Home, "Library", "LaunchAgents", LoginItemLabel+".plist")
}

// Enabled は、エージェントが登録されているかを報告する。
func (l LoginItem) Enabled() bool {
	_, err := os.Stat(l.plistPath())
	return err == nil
}

// Enable はエージェントを書き出し、launchd に取り込むよう求める。
func (l LoginItem) Enable(ctx context.Context, program string) error {
	if !filepath.IsAbs(program) {
		return ErrLoginItemPathNotAbsolute
	}
	path := l.plistPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(agentPlist(program)), 0o600); err != nil {
		return err
	}
	// 先に bootout するのは、以前のものを読み込んだままにせず、プログラムパスの
	// 変更を拾わせるためである。
	_ = l.launchctl(ctx, "bootout", l.domain()+"/"+LoginItemLabel)
	return l.launchctl(ctx, "bootstrap", l.domain(), path)
}

// Disable はエージェントを止め、ファイルを取り除く。
func (l LoginItem) Disable(ctx context.Context) error {
	_ = l.launchctl(ctx, "bootout", l.domain()+"/"+LoginItemLabel)
	if err := os.Remove(l.plistPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (l LoginItem) domain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

func (l LoginItem) launchctl(ctx context.Context, arguments ...string) error {
	program := l.Launchctl
	if program == "" {
		program = "/bin/launchctl"
	}
	if l.Runner == nil {
		return errors.New("no runner to start launchctl with")
	}
	_, err := l.Runner.RunOutput(ctx, platform.Command{Path: program, Arguments: arguments})
	return err
}

// agentPlist は launchd が読むプロパティリスト。
//
// プログラムパスは生のまま連結せず XML エスケープする。これは os.Executable から
// 来るものでユーザー入力ではないが、アンパサンドを含むパスがあると、launchd が
// 解析を拒否するファイルができてしまうからだ。
func agentPlist(program string) string {
	escape := func(value string) string {
		replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
		return replacer.Replace(value)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-open=false</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
`, LoginItemLabel, escape(program))
}
