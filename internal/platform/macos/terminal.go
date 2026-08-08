package macos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"sshc/internal/platform"
)

var ErrUnknownTerminal = errors.New("unknown terminal")

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

// iTermWindow は、書き込む先のウィンドウを一枚だけ用意する。
//
// iTerm2 が動いていなければ activate 自身がウィンドウを開くので、そこへ更に
// create window を重ねると、ユーザーは頼んでいない二枚目を受け取る。したがって
// 起動していたかどうかを先に見る。running を読むことはアプリケーションを
// 起こさない。既に動いていたときだけ新しいウィンドウを作るのは、実行中の
// セッションへ ssh を打ち込まないためである。
const iTermWindow = `	set wasRunning to running of application "iTerm2"
	tell application "iTerm2"
		activate
		if wasRunning then
			set targetWindow to (create window with default profile)
		else
			repeat 50 times
				if (count of windows) > 0 then exit repeat
				delay 0.1
			end repeat
			if (count of windows) = 0 then
				set targetWindow to (create window with default profile)
			else
				set targetWindow to current window
			end if
		end if
		tell current session of targetWindow to write text sshCommand
	end tell
end run
`

const ITermScript = `on run argv
	set targetAlias to item 1 of argv
	set sshCommand to "ssh -- " & quoted form of targetAlias
` + iTermWindow

const ITermPasswordScript = `on run argv
	set targetAlias to item 1 of argv
	set helperPath to item 2 of argv
	set sshCommand to quoted form of helperPath & " " & quoted form of targetAlias
` + iTermWindow

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

// profile は、ひとつの端末をどう開くかである。
//
// 端末に「このコマンドを実行しろ」と伝える方法は macOS に二つしかない。CLI を
// 持つものへは argv で渡し、持たないものへは AppleScript で伝える。CLI を持たない
// 端末は Terminal.app と iTerm2 の二つで打ち止めなので、**増えるのは argv 側だけ**
// である。したがって表になっているのはそちらで、新しい端末を足すことは行をひとつ
// 書くことに等しい。
//
// argv 側を `open` 経由にしているのは、アプリケーションを探すのが Launch Services
// の仕事だからである。こちらがバンドルの置き場所を当てにすると、/Applications に
// 入れなかった人の環境で黙って壊れる。
type profile struct {
	ID platform.TerminalID
	// Bundle は Launch Services に尋ねる識別子。
	Bundle string
	// Application は在庫の確認にだけ使うバンドル名である。起動には使わない。
	Application string
	// Arguments は、実行するプログラムの前に置く引数。ここに現れるのは
	// このパッケージの定数だけで、設定から来る値は custom を通る。
	Arguments []string
	// Script は AppleScript 側の端末が使う二つのペイロード。空なら argv 側である。
	Script         string
	PasswordScript string
}

// profiles は端末の表であり、画面に並ぶ順でもある。
//
// hold に相当する引数を置いているのは、子プロセスが終わるとウィンドウごと閉じる
// 端末では、接続が即座に失敗したときにユーザーが理由を一文字も読めないからである。
// WezTerm にはこれに当たるコマンドライン引数が無く、`exit_behavior` は設定ファイル
// 側にあるので、ここでは何も足していない。
var profiles = []profile{
	{ID: platform.TerminalApple, Script: TerminalScript, PasswordScript: TerminalPasswordScript},
	{
		ID: platform.TerminalITerm2, Application: "iTerm.app",
		Script: ITermScript, PasswordScript: ITermPasswordScript,
	},
	{
		ID: platform.TerminalKitty, Bundle: "net.kovidgoyal.kitty", Application: "kitty.app",
		Arguments: []string{"--hold"},
	},
	{
		ID: platform.TerminalGhostty, Bundle: "com.mitchellh.ghostty", Application: "Ghostty.app",
		Arguments: []string{"--wait-after-command=true", "-e"},
	},
	{
		ID: platform.TerminalWezTerm, Bundle: "com.github.wez.wezterm", Application: "WezTerm.app",
		Arguments: []string{"start", "--"},
	},
	// custom の開く先は表ではなく選択が運ぶ。
	{ID: platform.TerminalCustom},
}

func profileFor(id platform.TerminalID) (profile, bool) {
	for _, candidate := range profiles {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return profile{}, false
}

// applicationDirectories は、アプリケーションを探す場所である。PATH も
// Spotlight も見ない。ここに無いものは、このアプリケーションからは選べない。
func applicationDirectories(home string) []string {
	directories := []string{
		"/Applications",
		"/Applications/Utilities",
		"/System/Applications",
		"/System/Applications/Utilities",
	}
	if home != "" {
		directories = append(directories, filepath.Join(home, "Applications"))
	}
	return directories
}

// Terminal は、選ばれた端末で対話セッションを開く。
type Terminal struct {
	Runner  platform.OutputRunner
	Program string
	// Open は `open` の絶対パス。argv 側の端末はこれを通して起こす。
	Open    string
	Timeout time.Duration
	// Home は ~/Applications を探すために使う。空でもシステムの場所は探す。
	Home string
	// Entries はディレクトリの一覧を返す唯一の継ぎ目であり、テストはここを
	// 差し替える。
	Entries func(string) []string
}

// NewTerminal は macOS の端末ランチャーを返す。
func NewTerminal(runner platform.OutputRunner, home string) Terminal {
	return Terminal{
		Runner:  runner,
		Program: "/usr/bin/osascript",
		Open:    "/usr/bin/open",
		Timeout: 10 * time.Second,
		Home:    home,
		Entries: readDirectory,
	}
}

func readDirectory(path string) []string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// Applications は、このマシンで見つかったアプリケーションバンドルを名前順で返す。
//
// これは custom の選択肢そのものである。ユーザーはここに出たものだけを選べ、
// 保存されるのはここに出たパスだけなので、設定からパスを組み立てて渡す経路は
// どこにも無い。
func (t Terminal) Applications() []platform.Application {
	entries := t.Entries
	if entries == nil {
		entries = readDirectory
	}
	seen := map[string]bool{}
	found := make([]platform.Application, 0)
	for _, directory := range applicationDirectories(t.Home) {
		for _, name := range entries(directory) {
			if !strings.HasSuffix(name, ".app") || seen[name] {
				continue
			}
			seen[name] = true
			found = append(found, platform.Application{
				Name: strings.TrimSuffix(name, ".app"),
				Path: filepath.Join(directory, name),
			})
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		return strings.ToLower(found[i].Name) < strings.ToLower(found[j].Name)
	})
	return found
}

// selectable は、そのパスがアプリケーションの置き場所として認めた
// ディレクトリの直下にあるかを答える。
func (t Terminal) selectable(path string) bool {
	for _, directory := range applicationDirectories(t.Home) {
		if filepath.Dir(path) == directory {
			return true
		}
	}
	return false
}

// exists は、選ばれたアプリケーションが今もそこにあるかを答える。
func (t Terminal) exists(path string) bool {
	entries := t.Entries
	if entries == nil {
		entries = readDirectory
	}
	return slices.Contains(entries(filepath.Dir(path)), filepath.Base(path))
}

// installed は、その端末がこのマシンで見つかるかを答える。
//
// Terminal.app は OS の一部なので置き場所を当てにしない。custom は選択が運ぶ
// パスがすべてで、そのパスは選べた時点で存在していたものである。
func (t Terminal) installed(id platform.TerminalID) bool {
	candidate, ok := profileFor(id)
	if !ok {
		return false
	}
	if candidate.Application == "" {
		return true
	}
	for _, application := range t.Applications() {
		if filepath.Base(application.Path) == candidate.Application {
			return true
		}
	}
	return false
}

// Terminals は、選択肢とそれぞれがこのマシンで見つかるかを、画面に並ぶ順で返す。
func (t Terminal) Terminals() []platform.TerminalAvailability {
	available := make([]platform.TerminalAvailability, 0, len(profiles))
	for _, candidate := range profiles {
		available = append(available, platform.TerminalAvailability{
			ID: candidate.ID, Installed: t.installed(candidate.ID),
		})
	}
	return available
}

// explain は、見つからない端末に対する失敗を、選び直せば直ると分かる答えに変える。
//
// 起動そのものは止めない。アプリケーションを探すのは Launch Services であり、
// こちらが場所を知らないことは、開けない理由にはならないからだ。開けなかった
// ときにだけ、見つからなかったことを理由として添える。
func (t Terminal) explain(id platform.TerminalID, err error) error {
	if err == nil || t.installed(id) {
		return err
	}
	return fmt.Errorf("%s: %w", id, platform.ErrTerminalNotInstalled)
}

// LaunchWithPassword は、askpass ヘルパーを武装させた状態で Terminal に ssh を開く。
//
// ヘルパーのパスは、PATH 経由で解決されないよう絶対でなければならない。トークンは
// 単回使用でこの alias に属する。Terminal ウィンドウのスクロールバックとプロセス
// テーブルからは見えるが、そこから分かるのは接続が行われているということだけで、
// パスワードそのものについては何も分からない。
func (t Terminal) LaunchWithPassword(ctx context.Context, alias, helperPath, endpoint, token string) error {
	return t.LaunchWithPasswordIn(
		ctx, platform.TerminalChoice{ID: platform.TerminalApple}, alias, helperPath, endpoint, token)
}

func (t Terminal) LaunchWithPasswordIn(
	ctx context.Context, choice platform.TerminalChoice, alias, helperPath, endpoint, token string,
) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	// ウィンドウが実行するのはこのバイナリと alias である。トークンはその
	// プロセスが自分で要求するので、コマンドラインには現れない。
	if !filepath.IsAbs(helperPath) {
		return ErrHelperPathNotAbsolute
	}
	return t.launch(ctx, choice, alias, helperPath, []string{helperPath, alias})
}

// Launch は、新しいウィンドウで `ssh -- <alias>` を開く。
func (t Terminal) Launch(ctx context.Context, alias string) error {
	return t.LaunchIn(ctx, platform.TerminalChoice{ID: platform.TerminalApple}, alias)
}

func (t Terminal) LaunchIn(ctx context.Context, choice platform.TerminalChoice, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	return t.launch(ctx, choice, alias, "", []string{"/usr/bin/ssh", "--", alias})
}

// launch は、両方の経路が合流する一点である。
//
// AppleScript 側は alias とヘルパーを argv として渡す。したがって、そこに
// 抜け出すべき AppleScript の文字列は存在しない。argv 側はシェルを一度も通らない
// ので、引用の層そのものが無い。
func (t Terminal) launch(
	ctx context.Context, choice platform.TerminalChoice, alias, helperPath string, program []string,
) error {
	candidate, ok := profileFor(choice.ID)
	if !ok {
		return ErrUnknownTerminal
	}
	if candidate.Script != "" {
		script, arguments := candidate.Script, []string{"-", alias}
		if helperPath != "" {
			script, arguments = candidate.PasswordScript, []string{"-", alias, helperPath}
		}
		return t.explain(choice.ID, t.run(ctx, t.Program, "/usr/bin/osascript", script, arguments))
	}

	// `open` はアプリケーションを Launch Services に探させ、--args より後ろを
	// そのアプリケーションへ渡す。-n が要るのは、既に動いている実体があるとき、
	// それが無いと引数がどこにも届かないからである。
	arguments := []string{"-n"}
	switch {
	case choice.ID == platform.TerminalCustom:
		if err := platform.ValidateTerminalChoice(choice); err != nil {
			return err
		}
		// 開く先は、アプリケーションを探す場所として認めているディレクトリの
		// 直下でなければならない。ユーザーが一覧から選んだものは必ずそこにあり、
		// 手で書き換えられた設定はここで止まる。
		if !t.selectable(choice.Application) {
			return fmt.Errorf("%s: %w", choice.Application, platform.ErrTerminalApplication)
		}
		if !t.exists(choice.Application) {
			return fmt.Errorf("%s: %w", choice.Application, platform.ErrTerminalNotInstalled)
		}
		arguments = append(arguments, "-a", choice.Application, "--args")
		arguments = append(arguments, choice.Arguments...)
	default:
		arguments = append(arguments, "-b", candidate.Bundle, "--args")
		arguments = append(arguments, candidate.Arguments...)
	}
	arguments = append(arguments, program...)
	return t.explain(choice.ID, t.run(ctx, t.Open, "/usr/bin/open", "", arguments))
}

func (t Terminal) run(ctx context.Context, program, fallback, script string, arguments []string) error {
	if program == "" {
		program = fallback
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
