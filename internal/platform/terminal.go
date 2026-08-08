package platform

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

type TerminalID string

const (
	TerminalApple   TerminalID = "terminal"
	TerminalITerm2  TerminalID = "iterm2"
	TerminalKitty   TerminalID = "kitty"
	TerminalGhostty TerminalID = "ghostty"
	TerminalWezTerm TerminalID = "wezterm"
	// TerminalCustom は、この表に無いアプリケーションを指す。どれを開くかは
	// TerminalChoice が運ぶ。
	TerminalCustom TerminalID = "custom"
)

// TerminalIDs は語彙そのものであり、画面に並ぶ順でもある。ここが唯一の一覧で、
// 検証も在庫も、選択肢を二箇所で数えないためにこれを読む。
var TerminalIDs = []TerminalID{
	TerminalApple, TerminalITerm2, TerminalKitty, TerminalGhostty, TerminalWezTerm, TerminalCustom,
}

func ValidTerminalID(id TerminalID) bool { return slices.Contains(TerminalIDs, id) }

// ErrTerminalNotInstalled は、選ばれた端末がこのマシンに無いことを報告する。
//
// 「開けなかった」とは別の答えである。前者はユーザーが選び直すかインストール
// すれば直り、後者はそうではない。両方を同じ失敗にまとめると、画面は
// どちらかを言えなくなる。
var ErrTerminalNotInstalled = errors.New("terminal is not installed")

// ErrTerminalApplication は、開く先として受け取れないアプリケーションを報告する。
var ErrTerminalApplication = errors.New("terminal application is not one this may open")

// TerminalChoice は「何で開くか」の全体である。
//
// 定義済みの端末では ID だけで足り、Application と Arguments は空になる。
// custom では、ユーザーが選んだアプリケーションバンドルと、その前に置く引数を
// 運ぶ。**引数はシェルの文字列ではなく argv の要素である。** 間にシェルは
// 無いので、ここに書かれた値が別のコマンドへ化ける経路は存在しない。それでも
// 開く先のアプリケーションには渡るので、語数と長さには上限がある。
type TerminalChoice struct {
	ID          TerminalID
	Application string
	Arguments   []string
}

// 引数の上限。`-e` や `start --` を通すには十分で、設定ファイルを
// コマンドラインの置き場に変えるには足りない。
const (
	MaxTerminalArguments      = 8
	MaxTerminalArgumentLength = 64
)

// ValidateTerminalChoice は、開く先として受け取れる形かどうかを答える。
//
// ここが見るのは形だけである。「そのアプリケーションがこのマシンにあるか」は
// 起動する側が知っていることで、保存の可否をディスクの今の状態に結び付けると、
// アンインストールしただけで設定が保存できなくなる。
//
// Application と Arguments を持てるのは custom だけである。定義済みの端末が
// 開く先はこのアプリケーションが決めており、設定から来ることはない。
func ValidateTerminalChoice(choice TerminalChoice) error {
	if !ValidTerminalID(choice.ID) {
		return errors.New("unknown terminal")
	}
	if choice.ID != TerminalCustom {
		if choice.Application != "" || len(choice.Arguments) != 0 {
			return ErrTerminalApplication
		}
		return nil
	}
	// 開けるのはアプリケーションバンドルだけであり、その場所は組み立てではなく
	// 選択の結果でなければならない。
	if !filepath.IsAbs(choice.Application) ||
		filepath.Clean(choice.Application) != choice.Application ||
		filepath.Ext(choice.Application) != ".app" {
		return ErrTerminalApplication
	}
	if len(choice.Arguments) > MaxTerminalArguments {
		return ErrTerminalApplication
	}
	for _, argument := range choice.Arguments {
		if argument == "" || utf8.RuneCountInString(argument) > MaxTerminalArgumentLength {
			return ErrTerminalApplication
		}
		// 空白を拒むのは、ひとつの語をふたつに割れなくするためである。argv は
		// 分かち書きしないので、語の中の空白は語の一部にしかならず、それを
		// 期待した人の設定は黙って別の意味になる。
		if strings.ContainsFunc(argument, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
			return ErrTerminalApplication
		}
	}
	return nil
}

// Application は、このマシンで見つかったアプリケーションバンドルひとつである。
type Application struct {
	Name string
	Path string
}

// TerminalAvailability は、選択肢ひとつと、それがこのマシンで見つかるかを報告する。
type TerminalAvailability struct {
	ID        TerminalID
	Installed bool
}

// TerminalInventory は、どの端末が今このマシンにあるかと、ユーザーが custom として
// 選べるアプリケーションを報告する。
//
// 起動可否の判定ではなく、画面が「選べるが多分開けない」を先に言うための情報で
// ある。見つからなくても起動を止めるのは、こちらがパスを持っている必要がある
// 場合だけである。
type TerminalInventory interface {
	Terminals() []TerminalAvailability
	Applications() []Application
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

// SelectableTerminalLauncher は、選ばれた端末で開く。受け取るのは TerminalChoice
// であって、コマンド文字列ではない。それが、設定ファイルの値をシェルへ変える経路を
// 作らない境界である。
type SelectableTerminalLauncher interface {
	TerminalLauncher
	LaunchIn(ctx context.Context, choice TerminalChoice, alias string) error
}

type SelectablePasswordTerminalLauncher interface {
	PasswordTerminalLauncher
	LaunchWithPasswordIn(ctx context.Context, choice TerminalChoice, alias, helperPath, endpoint, token string) error
}
