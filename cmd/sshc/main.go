package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sshc/internal/app"
	"sshc/internal/platform"
	"sshc/internal/platform/macos"
	"sshc/internal/selfupdate"
	"sshc/internal/ui"
)

var version = "dev"

// openBrowser はここで宣言される。フラグを解析するのはサブコマンドを見分けた
// 後だが、usage はどの経路からでもフラグを一覧できなければならないからである。
var openBrowser = flag.Bool("open", true,
	"open the UI in the default browser; -open=false prints the URL on standard output instead")

// urlPrinter は URL を開く代わりに書き出すことで platform.BrowserLauncher を満たす。
// これは自動化のためにある — エンドツーエンドのスイートとパッケージングのスモーク
// テストで、ユーザー自身のブラウザに有効なブートストラップトークンを渡してはならない
// からだ。トークンの露出は `open` の argv にすでにある以上のものではなく、しかもこの
// フラグは明示的に指定しなければならない。
type urlPrinter struct{ out io.Writer }

func (p urlPrinter) Open(_ context.Context, target string) error {
	_, err := fmt.Fprintln(p.out, target)
	return err
}

// AskpassSubcommand は、このバイナリを「OpenSSH がパスワードを尋ねる相手のプログラム」
// に変える argv の語。二つ目のバイナリではなくサブコマンドにしてあるのは、インストール・
// 署名・公証、そして武装元のアプリケーションとの歩調合わせを、余計にひとつ増やさない
// ためである。
const AskpassSubcommand = "askpass"

// HelpSubcommand は使い方を出す語。
//
// これを予約するのは `open` と同じ理由である。裸の語は alias なので、これがないと
// "help" はホスト名として ssh へ渡り、使い方を求めた人は
// "Could not resolve hostname help" を受け取る。-h は flag パッケージが拾うが、
// 打つ言葉として自然なのはこちらだ。
const HelpSubcommand = "help"

// helpInvocation は、このプロセスが使い方を求めて起動されたかを報告する。
//
// 引数を伴う場合は使い方ではない。`sshc help me` は、まだ理解されていない何かで
// あって、"help" というホストへの接続ではない。
func helpInvocation(argv []string) bool {
	if len(argv) != 2 {
		return false
	}
	switch argv[1] {
	case HelpSubcommand, "-h", "--help":
		return true
	}
	return false
}

// askpassInvocation は、このプロセスが OpenSSH のプロンプトに答えるために起動された
// かを報告し、ヘルパーが読むべき引数を返す。
//
// サブコマンドの語は手で実行するための手段である。OpenSSH の実行方法ではない。
// SSH_ASKPASS はプログラムを指定し、OpenSSH はプロンプトだけを引数としてそのプログラム
// を exec する — シェルがないので、サブコマンドの語が入る場所はどこにもない。これが
// なかったために、出荷された機能はアプリケーション全体の二つ目のコピーをブラウザごと
// 起動し、ssh には決して送られてこないパスワードが渡された。見つけたのは、実物の sshd
// に対する統合テストスイートである。
//
// 目印にトークンを使うのは、それがちょうどひとつの接続のために存在し、この
// アプリケーション以外に設定するものがないからだ。エンドポイントも併せて必須なのは、
// 古い変数ひとつでアプリケーションが黙ってヘルパーに変わらないようにするためである。
func askpassInvocation(argv []string, lookup func(string) string) ([]string, bool) {
	if len(argv) > 1 && argv[1] == AskpassSubcommand {
		return argv[2:], true
	}
	if lookup(TokenVariable) != "" && lookup(URLVariable) != "" {
		return argv[1:], true
	}
	return nil, false
}

// usage は、このバイナリが答える語をすべて並べる。
//
// `sshc <alias>` は裸の語であり、ここに並ぶ語だけがそれより先に読まれる。
// それを書いておかないと、`open` という名前のホストに接続できない理由が
// どこにも書かれていないことになる。
func usage(out io.Writer) {
	fmt.Fprint(out, `usage:
  sshc                 open the user interface in the default browser
  sshc <alias>         connect to a host from ~/.ssh/config in this terminal
  sshc connect [text]  choose a host in this terminal, then connect
  sshc list            print every concrete Host alias, one per line
  sshc open            ask the running application for a new way in
  sshc askpass         answer an OpenSSH prompt; OpenSSH runs this, not you
  sshc help            print this

flags:
`)
	flag.PrintDefaults()
	fmt.Fprint(out, `
Those words are read before the alias, so a host named after one of them is
still reachable with ssh itself, but not through this command.
`)
}

func main() {
	// この分岐が flag.Parse より前にあるのは、OpenSSH が渡すプロンプトが任意の文字列で
	// あり、そうしなければフラグとして読まれてしまうからである。
	if arguments, ok := askpassInvocation(os.Args, os.Getenv); ok {
		os.Exit(runAskpass(
			context.Background(),
			arguments,
			os.Getenv,
			&http.Client{Timeout: 15 * time.Second},
			os.Stdout,
			os.Stderr,
		))
	}

	if len(os.Args) == 2 && os.Args[1] == OpenSubcommand {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sshc: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runOpen(
			context.Background(), app.HandoffDir(home),
			&http.Client{Timeout: connectTimeout},
			func(target string) error {
				return macos.NewBrowser(macos.NewOutputRunner()).Open(context.Background(), target)
			},
			os.Stderr,
		))
	}
	if helpInvocation(os.Args) {
		usage(os.Stdout)
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == ListSubcommand {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sshc: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runList(home, os.Stdout, os.Stderr))
	}
	if query, ok := tuiInvocation(os.Args); ok {
		if len(os.Args) > 3 {
			fmt.Fprintln(os.Stderr, "usage: sshc connect [search]")
			os.Exit(2)
		}
		// 検索語はフラグではないが、ヘルプを求めた人に接続先を探させはしない。
		if query == "-h" || query == "--help" {
			usage(os.Stdout)
			os.Exit(0)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sshc: %v\n", err)
			os.Exit(1)
		}
		alias, err := chooseTUIHost(home, query, os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			if errors.Is(err, errTUIClosed) {
				os.Exit(0)
			}
			fmt.Fprintf(os.Stderr, "sshc: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runConnect(
			context.Background(), alias, app.HandoffDir(home),
			&http.Client{Timeout: connectTimeout}, macos.NewToolchain(), os.Stderr,
		))
	}

	// `sshc <alias>` は接続する。askpass の分岐のあと、フラグ解析の前で判定する。alias は
	// 裸の語であり、flag.Parse はそこで止まってしまうため、接続する代わりにアプリケーション
	// が起動してしまうからだ。
	if alias, ok := connectInvocation(os.Args); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sshc: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runConnect(
			context.Background(), alias, app.HandoffDir(home),
			&http.Client{Timeout: connectTimeout}, macos.NewToolchain(), os.Stderr,
		))
	}

	// 既定の usage はフラグしか知らない。サブコマンドは argv の裸の語であり、
	// flag パッケージから見えないので、ここで一度だけ書く。
	flag.Usage = func() { usage(flag.CommandLine.Output()) }
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	assets, err := ui.FS()
	if err != nil {
		logger.Error("load embedded UI", "error", err)
		os.Exit(1)
	}

	// askpass ヘルパーはこのバイナリである。ここで一度だけ解決するのが唯一それの可能な
	// 場所だ。アプリケーションの内側には、それがどこにインストールされたかを知るものが
	// ない。解決できないパスの場合は、そこにないかもしれないヘルパーを武装させるのでは
	// なく、すべての端末起動を素の経路のままにしておく。
	helperPath, err := os.Executable()
	if err != nil {
		logger.Warn("resolve this binary; stored passwords will not be offered", "error", err)
		helperPath = ""
	}

	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("resolve home directory", "error", err)
		os.Exit(1)
	}

	// OpenSSH のプログラムを起動するすべてのサブシステムが、ひとつのプロセスランナーと
	// ひとつのツールチェーンを共有する。これにより argv、子プロセスの環境、出力の上限を
	// 決める場所はひとつだけになる。
	runner := macos.NewOutputRunner()
	toolchain := macos.NewToolchain()

	var browser platform.BrowserLauncher = macos.NewBrowser(runner)
	if !*openBrowser {
		browser = urlPrinter{out: os.Stdout}
	}

	dependencies := app.Dependencies{
		Random:  rand.Reader,
		Browser: browser,
		// ユーザーがインターフェースから有効にしない限りオフ。ここでは何も登録しない。
		// スイッチに手が届くようにするだけである。
		LoginItem: macos.LoginItem{Runner: runner, Home: home},
		// このアプリケーションが自分自身以外のホストに接触する唯一の場所であり、
		// 誰かが求めたときにだけ行う。何も取得せず、何も置き換えない。
		// 新しいバージョンが公開されているかを報告するだけである。
		Updates: &selfupdate.Checker{
			API:  "https://api.github.com/repos/aida0710/sshc/releases/latest",
			HTTP: &http.Client{Timeout: 30 * time.Second},
		},
		Listen:    net.Listen,
		UI:        assets,
		Logger:    logger,
		Home:      home,
		Runner:    runner,
		Toolchain: toolchain,
		KeyAgent:  macos.NewKeyAgent(runner, toolchain, os.LookupEnv),
		Terminal:  macos.NewTerminal(runner, home),
		Lookup:    os.LookupEnv,
		// ヘルパーとサーバーは同じ関数から同じルールを適用する。そのため「このプロンプト
		// には答えるのか」という問いに対して、両者の答えが食い違っていくことは
		// あり得ない。
		AskpassHelper: helperPath,
		Answerable:    AnswerablePrompt,
	}
	if err := app.Run(ctx, dependencies, version); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("sshc stopped", "error", err)
		os.Exit(1)
	}
}
