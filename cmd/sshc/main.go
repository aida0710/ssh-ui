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
				return macos.NewBrowser(macos.NewExecRunner()).Open(context.Background(), target)
			},
			os.Stderr,
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

	openBrowser := flag.Bool("open", true,
		"open the UI in the default browser; -open=false prints the URL on standard output instead")
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

	var browser platform.BrowserLauncher = macos.NewBrowser(macos.NewExecRunner())
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
		Terminal:  macos.NewTerminal(runner),
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
