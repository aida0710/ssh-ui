package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sshc/internal/handoff"
	"sshc/internal/httpserver"
	"sshc/internal/platform"
)

// connectResponse は、起動中のアプリケーションが返す内容。
type connectAnswer struct {
	Alias        string   `json:"alias"`
	AskpassToken string   `json:"askpassToken"`
	AskpassURL   string   `json:"askpassUrl"`
	Warnings     []string `json:"warnings"`
}

// connectInvocation は、このプロセスが接続のために起動されたかを報告する。
//
// フラグでもなく askpass サブコマンドでもない裸の語は alias である。コマンドは
// それで全部だ。`sshc <alias>`。これが置き換える五つの環境変数は、Terminal の
// ボタンがすでに自前でやっていたことを手書きにした形にすぎず、そもそも人が打ち込む
// ためのものではなかった。
func connectInvocation(argv []string) (string, bool) {
	if len(argv) != 2 {
		return "", false
	}
	word := argv[1]
	if word == "" || word[0] == '-' || word == AskpassSubcommand || word == OpenSubcommand || word == ListSubcommand || word == ConnectSubcommand || word == HelpSubcommand {
		return "", false
	}
	return word, true
}

// OpenSubcommand は、起動中のアプリケーションをブラウザで開く。
//
// ブートストラップトークンは初回の使用で消費される。標準出力がどこにも届かないよう
// 意図して作られたバックグラウンドエージェント — その URL は有効なトークンを運ぶ
// からだ — には、これを配る手段がない。そこで、ユーザーが何かを見たいときには
// 新しいものを要求する。"open" という名のホストは、この方法では名前で接続できない
// ホストになる。語はひとつだけで、それがこれである。
const OpenSubcommand = "open"

// runOpen は、起動中のアプリケーションに入口を求め、ブラウザを開く。
func runOpen(ctx context.Context, stateDir string, client *http.Client, browser func(string) error, stderr io.Writer) int {
	found, err := handoff.Read(stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "sshc: not running")
		return 1
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, found.URL+httpserver.OpenPath, bytes.NewReader([]byte("{}")))
	if err != nil {
		fmt.Fprintf(stderr, "sshc: %v\n", err)
		return 1
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(handoff.HeaderName, found.Secret)
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintln(stderr, "sshc: not answering")
		return 1
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "sshc: refused")
		return 1
	}
	var answer struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&answer); err != nil || answer.URL == "" {
		fmt.Fprintln(stderr, "sshc: the answer carried no way in")
		return 1
	}
	// URL はブラウザに渡すだけで、決して表示しない。有効なブートストラップトークンを
	// 運んでおり、端末は見せられたものを残すからだ。
	if err := browser(answer.URL); err != nil {
		fmt.Fprintf(stderr, "sshc: %v\n", err)
		return 1
	}
	return 0
}

// sshFinder は ssh プログラムを解決する。このアプリケーションの他のすべての部分が
// 使うのと同じ継ぎ目なので、「どの ssh か」への答えはひとつしかない。
type sshFinder interface{ SSH() (string, error) }

// connectEnvironment は、ssh を実行する環境である。
//
// ユーザー自身の環境はそのまま引き継ぐ。これはユーザーが自分で行ったであろう接続
// だからである。askpass ヘルパーを武装させる五つの変数は引き継がない。いったん
// 取り除いてから設定するので、OpenSSH が読むのは、このコードが決めた値になる。
//
// これは見た目以上に重要である。syscall.Exec は配列をそのまま渡し、getenv は
// その中で最初に一致したものを返す。したがって追記方式では、ユーザーが何年も前に
// エクスポートした SSH_ASKPASS に負ける — しかも負けながら、保存済みパスワードと
// 引き換えられるワンタイムトークンをそのプログラムに渡してしまう。武装しない接続
// でもこれらを取り除くのは、古い変数が接続を武装させてしまわないようにするため
// である。
func connectEnvironment(inherited []string, helper, url, token, alias string) []string {
	decided := map[string]string{}
	if helper != "" && token != "" {
		decided = map[string]string{
			"SSH_ASKPASS":         helper,
			"SSH_ASKPASS_REQUIRE": "force",
			URLVariable:           url,
			TokenVariable:         token,
			AliasVariable:         alias,
		}
	}
	ours := map[string]bool{
		"SSH_ASKPASS": true, "SSH_ASKPASS_REQUIRE": true,
		URLVariable: true, TokenVariable: true, AliasVariable: true,
	}

	environment := make([]string, 0, len(inherited)+len(decided))
	for _, entry := range inherited {
		name, _, found := strings.Cut(entry, "=")
		if found && ours[name] {
			continue
		}
		environment = append(environment, entry)
	}
	for _, name := range []string{"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", URLVariable, TokenVariable, AliasVariable} {
		if value, set := decided[name]; set {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

// runConnect は、この接続に必要なものを起動中のアプリケーションに尋ね、端末を ssh に
// 引き渡す。
//
// アプリケーションが動いていないことはエラーではない。ユーザーはホストへ接続したいの
// であり、`ssh <alias>` は本人が打ち込んだであろうコマンドだ。OpenSSH が自分で
// パスワードを尋ねる以上、それは機能する接続である。stderr にその旨を書けば、邪魔に
// ならずに違いが見える。
func runConnect(ctx context.Context, alias string, stateDir string, client *http.Client, toolchain sshFinder, stderr io.Writer) int {
	if err := platform.ValidateAlias(alias); err != nil {
		fmt.Fprintf(stderr, "sshc: %q is not an alias this will put on a command line\n", alias)
		return 2
	}

	armed := false
	helper, url, token := "", "", ""
	answer, err := askApplication(ctx, alias, stateDir, client)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "sshc: connecting without a stored password (%v)\n", err)
	default:
		for _, warning := range answer.Warnings {
			fmt.Fprintf(stderr, "sshc: %s\n", warning)
		}
		if answer.AskpassToken != "" {
			resolved, pathErr := os.Executable()
			if pathErr != nil {
				fmt.Fprintf(stderr, "sshc: connecting without a stored password (%v)\n", pathErr)
			} else {
				armed, helper, url, token = true, resolved, answer.AskpassURL, answer.AskpassToken
			}
		}
	}
	environment := connectEnvironment(os.Environ(), helper, url, token, alias)

	// このアプリケーションが起動する他のすべての OpenSSH プログラムと同じやり方で
	// 解決する。固定のディレクトリ一覧から絶対パスへ、である。PATH は参照しない。
	// さもなければ、上のトークンが PATH の先頭にあるものへ渡されてしまうから
	// である。
	ssh, err := toolchain.SSH()
	if err != nil || !filepath.IsAbs(ssh) {
		fmt.Fprintf(stderr, "sshc: ssh was not found where it is expected: %v\n", err)
		return 1
	}
	// ここから先、端末は ssh のものである。子プロセスではなく exec を使うのは、ユーザーと
	// 接続のあいだに二つ目のものを挟まないためだ — シグナルを転送する相手も、翻訳すべき
	// 終了ステータスもなくなる。
	arguments := []string{"ssh"}
	if armed {
		// 誤った保存済みパスワードを三度差し出すと、サーバーによってはロックアウトに数えられる。
		// そこで武装した接続には試行を一度だけ与える。保存済みパスワードがない場合は手を
		// 触れない。打っているのはユーザーであり、一度打ち間違えたことは、あきらめる理由に
		// ならない。
		arguments = append(arguments, "-o", "NumberOfPasswordPrompts=1")
	}
	arguments = append(arguments, "--", alias)
	if err := syscall.Exec(ssh, arguments, environment); err != nil {
		fmt.Fprintf(stderr, "sshc: %v\n", err)
		return 1
	}
	return 0
}

// askApplication はハンドオフを読み、接続一回分を要求する。
func askApplication(ctx context.Context, alias, stateDir string, client *http.Client) (connectAnswer, error) {
	found, err := handoff.Read(stateDir)
	if err != nil {
		return connectAnswer{}, fmt.Errorf("sshc is not running")
	}
	body, err := json.Marshal(map[string]string{"alias": alias})
	if err != nil {
		return connectAnswer{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		found.URL+httpserver.ConnectPath, bytes.NewReader(body))
	if err != nil {
		return connectAnswer{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(handoff.HeaderName, found.Secret)

	response, err := client.Do(request)
	if err != nil {
		return connectAnswer{}, fmt.Errorf("sshc is not answering")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return connectAnswer{}, fmt.Errorf("sshc refused the request")
	}
	var answer connectAnswer
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&answer); err != nil {
		return connectAnswer{}, err
	}
	return answer, nil
}

// connectTimeout は、これが行う唯一のリクエストに上限を設ける。ネットワーク越しに何か
// をするのではなく、このマシン上のプロセスにトークンを尋ねているだけだ。
const connectTimeout = 5 * time.Second
