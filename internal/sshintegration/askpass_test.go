// Package sshintegration は、本物の OpenSSH サーバーを必要とするテストを収める。
//
// ここにあるものはすべて、SSHC_TEST_SSH_ADDR がサーバーを指していない限りスキップ
// される。`make integration` はコンテナで起動して変数を設定し、CI も同じことをする。
//
// 要点は、どんな偽物にも確かめられない唯一のこと。すなわち、askpass ヘルパーが
// 渡したものを OpenSSH が受け取り、認証が通るということである。パスワード機能の
// それ以外 — プロンプトのルール、トークンの意味論、拒否の挙動 — は密閉された形で
// 網羅されているが、それらはすべて「こうあるべき」の記述にすぎない。ここで見るの
// は「実際にそうなるか」である。
//
// 差し替える本番コンポーネントは Terminal.app だけであり、しかもその AppleScript
// が実行したであろうコマンドそのもので差し替えている。ヘルパー、エンドポイント、
// vault、トークンは、出荷されるコードそのものだ。
package sshintegration_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crypto/rand"

	"sshc/internal/httpserver"
	"sshc/internal/secret"
	"sshc/internal/session"
	"sshc/internal/storage"
)

const (
	addressVariable  = "SSHC_TEST_SSH_ADDR"
	userVariable     = "SSHC_TEST_SSH_USER"
	passwordVariable = "SSHC_TEST_SSH_PASSWORD"

	alias      = "integration"
	passphrase = "correct horse battery staple"
)

type target struct{ host, port, user, password string }

func requireTarget(t *testing.T) target {
	t.Helper()
	address := os.Getenv(addressVariable)
	if address == "" {
		t.Skipf("%s is not set; start a server with `make integration` to run this", addressVariable)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("%s = %q: %v", addressVariable, address, err)
	}
	return target{host: host, port: port, user: os.Getenv(userVariable), password: os.Getenv(passwordVariable)}
}

func helperPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "bin", "sshc"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the binary under test is missing; run `make build` first: %v", err)
	}
	return path
}

// buildHome は、唯一のホストがコンテナであり、そのホスト鍵がすでに既知である
// ワークスペースを書き出す。
//
// 検査を無効にするのではなく鍵をスキャンしているのは意図的である。この機能は
// ホスト鍵の問いに答えることを拒否するので、StrictHostKeyChecking を切るテストは、
// このアプリケーションが決して作らない設定を試していることに
// なってしまう。
func buildHome(t *testing.T, destination target) string {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "known_hosts"), hostKeyOf(t, destination), 0o600); err != nil {
		t.Fatal(err)
	}

	configuration := strings.Join([]string{
		"Host " + alias,
		"\tHostName " + destination.host,
		"\tPort " + destination.port,
		"\tUser " + destination.user,
		// 絶対パスにするのは、OpenSSH が ~ を HOME ではなく passwd データベースから
		// 展開するからである。相対 Include なら HOME の設定だけで足りるが、これには
		// 足りない。このスイートの初回 CI 実行が失敗したのがまさにそれだ。ssh は設定を
		// まったく読まず、alias をホスト名として解決しようと
		// した。
		"\tUserKnownHostsFile " + filepath.Join(root, "known_hosts"),
		// 要点はパスワードの経路なので、鍵による経路は塞いである。
		"\tPubkeyAuthentication no",
		"\tPreferredAuthentications password",
		"\tStrictHostKeyChecking yes",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "config"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

var (
	hostKeyMutex sync.Mutex
	hostKey      []byte
	hostKeyError error
	hostKeyKnown bool
)

// hostKeyOf は、パッケージ全体で一度だけサーバーのホスト鍵をスキャンする。
//
// 以前はテストごとにスキャンしていた。テストが四つあれば、テスト自身が張る接続に
// 加えて四回のスキャンになる。CI では最初の二つが通った直後に、三つ目と四つ目が
// 空で返ってきた。コンテナの sshd は、同時に開始する未認証接続の数を制限して
// おり、keyscan もそのひとつだからである。鍵は毎回同じ鍵なので、もう一度
// スキャンすることは、その予算を使う以外に何ひとつしていなかったことに
// なる。
//
// リトライを入れているのも、一般的な不安定さ対策ではなく同じ理由からである。
// ここでの拒否は「いまはだめ」という意味であり、1 秒待てばそれではなくなる。
// すべての試行が拒否された場合は、それを覆い隠さずに報告する。
func hostKeyOf(t *testing.T, destination target) []byte {
	t.Helper()
	hostKeyMutex.Lock()
	defer hostKeyMutex.Unlock()
	if hostKeyKnown {
		if hostKeyError != nil {
			t.Fatalf("ssh-keyscan produced nothing: %v", hostKeyError)
		}
		return hostKey
	}

	empty := t.TempDir()
	for attempt := range 5 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		scan := exec.Command("ssh-keyscan", "-p", destination.port, destination.host)
		scan.Env = []string{"HOME=" + empty, "PATH=" + os.Getenv("PATH")}
		scanned, err := scan.Output()
		switch {
		case err != nil:
			hostKeyError = err
		case len(scanned) == 0:
			hostKeyError = errors.New("the scan succeeded but returned no key")
		default:
			hostKey, hostKeyError = scanned, nil
		}
		if hostKeyError == nil {
			break
		}
	}
	hostKeyKnown = true
	if hostKeyError != nil {
		t.Fatalf("ssh-keyscan produced nothing after 5 attempts: %v", hostKeyError)
	}
	return hostKey
}

// countingListener は、サーバーが受け付けた接続を数える。
//
// これは、「この vault が持つパスワードを ssh が拒否した」のか「ヘルパーがそもそも
// 尋ねなかった」のかをテストが見分ける唯一の手段である。どちらも Permission denied
// で終わる。ある CI 実行では、ヘルパーが答える代わりにアプリケーションの二つ目の
// コピーを起動していたにもかかわらず、ここの否定テストはすべて通ってしまった。
// SSH_ASKPASS はプログラムを指定し、OpenSSH はプロンプトだけを引数にそれを exec
// する。バイナリの方は、決して届くはずのないサブコマンドの語を探していた。
type countingListener struct {
	net.Listener
	connections atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.connections.Add(1)
	}
	return connection, err
}

func requireTheHelperAsked(t *testing.T, listener *countingListener, before int64, output string) {
	t.Helper()
	if listener.connections.Load() <= before {
		t.Fatalf("the helper never reached this application, so nothing about the password was tested:\n%s", output)
	}
}

// startServer は、本物の /askpass エンドポイントを持つ本物の HTTP サーバーを動かす。
func startServer(t *testing.T, home string) (*secret.Service, string, *countingListener) {
	t.Helper()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	vault := secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now)
	if err := vault.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	bare, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countingListener{Listener: bare}
	sessions, _, err := session.NewManager(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := httpserver.New(httpserver.Options{
		Listener:   listener,
		Sessions:   sessions,
		UI:         os.DirFS(home),
		Version:    "integration",
		Passwords:  vault,
		Answerable: answerable,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveContext, stop := context.WithCancel(context.Background())
	go func() { _ = server.Serve(serveContext) }()
	t.Cleanup(stop)
	// server.URL() はワンタイムのブートストラップフラグメントを含む。askpass の
	// エンドポイントに必要なのはオリジンだけで、セッショントークンを渡してはならない。
	origin := server.URL()
	if index := strings.Index(origin, "#"); index >= 0 {
		origin = origin[:index]
	}
	return vault, strings.TrimSuffix(origin, "/") + httpserver.AskpassPath, listener
}

// answerable は本番のルールである。cmd/sshc は main パッケージで import できない
// ため、ここで書き直してある。より緩いルールを使うテストは、出荷されるものに
// ついて何も証明しない。したがってこれは同じ述語だ。プロンプトが OpenSSH の
// パスワードサフィックスで終わり、それ以外の何にも触れていないこと。
func answerable(_ string, prompt string) bool {
	trimmed := strings.ToLower(strings.TrimRight(prompt, " \t\r\n"))
	for _, marker := range []string{"passphrase", "continue connecting", "fingerprint", "yes/no"} {
		if strings.Contains(trimmed, marker) {
			return false
		}
	}
	return strings.HasSuffix(trimmed, "'s password:")
}

func runSSH(t *testing.T, home, endpoint, token string, arguments ...string) (string, error) {
	t.Helper()
	// TerminalPasswordScript がシェルに実行させるものそのもの。
	// -F を明示するのは UserKnownHostsFile と同じ理由である。既定のユーザー設定の
	// パスは HOME ではなく passwd データベースから来るので、HOME しか設定しない
	// テストは、設定なしで黙って走ってしまう。
	command := exec.Command("ssh", append([]string{
		"-F", filepath.Join(home, ".ssh", "config"),
		"-o", "NumberOfPasswordPrompts=1",
		"-o", "BatchMode=no",
		"--", alias,
	}, arguments...)...)
	command.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"SSH_ASKPASS=" + helperPath(t),
		"SSH_ASKPASS_REQUIRE=force",
		"SSHC_ASKPASS_URL=" + endpoint,
		"SSHC_ASKPASS_TOKEN=" + token,
		"SSHC_ASKPASS_ALIAS=" + alias,
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestTheHelperAuthenticatesAgainstARealServer(t *testing.T) {
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token, "echo", "authenticated-by-askpass")
	if err != nil {
		t.Fatalf("ssh = %v\n%s", err, output)
	}
	requireTheHelperAsked(t, listener, asked, output)
	if !strings.Contains(output, "authenticated-by-askpass") {
		t.Errorf("the remote command did not run:\n%s", output)
	}
}

func TestTheWrongStoredPasswordFailsOnceRatherThanRepeatedly(t *testing.T) {
	// 出荷されるコマンドに NumberOfPasswordPrompts=1 が入っているのは、誤った保存済み
	// パスワードを三度差し出すと、サーバーによってはロックアウトに数えられるからだ。
	// ここが、それが主張で終わらなくなる場所である。
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password+"-wrong"); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token)
	if err == nil {
		t.Fatalf("ssh authenticated with the wrong password:\n%s", output)
	}
	requireTheHelperAsked(t, listener, asked, output)
	requireAuthenticationWasAttempted(t, output)
	if attempts := strings.Count(output, "Permission denied"); attempts > 1 {
		t.Errorf("the password was offered %d times:\n%s", attempts, output)
	}
}

func TestASpentTokenDoesNotAuthenticate(t *testing.T) {
	// トークンは、それが作られた接続によって使い切られる。そうでなければ、プロセス
	// 一覧で一度見えただけのトークンが、その 2 分間が尽きるまで使えてしまうことに
	// なる。
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runSSH(t, home, endpoint, token, "true"); err != nil {
		t.Fatalf("the first connection = %v\n%s", err, output)
	}

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token, "true")
	if err == nil {
		t.Fatalf("the spent token authenticated a second connection:\n%s", output)
	}
	// ヘルパーは二度目も尋ねたうえで断られたのであって、尋ねなかったのではない。
	requireTheHelperAsked(t, listener, asked, output)
	requireAuthenticationWasAttempted(t, output)
}

func TestALockedVaultCannotAnswer(t *testing.T) {
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}
	vault.Lock()

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token, "true")
	if err == nil {
		t.Fatalf("a locked vault still answered:\n%s", output)
	}
	requireTheHelperAsked(t, listener, asked, output)
	requireAuthenticationWasAttempted(t, output)
}

// requireAuthenticationWasAttempted は、テストが誤った理由で通るのを防ぐ。
//
// ここの否定ケースはいずれも ssh が失敗したことを表明するが、ssh はさまざまな理由
// で失敗する。このスイートの初回 CI 実行では、ssh がサーバーにまったく到達して
// いないのに二つが通っていた — 設定を一度も読んでいなかったため、alias を解決
// できなかったのである。「パスワードが拒否された」と「そもそも接続がなかった」を
// 区別できないテストは、パスワードを試験していない。
func requireAuthenticationWasAttempted(t *testing.T, output string) {
	t.Helper()
	for _, symptom := range []string{
		"Could not resolve hostname",
		"Connection refused",
		"No route to host",
		"Host key verification failed",
	} {
		if strings.Contains(output, symptom) {
			t.Fatalf("ssh failed before authentication (%s):\n%s", symptom, output)
		}
	}
	if !strings.Contains(output, "Permission denied") {
		t.Fatalf("ssh did not report a refused authentication, so it may have failed earlier:\n%s", output)
	}
}
