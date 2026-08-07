package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OpenSSH が実際に出すプロンプトを書き写したもの。この表の要点は、答えてよいのが
// 最初のひとつだけで、残りはこのヘルパーが決して答えてはならない問いだという
// ことだ。ホスト鍵のものは、この関数が存在する理由そのものである。
func TestAnswerablePromptAcceptsOnlyThePasswordPrompt(t *testing.T) {
	answerable := []string{
		"ops@203.0.113.10's password: ",
		"ops@203.0.113.10's password:",
		"root@nas's password: ",
		"a-very-long-user-name@some.host.example's password: ",
	}
	for _, prompt := range answerable {
		if !AnswerablePrompt(prompt) {
			t.Errorf("AnswerablePrompt(%q) = false, want true", prompt)
		}
	}

	refused := []string{
		"",
		"   ",
		"Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
		"Please type 'yes', 'no' or the fingerprint: ",
		"Enter passphrase for key '/Users/tester/.ssh/id_ed25519': ",
		"Enter passphrase for /Users/tester/.ssh/id_rsa: ",
		"Verification code: ",
		"Enter your one-time token: ",
		"(ops@203.0.113.10) Password: ",   // keyboard-interactive、別のフロー
		"Enter PIN for authenticator: ",   // FIDO
		"Confirm user presence for key: ", // FIDO
		"password",
		"Enter passphrase for key 'x': ops@h's password: ", // 両方に該当、拒否される
	}
	for _, prompt := range refused {
		if AnswerablePrompt(prompt) {
			t.Errorf("AnswerablePrompt(%q) = true, want false", prompt)
		}
	}
}

type askpassEnvironment map[string]string

func (e askpassEnvironment) lookup(name string) string { return e[name] }

func fullEnvironment(endpoint string) askpassEnvironment {
	return askpassEnvironment{
		AliasVariable: "bastion",
		URLVariable:   endpoint,
		TokenVariable: "one-time-token",
	}
}

func TestAskpassWritesOnlyThePasswordOnStandardOutput(t *testing.T) {
	var seen askpassRequest
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = r.Header.Get(AskpassTokenHeader)
		_ = json.NewDecoder(r.Body).Decode(&seen)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"password":"hunter2 "}`))
	}))
	defer server.Close()

	var out, errOut bytes.Buffer
	status := runAskpass(context.Background(), []string{"ops@203.0.113.10's password: "},
		fullEnvironment(server.URL).lookup, server.Client(), &out, &errOut)

	if status != askpassOK {
		t.Fatalf("status = %d, stderr = %q", status, errOut.String())
	}
	// 末尾の改行ひとつは OpenSSH が取り除くので、空白で終わるパスワードもそのまま
	// 無傷で残る。
	if out.String() != "hunter2 \n" {
		t.Errorf("stdout = %q, want %q", out.String(), "hunter2 \n")
	}
	if token != "one-time-token" {
		t.Errorf("token header = %q", token)
	}
	if seen.Alias != "bastion" {
		t.Errorf("alias = %q", seen.Alias)
	}
}

func TestAskpassWritesNothingOnStandardOutputWhenItRefuses(t *testing.T) {
	// 標準出力に診断メッセージを出すヘルパーは、それを OpenSSH にパスワードとして
	// 渡してしまう。ひとつではなく、拒否経路のすべてを検査する。
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	cases := map[string]struct {
		arguments   []string
		environment askpassEnvironment
	}{
		"no argument":    {nil, fullEnvironment(server.URL)},
		"no alias":       {[]string{"x's password: "}, askpassEnvironment{URLVariable: server.URL, TokenVariable: "t"}},
		"no url":         {[]string{"x's password: "}, askpassEnvironment{AliasVariable: "bastion", TokenVariable: "t"}},
		"no token":       {[]string{"x's password: "}, askpassEnvironment{AliasVariable: "bastion", URLVariable: server.URL}},
		"host key":       {[]string{"Are you sure you want to continue connecting (yes/no/[fingerprint])? "}, fullEnvironment(server.URL)},
		"passphrase":     {[]string{"Enter passphrase for key '/x/id': "}, fullEnvironment(server.URL)},
		"server said no": {[]string{"x's password: "}, fullEnvironment(server.URL)},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			status := runAskpass(context.Background(), test.arguments,
				test.environment.lookup, server.Client(), &out, &errOut)

			if status == askpassOK {
				t.Fatalf("status = %d, want a refusal", status)
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", out.String())
			}
			if errOut.Len() == 0 {
				t.Error("nothing was written to stderr, so the user sees no reason")
			}
		})
	}
}

func TestAskpassRefusesAnEndpointThatIsNotLoopback(t *testing.T) {
	// エンドポイントは環境変数で渡される以上それは入力である。別の場所を指す
	// SSHC_ASKPASS_URL がエクスポートされていれば、このヘルパーは、いま取得しようと
	// しているパスワードの持ち出し道具になってしまう。
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"password":"hunter2"}`))
	}))
	defer server.Close()

	elsewhere := []string{
		"http://198.51.100.7:8080/askpass",
		"https://example.com/askpass",
		"http://[::1]:9000/askpass",
		"http://localhost:9000/askpass",
		strings.Replace(server.URL, "127.0.0.1", "0.0.0.0", 1),
	}
	for _, endpoint := range elsewhere {
		t.Run(endpoint, func(t *testing.T) {
			var out, errOut bytes.Buffer
			environment := fullEnvironment(endpoint)
			status := runAskpass(context.Background(), []string{"x's password: "},
				environment.lookup, server.Client(), &out, &errOut)

			if status == askpassOK || out.Len() != 0 {
				t.Errorf("status = %d, stdout = %q", status, out.String())
			}
		})
	}
	if reached {
		t.Error("a request reached a server that is not 127.0.0.1")
	}
}

func TestAskpassDistinguishesNothingStoredFromRefused(t *testing.T) {
	// 「このホストにパスワードがない、または vault がロックされている」ことと
	// 「リクエストが拒否された」ことは、Terminal のウィンドウを見つめている人に
	// 伝える内容として別物である。
	for status, want := range map[int]int{
		http.StatusNotFound:            askpassNoEntry,
		http.StatusConflict:            askpassNoEntry,
		http.StatusForbidden:           askpassRefused,
		http.StatusBadRequest:          askpassRefused,
		http.StatusInternalServerError: askpassRefused,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		var out, errOut bytes.Buffer
		environment := fullEnvironment(server.URL)
		got := runAskpass(context.Background(), []string{"x's password: "},
			environment.lookup, server.Client(), &out, &errOut)
		server.Close()

		if got != want {
			t.Errorf("HTTP %d gave exit status %d, want %d", status, got, want)
		}
	}
}

func TestAskpassRefusesAnEmptyPasswordFromTheServer(t *testing.T) {
	// 空の回答はプロンプト上で誤ったパスワードと区別がつかず、それを書けばパスワードの
	// 試行回数を無駄にひとつ消費することになる。
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"password":""}`))
	}))
	defer server.Close()

	var out, errOut bytes.Buffer
	environment := fullEnvironment(server.URL)
	if status := runAskpass(context.Background(), []string{"x's password: "},
		environment.lookup, server.Client(), &out, &errOut); status != askpassNoEntry {
		t.Fatalf("status = %d, want askpassNoEntry", status)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestOpenSSHsInvocationIsRecognisedAsTheHelperAndNotAsTheApplication(t *testing.T) {
	// SSH_ASKPASS はプログラムを指定する。OpenSSH はプロンプトだけを引数としてそれを
	// exec する — シェルがないので、サブコマンドの語が届く余地はない。argv[1] を
	// サブコマンドとして読んでいたため、実際の起動はアプリケーション側へ落ち、二つ目の
	// サーバーを立ててブラウザを開く一方で、ssh は決して送られてこないパスワードを
	// 待ち続けた。
	environment := fullEnvironment("http://127.0.0.1:1/askpass")
	arguments, ok := askpassInvocation(
		[]string{"/opt/sshc", "ops@203.0.113.10's password: "}, environment.lookup)
	if !ok {
		t.Fatal("the invocation OpenSSH actually makes was not recognised as the helper")
	}
	if len(arguments) != 1 || arguments[0] != "ops@203.0.113.10's password: " {
		t.Errorf("arguments = %#v, want the prompt alone", arguments)
	}
}

func TestTheSubcommandStillWorksForRunningItByHand(t *testing.T) {
	arguments, ok := askpassInvocation(
		[]string{"/opt/sshc", AskpassSubcommand, "a prompt"}, askpassEnvironment{}.lookup)
	if !ok {
		t.Fatal("the explicit subcommand was not recognised")
	}
	if len(arguments) != 1 || arguments[0] != "a prompt" {
		t.Errorf("arguments = %#v, want the prompt alone", arguments)
	}
}

func TestAnOrdinaryStartIsNotTurnedIntoTheHelper(t *testing.T) {
	// 環境に古い変数が転がっている場合も含め、アプリケーションは通常どおり起動しなければ
	// ならない。このバイナリがパスワードヘルパーになるには、トークンとエンドポイントの
	// 両方が必要である。
	for name, environment := range map[string]askpassEnvironment{
		"nothing set":    {},
		"only the token": {TokenVariable: "one-time-token"},
		"only the URL":   {URLVariable: "http://127.0.0.1:1/askpass"},
		"only the alias": {AliasVariable: "bastion"},
		"an empty token": {TokenVariable: "", URLVariable: "http://127.0.0.1:1/askpass"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := askpassInvocation([]string{"/opt/sshc", "-open=false"}, environment.lookup); ok {
				t.Error("an ordinary start was taken for an askpass invocation")
			}
		})
	}
}
