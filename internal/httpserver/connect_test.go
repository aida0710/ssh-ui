package httpserver

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/labstack/echo/v5"

	"sshc/internal/handoff"
)

func connectEngine(t *testing.T, handlers ConnectHandlers) *echo.Echo {
	t.Helper()
	engine := echo.New()
	registerConnectRoutes(engine, handlers)
	return engine
}

// secret がなければ、このエンドポイントは何も語らない——alias が
// 未知であることも、パスワードが保存されていることも、いないことも。
func TestConnectRefusesWithoutTheSecretAndSaysNothingElse(t *testing.T) {
	engine := connectEngine(t, ConnectHandlers{Secret: "the secret for this run"})

	for _, presented := range []string{"", "the wrong secret", "the secret for this ru"} {
		recorder := send(t, engine, http.MethodPost, ConnectPath, `{"alias":"bastion"}`,
			map[string]string{handoff.HeaderName: presented})
		if recorder.Code != http.StatusForbidden {
			t.Errorf("with %q = %d, want 403", presented, recorder.Code)
		}
		if recorder.Body.Len() != 0 {
			t.Errorf("with %q the body is %q", presented, recorder.Body.String())
		}
	}
}

// handoff を書けなかったサーバーは、すべてを受け入れるのではなく
// 何も受け入れない。
func TestConnectWithNoSecretConfiguredRefusesEveryone(t *testing.T) {
	engine := connectEngine(t, ConnectHandlers{})
	recorder := send(t, engine, http.MethodPost, ConnectPath, `{"alias":"bastion"}`,
		map[string]string{handoff.HeaderName: ""})
	if recorder.Code != http.StatusForbidden {
		t.Errorf("= %d, want 403", recorder.Code)
	}
}

// vault がない場合の答えはトークンなしの接続であり、それは正常な接続である。
// OpenSSH 自身がパスワードを尋ねる。
func TestConnectAnswersWithoutATokenWhenNothingIsStored(t *testing.T) {
	const secret = "the secret for this run"
	engine := connectEngine(t, ConnectHandlers{
		Secret:     secret,
		AskpassURL: "http://127.0.0.1:1/askpass",
		Warnings:   func(string) []string { return []string{"ProxyCommand runs on connect"} },
	})

	recorder := send(t, engine, http.MethodPost, ConnectPath, `{"alias":"bastion"}`,
		map[string]string{handoff.HeaderName: secret})
	if recorder.Code != http.StatusOK {
		t.Fatalf("= %d: %s", recorder.Code, recorder.Body.String())
	}
	var answer connectResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.AskpassToken != "" {
		t.Errorf("a token was minted with no vault: %+v", answer)
	}
	if len(answer.Warnings) != 1 {
		t.Errorf("the warnings did not travel: %+v", answer)
	}
}

func TestConnectRefusesAnAliasItWouldNotPutOnACommandLine(t *testing.T) {
	const secret = "the secret for this run"
	engine := connectEngine(t, ConnectHandlers{Secret: secret})
	for _, alias := range []string{"", "-oProxyCommand=id", "a b", "a;b"} {
		body := `{"alias":"` + alias + `"}`
		if code := send(t, engine, http.MethodPost, ConnectPath, body,
			map[string]string{handoff.HeaderName: secret}).Code; code != http.StatusBadRequest {
			t.Errorf("alias %q = %d, want 400", alias, code)
		}
	}
}
