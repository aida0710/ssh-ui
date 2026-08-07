package httpserver

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/handoff"
	"sshc/internal/platform"
	"sshc/internal/secret"
	"sshc/internal/session"
)

// ConnectPath は、コマンドラインが接続に必要なものを尋ねる場所である。
//
// これは意図的に /api/ の下に置かれていない。その面はブラウザ向けであり、
// セッション cookie と CSRF ヘッダーと Fetch Metadata で守られている。
// シェルはそのいずれでもなく、そのいずれも持たない。このルートは代わりに、
// 実行中のアプリケーションが state ディレクトリに残した secret で認証する。
// askpass エンドポイントも /api/ の外に置かれているのと同じ理由による。
const ConnectPath = "/cli/connect"

// maxConnectBody はリクエストを制限する。alias は 1 語である。
const maxConnectBody = 4 << 10

// ConnectHandlers は `sshc <alias>` に応答する。
type ConnectHandlers struct {
	// Secret は呼び出し側が提示すべきものである。空であればすべての
	// リクエストを拒否する。handoff を書けなかったサーバーは受け付けてはならない。
	Secret string
	// Passwords は一度限りの askpass トークンを発行する。nil であれば
	// 保存されたパスワードは一切提供されず、それはプロンプトが出る正常な接続である。
	Passwords *secret.Service
	// AskpassURL は、ヘルパーがそのトークンを引き換える場所である。
	AskpassURL string
	// Warnings は、OpenSSH がこの host に対して実行するディレクティブを報告する。
	// 接続の最中に気付くのではなく、事前に伝えられる。
	Warnings func(alias string) []string
	// Sessions はブラウザへの入口を発行し、BaseURL はその入口が導く先である。
	// 両方が nil であれば、このアプリケーションはコマンドラインから開けない。
	// これは session manager を持たないビルドの状態である。
	Sessions *session.Manager
	BaseURL  string
}

type connectRequest struct {
	Alias string `json:"alias"`
}

type connectResponse struct {
	Alias        string   `json:"alias"`
	AskpassToken string   `json:"askpassToken,omitempty"`
	AskpassURL   string   `json:"askpassUrl"`
	Warnings     []string `json:"warnings"`
}

// OpenPath は、コマンドラインがブラウザへの入口を求める場所である。
//
// bootstrap トークンは初回使用時に消費され、別のトークンを出力できるのは新しい
// プロセスだけだった。これは、ユーザーがアプリケーションを起動して URL が印字
// される場合には問題ないが、標準出力がどこにも届かないバックグラウンドエージェント
// では役に立たない。その URL を——何にも守られていない場所にある生きた credential
// を——ログファイルへ書く代わりに、誰かが尋ねたときにここで発行する。
const OpenPath = "/cli/open"

type openResponse struct {
	URL string `json:"url"`
}

func registerConnectRoutes(engine *echo.Echo, handlers ConnectHandlers) {
	engine.POST(ConnectPath, handlers.Connect)
	engine.POST(OpenPath, handlers.Open)
}

// Open は、セッションを確立する URL で応答する。
func (h ConnectHandlers) Open(c *echo.Context) error {
	if !h.authorised(c.Request()) {
		return c.NoContent(http.StatusForbidden)
	}
	if h.Sessions == nil || h.BaseURL == "" {
		return c.NoContent(http.StatusServiceUnavailable)
	}
	bootstrap, err := h.Sessions.Reissue()
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, openResponse{URL: h.BaseURL + "/#bootstrap=" + bootstrap})
}

// authorised は、呼び出し側が handoff を推測ではなく読んだかどうかを報告する。
// あらゆる拒否は外から見て同じ形をしているので、secret を持たない呼び出し側は
// 何も知ることができない。
func (h ConnectHandlers) authorised(request *http.Request) bool {
	presented := request.Header.Get(handoff.HeaderName)
	return h.Secret != "" && len(presented) == len(h.Secret) &&
		subtle.ConstantTimeCompare([]byte(presented), []byte(h.Secret)) == 1
}

// Connect は、1 個の接続が必要とするものだけを返し、それより長生きするものは何も返さない。
//
// あらゆる拒否は外から見て同じ形をしているので、このエンドポイントを
// 使ってどの alias が存在するか、どれにパスワードがあるかを知ることはできない。
// secret を持たない呼び出し側は何も知ることができない。
func (h ConnectHandlers) Connect(c *echo.Context) error {
	request := c.Request()
	if request.Header.Get(echo.HeaderContentType) != "application/json" {
		return c.NoContent(http.StatusUnsupportedMediaType)
	}
	if !h.authorised(request) {
		return c.NoContent(http.StatusForbidden)
	}

	var decoded connectRequest
	if err := json.NewDecoder(io.LimitReader(request.Body, maxConnectBody)).Decode(&decoded); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	if err := platform.ValidateAlias(decoded.Alias); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}

	answer := connectResponse{Alias: decoded.Alias, AskpassURL: h.AskpassURL, Warnings: []string{}}
	if h.Warnings != nil {
		if warnings := h.Warnings(decoded.Alias); len(warnings) > 0 {
			answer.Warnings = warnings
		}
	}
	// トークンが存在するのは、それと引き換えるものがある場合だけである。
	// それ以外——閉じた vault、保存されたパスワードなし、エンドポイントなし——は
	// すべて OpenSSH 自身がパスワードを尋ねる接続であり、それは正常な接続である。
	if h.Passwords != nil && h.AskpassURL != "" {
		if token, err := h.Passwords.IssueToken(decoded.Alias); err == nil {
			answer.AskpassToken = token
		}
	}
	return c.JSON(http.StatusOK, answer)
}
