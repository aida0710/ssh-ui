package httpserver

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/session"
)

const (
	SessionCookie     = "sshc_session"
	CSRFHeader        = "X-SSHC-CSRF"
	SessionContextKey = "sshc-session"

	contentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; require-trusted-types-for 'script'"

	// spaFallbackRoute は single-page application を配信するパターンである。
	// これにしかマッチしなかったリクエストは、どの API ルートにもマッチしなかったことになる。
	spaFallbackRoute = "/*"

	// MaxRequestBodyCeiling は、あらゆる /api/ リクエストの body を読む際の
	// 絶対的な上限である。各ハンドラは自前のより小さな制限を課すが、これが存在するのは、
	// 後で追加されたルートが忘れて無制限の body を読めないようにするためだ。
	MaxRequestBodyCeiling = 2 << 20
)

type Security struct {
	ExpectedHost   string
	ExpectedOrigin string
	Sessions       *session.Manager
	// Unlocked はマスターパスワードが与えられたかどうかを報告する。
	// vault そのものではなく関数にしてあるのは、このファイルが secret
	// について何も知らないままでいるためであり、nil は施錠を意味する。
	// 配線し忘れが、施錠された application と開いた application の違いになってはならない。
	Unlocked func() bool
}

// gateExempt は vault が施錠中でも応答するルートを名指しする。
//
// それらはゲート自身と、そもそも解錠すべき何かが生じる前に動く
// 必要のある 2 つのものである。それ以外はすべてマスターパスワードの
// 向こう側にあり、それが「application が施錠されている」の意味だ
// ——「各画面が必要なときに尋ねる」ではない。以前はそうだった。
func gateExempt(method, path string) bool {
	switch path {
	case "/api/v1/health":
		return method == http.MethodGet
	case "/api/v1/session/bootstrap", "/api/v1/session/renew":
		return method == http.MethodPost
	case "/api/v1/passwords":
		return method == http.MethodGet
	case "/api/v1/passwords/initialise", "/api/v1/passwords/unlock":
		return method == http.MethodPost
	}
	return false
}

func (s Security) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		request := c.Request()
		isAPI := strings.HasPrefix(request.URL.Path, "/api/")
		setSecurityHeaders(c.Response().Header(), isAPI)

		if request.Host != s.ExpectedHost {
			return problem(c, http.StatusForbidden, "invalid_host")
		}

		if !isAPI {
			return next(c)
		}

		// Fetch Metadata はすべての API リクエストでチェックされ、状態を
		// 変えるものだけではない。cross-site の GET はすでに SameSite=Strict
		// によって cookie を奪われているが、design §8.1 はヘッダを完全一致で
		// 検証するよう求めている。SameSite の扱いを誤るブラウザが、他のサイト
		// とこの API の間に立つ唯一のものになってはならないからだ。
		if request.Header.Get("Sec-Fetch-Site") != "same-origin" {
			return problem(c, http.StatusForbidden, "cross_site_request")
		}
		// この上限はリクエストへの制限であり、ハンドラがたまたま読む量への
		// 制限にとどまらない。上限を超えると宣言された長さは、ハンドラが
		// 実行される前に拒否される。だから body を無視するルート——現状の
		// /diagnostics/config と /keys/:keyId/trash、そしてパスだけから
		// 入力を得る後日追加されるどんなルートも——無制限の body を渡されずに済む。
		if request.ContentLength > MaxRequestBodyCeiling {
			return problem(c, http.StatusRequestEntityTooLarge, "request_body_too_large")
		}
		// chunked リクエストは長さを宣言しないため、読み取るハンドラのために
		// reader 自体にも上限を設けておく必要がある。
		if request.Body != nil {
			request.Body = http.MaxBytesReader(c.Response(), request.Body, MaxRequestBodyCeiling)
		}

		isBootstrap := request.Method == http.MethodPost && request.URL.Path == "/api/v1/session/bootstrap"
		// CSRF トークンの更新は、トークンを提示できない。reload には cookie
		// だけがあって他は何もないからだ。除外されているのはこの確認だけで、
		// 以下のセッションは依然として必須である。これは bootstrap の除外が
		// そうではないのとは違う。
		isRenew := request.Method == http.MethodPost && request.URL.Path == "/api/v1/session/renew"
		isStateChanging := request.Method != http.MethodGet && request.Method != http.MethodHead
		if (isStateChanging || isBootstrap) && request.Header.Get(echo.HeaderOrigin) != s.ExpectedOrigin {
			return problem(c, http.StatusForbidden, "cross_site_request")
		}
		if isBootstrap {
			return next(c)
		}

		cookie, err := request.Cookie(SessionCookie)
		if err != nil {
			return problem(c, http.StatusUnauthorized, "session_required")
		}
		if s.Sessions == nil {
			return problem(c, http.StatusUnauthorized, "invalid_session")
		}
		if !s.Sessions.Authenticate(cookie.Value) {
			return problem(c, http.StatusUnauthorized, "invalid_session")
		}
		// トークンは書き込みだけでなく読み取りにも必要である。cookie は
		// ポートに紐づかず site もそうなので、127.0.0.1 上の別のサーバーが
		// これを受け取ってしまう——SameSite は scheme と registrable domain
		// を比較し、IP はそれ自体が site のすべてだからだ。トークンは
		// ページのメモリに存在してそこへは決して渡らないため、それを要求
		// することで漏洩した cookie 単体を無価値にしている。
		//
		// 更新が除外されているのは、トークンを失ったページがそれを得る
		// 手段だからだ。reload には cookie だけがあり他は何もない。
		claimed := c.Path() != "" && c.Path() != spaFallbackRoute
		// Health はトークンからもゲートからも除外されている。これが運ぶ
		// のはバージョン文字列だけであり、ページが落ち着く前になされる
		// 唯一のリクエストでもあるため、ここでトークンを要求すれば、得る
		// ものなく bootstrap の順序の罠にはまるだけになる。
		isHealth := request.Method == http.MethodGet && request.URL.Path == "/api/v1/health"
		if (isStateChanging || claimed) && !isRenew && !isHealth &&
			!s.Sessions.VerifyCSRF(cookie.Value, request.Header.Get(CSRFHeader)) {
			return problem(c, http.StatusForbidden, "invalid_csrf")
		}

		// どの API ルートも主張しないパスは、ゲートではなく router が応答
		// する。「そんなルートはない」と「vault が施錠中である」は別の
		// 事実であり、両方に後者で答えれば、URL の typo が、ユーザーが
		// 解錠すれば抜け出せる状態であるかのように見えてしまう。Middleware
		// はルート検索の後に走るため、空のパターンは何もマッチしなかった
		// ことを意味し、SPA の catch-all は API 内で何もマッチしなかった
		// ことを意味する——/api/ 配下のすべてに自ら 404 を返すのだ。
		if claimed && !gateExempt(request.Method, request.URL.Path) && (s.Unlocked == nil || !s.Unlocked()) {
			return problem(c, http.StatusConflict, "vault_locked")
		}

		c.Set(SessionContextKey, cookie.Value)
		return next(c)
	}
}

func setSecurityHeaders(header http.Header, apiResponse bool) {
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	if apiResponse {
		header.Set("Cache-Control", "no-store")
	}
}

func problem(c *echo.Context, status int, code string) error {
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, api.Problem{Code: code, Message: "request rejected"})
}

// problemDetail は上限のある説明付きで拒否を返す。
//
// 呼び出し元は、固定文字列か、platform 層がすでに無害化した
// メッセージのどちらかを渡さなければならない。detail に鍵材料、
// パスフレーズ、セッションやアクショントークン、絶対パスを含めてはならない。
func problemDetail(c *echo.Context, status int, code, detail string) error {
	const detailLimit = 512
	if len(detail) > detailLimit {
		detail = detail[:detailLimit]
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, api.Problem{Code: code, Message: "request rejected", Detail: &detail})
}
