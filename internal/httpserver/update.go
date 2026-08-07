package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/selfupdate"
)

// UpdateHandlers はバージョンと、新しいものが公開されているかを報告する。
//
// これは application の中で唯一、自分以外のホストと通信する部分
// であり、それも求められたときだけ行う。ブラウザは決して行わない。
// リクエストはここから出て行くため、ページの connect-src は 'self' のままであり、
// 外部の origin に接続しないという end-to-end テストも interface について真であり続ける。
//
// 何も fetch せず、何も置き換えない。動作中のバイナリをネットワーク
// から置き換える機能はかつてここにあったが、なくなった。それを
// 守っていた署名は release workflow が読める鍵を必要としており、
// その鍵はリポジトリを制御できる者なら誰でも読めるものだった。
// つまり防御と攻撃が同じ鍵を持っていたのだ。「新しいものがある、
// ここで詳細が読める」と伝えることで、使い道は残し危険は手放した。
type UpdateHandlers struct {
	Current string
	// Checker は、このビルドが自身と比較すべきものを持たない場合に
	// nil になる。その場合バージョンだけが報告され、他は何も報告されない。
	Checker *selfupdate.Checker
}

func registerUpdateRoutes(engine *echo.Echo, handlers *UpdateHandlers) {
	engine.GET("/api/v1/update", handlers.Check)
}

func (h *UpdateHandlers) answer(c *echo.Context, latest selfupdate.Release, available bool) error {
	status := api.UpdateStatus{Current: h.Current, Available: available}
	if latest.Version != "" {
		version, page := latest.Version, latest.PageURL
		status.Latest, status.PageUrl = &version, &page
	}
	return c.JSON(http.StatusOK, status)
}

// Check は最新のリリースが何かを尋ねる。
func (h *UpdateHandlers) Check(c *echo.Context) error {
	if h.Checker == nil {
		return h.answer(c, selfupdate.Release{}, false)
	}
	latest, err := h.Checker.Latest(c.Request().Context())
	switch {
	case errors.Is(err, selfupdate.ErrNoRelease):
		return h.answer(c, selfupdate.Release{}, false)
	case err != nil:
		return problem(c, http.StatusBadGateway, "update_check_failed")
	}
	return h.answer(c, latest, selfupdate.Newer(h.Current, latest.Version))
}
