package httpserver

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
)

// LoginItemController は「ログイン時に起動」の on/off を切り替える。
//
// macOS の型ではなく interface にしてあるのは、このパッケージが
// launchd について何も知らないままでよく、テストも agent を登録しないで済むためだ。
type LoginItemController interface {
	Enabled() bool
	Enable(ctx context.Context, program string) error
	Disable(ctx context.Context) error
}

// LoginItemHandlers はこの設定を提供する。
type LoginItemHandlers struct {
	// Controller は、対応していないプラットフォーム向けのビルドや、
	// 自身のパスを解決できなかったビルドでは nil になる。どちらの場合も
	// 設定は動くふりをせず、非対応であると報告する。
	Controller LoginItemController
	// Program は launchd に実行させる絶対パスである。
	Program string
}

func registerLoginItemRoutes(engine *echo.Echo, handlers LoginItemHandlers) {
	engine.GET("/api/v1/login-item", handlers.Status)
	engine.PUT("/api/v1/login-item", handlers.Set)
}

func (h LoginItemHandlers) supported() bool {
	return h.Controller != nil && h.Program != ""
}

func (h LoginItemHandlers) answer(c *echo.Context) error {
	enabled := false
	if h.supported() {
		enabled = h.Controller.Enabled()
	}
	return c.JSON(http.StatusOK, api.LoginItem{Enabled: enabled, Supported: h.supported()})
}

func (h LoginItemHandlers) Status(c *echo.Context) error { return h.answer(c) }

// Set は agent を起動または停止する。
//
// Off が既定値であり既定値のままである。ユーザーがこのリクエストで
// 求めない限り、ここでは何も実行されない。
func (h LoginItemHandlers) Set(c *echo.Context) error {
	var request api.LoginItem
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if !h.supported() {
		return problem(c, http.StatusConflict, "login_item_unsupported")
	}
	var err error
	if request.Enabled {
		err = h.Controller.Enable(c.Request().Context(), h.Program)
	} else {
		err = h.Controller.Disable(c.Request().Context())
	}
	if err != nil {
		return problem(c, http.StatusConflict, "login_item_failed")
	}
	return h.answer(c)
}
