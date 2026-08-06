package httpserver

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/api"
)

// LoginItemController turns "start at login" on and off.
//
// It is an interface rather than the macOS type so this package goes on
// knowing nothing about launchd, and so no test registers an agent.
type LoginItemController interface {
	Enabled() bool
	Enable(ctx context.Context, program string) error
	Disable(ctx context.Context) error
}

// LoginItemHandlers serve the setting.
type LoginItemHandlers struct {
	// Controller is nil on a platform this is not built for, and on a build
	// that could not resolve its own path. Either way the setting reports
	// itself unsupported rather than pretending to work.
	Controller LoginItemController
	// Program is the absolute path launchd would be told to run.
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

// Set starts or stops the agent.
//
// Off is the default and stays the default: nothing here runs unless the user
// asked for it in this request.
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
