package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/selfupdate"
)

// UpdateHandlers report the version and whether a newer one is published.
//
// This is the only part of the application that contacts a host other than
// itself, and it does so only when asked. The browser never does: the request
// goes out from here, so the page's connect-src stays 'self' and the end-to-end
// test that no foreign origin is contacted stays true of the interface.
//
// It fetches nothing and replaces nothing. Replacing the running binary from
// the network was here and is gone: the signature that guarded it needed a key
// the release workflow could read, which is a key anybody who controls the
// repository can read, so the defence and the attack had the same key. Saying
// "there is a newer one, here is where to read about it" keeps the use and
// drops the risk.
type UpdateHandlers struct {
	Current string
	// Checker is nil when this build has nothing to compare itself with, in
	// which case the version is reported and nothing else is.
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

// Check asks what the newest release is.
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
