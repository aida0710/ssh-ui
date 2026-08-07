package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/api"
	"ssh-ui/internal/selfupdate"
)

// UpdateHandlers serve the version and the update.
//
// This is the only part of the application that contacts a host other than
// itself, and it does so only when asked. The browser never does: the request
// goes out from here, so the page's connect-src stays 'self' and the end-to-end
// test that no foreign origin is contacted stays true of the interface.
type UpdateHandlers struct {
	Current string
	// Checker is nil when this build has no release to compare itself with, in
	// which case the version is reported and nothing is offered.
	Checker *selfupdate.Checker
	// Path is the binary this would replace. Empty means it cannot be resolved,
	// and then nothing is offered either.
	Path string
	// Restarted reports whether the file on disk has already been replaced, so
	// the answer can say that what is running is not what is installed.
	restarted bool
}

func registerUpdateRoutes(engine *echo.Echo, handlers *UpdateHandlers) {
	engine.GET("/api/v1/update", handlers.Check)
	engine.POST("/api/v1/update", handlers.Apply)
}

func (h *UpdateHandlers) answer(c *echo.Context, latest selfupdate.Release, available bool) error {
	status := api.UpdateStatus{
		Current:         h.Current,
		Available:       available,
		Updatable:       h.Checker != nil && h.Path != "",
		RestartRequired: h.restarted,
	}
	if latest.Version != "" {
		version, page := latest.Version, latest.PageURL
		status.Latest, status.PageUrl = &version, &page
	}
	if h.Path != "" {
		path := h.Path
		status.Path = &path
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

// Apply replaces the binary on disk.
//
// What is running goes on running: replacing a file does not replace what is
// already in memory, so the answer says a restart is needed rather than
// pretending the update took effect.
func (h *UpdateHandlers) Apply(c *echo.Context) error {
	if h.Checker == nil || h.Path == "" {
		return problem(c, http.StatusConflict, "update_unsupported")
	}
	latest, err := h.Checker.Latest(c.Request().Context())
	switch {
	case errors.Is(err, selfupdate.ErrNoRelease), errors.Is(err, selfupdate.ErrAssetMissing):
		return problem(c, http.StatusConflict, "update_unavailable")
	case err != nil:
		return problem(c, http.StatusBadGateway, "update_check_failed")
	}
	if !selfupdate.Newer(h.Current, latest.Version) {
		return h.answer(c, latest, false)
	}

	switch err := h.Checker.Apply(c.Request().Context(), latest, h.Path); {
	case errors.Is(err, selfupdate.ErrNotWritable):
		return problem(c, http.StatusConflict, "update_not_writable")
	case errors.Is(err, selfupdate.ErrChecksumMismatch):
		return problem(c, http.StatusBadGateway, "update_checksum_mismatch")
	case err != nil:
		return problem(c, http.StatusBadGateway, "update_failed")
	}
	h.restarted = true
	return h.answer(c, latest, false)
}
