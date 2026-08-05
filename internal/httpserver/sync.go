package httpserver

import (
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v5"

	"ssh-ui/internal/api"
	"ssh-ui/internal/envelope"
	"ssh-ui/internal/objectstore"
	"ssh-ui/internal/remotesync"
)

// SyncHandlers serves the remote snapshot.
type SyncHandlers struct {
	Service *remotesync.Service
}

func registerSyncRoutes(engine *echo.Echo, handlers SyncHandlers) {
	engine.GET("/api/v1/sync", handlers.Status)
	engine.PUT("/api/v1/sync/settings", handlers.Configure)
	engine.POST("/api/v1/sync/push", handlers.Push)
	engine.POST("/api/v1/sync/pull", handlers.Pull)
}

func (h SyncHandlers) status(c *echo.Context) error {
	endpoint, bucket := h.Service.Target()
	synced, at, origin, files := h.Service.LastSync()
	response := api.SyncStatus{
		Configured: h.Service.Configured(),
		Endpoint:   endpoint,
		Bucket:     bucket,
		Synced:     synced,
		Direction:  api.SyncDirection(h.Service.Direction()),
	}
	if synced {
		response.LastSyncedAt = &at
		response.Origin = &origin
		response.FileCount = &files
	}
	return c.JSON(http.StatusOK, response)
}

func (h SyncHandlers) Status(c *echo.Context) error { return h.status(c) }

// Configure points this run at a bucket.
//
// The credentials live in memory for the life of the process and are never
// written into the workspace. A snapshot that carried the key to its own
// bucket would be a bootstrapping convenience and a much larger blast radius,
// and it would mean anybody who obtained one snapshot could fetch every later
// one.
func (h SyncHandlers) Configure(c *echo.Context) error {
	var request api.SyncSettingsRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	parsed, err := url.Parse(request.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return problem(c, http.StatusBadRequest, "endpoint_must_be_https")
	}
	if !safeBucketName(request.Bucket) {
		return problem(c, http.StatusBadRequest, "unsafe_bucket_name")
	}
	region := "auto"
	if request.Region != nil && *request.Region != "" {
		region = *request.Region
	}
	direction := remotesync.DirectionBoth
	if request.Direction != nil {
		parsed, ok := remotesync.ParseDirection(string(*request.Direction))
		if !ok {
			return problem(c, http.StatusBadRequest, "unknown_sync_direction")
		}
		direction = parsed
	}

	credentials := objectstore.Credentials{
		AccessKeyID:     request.AccessKeyId,
		SecretAccessKey: request.SecretAccessKey,
	}
	config := remotesync.Config{
		Endpoint: request.Endpoint, Bucket: request.Bucket, Region: region, Direction: direction,
	}
	h.Service.Configure(config, credentials, &objectstore.Client{
		Endpoint: config.Endpoint, Bucket: config.Bucket, Region: config.Region, Creds: credentials,
	})
	return h.status(c)
}

func (h SyncHandlers) Push(c *echo.Context) error {
	var request api.PassphraseRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := h.Service.Push(c.Request().Context(), request.Passphrase); err != nil {
		return syncProblem(c, err)
	}
	return h.status(c)
}

// Pull previews by default and applies only when asked.
//
// The response carries paths and never contents: a pull response holding file
// bytes would put a private key in a response body, and the per-file preview
// the user approves is assembled from files this application can already read.
func (h SyncHandlers) Pull(c *echo.Context) error {
	var request api.PullRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	result, err := h.Service.Pull(c.Request().Context(), request.Passphrase)
	if err != nil && !errors.Is(err, remotesync.ErrNothingToApply) {
		return syncProblem(c, err)
	}

	response := api.PullResponse{
		Applied:   false,
		Conflicts: make([]api.SyncConflict, 0, len(result.Conflicts)),
		Written:   make([]string, 0, len(result.Request.Changes)),
		Removed:   make([]string, 0, len(result.Request.Removals)),
	}
	for _, conflict := range result.Conflicts {
		response.Conflicts = append(response.Conflicts, api.SyncConflict{
			Path:         conflict.Path,
			ChangedHere:  conflict.LocalDigest != "" && conflict.LocalDigest != conflict.BaseDigest,
			ChangedThere: conflict.RemoteDigest != conflict.BaseDigest,
		})
	}
	for _, change := range result.Request.Changes {
		response.Written = append(response.Written, h.Service.DisplayPath(change.Path))
	}
	for _, removal := range result.Request.Removals {
		response.Removed = append(response.Removed, h.Service.DisplayPath(removal.Path))
	}
	if result.Origin != "" {
		origin := result.Origin
		response.Origin = &origin
	}

	if request.Apply != nil && *request.Apply {
		if err := h.Service.Apply(result); err != nil {
			return syncProblem(c, err)
		}
		response.Applied = true
	}
	return c.JSON(http.StatusOK, response)
}

// safeBucketName is deliberately narrow. The name becomes a path segment in a
// URL this application signs, so anything that could add a segment or a query
// is refused rather than escaped.
func safeBucketName(name string) bool {
	if name == "" || len(name) > 255 || strings.Contains(name, "/") || strings.Contains(name, "..") {
		return false
	}
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '-', character == '.', character == '_':
		default:
			return false
		}
	}
	return filepath.Base(name) == name
}

func syncProblem(c *echo.Context, err error) error {
	switch {
	case errors.Is(err, remotesync.ErrNotConfigured):
		return problem(c, http.StatusConflict, "sync_not_configured")
	case errors.Is(err, remotesync.ErrRemoteMoved):
		return problem(c, http.StatusConflict, "sync_remote_moved")
	case errors.Is(err, remotesync.ErrNoSnapshot):
		return problem(c, http.StatusNotFound, "sync_no_snapshot")
	case errors.Is(err, remotesync.ErrConflicts):
		return problem(c, http.StatusConflict, "sync_conflicts")
	case errors.Is(err, remotesync.ErrPushRefused):
		return problem(c, http.StatusConflict, "sync_push_refused")
	case errors.Is(err, remotesync.ErrApplyRefused):
		return problem(c, http.StatusConflict, "sync_apply_refused")
	case errors.Is(err, envelope.ErrWrongPassphrase):
		return problem(c, http.StatusForbidden, "wrong_passphrase")
	case errors.Is(err, envelope.ErrWeakPassphrase):
		return problem(c, http.StatusBadRequest, "passphrase_too_short")
	case errors.Is(err, envelope.ErrCostRefused):
		return problem(c, http.StatusConflict, "snapshot_cost_refused")
	case errors.Is(err, envelope.ErrUnsupportedVersion), errors.Is(err, remotesync.ErrUnsupportedVersion):
		return problem(c, http.StatusConflict, "snapshot_too_new")
	case errors.Is(err, remotesync.ErrUnsafePath), errors.Is(err, remotesync.ErrUnsafeMode),
		errors.Is(err, remotesync.ErrManifestMismatch), errors.Is(err, remotesync.ErrNotASnapshot):
		return problem(c, http.StatusConflict, "snapshot_rejected")
	case errors.Is(err, objectstore.ErrRefused), errors.Is(err, objectstore.ErrInsecureEndpoint):
		return problem(c, http.StatusBadGateway, "bucket_refused")
	default:
		return problem(c, http.StatusBadGateway, "sync_failed")
	}
}
