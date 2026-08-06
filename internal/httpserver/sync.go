package httpserver

import (
	"context"
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
	"ssh-ui/internal/secret"
)

// SyncHandlers serves the remote snapshot.
type SyncHandlers struct {
	Service *remotesync.Service
	// Secrets holds the object store settings, sealed with the master password
	// and kept beside the vault rather than inside it — the vault travels, and
	// the key to the bucket must not be in the bucket. A nil one means the
	// settings are per-run, which is what this did before they were stored.
	Secrets *secret.Service
	// Reach asks whether settings work before they are stored. It is injected
	// because storing settings is this handler's job and reaching a bucket is
	// not, and because no test in this package may touch a network. A nil one
	// means the real check: a forgotten wiring must not become a silent
	// "everything is fine".
	Reach func(ctx context.Context, client *objectstore.Client, key string) error
}

func (h SyncHandlers) reach(ctx context.Context, client *objectstore.Client, key string) error {
	if h.Reach == nil {
		return remotesync.Check(ctx, client, key)
	}
	return h.Reach(ctx, client, key)
}

func registerSyncRoutes(engine *echo.Echo, handlers SyncHandlers) {
	engine.GET("/api/v1/sync", handlers.Status)
	engine.PUT("/api/v1/sync/settings", handlers.Configure)
	engine.POST("/api/v1/sync/push", handlers.Push)
	engine.POST("/api/v1/sync/pull", handlers.Pull)
}

// restore configures the client from the stored settings, so unlocking is all
// it takes for the screen to be filled in and a push to work.
//
// A shut vault is not an error here: the status says so and the form says why
// it is empty. Nothing is asked at startup, and this is the screen asking for
// itself when it needs to.
func (h SyncHandlers) restore() {
	if h.Secrets == nil || !h.Secrets.Unlocked() || h.Service.Configured() {
		return
	}
	settings, err := h.Secrets.SyncSettings()
	if err != nil || settings.Bucket == "" {
		return
	}
	direction, ok := remotesync.ParseDirection(settings.Direction)
	if !ok {
		direction = remotesync.DirectionBoth
	}
	credentials := objectstore.Credentials{
		AccessKeyID: settings.AccessKeyID, SecretAccessKey: settings.SecretAccessKey,
	}
	config := remotesync.Config{
		Endpoint: settings.Endpoint, Bucket: settings.Bucket, Path: settings.Path,
		Region: settings.Region, Direction: direction,
	}
	h.Service.Configure(config, credentials, &objectstore.Client{
		Endpoint: config.Endpoint, Bucket: config.Bucket, Region: config.Region, Creds: credentials,
	})
}

func (h SyncHandlers) status(c *echo.Context) error {
	h.restore()
	endpoint, bucket, path := h.Service.Target()
	synced, at, origin, files := h.Service.LastSync()
	response := api.SyncStatus{
		Configured: h.Service.Configured(),
		Endpoint:   endpoint,
		Bucket:     bucket,
		Path:       &path,
		Synced:     synced,
		Direction:  api.SyncDirection(h.Service.Direction()),
		// Why the form is empty, when it is. Never the access key or the
		// secret: those go one way, into the sealed file.
		Locked: h.Secrets != nil && !h.Secrets.Unlocked(),
	}
	if synced {
		response.LastSyncedAt = &at
		response.Origin = &origin
		response.FileCount = &files
	}
	return c.JSON(http.StatusOK, response)
}

func (h SyncHandlers) Status(c *echo.Context) error { return h.status(c) }

// Configure points this machine at a bucket.
//
// The credentials are sealed with the master password and kept beside the vault
// rather than inside it. The vault travels — Collect names ssh-ui/secrets
// outright — and a snapshot that carried the key to its own bucket would be a
// bootstrapping convenience and a much larger blast radius: anybody who
// obtained one snapshot could fetch every later one.
func (h SyncHandlers) Configure(c *echo.Context) error {
	var request api.SyncSettingsRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	parsed, err := url.Parse(request.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return problem(c, http.StatusBadRequest, "endpoint_must_be_https")
	}
	// The client replaces the whole path with /bucket/key, so a pasted
	// ".../my-bucket" would be dropped without a word and the user would look
	// for their objects somewhere this application never wrote. A bare slash is
	// what a browser adds to a host and means nothing, so it is removed rather
	// than refused — and removing it is also what stops the screen showing
	// "https://host//bucket".
	if strings.Trim(parsed.Path, "/") != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return problem(c, http.StatusBadRequest, "endpoint_must_have_no_path")
	}
	endpoint := strings.TrimRight(request.Endpoint, "/")
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
	path := ""
	if request.Path != nil {
		path = strings.Trim(*request.Path, "/")
	}
	if !safeObjectPath(path) {
		return problem(c, http.StatusBadRequest, "unsafe_object_path")
	}
	config := remotesync.Config{
		Endpoint: endpoint, Bucket: request.Bucket, Path: path, Region: region, Direction: direction,
	}
	// Tried before it is stored. Settings that were never tried are settings
	// whose typo surfaces on the first push, hours later and somewhere else,
	// and this is the one screen where the user can still see what they typed.
	client := &objectstore.Client{
		Endpoint: config.Endpoint, Bucket: config.Bucket, Region: config.Region, Creds: credentials,
	}
	if err := h.reach(c.Request().Context(), client, remotesync.ObjectKeyFor(config)); err != nil {
		return syncProblem(c, err)
	}

	// Stored before it is used, so the answer never claims a configuration that
	// would be gone on the next run.
	if h.Secrets != nil {
		if err := h.Secrets.SetSyncSettings(secret.SyncSettings{
			Endpoint: endpoint, Bucket: request.Bucket, Path: path, Region: region,
			AccessKeyID: request.AccessKeyId, SecretAccessKey: request.SecretAccessKey,
			Direction: string(direction),
		}); err != nil {
			if errors.Is(err, secret.ErrLocked) {
				return problem(c, http.StatusConflict, "vault_locked")
			}
			return problem(c, http.StatusInternalServerError, "vault_failed")
		}
	}
	h.Service.Configure(config, credentials, client)
	return h.status(c)
}

// masterPassword refuses a password that is not this workspace's master one.
//
// The snapshot is sealed with the master password rather than a second one, and
// the field that takes it can therefore be checked. Without this a typo sealed
// an archive nobody could ever open, and said so on the next machine, months
// later.
// It reports whether the request may go on. When it may not it has already
// written the refusal, and the error it hands back is what the caller returns —
// nil, because writing the response is how this application refuses. Returning
// only that error would let the caller carry on and do the thing it just
// refused, over the top of its own answer.
func (h SyncHandlers) masterPassword(c *echo.Context, passphrase string) (bool, error) {
	if h.Secrets == nil {
		return true, nil
	}
	ok, err := h.Secrets.Verify(passphrase)
	switch {
	case errors.Is(err, secret.ErrNoVault):
		// A machine that has never made a vault is a machine doing its first
		// pull. What it typed is the key to the archive; nothing here can check
		// it, and the archive itself will.
		return true, nil
	case err != nil:
		return false, problem(c, http.StatusInternalServerError, "vault_unreadable")
	case !ok:
		return false, problem(c, http.StatusForbidden, "wrong_master_password")
	}
	return true, nil
}

func (h SyncHandlers) Push(c *echo.Context) error {
	h.restore()
	var request api.PassphraseRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if allowed, err := h.masterPassword(c, request.Passphrase); !allowed {
		return err
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
	h.restore()
	var request api.PullRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if allowed, err := h.masterPassword(c, request.Passphrase); !allowed {
		return err
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

// safeObjectPath is as narrow as the bucket name, and for the same reason: the
// path becomes segments in a URL this application signs, so anything that could
// add a segment of its own or escape upwards is refused rather than escaped.
func safeObjectPath(path string) bool {
	if path == "" {
		return true
	}
	if len(path) > 255 || strings.Contains(path, "..") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || !safeBucketName(segment) {
			return false
		}
	}
	return true
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
