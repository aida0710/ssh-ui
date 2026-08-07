package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/knownhosts"
	"sshc/internal/platform"
	"sshc/internal/session"
	"sshc/internal/storage"
)

// maxDeleteTargets は一度の削除リクエストの上限を定める。
const maxDeleteTargets = 256

// KnownHostsHandlers は known_hosts の検索と保守を公開する。
type KnownHostsHandlers struct {
	Service *knownhosts.Service
	Actions ActionHandlers
}

func registerKnownHostsRoutes(engine *echo.Echo, handlers KnownHostsHandlers) {
	engine.GET("/api/v1/known-hosts", handlers.List)
	engine.POST("/api/v1/known-hosts/delete", handlers.Delete)
	engine.POST("/api/v1/known-hosts/scan", handlers.Scan)
	engine.POST("/api/v1/known-hosts/add", handlers.Add)
}

// addKnownHostsActions はこのサブシステムが持つ確認を登録する。
//
// ファイルへの変更はその時点の内容に紐づくため、確認とリクエ
// ストの間に編集が入るとトークンは無効になる。一方スキャンは
// ディスク上の何も変えず、スキャン対象のホストの方に紐づく。
// 留め金として意味を持つのは、その対象だけだからだ。
func addKnownHostsActions(registry actionRegistry, service *knownhosts.Service) {
	fileEvidence := func(string) (string, error) { return service.Evidence() }
	for _, kind := range []string{session.ActionKnownHostsDelete, session.ActionKnownHostsAdd} {
		registry[kind] = actionKind{evidence: fileEvidence, fail: knownHostsProblem}
	}
	registry[session.ActionKnownHostsScan] = actionKind{
		evidence: func(target string) (string, error) {
			if err := platform.ValidateHostname(target); err != nil {
				return "", err
			}
			return storage.Digest([]byte(target)), nil
		},
		fail: knownHostsProblem,
	}
}

func knownHostsProblem(c *echo.Context, err error) error {
	switch {
	case errors.Is(err, knownhosts.ErrEntryChanged):
		return problem(c, http.StatusConflict, "entry_changed")
	case errors.Is(err, knownhosts.ErrNoSuchEntry):
		return problem(c, http.StatusNotFound, "not_found")
	case errors.Is(err, knownhosts.ErrUnverifiedCandidate):
		return problem(c, http.StatusConflict, "unverified_candidate")
	case errors.Is(err, knownhosts.ErrUnsupportedKeyType):
		return problem(c, http.StatusBadRequest, "unsupported_key_type")
	case errors.Is(err, knownhosts.ErrInvalidKey):
		return problem(c, http.StatusBadRequest, "invalid_key")
	case errors.Is(err, platform.ErrUnsafeHostname):
		return problem(c, http.StatusBadRequest, "unsafe_hostname")
	case errors.Is(err, platform.ErrUnsafePort):
		return problem(c, http.StatusBadRequest, "unsafe_port")
	}
	var conflict *storage.ConflictError
	if errors.As(err, &conflict) {
		return problem(c, http.StatusConflict, "external_change")
	}
	return problem(c, http.StatusInternalServerError, "known_hosts_failed")
}

// List はクエリに合致するエントリを返す。読むだけなので、
// 確認は要らない。
func (h KnownHostsHandlers) List(c *echo.Context) error {
	query := c.Request().URL.Query().Get("query")
	if len(query) > maxAliasLength {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	listing, err := h.Service.Listing(query)
	if err != nil {
		return knownHostsProblem(c, err)
	}

	response := api.KnownHostsResponse{
		Path:    listing.Path,
		Entries: make([]api.KnownHostEntry, 0, len(listing.Lines)),
	}
	for _, line := range listing.Lines {
		response.Entries = append(response.Entries, api.KnownHostEntry{
			Line:        line.Number,
			Digest:      storage.Digest([]byte(line.Raw)),
			Marker:      line.Entry.Marker,
			Hosts:       line.Entry.Hosts,
			Hashed:      line.Entry.Hashed,
			KeyType:     line.Entry.KeyType,
			Fingerprint: line.Entry.Fingerprint,
			Comment:     line.Entry.Comment,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Delete はトランザクションマネージャ経由で確認済みのエントリを削除する。
func (h KnownHostsHandlers) Delete(c *echo.Context) error {
	var request api.KnownHostsDeleteRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if len(request.Entries) == 0 || len(request.Entries) > maxDeleteTargets {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if allowed, response := h.Actions.consume(c, session.ActionKnownHostsDelete, h.Service.Path()); !allowed {
		return response
	}

	targets := make([]knownhosts.Target, 0, len(request.Entries))
	for _, entry := range request.Entries {
		targets = append(targets, knownhosts.Target{Line: entry.Line, Digest: entry.Digest})
	}
	result, err := h.Service.Delete(targets)
	if err != nil {
		return knownHostsProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.KnownHostsChangeResponse{Changed: true, TransactionId: result.ID})
}

// Scan はホストの鍵を ssh-keyscan に尋ねる。候補はすべて未検証である。
func (h KnownHostsHandlers) Scan(c *echo.Context) error {
	var request api.KnownHostsScanRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateHostname(request.Host); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_hostname")
	}
	if err := platform.ValidatePort(request.Port); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_port")
	}
	if allowed, response := h.Actions.consume(c, session.ActionKnownHostsScan, request.Host); !allowed {
		return response
	}

	candidates, err := h.Service.Scan(c.Request().Context(), request.Host, request.Port)
	if err != nil {
		return knownHostsProblem(c, err)
	}
	response := api.KnownHostsScanResponse{
		Notice:     knownhosts.UnverifiedNotice,
		Candidates: make([]api.KnownHostCandidate, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		response.Candidates = append(response.Candidates, api.KnownHostCandidate{
			Host:        candidate.Host,
			Port:        candidate.Port,
			KeyType:     candidate.KeyType,
			Key:         candidate.Key,
			Fingerprint: candidate.Fingerprint,
			// 常に false 以外にはならない。スキャンは身元を証明できない。
			Verified: candidate.Verified,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Add は証明されたか明示的に了承された後、ホスト鍵を 1 つ書き込む。
func (h KnownHostsHandlers) Add(c *echo.Context) error {
	var request api.KnownHostsAddRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateHostname(request.Host); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_hostname")
	}
	if err := platform.ValidatePort(request.Port); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_port")
	}
	if allowed, response := h.Actions.consume(c, session.ActionKnownHostsAdd, request.Host); !allowed {
		return response
	}

	result, err := h.Service.Add(knownhosts.Candidate{
		Host:    request.Host,
		Port:    request.Port,
		KeyType: request.KeyType,
		Key:     request.Key,
	}, request.ExpectedFingerprint, request.Acknowledged)
	if err != nil {
		return knownHostsProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.KnownHostsChangeResponse{Changed: result.ID != "", TransactionId: result.ID})
}
