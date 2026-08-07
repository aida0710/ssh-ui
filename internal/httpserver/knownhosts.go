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

// maxDeleteTargets bounds one deletion request.
const maxDeleteTargets = 256

// KnownHostsHandlers exposes known_hosts search and maintenance.
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

// addKnownHostsActions registers the confirmations this subsystem owns.
//
// A change to the file is bound to the file's current contents, so an edit
// between the confirmation and the request invalidates the token. A scan is
// bound to the host being scanned instead, because it changes nothing on disk
// and its target is the only thing worth pinning.
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

// List returns the entries matching an optional query. It reads only, so it
// needs no confirmation.
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

// Delete removes the confirmed entries through the transaction manager.
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

// Scan asks ssh-keyscan for a host's keys. Every candidate is unverified.
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
			// Never anything but false: a scan cannot establish identity.
			Verified: candidate.Verified,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Add writes one host key after it was proven or explicitly acknowledged.
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
