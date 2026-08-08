package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/application"
	"sshc/internal/keys"
	"sshc/internal/platform"
	"sshc/internal/secret"
	"sshc/internal/session"
	"sshc/internal/storage"
)

// ActionHeader は、reveal と permanent delete がセッション cookie と
// CSRF ヘッダーに加えて必要とする一度限りのトークンを運ぶ。
const ActionHeader = "X-SSHC-Action"

// maxKeyRequestBody は鍵 vault のリクエストボディを制限する。
const maxKeyRequestBody = 64 << 10

var errBodyTooLarge = errors.New("request body is larger than the supported maximum")

// confirmationSubjects は、session パッケージが共有する action の語彙を
// このサブシステム独自のものへ対応付ける。通信上の値を session パッケージが
// 所有するのは、操作を確認するすべてのサブシステムが同じ表を参照するからである。
var confirmationSubjects = map[string]keys.ConfirmationSubject{
	session.ActionRevealPrivateKey: keys.ConfirmRevealKey,
	session.ActionPurgeTrashEntry:  keys.ConfirmPurgeEntry,
}

// KeyService は、HTTP 層が必要とする鍵 vault の一部分である。
// ハンドラのテストはこれを stub に差し替えるので、ハンドラのテストが
// filesystem や agent、子プロセスに触れることはない。
type KeyService interface {
	Inventory() (*keys.Inventory, error)
	ConfirmationEvidence(subject keys.ConfirmationSubject, target string) (string, error)
	AgentIdentities(ctx context.Context) ([]platform.AgentIdentity, bool)
	Algorithms(ctx context.Context) keys.Catalogue
	Generate(request keys.GenerateRequest) (keys.GenerateResult, error)
	HardwareCommand(algorithm keys.Algorithm, fileName, group, comment string) ([]string, error)
	ChangePassphrase(change keys.PassphraseChange) (keys.PassphraseResult, error)
	Reveal(keyID string) (keys.RevealResult, error)
	PublicKey(keyID string) (keys.PublicKeyResult, error)
	Register(ctx context.Context, request keys.RegisterRequest) (keys.RegisterResult, error)
	Deregister(ctx context.Context, keyID string) error
	Trash(keyID string) (keys.TrashResult, error)
	ListTrash() ([]keys.TrashEntry, error)
	Restore(entryID string) (keys.RestoreResult, error)
	Purge(entryID string) (keys.PurgeResult, error)
}

type KeyHandlers struct {
	Keys KeyService
	// Config は鍵を relocate する。relocation は設定ファイルを書き換えるので、
	// configuration サービスのトランザクションマネージャを通じてコミットされる。
	// これは何かが反映される前に再パースと再解決を行う——鍵 vault 自身の
	// マネージャには、意図的にそのような validator がない。
	Config   *application.Service
	Secrets  *secret.Service
	Sessions *session.Manager
	// Actions は確認を発行し、消費する。それを発行するエンドポイントは
	// 他のすべてのサブシステムと共有されるので、どこか別の場所で一度だけ登録される。
	Actions ActionHandlers
}

func registerKeyRoutes(engine *echo.Echo, handlers KeyHandlers) {
	engine.GET("/api/v1/keys", handlers.List)
	engine.POST("/api/v1/keys", handlers.Generate)
	engine.GET("/api/v1/keys/algorithms", handlers.Algorithms)
	engine.POST("/api/v1/keys/hardware-command", handlers.HardwareCommand)
	engine.POST("/api/v1/keys/:keyId/passphrase", handlers.ChangePassphrase)
	engine.POST("/api/v1/keys/:keyId/reveal", handlers.Reveal)
	engine.GET("/api/v1/keys/:keyId/public", handlers.PublicKey)
	engine.POST("/api/v1/keys/:keyId/location", handlers.Relocate)
	engine.POST("/api/v1/keys/:keyId/agent", handlers.Register)
	engine.DELETE("/api/v1/keys/:keyId/agent", handlers.Deregister)
	engine.POST("/api/v1/keys/:keyId/trash", handlers.Trash)
	engine.GET("/api/v1/trash", handlers.ListTrash)
	engine.POST("/api/v1/trash/:entryId/restore", handlers.Restore)
	engine.DELETE("/api/v1/trash/:entryId", handlers.Purge)
}

// decodeBody は、上限付きのリクエストボディを読み取り、生のバイト列を上書きする。
//
// JSON からデコードされたパスフレーズは Go の string になる。これは
// immutable で消去できない——消去できるのは生のバッファだけである。
// この限界は保証として示すのではなく、ここに明記されている。
func decodeBody(c *echo.Context, target any) error {
	body := c.Request().Body
	if body == nil {
		return errBodyTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxKeyRequestBody+1))
	if err != nil {
		return err
	}
	defer wipeBuffer(raw)
	if len(raw) > maxKeyRequestBody {
		return errBodyTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errBodyTooLarge
	}
	return nil
}

func wipeBuffer(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}

func (h KeyHandlers) sessionID(c *echo.Context) string {
	value, _ := c.Get(SessionContextKey).(string)
	return value
}

// consumeAction は、この操作が必要とする一度限りのトークンを消費する。
//
// evidence はリクエストから受け取るのではなく再計算される。そのため
// 確認は、ダイアログが実際に表示した状態だけを認可する。
// 真偽値は呼び出し側が続行してよいかを報告し、
// false のときはすでにレスポンスが書き込まれている。
func (h KeyHandlers) consumeAction(c *echo.Context, kind, target string) (bool, error) {
	return h.Actions.consume(c, kind, target)
}

func (h KeyHandlers) List(c *echo.Context) error {
	inventory, err := h.Keys.Inventory()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inventory_failed")
	}
	identities, available := h.Keys.AgentIdentities(c.Request().Context())
	return c.JSON(http.StatusOK, inventoryResponse(inventory, identities, available))
}

func (h KeyHandlers) Algorithms(c *echo.Context) error {
	catalogue := h.Keys.Algorithms(c.Request().Context())
	response := api.KeyAlgorithmsResponse{
		Variants:   make([]api.KeyVariant, 0, len(catalogue.Variants)),
		Source:     catalogue.Source,
		Diagnostic: catalogue.Diagnostic,
	}
	for _, variant := range catalogue.Variants {
		response.Variants = append(response.Variants, api.KeyVariant{
			Algorithm: string(variant.Algorithm),
			Bits:      variant.Bits,
			Label:     variant.Label,
			InProcess: variant.InProcess,
			Reason:    variant.Reason,
		})
	}
	return c.JSON(http.StatusOK, response)
}

func (h KeyHandlers) Generate(c *echo.Context) error {
	var body api.GenerateKeyRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	result, err := h.Keys.Generate(keys.GenerateRequest{
		Algorithm:   keys.Algorithm(body.Algorithm),
		Bits:        optionalInt(body.Bits),
		FileName:    body.FileName,
		Group:       optionalString(body.Group),
		Comment:     body.Comment,
		Passphrase:  []byte(body.Passphrase),
		Unencrypted: body.Unencrypted,
	})
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusCreated, api.GenerateKeyResponse{
		Id:                 result.ID,
		RelativePath:       result.RelativePath,
		PublicRelativePath: result.PublicRelativePath,
		Fingerprint:        result.Fingerprint,
		KeyType:            result.KeyType,
		Bits:               result.Bits,
		Encrypted:          result.Encrypted,
		TransactionId:      result.TransactionID,
	})
}

func (h KeyHandlers) HardwareCommand(c *echo.Context) error {
	var body api.HardwareCommandRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	command, err := h.Keys.HardwareCommand(keys.Algorithm(body.Algorithm), body.FileName, optionalString(body.Group), body.Comment)
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.HardwareCommandResponse{
		Algorithm: body.Algorithm,
		Command:   command,
		Note:      "run_in_terminal",
	})
}

func (h KeyHandlers) ChangePassphrase(c *echo.Context) error {
	var body api.ChangePassphraseRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	result, err := h.Keys.ChangePassphrase(keys.PassphraseChange{
		KeyID:       c.Param("keyId"),
		Current:     []byte(body.CurrentPassphrase),
		New:         []byte(body.NewPassphrase),
		Unencrypted: body.Unencrypted,
	})
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.ChangePassphraseResponse{
		Id:            result.ID,
		RelativePath:  result.RelativePath,
		Encrypted:     result.Encrypted,
		Notes:         nonNilStrings(result.Notes),
		TransactionId: result.TransactionID,
	})
}

func (h KeyHandlers) Reveal(c *echo.Context) error {
	keyID := c.Param("keyId")
	if allowed, response := h.consumeAction(c, session.ActionRevealPrivateKey, keyID); !allowed {
		return response
	}
	result, err := h.Keys.Reveal(keyID)
	if err != nil {
		return keyProblem(c, err)
	}
	defer keys.Wipe(result.Contents)
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, api.RevealPrivateKeyResponse{
		Id:            result.ID,
		RelativePath:  result.RelativePath,
		PrivateKey:    string(result.Contents),
		Encrypted:     result.Encrypted,
		Fingerprint:   result.Fingerprint,
		TransactionId: result.TransactionID,
	})
}

// PublicKey は、1 個の公開鍵または証明書のテキストで応答する。
//
// Reveal と異なり、これは確認を消費せず、監査記録も書かない。
// サービスは公開鍵または証明書以外のものをすべて拒否するので、
// このルートが秘密鍵の材料を返すことはなく、記録すべきものも何もない。
func (h KeyHandlers) PublicKey(c *echo.Context) error {
	result, err := h.Keys.PublicKey(c.Param("keyId"))
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.PublicKeyResponse{
		Id:           result.ID,
		RelativePath: result.RelativePath,
		PublicKey:    result.Contents,
		Fingerprint:  result.Fingerprint,
		Comment:      result.Comment,
	})
}

// Relocate は、relocation が移動し書き換えたものか、
// それを阻んだものかで応答する。
//
// 阻まれた relocation は、成功時と同じボディを運ぶ 409 である。
// これにより、画面は変更点を列挙するはずだった場所に理由を列挙できる。
// その場合は何も書き込まれていない。blockers は transaction を
// 組み立てる前に計算される。
func (h KeyHandlers) Relocate(c *echo.Context) error {
	var body api.RelocateKeyRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	inventory, err := h.Keys.Inventory()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inventory_failed")
	}
	result, err := h.Config.RelocateKey(inventory, application.KeyRelocateRequest{
		KeyID:   c.Param("keyId"),
		NewName: body.NewName,
		Group:   body.Group,
	})
	response := relocateKeyResponse(result)
	if errors.Is(err, application.ErrKeyRelocateBlocked) {
		return c.JSON(http.StatusConflict, response)
	}
	if err != nil {
		return keyProblem(c, err)
	}
	if h.Secrets != nil {
		if err := h.Secrets.RelocateKeyPassphrases(keyRelocationMap(result.Files)); err != nil {
			return serviceProblem(c, err)
		}
	}
	return c.JSON(http.StatusOK, response)
}

func keyRelocationMap(files []application.RelocatedKeyFile) map[string]string {
	relocations := make(map[string]string, len(files))
	for _, file := range files {
		relocations[file.From] = file.To
	}
	return relocations
}

func relocateKeyResponse(result application.KeyRelocateResult) api.RelocateKeyResponse {
	response := api.RelocateKeyResponse{
		Id:            result.ID,
		RelativePath:  result.RelativePath,
		Group:         result.Group,
		Files:         make([]api.RelocatedKeyFile, 0, len(result.Files)),
		References:    make([]api.RewrittenKeyReference, 0, len(result.References)),
		Skipped:       nonNilStrings(result.Skipped),
		Notes:         nonNilStrings(result.Notes),
		Blockers:      nonNilStrings(result.Blockers),
		TransactionId: result.TransactionID,
	}
	for _, file := range result.Files {
		response.Files = append(response.Files, api.RelocatedKeyFile{From: file.From, To: file.To})
	}
	for _, reference := range result.References {
		response.References = append(response.References, api.RewrittenKeyReference{
			Directive:  reference.Directive,
			ConfigPath: reference.ConfigPath,
			Line:       reference.Line,
			From:       reference.From,
			To:         reference.To,
		})
	}
	return response
}

// Deregister は、1 個の鍵を agent から取り除く。
//
// 確認トークンは不要である。これは何も破壊せず、ユーザーに課す最悪の
// コストはパスフレーズを再度尋ねられることだけである。応答は、その後
// agent が保持しているものを運ぶので、画面は推測ではなく結果を示す。
func (h KeyHandlers) Deregister(c *echo.Context) error {
	keyID := c.Param("keyId")
	if err := h.Keys.Deregister(c.Request().Context(), keyID); err != nil {
		return keyProblem(c, err)
	}
	identities, available := h.Keys.AgentIdentities(c.Request().Context())
	described := make([]api.AgentIdentity, 0, len(identities))
	for _, identity := range identities {
		described = append(described, api.AgentIdentity{
			Bits: identity.Bits, Fingerprint: identity.Fingerprint,
			Comment: identity.Comment, Algorithm: identity.Algorithm,
		})
	}
	return c.JSON(http.StatusOK, api.AgentIdentitiesResponse{
		Id: keyID, AgentAvailable: available, Identities: described,
	})
}

func (h KeyHandlers) Register(c *echo.Context) error {
	var body api.RegisterKeyRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	result, err := h.Keys.Register(c.Request().Context(), keys.RegisterRequest{
		KeyID:           c.Param("keyId"),
		Passphrase:      []byte(body.Passphrase),
		LifetimeSeconds: body.LifetimeSeconds,
		StoreInKeychain: body.StoreInKeychain,
	})
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.RegisterKeyResponse{
		Id:               result.ID,
		RelativePath:     result.RelativePath,
		Fingerprint:      result.Fingerprint,
		LifetimeSeconds:  result.LifetimeSeconds,
		StoredInKeychain: result.StoredInKeychain,
		Identities:       agentIdentities(result.Identities),
	})
}

func (h KeyHandlers) Trash(c *echo.Context) error {
	result, err := h.Keys.Trash(c.Param("keyId"))
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.TrashKeyResponse{
		EntryId:       result.EntryID,
		Files:         trashFiles(result.Files),
		Skipped:       nonNilStrings(result.Skipped),
		TransactionId: result.TransactionID,
	})
}

func (h KeyHandlers) ListTrash(c *echo.Context) error {
	entries, err := h.Keys.ListTrash()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "trash_unreadable")
	}
	response := api.TrashListResponse{
		Entries:       make([]api.TrashEntrySummary, 0, len(entries)),
		RetentionDays: keys.TrashRetentionDays,
	}
	for _, entry := range entries {
		response.Entries = append(response.Entries, api.TrashEntrySummary{
			Id:         entry.ID,
			DeletedAt:  entry.DeletedAt.UTC().Format(time.RFC3339),
			AgeDays:    entry.AgeDays,
			Stale:      entry.Stale,
			Files:      trashFiles(entry.Files),
			Restorable: entry.Restorable,
			Blockers:   nonNilStrings(entry.Blockers),
		})
	}
	return c.JSON(http.StatusOK, response)
}

func (h KeyHandlers) Restore(c *echo.Context) error {
	result, err := h.Keys.Restore(c.Param("entryId"))
	response := api.RestoreTrashResponse{
		EntryId:       result.EntryID,
		Restored:      nonNilStrings(result.Restored),
		Blockers:      nonNilStrings(result.Blockers),
		TransactionId: result.TransactionID,
	}
	if errors.Is(err, keys.ErrRestoreBlocked) {
		return c.JSON(http.StatusConflict, response)
	}
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, response)
}

func (h KeyHandlers) Purge(c *echo.Context) error {
	entryID := c.Param("entryId")
	if allowed, response := h.consumeAction(c, session.ActionPurgeTrashEntry, entryID); !allowed {
		return response
	}
	result, err := h.Keys.Purge(entryID)
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.PurgeTrashResponse{
		EntryId:       result.EntryID,
		Removed:       nonNilStrings(result.Removed),
		TransactionId: result.TransactionID,
	})
}

// keyProblem は、use case のエラーを、設計のエラー分類が求める
// status と安定した code に対応付ける。メッセージが secret を運ぶことは決してない。
func keyProblem(c *echo.Context, err error) error {
	switch {
	case errors.Is(err, keys.ErrUnknownKey), errors.Is(err, keys.ErrUnknownTrashEntry):
		return problem(c, http.StatusNotFound, "not_found")
	case errors.Is(err, keys.ErrUnknownConfirmation):
		return problem(c, http.StatusBadRequest, "unknown_action_kind")
	case errors.Is(err, keys.ErrInvalidFileName), errors.Is(err, keys.ErrInvalidComment):
		return problem(c, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, application.ErrKeyRelocateUnchanged):
		return problem(c, http.StatusBadRequest, "location_unchanged")
	case errors.Is(err, application.ErrKeyRelocateNotSupported):
		return problem(c, http.StatusUnprocessableEntity, "relocate_not_supported")
	case errors.Is(err, application.ErrKeyReferenceMoved):
		return problem(c, http.StatusConflict, "external_change")
	case errors.Is(err, application.ErrInvalidGroupName):
		return problem(c, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, keys.ErrUnknownGroup), errors.Is(err, application.ErrGroupNotDeclared):
		return problem(c, http.StatusUnprocessableEntity, "group_not_declared")
	case errors.Is(err, keys.ErrUnsupportedAlgorithm), errors.Is(err, keys.ErrUnsupportedBits):
		return problem(c, http.StatusBadRequest, "unsupported_algorithm")
	case errors.Is(err, keys.ErrHardwareAlgorithm):
		return problem(c, http.StatusBadRequest, "hardware_algorithm")
	case errors.Is(err, keys.ErrPassphraseRequired):
		return problem(c, http.StatusBadRequest, "passphrase_required")
	case errors.Is(err, keys.ErrConflictingPassphraseChoice):
		return problem(c, http.StatusBadRequest, "conflicting_passphrase_choice")
	case errors.Is(err, keys.ErrWrongPassphrase):
		return problem(c, http.StatusForbidden, "wrong_passphrase")
	case errors.Is(err, keys.ErrNotPrivateKey):
		return problem(c, http.StatusUnprocessableEntity, "not_a_private_key")
	case errors.Is(err, platform.ErrAgentUnavailable):
		return problem(c, http.StatusBadGateway, "agent_unavailable")
	case errors.Is(err, platform.ErrAgentRejected):
		return problemDetail(c, http.StatusBadGateway, "agent_rejected", err.Error())
	case errors.Is(err, storage.ErrMoveTargetExists), errors.Is(err, keys.ErrTrashNameConflict):
		return problem(c, http.StatusConflict, "name_conflict")
	case errors.Is(err, storage.ErrOutsideWorkspace), errors.Is(err, storage.ErrSymlinkPath):
		return problem(c, http.StatusForbidden, "path_not_editable")
	}
	var conflict *storage.ConflictError
	if errors.As(err, &conflict) {
		return problem(c, http.StatusConflict, "external_change")
	}
	return problem(c, http.StatusInternalServerError, "operation_failed")
}

func inventoryResponse(inventory *keys.Inventory, identities []platform.AgentIdentity, agentAvailable bool) api.KeyInventoryResponse {
	response := api.KeyInventoryResponse{
		Items:                make([]api.KeyItem, 0, len(inventory.Items)),
		Unreadable:           make([]api.UnreadableFile, 0, len(inventory.Unreadable)),
		AgentDelegations:     referenceList(inventory.AgentDelegations),
		UnresolvedReferences: make([]api.UnresolvedReference, 0, len(inventory.UnresolvedReferences)),
		AgentAvailable:       agentAvailable,
		AgentIdentities:      agentIdentities(identities),
	}
	for _, item := range inventory.Items {
		response.Items = append(response.Items, keyItem(item))
	}
	for _, unreadable := range inventory.Unreadable {
		response.Unreadable = append(response.Unreadable, api.UnreadableFile{
			RelativePath: unreadable.RelativePath, Reason: unreadable.Reason,
		})
	}
	for _, unresolved := range inventory.UnresolvedReferences {
		response.UnresolvedReferences = append(response.UnresolvedReferences, api.UnresolvedReference{
			Directive: unresolved.Directive, Value: unresolved.Value,
			ConfigPath: unresolved.ConfigPath, Line: unresolved.Line, Reason: unresolved.Reason,
		})
	}
	return response
}

func agentIdentities(identities []platform.AgentIdentity) []api.AgentIdentity {
	converted := make([]api.AgentIdentity, 0, len(identities))
	for _, identity := range identities {
		converted = append(converted, api.AgentIdentity{
			Bits: identity.Bits, Fingerprint: identity.Fingerprint,
			Comment: identity.Comment, Algorithm: identity.Algorithm,
		})
	}
	return converted
}

func keyItem(item keys.Item) api.KeyItem {
	converted := api.KeyItem{
		Id:             item.ID,
		RelativePath:   item.RelativePath,
		Kind:           string(item.Kind),
		Container:      item.Container,
		Algorithm:      string(item.Algorithm),
		KeyType:        item.KeyType,
		Bits:           item.Bits,
		Encrypted:      item.Encrypted,
		Fingerprint:    item.Fingerprint,
		Comment:        item.Comment,
		Permission:     item.Permission,
		PermissionRisk: item.PermissionRisk,
		SizeBytes:      int(item.SizeBytes),
		References:     referenceList(item.References),
		Notes:          nonNilStrings(item.Notes),
	}
	if item.Certificate != nil {
		validBefore, neverExpires := certificateExpiry(item.Certificate.ValidBefore)
		converted.Certificate = &api.KeyCertificate{
			KeyId:                item.Certificate.KeyID,
			Principals:           nonNilStrings(item.Certificate.Principals),
			ValidBefore:          validBefore,
			NeverExpires:         neverExpires,
			SignedKeyType:        item.Certificate.SignedKeyType,
			SignedKeyFingerprint: item.Certificate.SignedKeyFingerprint,
		}
	}
	return converted
}

// certificateExpiry は、OpenSSH の符号なしの validity bound を変換する。
// OpenSSH は "never expires" を 2^64-1 と綴るが、これは符号付き整数に
// 収まらない。そのためこのケースは負の数に折り返すのではなく、flag として報告される。
func certificateExpiry(validBefore uint64) (int, bool) {
	if validBefore > uint64(math.MaxInt64) {
		return 0, true
	}
	return int(validBefore), false
}

func referenceList(references []keys.Reference) []api.KeyReference {
	converted := make([]api.KeyReference, 0, len(references))
	for _, reference := range references {
		converted = append(converted, api.KeyReference{
			Directive:    reference.Directive,
			ConfigPath:   reference.ConfigPath,
			Line:         reference.Line,
			Condition:    reference.Condition,
			HostPatterns: nonNilStrings(reference.HostPatterns),
			Value:        reference.Value,
		})
	}
	return converted
}

func trashFiles(files []keys.TrashFile) []api.TrashFileSummary {
	converted := make([]api.TrashFileSummary, 0, len(files))
	for _, file := range files {
		converted = append(converted, api.TrashFileSummary{
			OriginalRelativePath: file.OriginalRelativePath,
			TrashRelativePath:    file.TrashRelativePath,
			Kind:                 string(file.Kind),
			Fingerprint:          file.Fingerprint,
			Permission:           file.Permission,
		})
	}
	return converted
}

// nonNilStrings は、すべての JSON 配列を null ではなく配列のまま保つ。
func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func optionalInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
