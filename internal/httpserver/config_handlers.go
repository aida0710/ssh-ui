package httpserver

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/application"
)

// ConfigHandlers は、configuration・metadata・history の各エンドポイントを提供する。
// すべてのルートは same-origin であり、セッションで認証され、
// 変更操作については Security.Middleware が強制する CSRF ヘッダーの背後にある。
type ConfigHandlers struct {
	Service *application.Service
	// Keys は group 操作が必要とするインベントリを供給する。group の rename は
	// その鍵を移動させることを意味し、それらを指す IdentityFile をすべて書き換える。
	Keys KeyService
}

type groupRenameRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type groupDeleteRequest struct {
	Name string `json:"name"`
	// Destination は接続の移動先となる group である。空にすると接続は
	// connections ディレクトリ自体に移動し、ユーザーがどこかに配置するまで誰にも
	// 読まれない。設定ファイルが削除されることは決してない。
	Destination string `json:"destination"`
}

type historyList struct {
	Entries []application.HistoryEntry `json:"entries"`
}

type restoreRequest struct {
	TransactionID string `json:"transactionId"`
	Path          string `json:"path"`
}

type recoverRequest struct {
	TransactionID string `json:"transactionId"`
	Action        string `json:"action"`
}

type recoverResponse struct {
	Status string `json:"status"`
}

// registerConfigRoutes は、各エンドポイントを Echo インスタンスに配線する。
func registerConfigRoutes(engine *echo.Echo, handlers ConfigHandlers) {
	engine.GET("/api/v1/config/overview", handlers.Overview)
	engine.GET("/api/v1/config/host", handlers.Host)
	engine.GET("/api/v1/config/file", handlers.File)
	engine.POST("/api/v1/config/preview", handlers.Preview)
	engine.POST("/api/v1/config/save", handlers.Save)
	engine.POST("/api/v1/config/groups/rename", handlers.RenameGroup)
	engine.POST("/api/v1/config/groups/delete", handlers.DeleteGroup)
	engine.GET("/api/v1/metadata", handlers.Metadata)
	engine.GET("/api/v1/history", handlers.History)
	engine.POST("/api/v1/history/restore", handlers.Restore)
	engine.POST("/api/v1/history/recover", handlers.Recover)
}

func (h ConfigHandlers) Overview(c *echo.Context) error {
	overview, err := h.Service.Overview()
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, overview)
}

func (h ConfigHandlers) Host(c *echo.Context) error {
	query := c.Request().URL.Query()
	path, alias := query.Get("path"), query.Get("alias")
	if err := validatePathParameter(path); err != nil {
		return serviceProblem(c, err)
	}
	if err := validateAliasParameter(alias); err != nil {
		return serviceProblem(c, err)
	}
	detail, err := h.Service.HostDetail(path, alias)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, detail)
}

func (h ConfigHandlers) File(c *echo.Context) error {
	path := c.Request().URL.Query().Get("path")
	if err := validatePathParameter(path); err != nil {
		return serviceProblem(c, err)
	}
	contents, err := h.Service.FileContents(path)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, contents)
}

func (h ConfigHandlers) Preview(c *echo.Context) error {
	request, err := h.decodeEdit(c)
	if err != nil {
		return serviceProblem(c, err)
	}
	preview, err := h.Service.Preview(request)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, preview)
}

func (h ConfigHandlers) Save(c *echo.Context) error {
	request, err := h.decodeEdit(c)
	if err != nil {
		return serviceProblem(c, err)
	}
	result, err := h.Service.Save(request)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, result)
}

// RenameGroup は、group ディレクトリと、それを指すすべてのものをリネームする。
func (h ConfigHandlers) RenameGroup(c *echo.Context) error {
	var request groupRenameRequest
	if err := decodeJSON(c, &request); err != nil {
		return serviceProblem(c, err)
	}
	inventory, err := h.Keys.Inventory()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inventory_failed")
	}
	result, err := h.Service.RenameGroup(inventory, request.From, request.To)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, result)
}

// DeleteGroup は、group を削除し、その接続を移動する。
func (h ConfigHandlers) DeleteGroup(c *echo.Context) error {
	var request groupDeleteRequest
	if err := decodeJSON(c, &request); err != nil {
		return serviceProblem(c, err)
	}
	inventory, err := h.Keys.Inventory()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inventory_failed")
	}
	result, err := h.Service.DeleteGroup(inventory, request.Name, request.Destination)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, result)
}

func (h ConfigHandlers) decodeEdit(c *echo.Context) (application.EditRequest, error) {
	var request application.EditRequest
	if err := decodeJSON(c, &request); err != nil {
		return application.EditRequest{}, err
	}
	if err := validateEditRequest(request); err != nil {
		return application.EditRequest{}, err
	}
	return request, nil
}

func (h ConfigHandlers) Metadata(c *echo.Context) error {
	overview, err := h.Service.Overview()
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, overview.Metadata)
}

func (h ConfigHandlers) History(c *echo.Context) error {
	entries, err := h.Service.History()
	if err != nil {
		return serviceProblem(c, err)
	}
	if entries == nil {
		entries = []application.HistoryEntry{}
	}
	return c.JSON(http.StatusOK, historyList{Entries: entries})
}

func (h ConfigHandlers) Restore(c *echo.Context) error {
	var request restoreRequest
	if err := decodeJSON(c, &request); err != nil {
		return serviceProblem(c, err)
	}
	if err := validateIdentifier(request.TransactionID); err != nil {
		return serviceProblem(c, err)
	}
	if err := validatePathParameter(request.Path); err != nil {
		return serviceProblem(c, err)
	}
	result, err := h.Service.Restore(request.TransactionID, request.Path)
	if err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, result)
}

func (h ConfigHandlers) Recover(c *echo.Context) error {
	var request recoverRequest
	if err := decodeJSON(c, &request); err != nil {
		return serviceProblem(c, err)
	}
	if err := validateIdentifier(request.TransactionID); err != nil {
		return serviceProblem(c, err)
	}
	if request.Action != "complete" && request.Action != "rollback" {
		return serviceProblem(c, errInvalidEdit)
	}
	if err := h.Service.Recover(request.TransactionID, request.Action); err != nil {
		return serviceProblem(c, err)
	}
	return c.JSON(http.StatusOK, recoverResponse{Status: "ok"})
}
