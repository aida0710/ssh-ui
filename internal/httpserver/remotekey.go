package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/diagnostics"
	"sshc/internal/platform"
	"sshc/internal/remotekey"
	"sshc/internal/session"
)

// RemoteKeyHandlers はリモートホストに公開鍵を登録する。
//
// Diagnostics は、確認画面が表示する接続先と、接続時に実行される
// 実行可能ディレクティブを供給する。登録自体は設定を二度読む
// ことはない。
type RemoteKeyHandlers struct {
	Service     *remotekey.Service
	Diagnostics *diagnostics.Service
	Actions     ActionHandlers
}

func registerRemoteKeyRoutes(engine *echo.Echo, handlers RemoteKeyHandlers) {
	engine.POST("/api/v1/remote-keys/plan", handlers.Plan)
	engine.POST("/api/v1/remote-keys/register", handlers.Register)
}

func remoteKeyProblem(c *echo.Context, err error) error {
	switch {
	case errors.Is(err, remotekey.ErrInvalidPublicKey):
		return problem(c, http.StatusBadRequest, "invalid_public_key")
	case errors.Is(err, remotekey.ErrNotAcknowledged):
		return problem(c, http.StatusConflict, "executable_directive_not_acknowledged")
	case errors.Is(err, remotekey.ErrUnsupportedRemote):
		return problem(c, http.StatusUnprocessableEntity, "unsupported_remote")
	case errors.Is(err, platform.ErrUnsafeAlias):
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	return problem(c, http.StatusInternalServerError, "registration_failed")
}

// Plan はリモートホストに接続せずに変更内容を説明する。
func (h RemoteKeyHandlers) Plan(c *echo.Context) error {
	var request api.RemoteKeyPlanRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	key, fingerprint, err := remotekey.ParsePublicKey(request.PublicKey)
	if err != nil {
		return remoteKeyProblem(c, err)
	}
	key.Path = request.KeyPath

	// 接続先はこの application 自身が設定を読んだ結果によるもので、
	// プロセスを必要としない。plan の裏で ssh -G が実行されることはない。
	hostname, port, err := h.Diagnostics.Destination(request.Alias)
	if err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_destination")
	}
	user := ""
	if projected, ok := h.Diagnostics.ProjectedValue(request.Alias, "user"); ok {
		user = projected
	}
	report, err := h.Diagnostics.Safety()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}

	plan := h.Service.Plan(request.Alias, key, fingerprint, user, hostname, port, "engine")
	return c.JSON(http.StatusOK, api.RemoteKeyPlan{
		Alias:                plan.Alias,
		User:                 plan.User,
		Hostname:             plan.Hostname,
		Port:                 plan.Port,
		ValuesFrom:           plan.ValuesFrom,
		Fingerprint:          plan.Fingerprint,
		KeyPath:              plan.KeyPath,
		KeyLine:              plan.KeyLine,
		RemotePath:           plan.RemotePath,
		Routine:              plan.Routine,
		Supported:            plan.Supported,
		Manual:               plan.Manual,
		ExecutableDirectives: describeDirectives(report.Directives),
	})
}

// Register は確認が消費された後に鍵をインストールする。
func (h RemoteKeyHandlers) Register(c *echo.Context) error {
	var request api.RemoteKeyRegisterRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	key, _, err := remotekey.ParsePublicKey(request.PublicKey)
	if err != nil {
		return remoteKeyProblem(c, err)
	}
	key.Path = request.KeyPath

	if allowed, response := h.Actions.consume(c, session.ActionRemoteKeyRegister, request.Alias); !allowed {
		return response
	}
	report, err := h.Diagnostics.Safety()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}

	result, err := h.Service.Register(c.Request().Context(), report, request.Alias, key, request.AcknowledgeExecutable)
	if err != nil {
		return remoteKeyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.RemoteKeyRegisterResponse{
		Outcome:  result.Outcome,
		ExitCode: result.ExitCode,
		// ssh は読み込んだファイルを絶対パスで名指しするため、アカウント名は
		// 出力がこのプロセスを出る前に取り除かれる。
		Stderr:    platform.SanitiseHomePaths(result.Stderr, h.Diagnostics.Home()),
		Truncated: result.Truncated,
	})
}
