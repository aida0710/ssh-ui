package httpserver

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/config"
	"sshc/internal/diagnostics"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/secret"
	"sshc/internal/session"
)

// DiagnosticsHandlers は、個別に起動されるチェック群を公開する。
type DiagnosticsHandlers struct {
	Service *diagnostics.Service
	Actions ActionHandlers
	// Passwords、AskpassHelper、AskpassURL は、保存されたパスワードを持つ
	// host に対して起動に武装させる。3 つすべてが nil または空であれば、
	// すべての起動は素の経路をたどる。これは vault を持たないサーバーのふるまいである。
	Passwords     *secret.Service
	AskpassHelper string
	AskpassURL    string
}

func registerDiagnosticsRoutes(engine *echo.Echo, handlers DiagnosticsHandlers) {
	engine.POST("/api/v1/diagnostics/config", handlers.CheckConfig)
	engine.POST("/api/v1/diagnostics/effective", handlers.Effective)
	engine.POST("/api/v1/diagnostics/reachability", handlers.Reachability)
	engine.POST("/api/v1/diagnostics/authentication", handlers.Authentication)
	engine.POST("/api/v1/terminal/command", handlers.TerminalCommand)
	engine.POST("/api/v1/terminal/launch", handlers.TerminalLaunch)
}

// addDiagnosticsActions は、このサブシステムが所有する確認を登録する。
//
// そのいずれもが、現時点での設定が持つ実行可能なディレクティブに結び付く。
// それこそが確認ダイアログの表示内容そのものだからである。したがって、確認と
// リクエストの間に編集が入ると、別のコマンドを黙って実行するのではなく、
// トークンが無効になる。
func addDiagnosticsActions(registry actionRegistry, service *diagnostics.Service) {
	evidence := func(target string) (string, error) {
		if err := platform.ValidateAlias(target); err != nil {
			return "", err
		}
		report, err := service.Safety()
		if err != nil {
			return "", err
		}
		return report.Evidence(), nil
	}
	for _, kind := range []string{
		session.ActionEvaluate,
		session.ActionReachability,
		session.ActionAuthentication,
		session.ActionTerminalLaunch,
		// 鍵を登録すると接続が開かれるので、その確認は接続が実行するのと
		// 同じ実行可能なディレクティブを示す。
		session.ActionRemoteKeyRegister,
	} {
		registry[kind] = actionKind{evidence: evidence, fail: diagnosticsProblem}
	}
}

// diagnosticsProblem は、evidence 導出の失敗を通信形式に対応付ける。
func diagnosticsProblem(c *echo.Context, err error) error {
	if errors.Is(err, platform.ErrUnsafeAlias) {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	return problem(c, http.StatusInternalServerError, "config_unreadable")
}

// CheckConfig は構文チェックと Include チェックを実行する。プロセスを
// 起動しないので action トークンは不要で、セッションと CSRF ヘッダーだけでよい。
func (h DiagnosticsHandlers) CheckConfig(c *echo.Context) error {
	report, err := h.Service.ConfigCheck()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "config_unreadable")
	}

	response := api.ConfigCheckResponse{
		Root:        report.Root,
		Files:       make([]api.ConfigFileSummary, 0, len(report.Files)),
		Diagnostics: make([]api.ConfigDiagnostic, 0, len(report.Diagnostics)),
	}
	for _, file := range report.Files {
		response.Files = append(response.Files, api.ConfigFileSummary{
			Path: file.Path, Editable: file.Editable, Missing: file.Missing,
			Loads: file.Loads, Includes: file.Includes,
		})
	}
	for _, diagnostic := range report.Diagnostics {
		response.Diagnostics = append(response.Diagnostics, api.ConfigDiagnostic{
			Severity: severityName(diagnostic.Severity),
			Code:     diagnostic.Code,
			Path:     diagnostic.Path,
			Line:     diagnostic.Line,
			Detail:   diagnostic.Detail,
		})
	}
	return c.JSON(http.StatusOK, response)
}

// Effective は 1 個の alias を説明し、許されている場合はそれを評価する。
//
// action トークンが必要になるのは、評価がコマンドを実行する場合だけである。
// それはまさに設定が Match exec を持つ場合に一致する。
func (h DiagnosticsHandlers) Effective(c *echo.Context) error {
	var request api.AliasRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}

	confirmed := false
	if c.Request().Header.Get(ActionHeader) != "" {
		allowed, response := h.Actions.consume(c, session.ActionEvaluate, request.Alias)
		if !allowed {
			return response
		}
		confirmed = true
	}

	inspection, err := h.Service.Inspect(c.Request().Context(), request.Alias, confirmed)
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inspection_failed")
	}

	response := api.EffectiveResponse{
		Alias:                inspection.Alias,
		Evaluated:            inspection.Evaluated,
		RequiresConfirmation: inspection.RequiresConfirmation,
		TokenWarning:         effective.TokenEscapeWarning,
		ExecutableDirectives: describeDirectives(inspection.Report.Directives),
		Values:               make([]api.EffectiveValue, 0, len(inspection.Values.Keywords)),
		Sources:              make([]api.ValueSource, 0, len(inspection.Projection.Sources)),
		Complexities:         make([]api.ComplexityNote, 0, len(inspection.Projection.Complexities)),
		Route:                make([]api.JumpStage, 0, len(inspection.Route)),
		Failure:              api.OpenSSHFailure{},
	}
	for _, keyword := range inspection.Values.Keywords {
		response.Values = append(response.Values, api.EffectiveValue{
			Keyword: keyword,
			Values:  inspection.Values.All(keyword),
		})
	}
	for _, source := range inspection.Projection.Sources {
		response.Sources = append(response.Sources, api.ValueSource{
			Keyword: source.Keyword, Value: source.Value, Path: source.Path,
			Line: source.Line, Condition: source.Condition, Kind: source.Kind, Winner: source.Winner,
		})
	}
	for _, complexity := range append(inspection.Projection.Complexities, inspection.RouteComplexities...) {
		response.Complexities = append(response.Complexities, api.ComplexityNote{
			Code: complexity.Code, Path: complexity.Path, Line: complexity.Line,
			Condition: complexity.Condition, Detail: complexity.Detail,
		})
	}
	for _, stage := range inspection.Route {
		response.Route = append(response.Route, api.JumpStage{
			Order: stage.Order, Depth: stage.Depth, Parent: stage.Parent, Hop: stage.Hop.Raw,
			Hostname: stage.Hostname, User: stage.User, Port: stage.Port, Complex: stage.Complex,
		})
	}
	if inspection.Failure != nil {
		response.Failure = api.OpenSSHFailure{
			Failed:    true,
			ExitCode:  inspection.Failure.ExitCode,
			Stderr:    inspection.Failure.Stderr,
			Truncated: inspection.Failure.Truncated,
		}
	}
	return c.JSON(http.StatusOK, response)
}

// Reachability は接続先へ直接ダイアルする。
func (h DiagnosticsHandlers) Reachability(c *echo.Context) error {
	var request api.AliasRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	if allowed, response := h.Actions.consume(c, session.ActionReachability, request.Alias); !allowed {
		return response
	}

	result, err := h.Service.Reach(c.Request().Context(), request.Alias)
	if err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_destination")
	}
	return c.JSON(http.StatusOK, api.ReachabilityResponse{
		Address:   result.Address,
		Outcome:   result.Outcome,
		ElapsedMs: int(result.Elapsed.Milliseconds()),
		Detail:    result.Detail,
		Notice:    result.Notice,
	})
}

// Authentication は、上限付きの認証テストを実行する。
func (h DiagnosticsHandlers) Authentication(c *echo.Context) error {
	var request api.AuthenticationRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "unsafe_alias")
	}
	if allowed, response := h.Actions.consume(c, session.ActionAuthentication, request.Alias); !allowed {
		return response
	}

	result, err := h.Service.Authenticate(c.Request().Context(), request.Alias, request.AcknowledgeExecutable)
	var directiveError *diagnostics.ExecutableDirectiveError
	switch {
	case errors.As(err, &directiveError):
		return problem(c, http.StatusConflict, "executable_directive_not_acknowledged")
	case err != nil:
		return problem(c, http.StatusInternalServerError, "authentication_test_failed")
	}
	return c.JSON(http.StatusOK, api.AuthenticationResponse{
		Outcome:       result.Outcome,
		Authenticated: result.Authenticated,
		ExitCode:      result.ExitCode,
		Stderr:        result.Stderr,
		Truncated:     result.Truncated,
		ElapsedMs:     int(result.Elapsed.Milliseconds()),
	})
}

// TerminalCommand は、alias に対するコマンドテキストと、このアプリケーションが
// それを起動する意思があるかどうかを返す。
//
// これは、起動を拒否するはずの alias についても意図的に説明する。
// alias が安全な集合から外れているユーザーであっても、確認したうえで
// 自分自身で実行するためにコマンドを見る必要があるからだ。
func (h DiagnosticsHandlers) TerminalCommand(c *echo.Context) error {
	var request api.AliasRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if request.Alias == "" || len(request.Alias) > maxAliasLength {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	command, launchable, warning := h.Service.TerminalCommand(request.Alias)
	return c.JSON(http.StatusOK, api.TerminalCommandResponse{
		Command:    command,
		Launchable: launchable,
		Warning:    warning,
	})
}

// TerminalLaunch は、確認済みで安全な alias に対して Terminal を開く。
//
// alias は確認が消費される前にチェックされる。したがって、このアプリケーションが
// 起動しない alias は、トークンを消費することもできない。
func (h DiagnosticsHandlers) TerminalLaunch(c *echo.Context) error {
	var request api.AliasRequest
	if err := decodeJSON(c, &request); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if err := platform.ValidateAlias(request.Alias); err != nil {
		return problem(c, http.StatusBadRequest, "alias_not_launchable")
	}
	if allowed, response := h.Actions.consume(c, session.ActionTerminalLaunch, request.Alias); !allowed {
		return response
	}
	// 保存されたパスワードは、この 1 個の接続に対してヘルパーを武装させる。
	// トークンは確認が消費された後、ここで発行される。したがって、トークンが
	// 存在するのはユーザーがまさに承認した起動に対してだけである。
	if h.armed(request.Alias) {
		token, err := h.Passwords.IssueToken(request.Alias)
		if err != nil {
			return problem(c, http.StatusConflict, "vault_locked")
		}
		if err := h.Service.LaunchTerminalWithPassword(
			c.Request().Context(), request.Alias, h.AskpassHelper, h.AskpassURL, token,
		); err != nil {
			return problem(c, http.StatusInternalServerError, "terminal_launch_failed")
		}
		return c.JSON(http.StatusOK, api.TerminalLaunchResponse{Launched: true})
	}
	if err := h.Service.LaunchTerminal(c.Request().Context(), request.Alias); err != nil {
		return problem(c, http.StatusInternalServerError, "terminal_launch_failed")
	}
	return c.JSON(http.StatusOK, api.TerminalLaunchResponse{Launched: true})
}

func describeDirectives(directives []effective.Executable) []api.ExecutableDirective {
	described := make([]api.ExecutableDirective, 0, len(directives))
	for _, directive := range directives {
		described = append(described, api.ExecutableDirective{
			Keyword:     directive.Keyword,
			Command:     directive.Command,
			Path:        directive.Path,
			Line:        directive.Line,
			Condition:   directive.Condition,
			OnEvaluate:  directive.OnEvaluate,
			OnConnect:   directive.OnConnect,
			Overridable: directive.Overridable,
		})
	}
	return described
}

func severityName(severity config.Severity) string {
	switch severity {
	case config.SeverityError:
		return "error"
	case config.SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

// armed は、この起動が askpass ヘルパーを伴うべきかどうかを報告する。
//
// すべての部品がそろっていなければならない: vault、解錠済みであること、
// この alias 用の保存されたパスワード、ヘルパーのパス、そしてエンドポイント。
// 欠けている部品があれば、失敗するのではなく素の起動にフォールバックする。
// 開いて手でパスワードを尋ねる terminal は、それでも正常な接続だからである。
func (h DiagnosticsHandlers) armed(alias string) bool {
	return h.Passwords != nil &&
		h.AskpassHelper != "" &&
		h.AskpassURL != "" &&
		h.Passwords.Has(alias)
}
