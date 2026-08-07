package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"sshc/internal/application"
	"sshc/internal/storage"
)

// HTTP 境界におけるランタイム上限。生成された型は形を記述するが、
// こちらはサイズを制限する。ローカルな API であっても API には変わりないからだ。
const (
	maxRequestBody = 2 << 20
	maxPathLength  = 512
	maxAliasLength = 255
	maxFieldEdits  = 256
	maxFieldValues = 64
	maxValueLength = 1024
	maxRawLength   = 1 << 20
	// maxCommentLength は、1 個の Host ブロックに付くコメントを制限する。
	// ファイル全体よりはるかに小さいのは、コメントが 1 個の接続についての
	// 散文だからであり、この上限があるからこそ、ログ全体をうっかり設定に
	// 貼り付けてしまうことが防がれる。
	maxCommentLength = 4 << 10
	maxGroupCount    = 256
	maxHostCount     = 4096
	maxIDLength      = 128
)

var (
	errInvalidBody  = errors.New("invalid_request_body")
	errInvalidPath  = errors.New("invalid_path")
	errInvalidAlias = errors.New("invalid_alias")
	errInvalidEdit  = errors.New("invalid_edit")
)

// problemPayload は OpenAPI の Problem スキーマの通信形式である。
// location と安定した code を運ぶが、ファイルの中身は決して運ばない。
type problemPayload struct {
	Code        string                       `json:"code"`
	Message     string                       `json:"message"`
	Detail      string                       `json:"detail,omitempty"`
	Path        string                       `json:"path,omitempty"`
	Line        int                          `json:"line,omitempty"`
	Column      int                          `json:"column,omitempty"`
	Diagnostics []application.DiagnosticView `json:"diagnostics,omitempty"`
	Conflict    *application.ConflictReport  `json:"conflict,omitempty"`
	// Blockers は group 操作が拒否した理由を示す。これらはコロンの後に
	// detail を伴う安定した code であり、鍵の relocation が使うのと同じ形である。
	Blockers []string `json:"blockers,omitempty"`
}

// declaredGroup は、拒否された directory 操作が対象としていた group を示す。
// 拒否が他の理由による場合は空文字列となる。
func declaredGroup(err error) string {
	var declared *application.GroupDeclaredError
	if errors.As(err, &declared) {
		return declared.Group
	}
	return ""
}

func problemWith(c *echo.Context, status int, payload problemPayload) error {
	if payload.Message == "" {
		payload.Message = "request rejected"
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, payload)
}

// decodeJSON は、上限付きで厳密な JSON ボディを読む。未知のフィールドは
// 拒否されるので、タイプミスが黙って既定値になることはない。
func decodeJSON(c *echo.Context, target any) error {
	body := c.Request().Body
	if body == nil {
		return errInvalidBody
	}
	decoder := json.NewDecoder(io.LimitReader(body, maxRequestBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidBody
	}
	if decoder.More() {
		return errInvalidBody
	}
	return nil
}

// validatePathParameter は、traversal も制御文字もない、単一ルートの
// 相対 path のみを受け付ける。正式なチェックはワークスペースが行うが、これは
// 明らかに悪意ある入力をアプリケーション層から締め出すためのものである。
func validatePathParameter(value string) error {
	if value == "" || len(value) > maxPathLength {
		return errInvalidPath
	}
	if strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\n\r") {
		return errInvalidPath
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errInvalidPath
		}
	}
	return nil
}

func validateAliasParameter(value string) error {
	if value == "" || len(value) > maxAliasLength {
		return errInvalidAlias
	}
	for _, character := range value {
		if character <= ' ' || character == 0x7f {
			return errInvalidAlias
		}
	}
	return nil
}

func validateIdentifier(value string) error {
	if value == "" || len(value) > maxIDLength {
		return errInvalidEdit
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		isAllowed := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '.'
		if !isAllowed {
			return errInvalidEdit
		}
	}
	return nil
}

// validateEditRequest は、リクエストがアプリケーション層に届く前に
// kind ごとの要件を強制する。
func validateEditRequest(request application.EditRequest) error {
	if len(request.Raw) > maxRawLength || len(request.Base) > maxRawLength ||
		len(request.DestinationBase) > maxRawLength || len(request.Comment) > maxCommentLength {
		return errInvalidEdit
	}
	switch request.Kind {
	case application.EditHostFields, application.EditBlockRaw, application.EditFileRaw,
		application.EditRename, application.EditMove, application.EditComment,
		application.EditFileRename, application.EditFileDelete,
		application.EditDirectoryCreate, application.EditDirectoryDelete:
		if err := validatePathParameter(request.Path); err != nil {
			return err
		}
	case application.EditGroups, application.EditMetadata:
	default:
		return errInvalidEdit
	}

	switch request.Kind {
	case application.EditHostFields:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		if len(request.Fields) == 0 || len(request.Fields) > maxFieldEdits {
			return errInvalidEdit
		}
		for _, edit := range request.Fields {
			if err := validateFieldEdit(edit); err != nil {
				return err
			}
		}
	case application.EditBlockRaw:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		if request.Raw == "" {
			return errInvalidEdit
		}
	case application.EditComment:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		// 空のコメントはコメントを削除する手段なので、最小長というものはない。
		// carriage return は renderer によって正規化される。行を早期に
		// 終わらせてしまう他の文字はここで拒否される。テキスト内の newline だけが
		// 書き込まれるコメント行数を決めるものであり、迷い込んだ制御文字が
		// それを勝手に作り出してはならないからだ。
		if strings.ContainsAny(request.Comment, "\x00\v\f\u0085\u2028\u2029") {
			return errInvalidEdit
		}
	case application.EditFileRaw:
		// 空のファイルは、最後のブロックを削除した結果として正当にあり得る。
		// 既存のファイルを誤った空書き込みから守るのは、長さのチェックではなく
		// base digest の事前条件である。
	case application.EditRename:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		if err := application.ValidateAlias(request.NewAlias); err != nil {
			return errInvalidAlias
		}
	case application.EditMove:
		if err := validateAliasParameter(request.Alias); err != nil {
			return err
		}
		// move は移動先を二通りのいずれかで指定する。path をサービスが導出する
		// group か、path そのものかである。両方を指定することはそこで拒否される。
		// 両者が食い違い得るし、このアプリケーションはどちらかを選んだりしないからだ。
		if request.DestinationGroup != "" {
			if err := application.ValidateGroupName(request.DestinationGroup); err != nil {
				return err
			}
			break
		}
		if err := validatePathParameter(request.DestinationPath); err != nil {
			return err
		}
	case application.EditFileRename:
		if err := validatePathParameter(request.DestinationPath); err != nil {
			return err
		}
	case application.EditFileDelete:
		// base がすべての事前条件である。delete は新しいバイトを一切
		// 伴わないので、ここで他に検証すべきことは何もない。
	case application.EditGroups, application.EditMetadata:
		if request.Metadata == nil {
			return errInvalidEdit
		}
		if len(request.Metadata.Groups) > maxGroupCount || len(request.Metadata.Hosts) > maxHostCount {
			return errInvalidEdit
		}
		if err := application.ValidateMetadata(*request.Metadata); err != nil {
			return err
		}
	}
	return nil
}

func validateFieldEdit(edit application.FieldEdit) error {
	switch edit.Action {
	case application.ActionSet, application.ActionRemove:
		if edit.Line <= 0 {
			return errInvalidEdit
		}
	case application.ActionAdd:
		if edit.Keyword == "" {
			return errInvalidEdit
		}
	default:
		return errInvalidEdit
	}
	if len(edit.Keyword) > 64 || len(edit.Values) > maxFieldValues {
		return errInvalidEdit
	}
	for _, value := range edit.Values {
		if len(value) > maxValueLength {
			return errInvalidEdit
		}
	}
	return nil
}

// serviceProblem は、アプリケーションエラーを HTTP の problem レスポンスに
// 対応付ける。この対応付けにファイルの中身が含まれることは決してなく、
// 既定は汎用の 500 なので、予期しないエラーがメッセージを漏らすことはない。
func serviceProblem(c *echo.Context, err error) error {
	var syntaxError *application.SyntaxError
	var graphError *application.GraphError
	var conflictError *application.ConflictError
	var groupBlocked *application.GroupBlockedError
	switch {
	case errors.As(err, &groupBlocked):
		// 何も書き込まれていない。blockers は transaction を組み立てる前に
		// 計算され、ユーザーが必要とするのは素の 409 ではなくそれである。
		return problemWith(c, http.StatusConflict, problemPayload{
			Code:     "group_blocked",
			Blockers: groupBlocked.Blockers,
		})
	case errors.As(err, &syntaxError):
		return problemWith(c, http.StatusUnprocessableEntity, problemPayload{
			Code:   "config_syntax_error",
			Path:   syntaxError.Path,
			Line:   syntaxError.Line,
			Column: syntaxError.Column,
			Detail: syntaxError.Detail,
		})
	case errors.As(err, &graphError):
		return problemWith(c, http.StatusUnprocessableEntity, problemPayload{
			Code:        "config_graph_error",
			Diagnostics: graphError.Diagnostics,
		})
	case errors.As(err, &conflictError):
		report := conflictError.Report
		return problemWith(c, http.StatusConflict, problemPayload{
			Code:     "config_conflict",
			Path:     report.Path,
			Conflict: &report,
		})
	case declaredGroup(err) != "":
		// 名前が付いているのは、単に拒否するだけでなく、インターフェースが
		// その操作のある画面へユーザーを送れるようにするためである。
		return problemWith(c, http.StatusConflict, problemPayload{
			Code: "group_is_declared", Detail: declaredGroup(err),
		})
	case errors.Is(err, application.ErrHostNotFound), errors.Is(err, storage.ErrUnknownTransaction),
		errors.Is(err, application.ErrFileNotFound):
		return problemWith(c, http.StatusNotFound, problemPayload{Code: "not_found"})
	case errors.Is(err, application.ErrCannotTouchEntryFile):
		return problemWith(c, http.StatusConflict, problemPayload{Code: "entry_file_protected"})
	case errors.Is(err, application.ErrDestinationExists):
		return problemWith(c, http.StatusConflict, problemPayload{Code: "destination_exists"})
	case errors.Is(err, application.ErrSamePath):
		return problemWith(c, http.StatusBadRequest, problemPayload{Code: "invalid_request"})
	case errors.Is(err, application.ErrGroupNotDeclared):
		return problemWith(c, http.StatusUnprocessableEntity, problemPayload{Code: "group_not_declared"})
	case errors.Is(err, application.ErrRegionDamaged):
		// 内部の欠陥ではない。ファイルには、このアプリケーションが書く 2 種類の
		// マーカーのどちらかがあり、自分の行がどこで終わるかを推測したりしない。
		return problemWith(c, http.StatusConflict, problemPayload{Code: "region_damaged"})
	case errors.Is(err, application.ErrGroupExists):
		return problemWith(c, http.StatusConflict, problemPayload{Code: "group_exists"})
	case errors.Is(err, storage.ErrDirectoryNotEmpty):
		return problemWith(c, http.StatusConflict, problemPayload{Code: "directory_not_empty"})
	case errors.Is(err, application.ErrNotADirectory):
		return problemWith(c, http.StatusBadRequest, problemPayload{Code: "not_a_directory"})
	case errors.Is(err, application.ErrExternalPath), errors.Is(err, storage.ErrOutsideWorkspace),
		errors.Is(err, storage.ErrSymlinkPath), errors.Is(err, storage.ErrNotRegularFile),
		// 存在しないディレクトリを指す path や、ディレクトリでない要素を含む path は、
		// リクエストについての事実であり、内部の欠陥ではない。
		// この 2 つがなければ、呼び出し側が渡す "~/x/y" のような path は 500 を返していた。
		errors.Is(err, storage.ErrMissingDirectory), errors.Is(err, storage.ErrNotDirectory),
		errors.Is(err, application.ErrNotEditable):
		return problemWith(c, http.StatusForbidden, problemPayload{Code: "path_not_editable"})
	case errors.Is(err, application.ErrUnknownEditKind), errors.Is(err, application.ErrUnknownRecoveryAction),
		errors.Is(err, application.ErrMetadataSecret), errors.Is(err, application.ErrMetadataPath),
		errors.Is(err, application.ErrMetadataGroup), errors.Is(err, application.ErrMetadataVersion),
		errors.Is(err, application.ErrSameFileMove), errors.Is(err, application.ErrAmbiguousDestination),
		errors.Is(err, application.ErrInvalidGroupName), errors.Is(err, application.ErrGroupSelfNesting),
		errors.Is(err, application.ErrKeyRelocateUnchanged),
		errors.Is(err, errInvalidBody), errors.Is(err, errInvalidPath),
		errors.Is(err, errInvalidAlias), errors.Is(err, errInvalidEdit):
		return problemWith(c, http.StatusBadRequest, problemPayload{Code: "invalid_request"})
	case errors.Is(err, application.ErrUnquotableValue), errors.Is(err, application.ErrStructuralKeyword),
		errors.Is(err, application.ErrInvalidKeyword), errors.Is(err, application.ErrEmptyKeyword),
		errors.Is(err, application.ErrInvalidAlias), errors.Is(err, application.ErrRawBlockHeader),
		errors.Is(err, application.ErrRawBlockStructure), errors.Is(err, application.ErrEditLineOutsideBlock),
		errors.Is(err, application.ErrEditLineNotDirective), errors.Is(err, application.ErrDuplicateEditLine),
		errors.Is(err, application.ErrUnknownEditAction),
		errors.Is(err, application.ErrDuplicateDestinationAlias):
		return problemWith(c, http.StatusUnprocessableEntity, problemPayload{Code: "invalid_edit"})
	case errors.Is(err, application.ErrAliasAlreadyDeclared):
		// invalid_edit ではなく専用の code である。リクエストの形式に問題はなく、
		// ユーザーに伝えるべきは編集が不正だったことではなく、
		// 名前がすでに使われているということだからだ。
		return problemWith(c, http.StatusConflict, problemPayload{Code: "alias_already_declared"})
	default:
		return problemWith(c, http.StatusInternalServerError, problemPayload{Code: "internal_error"})
	}
}
