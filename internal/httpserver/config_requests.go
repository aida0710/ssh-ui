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

// Runtime limits at the HTTP boundary. Generated types describe shapes; these
// bound sizes, because a local API is still an API.
const (
	maxRequestBody = 2 << 20
	maxPathLength  = 512
	maxAliasLength = 255
	maxFieldEdits  = 256
	maxFieldValues = 64
	maxValueLength = 1024
	maxRawLength   = 1 << 20
	// maxCommentLength bounds the comment attached to one Host block. It is far
	// smaller than a whole file because a comment is prose about one
	// connection, and the ceiling is what stops a paste of an entire log from
	// being written into the configuration by accident.
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

// problemPayload is the wire form of the OpenAPI Problem schema. It carries a
// location and a stable code, never file contents.
type problemPayload struct {
	Code        string                       `json:"code"`
	Message     string                       `json:"message"`
	Detail      string                       `json:"detail,omitempty"`
	Path        string                       `json:"path,omitempty"`
	Line        int                          `json:"line,omitempty"`
	Column      int                          `json:"column,omitempty"`
	Diagnostics []application.DiagnosticView `json:"diagnostics,omitempty"`
	Conflict    *application.ConflictReport  `json:"conflict,omitempty"`
	// Blockers names the reasons a group operation refused. They are stable
	// codes with a detail after a colon, the same shape a key relocation uses.
	Blockers []string `json:"blockers,omitempty"`
}

// declaredGroup names the group a refused directory operation was aimed at, or
// an empty string when the refusal was something else.
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

// decodeJSON reads a bounded, strict JSON body. Unknown fields are rejected so
// a typo cannot silently become a default.
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

// validatePathParameter accepts only a relative, single-rooted path with no
// traversal or control characters. The workspace performs the authoritative
// check; this keeps obviously hostile input out of the application layer.
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

// validateEditRequest enforces per-kind requirements before the request reaches
// the application layer.
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
		// An empty comment is how a comment is removed, so there is no minimum.
		// A carriage return is normalised by the renderer; anything else that
		// would end a line early is refused here, because a newline inside the
		// text is the only thing that decides how many comment lines are
		// written and a stray control character must not invent one.
		if strings.ContainsAny(request.Comment, "\x00\v\f\u0085\u2028\u2029") {
			return errInvalidEdit
		}
	case application.EditFileRaw:
		// An empty file is a legitimate result of deleting the last block. The
		// base digest precondition, not a length check, is what protects an
		// existing file from an accidental empty write.
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
		// A move names its destination one way or the other: a group, whose
		// path the service derives, or a path. Naming both is refused there,
		// because the two can disagree and this application will not pick.
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
		// The base is the whole precondition. A delete carries no new bytes,
		// so there is nothing else about it to validate here.
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

// serviceProblem maps an application error onto an HTTP problem response. The
// mapping never includes file contents, and the default is a generic 500 so an
// unexpected error cannot leak its message.
func serviceProblem(c *echo.Context, err error) error {
	var syntaxError *application.SyntaxError
	var graphError *application.GraphError
	var conflictError *application.ConflictError
	var groupBlocked *application.GroupBlockedError
	switch {
	case errors.As(err, &groupBlocked):
		// Nothing was written: the blockers are computed before the transaction
		// is built, and they are what the user needs rather than a bare 409.
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
		// Named, so the interface can send the user to the screen where that
		// operation lives rather than only refusing.
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
		// Not an internal fault: the file has one of the two markers this
		// application writes, and it will not guess where its own lines stop.
		return problemWith(c, http.StatusConflict, problemPayload{Code: "region_damaged"})
	case errors.Is(err, application.ErrGroupExists):
		return problemWith(c, http.StatusConflict, problemPayload{Code: "group_exists"})
	case errors.Is(err, storage.ErrDirectoryNotEmpty):
		return problemWith(c, http.StatusConflict, problemPayload{Code: "directory_not_empty"})
	case errors.Is(err, application.ErrNotADirectory):
		return problemWith(c, http.StatusBadRequest, problemPayload{Code: "not_a_directory"})
	case errors.Is(err, application.ErrExternalPath), errors.Is(err, storage.ErrOutsideWorkspace),
		errors.Is(err, storage.ErrSymlinkPath), errors.Is(err, storage.ErrNotRegularFile),
		// A path naming a directory that does not exist, or a component that is
		// not a directory, is a fact about the request, not an internal fault.
		// Without these two a caller-supplied path such as "~/x/y" answered 500.
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
		// Its own code rather than invalid_edit: nothing about the request is
		// malformed, and the user needs to be told that the name is taken
		// rather than that their edit was.
		return problemWith(c, http.StatusConflict, problemPayload{Code: "alias_already_declared"})
	default:
		return problemWith(c, http.StatusInternalServerError, problemPayload{Code: "internal_error"})
	}
}
