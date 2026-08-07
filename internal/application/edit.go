package application

import (
	"errors"
	"sort"
	"strings"

	"sshc/internal/config"
)

// EditAction は host ブロックのディレクティブに対する変更の種類を表す。
type EditAction string

const (
	ActionSet    EditAction = "set"
	ActionAdd    EditAction = "add"
	ActionRemove EditAction = "remove"
)

var (
	ErrUnknownEditAction    = errors.New("unknown field edit action")
	ErrEditLineOutsideBlock = errors.New("edited line is outside the host block")
	ErrEditLineNotDirective = errors.New("edited line is not an editable directive")
	ErrDuplicateEditLine    = errors.New("the same line is edited twice")
	ErrUnquotableValue      = errors.New("value cannot be written in OpenSSH configuration quoting")
	ErrEmptyKeyword         = errors.New("directive keyword is required")
	ErrInvalidKeyword       = errors.New("directive keyword contains an unsupported character")
	ErrStructuralKeyword    = errors.New("Host, Match and Include are changed through their own operations")
	ErrRawBlockHeader       = errors.New("raw block must begin with a Host or Match line")
	ErrRawBlockStructure    = errors.New("raw block must contain exactly one Host or Match header")
	ErrInvalidAlias         = errors.New("alias must be 1-64 characters of letters, digits, dot, dash or underscore")
)

// structuralKeywords はファイルのブロック構造を変更する。
// フィールド編集はそれを導入も書き換えもしてはならない。ディレクティブを
// ブロック間で黙って移動させたり、読むファイルの集合を広げたりしてしまうからだ。
var structuralKeywords = map[string]bool{"host": true, "match": true, "include": true}

// FieldEdit は 1 件の変更要求である。Line は 1 始まりで、
// set と remove で必須、Keyword は add で必須、set では任意である。
type FieldEdit struct {
	Action  EditAction `json:"action"`
	Line    int        `json:"line,omitempty"`
	Keyword string     `json:"keyword,omitempty"`
	Values  []string   `json:"values,omitempty"`
}

// ApplyFieldEdits はユーザーが変更した行だけを書き換える。
// それ以外の行のコメント、空行、インデント、区切り、行末
// コメント、改行コードはすべて厳密に保持される。いずれかの編集が
// 拒否された場合、ファイルは変更されないままとなり、部分適用がディスクに届くことはない。
func ApplyFieldEdits(file *config.File, block config.Block, edits []FieldEdit) error {
	if err := validateFieldEdits(file, block, edits); err != nil {
		return err
	}
	staged := &config.File{Lines: append([]config.Line(nil), file.Lines...)}

	for _, edit := range edits {
		if edit.Action != ActionSet {
			continue
		}
		index := edit.Line - 1
		keyword := staged.Lines[index].Keyword
		if edit.Keyword != "" {
			keyword = edit.Keyword
		}
		rebuilt, err := rebuildDirective(staged.Lines[index], keyword, edit.Values)
		if err != nil {
			return err
		}
		staged.Lines[index] = rebuilt
	}

	removals := make([]int, 0, len(edits))
	for _, edit := range edits {
		if edit.Action == ActionRemove {
			removals = append(removals, edit.Line-1)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(removals)))
	for _, index := range removals {
		staged.Lines = append(staged.Lines[:index], staged.Lines[index+1:]...)
	}

	for _, edit := range edits {
		if edit.Action != ActionAdd {
			continue
		}
		current := staged.BlockAt(block.Header)
		line, err := buildDirectiveLine(blockIndent(staged, current), edit.Keyword, edit.Values, blockEnding(staged, current))
		if err != nil {
			return err
		}
		insertLine(staged, appendPosition(staged, current), line)
	}

	file.Lines = staged.Lines
	return nil
}

func validateFieldEdits(file *config.File, block config.Block, edits []FieldEdit) error {
	touched := make(map[int]bool, len(edits))
	for _, edit := range edits {
		switch edit.Action {
		case ActionSet, ActionRemove:
			index := edit.Line - 1
			if index < block.Start || index >= block.End || index >= len(file.Lines) {
				return ErrEditLineOutsideBlock
			}
			if touched[index] {
				return ErrDuplicateEditLine
			}
			touched[index] = true
			line := file.Lines[index]
			if line.Kind != config.LineDirective {
				return ErrEditLineNotDirective
			}
			if structuralKeywords[strings.ToLower(line.Keyword)] {
				return ErrStructuralKeyword
			}
			if edit.Action == ActionSet && edit.Keyword != "" {
				if err := validateKeyword(edit.Keyword); err != nil {
					return err
				}
			}
		case ActionAdd:
			if err := validateKeyword(edit.Keyword); err != nil {
				return err
			}
		default:
			return ErrUnknownEditAction
		}
	}
	return nil
}

func validateKeyword(keyword string) error {
	if keyword == "" {
		return ErrEmptyKeyword
	}
	if structuralKeywords[strings.ToLower(keyword)] {
		return ErrStructuralKeyword
	}
	if len(keyword) > 64 {
		return ErrInvalidKeyword
	}
	for index := 0; index < len(keyword); index++ {
		character := keyword[index]
		isLetter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		isTail := index > 0 && (character >= '0' && character <= '9' || character == '-')
		if !isLetter && !isTail {
			return ErrInvalidKeyword
		}
	}
	return nil
}

// ValidateAlias は UI から作成される alias を保守的な集合に
// 制限し、新しい Host 行がパターン、否定、空白を持つことを決してないようにする。
// ファイル中に既にある alias は書かれたとおりに表示され、書き換えられることはない。
func ValidateAlias(alias string) error {
	if len(alias) == 0 || len(alias) > 64 {
		return ErrInvalidAlias
	}
	for index := 0; index < len(alias); index++ {
		character := alias[index]
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9':
		case index > 0 && (character == '.' || character == '-' || character == '_'):
		default:
			return ErrInvalidAlias
		}
	}
	return nil
}

// splitCommentArguments はディレクティブの値引数を行末
// コメントから分離し、値の書き換えがコメントを保つようにする。
func splitCommentArguments(arguments []config.Argument) (values, comment []config.Argument) {
	for index, argument := range arguments {
		if strings.HasPrefix(argument.Raw, "#") {
			return arguments[:index], arguments[index:]
		}
	}
	return arguments, nil
}

func rebuildDirective(line config.Line, keyword string, values []string) (config.Line, error) {
	if err := validateKeyword(keyword); err != nil {
		return config.Line{}, err
	}
	return rebuildLine(line, keyword, values)
}

// rebuildLine はディレクティブ行の値引数を置き換えつつ、
// インデント、区切り、行末コメント、改行コードを保つ。
// keyword のポリシーチェックは行わないので、Host ヘッダーの書き換えにも使える。
func rebuildLine(line config.Line, keyword string, values []string) (config.Line, error) {
	existing, comment := splitCommentArguments(line.Arguments)
	rebuilt := line
	rebuilt.Keyword = keyword
	if rebuilt.Separator == "" {
		rebuilt.Separator = " "
	}

	arguments := make([]config.Argument, 0, len(values)+len(comment))
	for index, value := range values {
		lead := " "
		if index == 0 {
			lead = ""
		}
		if index < len(existing) {
			lead = existing[index].Lead
		}
		argument, err := renderArgument(lead, value)
		if err != nil {
			return config.Line{}, err
		}
		arguments = append(arguments, argument)
	}
	for index, argument := range comment {
		copied := argument
		if index == 0 && len(arguments) == 0 && copied.Lead == "" {
			copied.Lead = " "
		}
		arguments = append(arguments, copied)
	}
	rebuilt.Arguments = arguments
	return rebuilt, nil
}

// renderArgument は OpenSSH の引用規則に従って 1 つの値を
// 書き出す。その規則は ssh_config の構文なので、それを読むパーサーのそばに置く。
// このラッパーは HTTP problem マッピング用に、パッケージ独自のエラー識別子を保つ。
func renderArgument(lead, value string) (config.Argument, error) {
	argument, err := config.RenderArgument(lead, value)
	if err != nil {
		return config.Argument{}, ErrUnquotableValue
	}
	return argument, nil
}

func buildDirectiveLine(indent, keyword string, values []string, ending string) (config.Line, error) {
	if err := validateKeyword(keyword); err != nil {
		return config.Line{}, err
	}
	return buildLine(indent, keyword, values, ending)
}

// buildLine は keyword のポリシーチェックなしでディレクティブ行を組み立てる。
func buildLine(indent, keyword string, values []string, ending string) (config.Line, error) {
	line := config.Line{
		Kind:      config.LineDirective,
		Indent:    indent,
		Keyword:   keyword,
		Separator: " ",
		Ending:    ending,
	}
	for index, value := range values {
		lead := " "
		if index == 0 {
			lead = ""
		}
		argument, err := renderArgument(lead, value)
		if err != nil {
			return config.Line{}, err
		}
		line.Arguments = append(line.Arguments, argument)
	}
	return line, nil
}

// appendPosition は新しいディレクティブが属すべき位置、
// すなわちブロックの最後のディレクティブの直後を返す。
// 行末コメントや空行はそのままの場所にとどまる。
func appendPosition(file *config.File, block config.Block) int {
	position := block.Start
	for index := block.Start; index < block.End && index < len(file.Lines); index++ {
		if file.Lines[index].Kind == config.LineDirective {
			position = index + 1
		}
	}
	return position
}

func blockIndent(file *config.File, block config.Block) string {
	for index := block.End - 1; index >= block.Start; index-- {
		if index < len(file.Lines) && file.Lines[index].Kind == config.LineDirective {
			return file.Lines[index].Indent
		}
	}
	return "\t"
}

func blockEnding(file *config.File, block config.Block) string {
	for index := block.End - 1; index >= block.Start; index-- {
		if index < len(file.Lines) && file.Lines[index].Kind == config.LineDirective && file.Lines[index].Ending != "" {
			return file.Lines[index].Ending
		}
	}
	return dominantEnding(file)
}

// dominantEnding はファイルが既に使っている改行コードを
// 報告し、CRLF ファイルへの編集が単独の改行を持ち込まないようにする。
func dominantEnding(file *config.File) string {
	for _, line := range file.Lines {
		if line.Ending != "" {
			return line.Ending
		}
	}
	return "\n"
}

// insertLine は position の位置に 1 行を挿入し、ファイルが
// それまで改行なしで終わっていた場合は先行行に改行を与える。
func insertLine(file *config.File, position int, line config.Line) {
	if position > 0 && file.Lines[position-1].Ending == "" {
		file.Lines[position-1].Ending = line.Ending
	}
	file.Lines = append(file.Lines, config.Line{})
	copy(file.Lines[position+1:], file.Lines[position:])
	file.Lines[position] = line
}

// ReplaceBlock は 1 つの Host または Match ブロックの全文を
// 入れ替える。周囲のファイル構造を保つため、raw text は
// ちょうど 1 ブロックを表す必要があり、ブロックの前後は 1 バイトも変わらず保たれる。
func ReplaceBlock(file *config.File, block config.Block, raw string) error {
	if block.Header < 0 || block.Header >= len(file.Lines) {
		return ErrRawBlockHeader
	}
	replacement := config.Parse([]byte(raw))

	headers := 0
	firstDirective := -1
	for index, line := range replacement.Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		if firstDirective < 0 {
			firstDirective = index
		}
		if config.EqualKeyword(line.Keyword, "Host") || config.EqualKeyword(line.Keyword, "Match") {
			headers++
		}
	}
	if firstDirective < 0 {
		return ErrRawBlockHeader
	}
	header := replacement.Lines[firstDirective]
	if !config.EqualKeyword(header.Keyword, "Host") && !config.EqualKeyword(header.Keyword, "Match") {
		return ErrRawBlockHeader
	}
	if headers != 1 {
		return ErrRawBlockStructure
	}

	if block.End < len(file.Lines) {
		last := &replacement.Lines[len(replacement.Lines)-1]
		if last.Ending == "" {
			last.Ending = dominantEnding(file)
		}
	}
	updated := make([]config.Line, 0, len(file.Lines)+len(replacement.Lines))
	updated = append(updated, file.Lines[:block.Header]...)
	updated = append(updated, replacement.Lines...)
	updated = append(updated, file.Lines[block.End:]...)
	file.Lines = updated
	return nil
}

// RenameHostAlias は Host ヘッダー行の 1 つの alias を置き換え、
// 他のパターン、行末コメント、改行コードには一切手を触れない。
func RenameHostAlias(file *config.File, block config.Block, oldAlias, newAlias string) error {
	if err := ValidateAlias(newAlias); err != nil {
		return err
	}
	if block.Kind != config.BlockHost || block.Header < 0 || block.Header >= len(file.Lines) {
		return ErrRawBlockHeader
	}
	header := file.Lines[block.Header]
	values := header.Values()
	replaced := false
	updated := make([]string, 0, len(values))
	for _, value := range values {
		if !replaced && value == oldAlias {
			value = newAlias
			replaced = true
		}
		updated = append(updated, value)
	}
	if !replaced {
		return ErrHostNotFound
	}
	rebuilt, err := rebuildLine(header, header.Keyword, updated)
	if err != nil {
		return err
	}
	file.Lines[block.Header] = rebuilt
	return nil
}

// SetHostComment は host ブロックに付いたコメントを置き換える。
//
// 付随するコメントとは、config.File.CommentRun が定義する、
// Host 行の直前に連続するコメント行のことである。その連続の
// 外側は一切変更されない。これにより、空行で区切られた
// ファイルバナーが、先頭ブロックへの編集の影響を受けずに済む。
//
// 書き換えられる行は Host 行自身のインデントを引き継ぐので、
// Match の中でインデントされたブロックも、コメントの位置がそろったままになる。
func SetHostComment(file *config.File, block config.Block, text string) error {
	if block.Kind != config.BlockHost || block.Header < 0 || block.Header >= len(file.Lines) {
		return ErrHostNotFound
	}
	start := file.CommentRun(block.Header)
	indent := file.Lines[block.Header].Indent
	replacement := config.RenderComment(text, indent, blockEnding(file, block))

	lines := make([]config.Line, 0, len(file.Lines)-(block.Header-start)+len(replacement))
	lines = append(lines, file.Lines[:start]...)
	lines = append(lines, replacement...)
	lines = append(lines, file.Lines[block.Header:]...)
	file.Lines = lines
	return nil
}
