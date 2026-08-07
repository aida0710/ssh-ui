package config

import "strings"

// LineKind は、OpenSSH クライアント設定ファイルの物理行を分類する。
type LineKind uint8

const (
	// LineBlank は、空行または空白だけの行。
	LineBlank LineKind = iota
	// LineComment は、最初の非空白文字が '#' である行。
	LineComment
	// LineDirective は、キーワードと 0 個以上の引数。
	LineDirective
	// LineUnstructured は、構造を正確に再現できないためエンジンが逐語的に保存する行。
	// 書き換えられることは決してない。
	LineUnstructured
)

// Line は物理行ひとつ。LineDirective 以外のすべての種別では、完全な行テキストが
// Text に保持される。LineDirective では、各構成要素が
// Indent+Keyword+Separator+引数+Trailing == 元の行テキストを満たす。
type Line struct {
	Kind      LineKind
	Text      string
	Indent    string
	Keyword   string
	Separator string
	Arguments []Argument
	Trailing  string
	Ending    string
}

// Render は、ソースファイルに現れたとおりの行を返す。
func (l Line) Render() string {
	if l.Kind != LineDirective {
		return l.Text + l.Ending
	}
	var builder strings.Builder
	builder.WriteString(l.Indent)
	builder.WriteString(l.Keyword)
	builder.WriteString(l.Separator)
	for _, argument := range l.Arguments {
		builder.WriteString(argument.Lead)
		builder.WriteString(argument.Raw)
	}
	builder.WriteString(l.Trailing)
	builder.WriteString(l.Ending)
	return builder.String()
}

// Values は、ディレクティブ行の引用を外した引数値を返す。最初の引用されていない
// '#' トークンで止まるのは、OpenSSH の argv_split が設定行の引数リストをコメント
// で終わらせるからである。Arguments は完全なトークン列を保持するので、行は
// 1 バイトも違わずレンダリングできる。
func (l Line) Values() []string {
	if l.Kind != LineDirective || len(l.Arguments) == 0 {
		return nil
	}
	values := make([]string, 0, len(l.Arguments))
	for _, argument := range l.Arguments {
		if strings.HasPrefix(argument.Raw, "#") {
			break
		}
		values = append(values, argument.Value)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

// EqualKeyword は、OpenSSH と同じやり方で二つのディレクティブキーワードを比較
// する。ASCII のキーワードについては大文字小文字を区別しない。
func EqualKeyword(first, second string) bool {
	return strings.EqualFold(first, second)
}
