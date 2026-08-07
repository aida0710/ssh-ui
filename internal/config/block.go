package config

import "strings"

// BlockKind は、どの条件構文が行の範囲を所有しているかを識別する。
type BlockKind uint8

const (
	// BlockGlobal は、最初の Host 行または Match 行より前の行を保持する。空であっても
	// 常に存在する。
	BlockGlobal BlockKind = iota
	BlockHost
	BlockMatch
)

// Pattern は Host 行の引数ひとつ。
type Pattern struct {
	Raw      string
	Value    string
	Negated  bool
	Wildcard bool
}

// Criterion は Match 行の属性ひとつ。
type Criterion struct {
	Keyword  string
	Argument string
	Negated  bool
}

// Block は、ヘッダー行ひとつが支配する半開区間 [Start, End) の行範囲。
type Block struct {
	Kind     BlockKind
	Header   int
	Start    int
	End      int
	Patterns []Pattern
	Criteria []Criterion
}

// matchCriteriaWithArgument は、次のトークンを引数として消費する Match 属性を
// 列挙する。all、canonical、final は引数を取らない。
var matchCriteriaWithArgument = map[string]bool{
	"exec":         true,
	"host":         true,
	"localnetwork": true,
	"localuser":    true,
	"originalhost": true,
	"tagged":       true,
	"user":         true,
}

// Blocks は、ファイル順にすべてのブロックを返す。最初の要素は常にグローバル
// ブロックである。
func (f *File) Blocks() []Block {
	blocks := []Block{{Kind: BlockGlobal, Header: -1, Start: 0}}
	for index, line := range f.Lines {
		if line.Kind != LineDirective {
			continue
		}
		switch {
		case EqualKeyword(line.Keyword, "Host"):
			blocks[len(blocks)-1].End = index
			blocks = append(blocks, Block{
				Kind:     BlockHost,
				Header:   index,
				Start:    index + 1,
				Patterns: parsePatterns(line.Values()),
			})
		case EqualKeyword(line.Keyword, "Match"):
			blocks[len(blocks)-1].End = index
			blocks = append(blocks, Block{
				Kind:     BlockMatch,
				Header:   index,
				Start:    index + 1,
				Criteria: parseCriteria(line.Values()),
			})
		}
	}
	blocks[len(blocks)-1].End = len(f.Lines)
	return blocks
}

// BlockAt は、与えられた行インデックスを支配するブロックを返す。Host や Match の
// ヘッダー行は、それが開くブロックに属する。
func (f *File) BlockAt(line int) Block {
	blocks := f.Blocks()
	found := blocks[0]
	for _, block := range blocks {
		if block.Header == line || (line >= block.Start && line < block.End) {
			found = block
		}
	}
	return found
}

// Condition は、表示用にブロックのヘッダーテキストを返す。インデントと行末は
// 含まない。グローバルブロックには条件がない。
func (f *File) Condition(block Block) string {
	if block.Header < 0 || block.Header >= len(f.Lines) {
		return ""
	}
	return strings.TrimSpace(f.Lines[block.Header].Render())
}

func parsePatterns(values []string) []Pattern {
	patterns := make([]Pattern, 0, len(values))
	for _, value := range values {
		pattern := Pattern{Raw: value, Value: value}
		if strings.HasPrefix(pattern.Value, "!") {
			pattern.Negated = true
			pattern.Value = pattern.Value[1:]
		}
		pattern.Wildcard = strings.ContainsAny(pattern.Value, "*?")
		patterns = append(patterns, pattern)
	}
	return patterns
}

func parseCriteria(values []string) []Criterion {
	criteria := make([]Criterion, 0, len(values))
	for index := 0; index < len(values); index++ {
		keyword := values[index]
		criterion := Criterion{}
		if strings.HasPrefix(keyword, "!") {
			criterion.Negated = true
			keyword = keyword[1:]
		}
		// OpenSSH の strdelim は Match 属性とその引数を空白か単一の '=' で分割するので、
		// どちらの書き方も受け付けなければならない。
		name, argument, hasEquals := strings.Cut(keyword, "=")
		criterion.Keyword = strings.ToLower(name)
		if hasEquals {
			criterion.Argument = argument
			criteria = append(criteria, criterion)
			continue
		}
		if matchCriteriaWithArgument[criterion.Keyword] && index+1 < len(values) {
			index++
			criterion.Argument = values[index]
		}
		criteria = append(criteria, criterion)
	}
	return criteria
}

// CommentRun は、与えられたインデックスにヘッダーを持つブロックに付随するコメント
// 行の範囲を、半開区間 [start, header) として報告する。
//
// 付随するコメントとは、ヘッダーのすぐ上にある連続した LineComment 行の並びで
// ある。その並びは、空行、ディレクティブ、非構造化行、あるいはファイルの先頭で
// 止まる。
//
// 空行は意図的に区切りとして働く。このルールがないと、ファイル自身のバナー —
// 空行の上、先頭に置かれた "# Managed by hand since 2019" のような行 — が、
// たまたま最初に来た Host ブロックに取り込まれてしまい、そのブロックのコメントを
// 編集するとファイルのバナーが書き換わってしまう。隣接を要求することが、この
// 付随関係を推測ではなくテキストの性質にしている。
//
// コメントが付随していない場合、返る範囲は空になる（start == header）。
func (f *File) CommentRun(header int) (start int) {
	if header < 0 || header > len(f.Lines) {
		return header
	}
	start = header
	for start > 0 && f.Lines[start-1].Kind == LineComment {
		start--
	}
	return start
}

// CommentText は、付随するコメントをテキストとして返す。各行から先頭の '#' と、
// その直後の空白ひとつを取り除く。
//
// マーカーを取り除くのは、エディタに、それを運ぶ構文ではなくユーザーが書いた
// ものを見せるためである。戻すときには RenderComment が付け直す。"#" だけの
// コメント行はテキスト上では空行になる。これにより、コメントブロック内の意図的な
// 空行が往復を生き延びる。
func (f *File) CommentText(header int) string {
	start := f.CommentRun(header)
	if start == header {
		return ""
	}
	lines := make([]string, 0, header-start)
	for _, line := range f.Lines[start:header] {
		text := strings.TrimLeft(line.Text, " \t")
		text = strings.TrimSuffix(strings.TrimSuffix(text, "\n"), "\r")
		text = strings.TrimPrefix(text, "#")
		lines = append(lines, strings.TrimPrefix(text, " "))
	}
	return strings.Join(lines, "\n")
}

// RenderComment は、コメントテキストを設定行に戻す。
//
// すべての行に "# " を前置する。空行も含むが、末尾に空白を持ち込まないよう、
// 空行だけは "# " ではなく "#" と書く。すでに '#' で始まるテキストに二重の
// マーカーは付けない。"## section" と打ったユーザーはそう書きたいのであり、
// 付け直せば保存のたびにマーカーが増えていってしまう。
func RenderComment(text, indent, ending string) []Line {
	if text == "" {
		return nil
	}
	parts := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	lines := make([]Line, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimRight(part, " \t")
		var body string
		switch {
		case trimmed == "":
			body = "#"
		case strings.HasPrefix(trimmed, "#"):
			body = trimmed
		default:
			body = "# " + trimmed
		}
		lines = append(lines, Line{Kind: LineComment, Text: indent + body + ending})
	}
	return lines
}
