package config

import "strings"

// File は解析済みの設定ファイル。変更していない File をレンダリングすると、元の
// バイト列がそのまま返る。
type File struct {
	Lines []Line
}

// Parse は source を行に分割し、それぞれを分類する。Parse は決して失敗しない。
// 分解できない入力は LineUnstructured として保存される。
func Parse(source []byte) *File {
	file := &File{}
	remaining := string(source)
	for len(remaining) > 0 {
		content, ending, rest := splitLine(remaining)
		file.Lines = append(file.Lines, parseLine(content, ending))
		remaining = rest
	}
	return file
}

// Render はファイルの内容を返す。
func (f *File) Render() []byte {
	var builder strings.Builder
	for _, line := range f.Lines {
		builder.WriteString(line.Render())
	}
	return []byte(builder.String())
}

func splitLine(text string) (content, ending, rest string) {
	index := strings.IndexByte(text, '\n')
	if index < 0 {
		return text, "", ""
	}
	content, ending, rest = text[:index], "\n", text[index+1:]
	if strings.HasSuffix(content, "\r") {
		content, ending = content[:len(content)-1], "\r\n"
	}
	return content, ending, rest
}

func parseLine(content, ending string) Line {
	index := 0
	for index < len(content) && isSpace(content[index]) {
		index++
	}
	if index == len(content) {
		return Line{Kind: LineBlank, Text: content, Ending: ending}
	}
	if content[index] == '#' {
		return Line{Kind: LineComment, Text: content, Ending: ending}
	}

	indent := content[:index]
	keywordStart := index
	for index < len(content) && !isSpace(content[index]) && content[index] != '=' && content[index] != '"' {
		index++
	}
	keyword := content[keywordStart:index]
	if keyword == "" {
		return Line{Kind: LineUnstructured, Text: content, Ending: ending}
	}

	separatorStart := index
	for index < len(content) && isSpace(content[index]) {
		index++
	}
	if index < len(content) && content[index] == '=' {
		index++
		for index < len(content) && isSpace(content[index]) {
			index++
		}
	}
	separator := content[separatorStart:index]

	arguments, trailing, ok := splitArguments(content[index:])
	if !ok {
		return Line{Kind: LineUnstructured, Text: content, Ending: ending}
	}
	return Line{
		Kind:      LineDirective,
		Indent:    indent,
		Keyword:   keyword,
		Separator: separator,
		Arguments: arguments,
		Trailing:  trailing,
		Ending:    ending,
	}
}
