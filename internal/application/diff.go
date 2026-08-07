package application

import (
	"strings"

	"sshc/internal/storage"
)

// MaxDiffLines は二次関数的な最長共通部分列テーブルを
// 制限する。これを超えるファイルは Truncated を立てた
// 全面置換として報告され、UI は最小差分を装わずに済む。
const MaxDiffLines = 4000

// DiffOp は保存プレビューの 1 行を分類する。
type DiffOp string

const (
	DiffContext DiffOp = "context"
	DiffInsert  DiffOp = "insert"
	DiffDelete  DiffOp = "delete"
)

// DiffLine は表示される 1 行である。OldLine と NewLine は
// 1 始まりで、行が片側にしか無いときは 0 になる。
type DiffLine struct {
	Op      DiffOp `json:"op"`
	Text    string `json:"text"`
	OldLine int    `json:"oldLine,omitempty"`
	NewLine int    `json:"newLine,omitempty"`
}

// FileDiff は保留中のトランザクションにおける 1 ファイルのプレビューである。
type FileDiff struct {
	Path      string     `json:"path"`
	Created   bool       `json:"created,omitempty"`
	Removed   bool       `json:"removed,omitempty"`
	OldDigest string     `json:"oldDigest,omitempty"`
	NewDigest string     `json:"newDigest,omitempty"`
	Lines     []DiffLine `json:"lines"`
	Truncated bool       `json:"truncated,omitempty"`
}

// ConflictReport は、ディスク上のファイルがユーザーが
// 編集した対象と異なる場合に設計 §9 が要求する三者間ビューである。
type ConflictReport struct {
	Path           string     `json:"path"`
	BaseDigest     string     `json:"baseDigest,omitempty"`
	DiskDigest     string     `json:"diskDigest,omitempty"`
	ExternalChange []DiffLine `json:"externalChange"`
	LocalChange    []DiffLine `json:"localChange"`
}

// SplitLines は表示用にファイル内容を分割する。最終行の改行と
// CRLF ファイルの復帰文字を落とすのは diff ビューがテキストを
// 見せるためで、ディスクへ書くバイト列は常に構文木由来である。
func SplitLines(contents []byte) []string {
	if len(contents) == 0 {
		return nil
	}
	text := strings.TrimSuffix(string(contents), "\n")
	parts := strings.Split(text, "\n")
	for index := range parts {
		parts[index] = strings.TrimSuffix(parts[index], "\r")
	}
	return parts
}

// DiffLines は最長共通部分列によって最小の行差分を計算する。
func DiffLines(before, after []string) []DiffLine {
	if len(before) > MaxDiffLines || len(after) > MaxDiffLines {
		return replacementDiff(before, after)
	}
	table := make([][]int, len(before)+1)
	for index := range table {
		table[index] = make([]int, len(after)+1)
	}
	for beforeIndex := len(before) - 1; beforeIndex >= 0; beforeIndex-- {
		for afterIndex := len(after) - 1; afterIndex >= 0; afterIndex-- {
			switch {
			case before[beforeIndex] == after[afterIndex]:
				table[beforeIndex][afterIndex] = table[beforeIndex+1][afterIndex+1] + 1
			case table[beforeIndex+1][afterIndex] >= table[beforeIndex][afterIndex+1]:
				table[beforeIndex][afterIndex] = table[beforeIndex+1][afterIndex]
			default:
				table[beforeIndex][afterIndex] = table[beforeIndex][afterIndex+1]
			}
		}
	}

	lines := make([]DiffLine, 0, len(before)+len(after))
	beforeIndex, afterIndex := 0, 0
	for beforeIndex < len(before) && afterIndex < len(after) {
		switch {
		case before[beforeIndex] == after[afterIndex]:
			lines = append(lines, DiffLine{Op: DiffContext, Text: before[beforeIndex], OldLine: beforeIndex + 1, NewLine: afterIndex + 1})
			beforeIndex++
			afterIndex++
		case table[beforeIndex+1][afterIndex] >= table[beforeIndex][afterIndex+1]:
			lines = append(lines, DiffLine{Op: DiffDelete, Text: before[beforeIndex], OldLine: beforeIndex + 1})
			beforeIndex++
		default:
			lines = append(lines, DiffLine{Op: DiffInsert, Text: after[afterIndex], NewLine: afterIndex + 1})
			afterIndex++
		}
	}
	for ; beforeIndex < len(before); beforeIndex++ {
		lines = append(lines, DiffLine{Op: DiffDelete, Text: before[beforeIndex], OldLine: beforeIndex + 1})
	}
	for ; afterIndex < len(after); afterIndex++ {
		lines = append(lines, DiffLine{Op: DiffInsert, Text: after[afterIndex], NewLine: afterIndex + 1})
	}
	return lines
}

func replacementDiff(before, after []string) []DiffLine {
	lines := make([]DiffLine, 0, len(before)+len(after))
	for index, text := range before {
		lines = append(lines, DiffLine{Op: DiffDelete, Text: text, OldLine: index + 1})
	}
	for index, text := range after {
		lines = append(lines, DiffLine{Op: DiffInsert, Text: text, NewLine: index + 1})
	}
	return lines
}

// BuildFileDiff は 1 ファイルの変更をプレビューする。
func BuildFileDiff(path string, before, after []byte) FileDiff {
	beforeLines := SplitLines(before)
	afterLines := SplitLines(after)
	diff := FileDiff{
		Path:      path,
		Created:   before == nil,
		Removed:   after == nil,
		Lines:     DiffLines(beforeLines, afterLines),
		Truncated: len(beforeLines) > MaxDiffLines || len(afterLines) > MaxDiffLines,
	}
	if before != nil {
		diff.OldDigest = storage.Digest(before)
	}
	if after != nil {
		diff.NewDigest = storage.Digest(after)
	}
	return diff
}

// BuildConflictReport は外部での変更を説明する: 他の書き手がベースに対して
// 行ったことと、ユーザーの保留中の編集が同じベースに対して行っていたはずのことである。
func BuildConflictReport(path string, base, disk, edited []byte) ConflictReport {
	return ConflictReport{
		Path:           path,
		BaseDigest:     storage.Digest(base),
		DiskDigest:     storage.Digest(disk),
		ExternalChange: DiffLines(SplitLines(base), SplitLines(disk)),
		LocalChange:    DiffLines(SplitLines(base), SplitLines(edited)),
	}
}
