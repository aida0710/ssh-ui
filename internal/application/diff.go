package application

import (
	"strings"

	"ssh-ui/internal/storage"
)

// MaxDiffLines bounds the quadratic longest-common-subsequence table. A file
// larger than this is reported as a wholesale replacement with Truncated set,
// so the UI can say so instead of pretending to show a minimal diff.
const MaxDiffLines = 4000

// DiffOp classifies one line of a save preview.
type DiffOp string

const (
	DiffContext DiffOp = "context"
	DiffInsert  DiffOp = "insert"
	DiffDelete  DiffOp = "delete"
)

// DiffLine is one displayed line. OldLine and NewLine are 1-based and zero when
// the line exists on only one side.
type DiffLine struct {
	Op      DiffOp `json:"op"`
	Text    string `json:"text"`
	OldLine int    `json:"oldLine,omitempty"`
	NewLine int    `json:"newLine,omitempty"`
}

// FileDiff is the preview of one file in a pending transaction.
type FileDiff struct {
	Path      string     `json:"path"`
	Created   bool       `json:"created,omitempty"`
	Removed   bool       `json:"removed,omitempty"`
	OldDigest string     `json:"oldDigest,omitempty"`
	NewDigest string     `json:"newDigest,omitempty"`
	Lines     []DiffLine `json:"lines"`
	Truncated bool       `json:"truncated,omitempty"`
}

// ConflictReport is the three-way view design §9 requires when the file on disk
// is no longer the file the user edited.
type ConflictReport struct {
	Path           string     `json:"path"`
	BaseDigest     string     `json:"baseDigest,omitempty"`
	DiskDigest     string     `json:"diskDigest,omitempty"`
	ExternalChange []DiffLine `json:"externalChange"`
	LocalChange    []DiffLine `json:"localChange"`
}

// SplitLines splits file contents for display. It drops the final newline and
// the carriage returns of CRLF files, because the diff view shows text; the
// bytes written to disk always come from the syntax tree, never from here.
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

// DiffLines computes a minimal line diff through a longest common subsequence.
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

// BuildFileDiff previews one file change.
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

// BuildConflictReport explains an external change: what the other writer did to
// the base, and what the user's pending edit would have done to the same base.
func BuildConflictReport(path string, base, disk, edited []byte) ConflictReport {
	return ConflictReport{
		Path:           path,
		BaseDigest:     storage.Digest(base),
		DiskDigest:     storage.Digest(disk),
		ExternalChange: DiffLines(SplitLines(base), SplitLines(disk)),
		LocalChange:    DiffLines(SplitLines(base), SplitLines(edited)),
	}
}
