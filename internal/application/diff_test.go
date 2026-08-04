package application

import (
	"testing"

	"ssh-ui/internal/storage"
)

func TestBuildFileDiffMarksOnlyTheChangedLines(t *testing.T) {
	before := []byte("Host bastion\n\tUser ops\n\tPort 22\n")
	after := []byte("Host bastion\n\tUser ops\n\tPort 2222\n")

	diff := BuildFileDiff("config", before, after)
	if diff.Path != "config" || diff.Created || diff.Removed || diff.Truncated {
		t.Fatalf("diff = %#v", diff)
	}
	if diff.OldDigest != storage.Digest(before) || diff.NewDigest != storage.Digest(after) {
		t.Fatalf("digests = %q %q", diff.OldDigest, diff.NewDigest)
	}
	want := []DiffLine{
		{Op: DiffContext, Text: "Host bastion", OldLine: 1, NewLine: 1},
		{Op: DiffContext, Text: "\tUser ops", OldLine: 2, NewLine: 2},
		{Op: DiffDelete, Text: "\tPort 22", OldLine: 3},
		{Op: DiffInsert, Text: "\tPort 2222", NewLine: 3},
	}
	if len(diff.Lines) != len(want) {
		t.Fatalf("lines = %#v", diff.Lines)
	}
	for index := range want {
		if diff.Lines[index] != want[index] {
			t.Fatalf("line[%d] = %#v, want %#v", index, diff.Lines[index], want[index])
		}
	}
}

func TestBuildFileDiffReportsCreationAndTruncation(t *testing.T) {
	created := BuildFileDiff("groups.ssh-ui.conf", nil, []byte("Host build01\n\tUser ops\n"))
	if !created.Created || created.OldDigest != "" || len(created.Lines) != 2 {
		t.Fatalf("created diff = %#v", created)
	}
	if created.Lines[0].Op != DiffInsert {
		t.Fatalf("created lines = %#v", created.Lines)
	}

	large := make([]byte, 0, MaxDiffLines*8)
	for counter := 0; counter <= MaxDiffLines; counter++ {
		large = append(large, []byte("\tUser ops\n")...)
	}
	truncated := BuildFileDiff("config", large, append(large, []byte("\tPort 22\n")...))
	if !truncated.Truncated {
		t.Fatal("an oversized diff must be reported as truncated instead of silently trimmed")
	}
}

func TestBuildConflictReportShowsBothSidesOfAnExternalChange(t *testing.T) {
	base := []byte("Host bastion\n\tUser ops\n")
	disk := []byte("Host bastion\n\tUser ops\n\tPort 22\n")
	edited := []byte("Host bastion\n\tUser admin\n")

	report := BuildConflictReport("config", base, disk, edited)
	if report.Path != "config" || report.BaseDigest != storage.Digest(base) || report.DiskDigest != storage.Digest(disk) {
		t.Fatalf("report = %#v", report)
	}
	if len(report.ExternalChange) != 3 || report.ExternalChange[2].Op != DiffInsert {
		t.Fatalf("external change = %#v", report.ExternalChange)
	}
	if len(report.LocalChange) != 3 || report.LocalChange[1].Op != DiffDelete || report.LocalChange[2].Op != DiffInsert {
		t.Fatalf("local change = %#v", report.LocalChange)
	}
}

func TestSplitLinesDropsOnlyTheTrailingNewline(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"one", []string{"one"}},
		{"one\n", []string{"one"}},
		{"one\ntwo\n", []string{"one", "two"}},
		{"one\r\ntwo\r\n", []string{"one", "two"}},
		{"one\n\n", []string{"one", ""}},
	}
	for _, test := range tests {
		got := SplitLines([]byte(test.input))
		if len(got) != len(test.want) {
			t.Fatalf("SplitLines(%q) = %#v, want %#v", test.input, got, test.want)
		}
		for index := range test.want {
			if got[index] != test.want[index] {
				t.Fatalf("SplitLines(%q)[%d] = %q, want %q", test.input, index, got[index], test.want[index])
			}
		}
	}
}
