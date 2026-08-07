package config

import "testing"

func TestCommentRunStopsAtABlankLineSoAFileBannerIsNotAdopted(t *testing.T) {
	source := []byte("# Managed by hand since 2019. Do not reformat.\n" +
		"\n" +
		"# the production bastion\n" +
		"# ask infra before changing it\n" +
		"Host bastion\n" +
		"\tPort 2222\n")
	file := Parse(source)

	blocks := file.Blocks()
	var header int
	for _, block := range blocks {
		if block.Kind == BlockHost {
			header = block.Header
		}
	}
	if header != 4 {
		t.Fatalf("header = %d, want 4", header)
	}

	// バナーは空行の上にあるので、最初の Host ブロックではなくファイルに属する。
	// このブロックのコメントを編集しても、そこに触れてはならない。
	if got := file.CommentRun(header); got != 2 {
		t.Fatalf("CommentRun = %d, want 2", got)
	}
	if got := file.CommentText(header); got != "the production bastion\nask infra before changing it" {
		t.Fatalf("CommentText = %q", got)
	}
}

func TestCommentRunIsEmptyWhenADirectivePrecedesTheHeader(t *testing.T) {
	file := Parse([]byte("Host first\n\tPort 22\nHost second\n"))
	blocks := file.Blocks()
	header := blocks[len(blocks)-1].Header

	if got := file.CommentRun(header); got != header {
		t.Fatalf("CommentRun = %d, want %d", got, header)
	}
	if got := file.CommentText(header); got != "" {
		t.Fatalf("CommentText = %q, want empty", got)
	}
}

func TestCommentTextStripsTheMarkerAndKeepsADeliberateBlankLine(t *testing.T) {
	file := Parse([]byte("# first\n#\n# third\nHost nas\n"))

	if got := file.CommentText(3); got != "first\n\nthird" {
		t.Fatalf("CommentText = %q", got)
	}
}

func TestRenderCommentRoundTripsWhatCommentTextProduced(t *testing.T) {
	source := []byte("# first\n#\n# third\nHost nas\n")
	file := Parse(source)

	rendered := RenderComment(file.CommentText(3), "", "\n")
	if len(rendered) != 3 {
		t.Fatalf("rendered %d lines, want 3", len(rendered))
	}
	rebuilt := &File{Lines: append(rendered, file.Lines[3:]...)}
	if string(rebuilt.Render()) != string(source) {
		t.Fatalf("round trip = %q, want %q", rebuilt.Render(), source)
	}
}

func TestRenderCommentDoesNotGrowAMarkerOnTextThatAlreadyHasOne(t *testing.T) {
	// "## section" と打ったユーザーはそう書きたいのである。保存のたびに付け直すと、
	// ブロックを編集するごとに '#' がひとつずつ増えていく。
	lines := RenderComment("## section", "", "\n")
	if len(lines) != 1 || lines[0].Text != "## section\n" {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestRenderCommentWritesNoTrailingWhitespaceForABlankLine(t *testing.T) {
	lines := RenderComment("a\n\nb", "", "\n")
	if len(lines) != 3 {
		t.Fatalf("rendered %d lines, want 3", len(lines))
	}
	if lines[1].Text != "#\n" {
		t.Fatalf("blank comment line = %q, want %q", lines[1].Text, "#\n")
	}
}

func TestRenderCommentOfEmptyTextIsNothing(t *testing.T) {
	if lines := RenderComment("", "", "\n"); lines != nil {
		t.Fatalf("lines = %#v, want nil", lines)
	}
}
