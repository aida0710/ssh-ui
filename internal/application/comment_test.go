package application

import (
	"strings"
	"testing"

	"sshc/internal/config"
)

func TestSetHostCommentReplacesOnlyTheAttachedRun(t *testing.T) {
	source := "# Managed by hand since 2019. Do not reformat.\n" +
		"\n" +
		"# old note\n" +
		"Host bastion\n" +
		"\tPort 2222\n" +
		"\n" +
		"Host nas\n"
	file := config.Parse([]byte(source))
	block, ok := FindHostBlock(file, "bastion")
	if !ok {
		t.Fatalf("bastion block not found")
	}

	if err := SetHostComment(file, block, "the production bastion\nask infra first"); err != nil {
		t.Fatalf("SetHostComment error = %v", err)
	}

	got := string(file.Render())
	// The banner above the blank line is untouched, and so is every byte after
	// the Host line.
	if !strings.HasPrefix(got, "# Managed by hand since 2019. Do not reformat.\n\n") {
		t.Fatalf("the file banner was rewritten:\n%s", got)
	}
	if !strings.Contains(got, "# the production bastion\n# ask infra first\nHost bastion\n\tPort 2222\n") {
		t.Fatalf("comment not written as expected:\n%s", got)
	}
	if strings.Contains(got, "old note") {
		t.Fatalf("the previous comment survived:\n%s", got)
	}
	if !strings.HasSuffix(got, "\nHost nas\n") {
		t.Fatalf("the rest of the file moved:\n%s", got)
	}
}

func TestSetHostCommentToEmptyRemovesTheLines(t *testing.T) {
	file := config.Parse([]byte("# a\n# b\nHost nas\n\tPort 22\n"))
	block, _ := FindHostBlock(file, "nas")

	if err := SetHostComment(file, block, ""); err != nil {
		t.Fatalf("SetHostComment error = %v", err)
	}
	if got := string(file.Render()); got != "Host nas\n\tPort 22\n" {
		t.Fatalf("render = %q", got)
	}
}

func TestSetHostCommentKeepsTheHostLineIndent(t *testing.T) {
	file := config.Parse([]byte("Match host lab\n\tHost inner\n"))
	blocks := file.Blocks()
	block := blocks[len(blocks)-1]

	if err := SetHostComment(file, block, "indented"); err != nil {
		t.Fatalf("SetHostComment error = %v", err)
	}
	if got := string(file.Render()); got != "Match host lab\n\t# indented\n\tHost inner\n" {
		t.Fatalf("render = %q", got)
	}
}

func TestClearHostNoteKeepsEveryOtherFieldAndEntry(t *testing.T) {
	target := HostIdentity{Path: "config", Alias: "bastion"}
	metadata := Metadata{
		SchemaVersion: MetadataSchemaVersion,
		Hosts: []HostMetadata{
			{Identity: target, Note: "gone", Colour: "#f97316", Favourite: true},
			{Identity: HostIdentity{Path: "config", Alias: "nas"}, Note: "kept"},
		},
	}

	cleared := ClearHostNote(metadata, target)

	if len(cleared.Hosts) != 2 {
		t.Fatalf("hosts = %#v", cleared.Hosts)
	}
	if cleared.Hosts[0].Note != "" || cleared.Hosts[0].Colour != "#f97316" || !cleared.Hosts[0].Favourite {
		t.Fatalf("the target entry lost more than its note: %#v", cleared.Hosts[0])
	}
	if cleared.Hosts[1].Note != "kept" {
		t.Fatalf("another host's note was cleared: %#v", cleared.Hosts[1])
	}
	// The input must not be mutated: the planner still needs it if the save is
	// refused before it commits.
	if metadata.Hosts[0].Note != "gone" {
		t.Fatalf("ClearHostNote mutated its argument")
	}
}

func TestClearHostNoteDropsAnEntryThatHeldNothingElse(t *testing.T) {
	target := HostIdentity{Path: "config", Alias: "bastion"}
	cleared := ClearHostNote(Metadata{
		SchemaVersion: MetadataSchemaVersion,
		Hosts:         []HostMetadata{{Identity: target, Note: "only this"}},
	}, target)

	if len(cleared.Hosts) != 0 {
		t.Fatalf("hosts = %#v, want the empty entry dropped", cleared.Hosts)
	}
}

// Making the comment above a header mean something changed what a move must
// carry. Left behind, the description of the block that departed becomes the
// description of whichever block follows it in the source file.
func TestExtractHostBlockTakesTheAttachedCommentWithIt(t *testing.T) {
	file := config.Parse([]byte(
		"# the production bastion\n" +
			"Host bastion\n" +
			"\tPort 2222\n" +
			"\n" +
			"# the file server\n" +
			"Host nas\n"))

	extracted, err := ExtractHostBlock(file, "bastion")
	if err != nil {
		t.Fatalf("ExtractHostBlock error = %v", err)
	}

	moved := &config.File{Lines: extracted}
	if got := string(moved.Render()); got != "# the production bastion\nHost bastion\n\tPort 2222\n\n" {
		t.Fatalf("extracted = %q", got)
	}
	remaining := string(file.Render())
	if strings.Contains(remaining, "the production bastion") {
		t.Fatalf("the departed block's comment was left behind:\n%s", remaining)
	}
	// nas keeps its own, and does not inherit one.
	if remaining != "# the file server\nHost nas\n" {
		t.Fatalf("remaining = %q", remaining)
	}
}

func TestExtractHostBlockLeavesAFileBannerBehind(t *testing.T) {
	file := config.Parse([]byte(
		"# Managed by hand. Do not reformat.\n" +
			"\n" +
			"Host bastion\n" +
			"\tPort 2222\n"))

	if _, err := ExtractHostBlock(file, "bastion"); err != nil {
		t.Fatalf("ExtractHostBlock error = %v", err)
	}

	// The banner is separated by a blank line, so it belongs to the file and
	// stays with it.
	if got := string(file.Render()); got != "# Managed by hand. Do not reformat.\n\n" {
		t.Fatalf("remaining = %q", got)
	}
}
