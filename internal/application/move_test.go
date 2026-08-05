package application

import (
	"errors"
	"strings"
	"testing"

	"ssh-ui/internal/config"
)

// moveSource exercises every construct the move must carry across untouched:
// the comment attached above the header, an inline trailing comment, a comment
// line inside the block, blank lines and a line the engine cannot decompose.
//
// The first line has no blank line under it, so it is bastion's attached
// comment and not a file banner. That is the rule everywhere in the file: the
// same text in the middle of a file describes the block below it, and making
// the first block special would mean the same two lines meant different things
// depending on where they sat.
const moveSource = `# the comment attached to bastion
Host bastion
	User ops	# inline
	# comment inside the block

	SetEnv "broken

Host nas
	User aida
`

const movedBlock = "# the comment attached to bastion\nHost bastion\n\tUser ops\t# inline\n\t# comment inside the block\n\n\tSetEnv \"broken\n\n"

func TestMoveHostBlockCarriesTheBlockByteForByte(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host web\n\tUser www\n"))

	moved, err := MoveHostBlock(source, destination, "bastion")
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 7 {
		t.Fatalf("moved %d lines, want the attached comment, the header and five owned lines", len(moved))
	}

	// The comment left with the block it described. Leaving it would have made
	// it nas's description.
	const wantSource = "Host nas\n\tUser aida\n"
	if got := string(source.Render()); got != wantSource {
		t.Fatalf("source =\n%q\nwant\n%q", got, wantSource)
	}
	const wantDestination = "Host web\n\tUser www\n\n" + movedBlock
	if got := string(destination.Render()); got != wantDestination {
		t.Fatalf("destination =\n%q\nwant\n%q", got, wantDestination)
	}
	if !strings.Contains(moveSource, movedBlock) {
		t.Fatal("the fixture no longer contains the moved block verbatim")
	}
	if !strings.Contains(string(destination.Render()), movedBlock) {
		t.Fatal("the destination did not receive the block byte for byte")
	}
}

func TestMoveHostBlockKeepsUnstructuredLinesUnstructured(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host web\n\tUser www\n"))

	if _, err := MoveHostBlock(source, destination, "bastion"); err != nil {
		t.Fatal(err)
	}
	unstructured := 0
	for _, line := range destination.Lines {
		if line.Kind == config.LineUnstructured {
			unstructured++
			if line.Text != "\tSetEnv \"broken" {
				t.Fatalf("unstructured line = %q", line.Text)
			}
		}
	}
	if unstructured != 1 {
		t.Fatalf("destination has %d unstructured lines, want 1", unstructured)
	}
}

func TestMoveHostBlockRefusesADuplicateAliasInTheDestination(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host bastion\n\tUser other\n"))

	if _, err := MoveHostBlock(source, destination, "bastion"); !errors.Is(err, ErrDuplicateDestinationAlias) {
		t.Fatalf("error = %v, want ErrDuplicateDestinationAlias", err)
	}
	if got := string(source.Render()); got != moveSource {
		t.Fatal("a refused move must leave the source untouched")
	}
	if got := string(destination.Render()); got != "Host bastion\n\tUser other\n" {
		t.Fatal("a refused move must leave the destination untouched")
	}
}

func TestMoveHostBlockRefusesAnUnknownAlias(t *testing.T) {
	source := config.Parse([]byte(moveSource))
	destination := config.Parse([]byte("Host web\n\tUser www\n"))

	if _, err := MoveHostBlock(source, destination, "absent"); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("error = %v, want ErrHostNotFound", err)
	}
	if got := string(source.Render()); got != moveSource {
		t.Fatal("a refused move must leave the source untouched")
	}
}

func TestAppendHostBlockDoesNotDoubleTheSeparatorOrLoseAFinalNewline(t *testing.T) {
	moved := config.Parse([]byte("Host bastion\n\tUser ops\n")).Lines

	endsBlank := config.Parse([]byte("Host web\n\tUser www\n\n"))
	AppendHostBlock(endsBlank, moved)
	if got := string(endsBlank.Render()); got != "Host web\n\tUser www\n\nHost bastion\n\tUser ops\n" {
		t.Fatalf("blank-terminated destination = %q", got)
	}

	noFinalNewline := config.Parse([]byte("Host web\n\tUser www"))
	AppendHostBlock(noFinalNewline, moved)
	if got := string(noFinalNewline.Render()); got != "Host web\n\tUser www\n\nHost bastion\n\tUser ops\n" {
		t.Fatalf("unterminated destination = %q", got)
	}

	empty := config.Parse(nil)
	AppendHostBlock(empty, moved)
	if got := string(empty.Render()); got != "Host bastion\n\tUser ops\n" {
		t.Fatalf("empty destination = %q", got)
	}
}
