package application

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/config"
)

// regionSource は、グループが宣言された後にすべてのエントリファイルが取る形である。
// 生成領域は最初の catch-all の手前に挿入されるので、その上にある具体的な
// ブロックの行範囲の内側に収まる——ブロックの範囲は次のヘッダーまで
// 及ぶので、生成領域はその 2 つの間に座ることになる。
const regionSource = `Host bastion
	User ops

` + RegionStartMarker + `
Include connections/work/*.conf
Include groups.sshc.conf
` + RegionEndMarker + `

Host *
	ServerAliveInterval 30
`

// 生成領域はエントリファイル自身の構造であり、どの connection の
// 一部でもない。移動するブロックと一緒に持ち去ると、一度にすべての
// グループを未宣言にしてしまう。エントリファイルには終端マーカーだけが残り、
// FindRegion はそれを damaged として拒否し、Include 行は、そのうちの
// 1 個が名指したことによってのみ読まれているファイルに行き着いてしまう。
func TestExtractHostBlockLeavesTheGeneratedRegionBehind(t *testing.T) {
	file := config.Parse([]byte(regionSource))
	extracted, err := ExtractHostBlock(file, "bastion")
	if err != nil {
		t.Fatal(err)
	}

	moved := string((&config.File{Lines: extracted}).Render())
	if strings.Contains(moved, RegionStartMarker) || strings.Contains(moved, "Include connections/") {
		t.Errorf("the moved block carried the generated region:\n%s", moved)
	}

	remaining := string(file.Render())
	if !strings.Contains(remaining, "Include connections/work/*.conf") {
		t.Errorf("the entry file stopped declaring its group:\n%s", remaining)
	}
	if _, _, found, regionErr := FindRegion(config.Parse([]byte(remaining))); !found || regionErr != nil {
		t.Errorf("FindRegion after the move = found %v, err %v:\n%s", found, regionErr, remaining)
	}
}

// moveSource は、move が手つかずのまま運び越さなければならない
// あらゆる構造——ヘッダーの上に付随するコメント、行末の inline コメント、
// ブロック内のコメント行、空行、そしてエンジンが分解できない行——を演習する。
//
// 先頭行はその下に空行を持たないので、これはファイル banner ではなく
// bastion に付随するコメントである。これはファイル全体を通じて成り立つ
// 規則である。ファイルの途中にある同じテキストはその下のブロックを
// 説明するのであり、先頭のブロックだけを特別扱いすると、同じ 2 行が
// 置かれた場所によって違うことを意味してしまう。
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

	// コメントは、それが説明していたブロックと共に去った。残していたら、
	// それは nas の説明になってしまっていただろう。
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
