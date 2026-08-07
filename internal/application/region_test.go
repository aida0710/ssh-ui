package application

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/config"
)

// planAndApply は、呼び出し側が行うことのすべてなので、テストは誰も読まない
// plan struct ではなく、生成されたバイト列に対して assert する。ワイルドカードで
func planAndApply(t *testing.T, source string, groups []string) (string, error) {
	t.Helper()
	file := config.Parse([]byte(source))
	plan, err := PlanRegion(file, groups, DefaultGroupsFile)
	if err != nil {
		return "", err
	}
	if applyErr := ApplyRegion(file, plan); applyErr != nil {
		t.Fatalf("ApplyRegion error = %v", applyErr)
	}
	return string(file.Render()), nil
}

const expectedRegion = `# >>> sshc groups (generated). Child groups first: OpenSSH keeps the first value it reads.
# Edit through the UI; lines between these markers are replaced on the next save.
Include connections/work/eu/*.conf
Include connections/work/*.conf
Include connections/home/*.conf
Include groups.sshc.conf
# <<< sshc groups
`

func TestPlanRegionEmitsOneIncludePerGroupChildFirst(t *testing.T) {
	// はなくグループごとに 1 行である。'*' は区切り文字を越えないので、
	// connections/work/*.conf が connections/work/eu/lon.conf に届くことは決してない。
	rendered, err := planAndApply(t, "", []string{"work/eu", "work", "home"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if rendered != expectedRegion {
		t.Errorf("region =\n%s\nwant\n%s", rendered, expectedRegion)
	}
}

// Host 行の下に書かれた Include はそのブロックに属する。OpenSSH はいずれにせよ include
// されたファイルを parse する——debug 出力はそれについて"Reading configuration data"
// と言う——が、その option を適用するのはブロックが match するときだけである。
// OpenSSH 10.2p1 で確認した。top-level の Include は適用され、同じ行を Host 行の下に
// 移動すると適用されず、その間に空行を入れても何も変わらない。
//
// したがって、生成領域が何かを宣言する位置はちょうど 1 個しかない。
// エントリファイル内のすべての Host および Match 行の上である。それ以外の
// どこであっても、グループは無関係な 1 個のホストに接続するときにしか
// 読まれず、それは宣言されていないことと見分けがつかない。
func TestPlanRegionPutsTheRegionAboveEveryHostBlock(t *testing.T) {
	source := "# a banner\n\nHost bastion\n\tUser ops\n\nHost *\n\tServerAliveInterval 30\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	region := strings.Index(rendered, RegionStartMarker)
	firstHost := strings.Index(rendered, "Host ")
	if region < 0 {
		t.Fatalf("no region was written:\n%s", rendered)
	}
	if firstHost < region {
		t.Errorf("the region sits below a Host line, where its Includes are conditional:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Host bastion\n\tUser ops\n") || !strings.Contains(rendered, "Host *\n\tServerAliveInterval 30\n") {
		t.Errorf("the user's own blocks were disturbed:\n%s", rendered)
	}
}

// 生成領域は、最初のブロックに付随するコメントとそれが説明する Host 行
// の間にではなく、そのコメントの上に置かれる。
func TestPlanRegionDoesNotSeparateTheFirstBlockFromItsComment(t *testing.T) {
	source := "# the bastion, reachable from the office only\nHost bastion\n\tUser ops\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.HasSuffix(rendered, source) {
		t.Errorf("the comment was severed from its block:\n%s", rendered)
	}
}

func TestPlanRegionAppendsWhenTheFileDeclaresNoBlockAtAll(t *testing.T) {
	source := "# personal configuration\nInclude conf.d/*.conf\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.HasPrefix(rendered, source) {
		t.Errorf("the region did not go at the end:\n%s", rendered)
	}
	// Host も Match 行もどこにも無い場合でも、ファイルの末尾は依然として
	// global block なので、追記は無条件である。
	if !strings.HasSuffix(rendered, RegionEndMarker+"\n") {
		t.Errorf("the region did not close at the end:\n%s", rendered)
	}
}

// Include 行が条件付きになる場所に書かれた生成領域は、その場で置き
// 換えるのではなく移動しなければならない。これは、以前のバージョン
// で構築されたすべてのワークスペースが置かれている形である。生成領域はエントリファイル
// の末尾に追記され、それによって最後の Host ブロックの内側に入ってしまっていた。
func TestPlanRegionMovesARegionThatSitsInsideAHostBlock(t *testing.T) {
	source := "Host bastion\n\tUser ops\n\n" + RegionStartMarker + "\n" +
		"Include connections/work/*.conf\nInclude groups.sshc.conf\n" + RegionEndMarker + "\n"

	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	region := strings.Index(rendered, RegionStartMarker)
	firstHost := strings.Index(rendered, "Host ")
	if region < 0 || firstHost < region {
		t.Errorf("the region was left where OpenSSH reads it conditionally:\n%s", rendered)
	}
	if strings.Count(rendered, RegionStartMarker) != 1 || strings.Count(rendered, RegionEndMarker) != 1 {
		t.Errorf("the region was duplicated rather than moved:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Host bastion\n\tUser ops\n") {
		t.Errorf("the block the region was sitting in was disturbed:\n%s", rendered)
	}
}

func TestPlanRegionRefusesWhenAnExistingIncludeAlreadyReachesTheConnectionsTree(t *testing.T) {
	source := "Include connections/work/*.conf\nHost *\n\tUser ops\n"
	file := config.Parse([]byte(source))

	if _, err := PlanRegion(file, []string{"work"}, DefaultGroupsFile); !errors.Is(err, ErrRegionIncludeAlreadyPresent) {
		t.Fatalf("PlanRegion error = %v, want ErrRegionIncludeAlreadyPresent", err)
	}
}

func TestPlanRegionIgnoresAConditionalIncludeOfTheGroupsFile(t *testing.T) {
	// Host ブロックの内側にある Include は、そのホストに接続するときにしか
	// 読まれない。それを存在するものとして数えると、generated settings ファイルが
	// 他のどこからも到達不能になってしまい、これは以前の planner が行っていたことである。
	source := "Host bastion\n\tInclude groups.sshc.conf\n"
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if !strings.Contains(rendered, "\nInclude groups.sshc.conf\n") {
		t.Errorf("no top-level Include was planned:\n%s", rendered)
	}
}

func TestPlanRegionReplacesAnExistingRegionInPlace(t *testing.T) {
	first, err := planAndApply(t, "Host bastion\n\tUser ops\nHost *\n\tUser me\n", []string{"work"})
	if err != nil {
		t.Fatalf("first plan error = %v", err)
	}
	second, err := planAndApply(t, first, []string{"work/eu", "work"})
	if err != nil {
		t.Fatalf("second plan error = %v", err)
	}

	if !strings.Contains(second, "Include connections/work/eu/*.conf\nInclude connections/work/*.conf\n") {
		t.Errorf("the new group was not added in order:\n%s", second)
	}
	if strings.Count(second, RegionStartMarker) != 1 || strings.Count(second, RegionEndMarker) != 1 {
		t.Errorf("the region was duplicated:\n%s", second)
	}
	// 生成領域は今やファイルの先頭に来るので、変わってはならないのは
	// その下のすべてである。置き換えは mark された行だけを書き換え、他は何も変えない。
	if !strings.HasSuffix(second, "Host bastion\n\tUser ops\nHost *\n\tUser me\n") {
		t.Errorf("bytes outside the region changed:\n%s", second)
	}
}

func TestFindRegionRefusesAHalfMarkedRegion(t *testing.T) {
	for _, source := range []string{
		RegionStartMarker + "\nInclude groups.sshc.conf\n",
		"Include groups.sshc.conf\n" + RegionEndMarker + "\n",
	} {
		if _, _, _, err := FindRegion(config.Parse([]byte(source))); !errors.Is(err, ErrRegionDamaged) {
			t.Errorf("FindRegion(%q) error = %v, want ErrRegionDamaged", source, err)
		}
	}
}

func TestPlanRegionPreservesCRLF(t *testing.T) {
	rendered, err := planAndApply(t, "Host bastion\r\n\tUser ops\r\n", []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}
	if strings.Contains(strings.ReplaceAll(rendered, "\r\n", ""), "\n") {
		t.Errorf("a lone newline was introduced into a CRLF file: %q", rendered)
	}
}

func TestApplyRegionChangesNothingOutsideTheMarkers(t *testing.T) {
	// parser が正規化せずに保つあらゆる形——banner、key=value の綴り方、
	// 連続する空白、そのまま保たれる unbalanced な引用符。
	source := strings.Join([]string{
		"# hand written, do not reformat",
		"",
		"Host bastion",
		"\tHostName=203.0.113.10",
		"\tUser    ops",
		"\tProxyCommand \"unbalanced",
		"",
		"Host *",
		"\tServerAliveInterval 30",
		"",
	}, "\n")
	rendered, err := planAndApply(t, source, []string{"work"})
	if err != nil {
		t.Fatalf("PlanRegion error = %v", err)
	}

	start := strings.Index(rendered, RegionStartMarker)
	end := strings.Index(rendered, RegionEndMarker) + len(RegionEndMarker) + 1
	if start < 0 || end <= start {
		t.Fatalf("no region in:\n%s", rendered)
	}
	if rendered[:start]+rendered[end:] != source {
		t.Errorf("bytes outside the region changed:\n%q\nwant\n%q", rendered[:start]+rendered[end:], source)
	}
}
