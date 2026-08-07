package application

import (
	"errors"
	"path"
	"strings"
	"testing"
)

// グループは 1 つの Include 行だけによって読まれるので、この
// アプリケーションがグループに入れるファイルは、その行が一致する
// 名前を持たなければならない。まだ .conf ファイルでないソースから
// 宛先名を導出すると — 何よりもエントリファイル "config" は、宣言され
// ていないすべての connection の起点だが — OpenSSH が決して読まないファイルを書いてしまう。
func TestGroupFileNameIsAlwaysReadByTheGroupInclude(t *testing.T) {
	const group = "work"
	pattern := GroupIncludePattern(group)
	for _, source := range []string{"config", "10-home.conf", "hosts", "notes.txt", ".conf"} {
		derived := GroupFileName(source)
		matched, err := path.Match(pattern, GroupDirectory(group)+"/"+derived)
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Errorf("GroupFileName(%q) = %q, which %q does not read", source, derived, pattern)
		}
	}
}

func TestGroupFileNameKeepsANameTheIncludeAlreadyReads(t *testing.T) {
	if derived := GroupFileName("10-home.conf"); derived != "10-home.conf" {
		t.Errorf("GroupFileName = %q, want the name unchanged", derived)
	}
}

func TestValidateGroupNameRefusesEverythingThatIsNotASafeRelativeDirectory(t *testing.T) {
	accepted := []string{"work", "work/eu", "a-b_c.d", "Work", "x", strings.Repeat("a", 64)}
	for _, name := range accepted {
		if err := ValidateGroupName(name); err != nil {
			t.Errorf("ValidateGroupName(%q) = %v, want nil", name, err)
		}
	}

	refused := []string{
		"",             // グループには名前が必要
		"/work",        // 絶対パス
		"work/",        // 末尾の空セグメント
		"work//eu",     // 途中の空セグメント
		".",            // connections ディレクトリ自体
		"..",           // その上位
		"work/..",      // traverse による同じもの
		"work/../home", // クリーンにすると隠れてしまうもの
		"work\x00eu",   // NUL はパスに決して現れない
		".hidden",      // 先頭のドットは ~/.ssh が自分のファイルを隠す方法
		"work/.hidden", // どの深さでも
		"sshc",         // エンジン自身の状態ディレクトリ
		"SSHC",         // 大小文字を区別しないボリューム上の同じファイル
		"Config",       // アプリケーションが依存する名前
		"known_hosts",  //
		"authorized_keys",
		strings.Repeat("a", 65), // 制限より 1 セグメント長い
		"a/b/c/d/e/f/g",         // MaxGroupSegments より深い
		"work/eu/../..",         //
	}
	for _, name := range refused {
		if err := ValidateGroupName(name); !errors.Is(err, ErrInvalidGroupName) {
			t.Errorf("ValidateGroupName(%q) = %v, want ErrInvalidGroupName", name, err)
		}
	}
}

// MaxGroupSegments は別パッケージの制限に由来して存在するので、その
// 理由は、誰かが後で「整理」してしまう単なる数値として残すのではなく、明示的に検証する。
func TestMaxGroupSegmentsStaysInsideTheKeyScannerDepth(t *testing.T) {
	// keys/<segments…>/<file> は、~/.ssh から数えて
	// keys.maxScanDepth に収まらなければならない。さもなければ鍵は
	// depth_exceeded として報告され、一覧に載る代わりにインベントリから外れる。
	const keyScannerDepth = 8
	if 1+MaxGroupSegments+1 > keyScannerDepth {
		t.Fatalf("a key %d directories deep exceeds the scanner's %d", 1+MaxGroupSegments+1, keyScannerDepth)
	}
}

func TestGroupOfPathReadsMembershipFromTheDirectory(t *testing.T) {
	cases := []struct {
		path    string
		name    string
		inGroup bool
	}{
		{"connections/work/web.conf", "work", true},
		{"connections/work/eu/lon.conf", "work/eu", true},
		// connections/ の直下にあるファイルはどのグループにも属さない:
		// それに対して Include は生成されないので何にも読まれず、
		// そのために 4 番目の優先順位階層を作るのは、割に合わないほど説明が難しくなる。
		{"connections/loose.conf", "", false},
		{"conf.d/10.conf", "", false},
		{"config", "", false},
		{"sshc/metadata.json", "", false},
		{"connections", "", false},
	}
	for _, testCase := range cases {
		name, inGroup := GroupOfPath(testCase.path)
		if name != testCase.name || inGroup != testCase.inGroup {
			t.Errorf("GroupOfPath(%q) = (%q, %v), want (%q, %v)",
				testCase.path, name, inGroup, testCase.name, testCase.inGroup)
		}
	}
}

func TestGroupOfKeyPathReadsTheKeyDirectory(t *testing.T) {
	cases := []struct {
		path    string
		name    string
		inGroup bool
	}{
		{"keys/work/id_ed25519", "work", true},
		{"keys/work/eu/id_ed25519.pub", "work/eu", true},
		{"keys/loose_key", "", false},
		{"id_ed25519", "", false},
		{"connections/work/web.conf", "", false},
	}
	for _, testCase := range cases {
		name, inGroup := GroupOfKeyPath(testCase.path)
		if name != testCase.name || inGroup != testCase.inGroup {
			t.Errorf("GroupOfKeyPath(%q) = (%q, %v), want (%q, %v)",
				testCase.path, name, inGroup, testCase.name, testCase.inGroup)
		}
	}
}

func TestGroupDirectoriesAreWorkspaceRelativeAndSlashSeparated(t *testing.T) {
	if got := GroupDirectory("work/eu"); got != "connections/work/eu" {
		t.Errorf("GroupDirectory = %q", got)
	}
	if got := GroupKeyDirectory("work/eu"); got != "keys/work/eu" {
		t.Errorf("GroupKeyDirectory = %q", got)
	}
	if got := GroupIncludePattern("work/eu"); got != "connections/work/eu/*.conf" {
		t.Errorf("GroupIncludePattern = %q", got)
	}
}

func TestParentGroupNameIsTheParentDirectory(t *testing.T) {
	if got := ParentGroupName("work/eu/lon"); got != "work/eu" {
		t.Errorf("ParentGroupName = %q, want work/eu", got)
	}
	if got := ParentGroupName("work"); got != "" {
		t.Errorf("ParentGroupName of a top-level group = %q, want empty", got)
	}
	if got := GroupDepth("work/eu"); got != 2 {
		t.Errorf("GroupDepth = %d, want 2", got)
	}
}

func TestGroupNameOrderPutsChildrenBeforeParents(t *testing.T) {
	// OpenSSH は最初に読んだ値を保持するので、より深いグループの
	// Include が先に来なければ、親が自分の子に勝ってしまう。
	ordered := GroupNameOrder([]string{"work", "work/eu", "home"}, nil)
	want := []string{"work/eu", "home", "work"}
	if len(ordered) != len(want) {
		t.Fatalf("GroupNameOrder = %#v", ordered)
	}
	for index := range want {
		if ordered[index] != want[index] {
			t.Fatalf("GroupNameOrder = %#v, want %#v", ordered, want)
		}
	}
}

func TestGroupNameOrderBreaksADepthTieByOrderThenName(t *testing.T) {
	ordered := GroupNameOrder([]string{"alpha", "beta", "gamma"}, map[string]int{"gamma": -1})
	want := []string{"gamma", "alpha", "beta"}
	for index := range want {
		if ordered[index] != want[index] {
			t.Fatalf("GroupNameOrder = %#v, want %#v", ordered, want)
		}
	}
}
