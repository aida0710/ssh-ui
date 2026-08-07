package application

import (
	"errors"
	"strings"

	"sshc/internal/config"
)

// 生成領域は 2 本のコメント行で区切られる。これらは普通の
// OpenSSH コメントなので、このアプリケーションのことを聞いたことの
// ない読者でも、そのブロックが何であり、編集しても意味がないことが分かる。
const (
	RegionStartMarker = "# >>> sshc groups (generated). Child groups first: OpenSSH keeps the first value it reads."
	RegionEndMarker   = "# <<< sshc groups"
	regionNote        = "# Edit through the UI; lines between these markers are replaced on the next save."
)

var (
	// ErrRegionDamaged は、2 個のマーカーのうち片方しか持たない生成領域を報告する。
	ErrRegionDamaged = errors.New("the generated group region has only one of its markers")
	// ErrRegionIncludeAlreadyPresent は、connections tree または generated
	// グループファイルに既に届いている、ユーザーが書いた Include を報告する。
	ErrRegionIncludeAlreadyPresent = errors.New("an existing Include already reaches the generated group files")
)

// 生成領域 planner が生成する Notice code である。
const (
	NoticeGroupIncludePresent = "group_include_already_present"
	// NoticeRegionDamaged は、2 個のマーカーのうち片方しか持たない
	// 生成領域を報告する。これはそれ自体の事実であり、グループ側の
	// 問題ではない。DeclaredGroups は生成領域を読み、damaged な生成領域は
	// 何も宣言しないので、この通知が無ければ宣言済みのすべてのグループ
	// が未宣言に見え、Include 行がまさにそこにあって機能しているディレクトリ
	// についてまで、画面が"no Include line names this directory"で埋め尽くされてしまう。
	NoticeRegionDamaged = "generated_region_damaged"
)

// RegionPlan は、生成領域を設置する編集を記述する。
//
// ReplaceFrom/ReplaceTo は、生成領域が本来あるべき場所に既に存在する
// 場合の、既存行の半開区間である。RemoveFrom/RemoveTo は、生成領域を
// 取り出して別の場所に書かなければならない場合の同じ区間である。
// このとき InsertAt は、その区間が既に取り除かれた状態のファイルへの
// index となる。それ以外の場合は、行は InsertAt に挿入される。
type RegionPlan struct {
	InsertAt    int
	ReplaceFrom int
	ReplaceTo   int
	Replacing   bool
	RemoveFrom  int
	RemoveTo    int
	Removing    bool
	Lines       []config.Line
}

// FindRegion は、マーカーによって生成領域を見つける。
//
// マーカーを 1 個だけ持つファイルは、修復されるのではなく拒否される。
// 半分だけ mark された生成領域がどこで終わっているかを知ることは推測
// することを意味し、ここで推測すればユーザーが書いた行を書き換えてしまう。
func FindRegion(file *config.File) (start, end int, found bool, err error) {
	start, end = -1, -1
	for index, line := range file.Lines {
		if line.Kind != config.LineComment {
			continue
		}
		switch strings.TrimSpace(line.Text) {
		case RegionStartMarker:
			if start < 0 {
				start = index
			}
		case RegionEndMarker:
			if end < 0 {
				end = index
			}
		}
	}
	switch {
	case start >= 0 && end > start:
		return start, end, true, nil
	case start < 0 && end < 0:
		return -1, -1, false, nil
	default:
		return -1, -1, false, ErrRegionDamaged
	}
}

// ClampToRegion は、ブロックの半開の行範囲を短くし、生成領域を飲み込むのではなく
// その手前で止まるようにする。
//
// ブロックの範囲は次のヘッダーまで及び、生成領域は最初の catch-all の直前に挿入される
// ——そのため、グループを宣言するすべてのエントリファイルにおいて、生成領域は
// その上にある具体的なブロックの範囲の内側に座る。生成領域はファイル自身の構造であってどの
// connection にも属さないので、ブロックの範囲をそのブロック自身のテキストとして扱う
// すべての path はここで止まらなければならない。さもなければ、無関係な 1 個の
// connection を移動または書き換えると、すべてのグループを宣言する Include
// 行を一緒に持ち去ってしまい、エントリファイルには単独のマーカーが残り、
// FindRegion はそれを damaged として拒否してしまう。
//
// 鏡合わせのケースも clamp される。ヘッダーの上のコメントの連なりは
// そのヘッダーに付随するコメントとして読まれるので、生成領域の直下に
// 書かれたブロックは、end マーカーを自分自身の説明として主張してしまうことになる。
func ClampToRegion(file *config.File, start, end int) (int, int) {
	regionStart, regionEnd, found, err := FindRegion(file)
	if err != nil || !found {
		return start, end
	}
	if regionStart > start && regionStart < end {
		end = regionStart
	}
	if regionEnd >= start && regionEnd < end {
		start = regionEnd + 1
	}
	return start, end
}

// PlanRegion は、生成領域が何を含み、どこに属するべきかを決める。
//
// groups は、読まれるべき順序で並んだ宣言済みグループ名である。
// 呼び出し側は既に GroupNameOrder を適用しているので、この関数は
// それらを並べ替えない。groupsFile は生成された settings ファイルで
// あり、最後に include されるので、グループの設定がホスト自身の値に勝つことは決してない。
func PlanRegion(file *config.File, groups []string, groupsFile string) (RegionPlan, error) {
	start, end, found, err := FindRegion(file)
	if err != nil {
		return RegionPlan{}, err
	}

	ending := dominantEnding(file)
	lines := []config.Line{
		{Kind: config.LineComment, Text: RegionStartMarker, Ending: ending},
		{Kind: config.LineComment, Text: regionNote, Ending: ending},
	}
	for _, pattern := range append(groupPatterns(groups), groupsFile) {
		include, buildErr := buildLine("", "Include", []string{pattern}, ending)
		if buildErr != nil {
			return RegionPlan{}, buildErr
		}
		lines = append(lines, include)
	}
	lines = append(lines, config.Line{Kind: config.LineComment, Text: RegionEndMarker, Ending: ending})

	if found {
		if file.Condition(file.BlockAt(start)) == "" {
			return RegionPlan{ReplaceFrom: start, ReplaceTo: end + 1, Replacing: true, Lines: lines}, nil
		}
		// 生成領域は Host または Match ブロックの内側に座っていて、その Include
		// 行はその 1 個のホストに接続するときにしか読まれない。あった場所に
		// 置き換えてもそこにとどまってしまうので、取り出してそれが何かを
		// 宣言する場所に書き直す。位置は生成領域を除いたファイルに対して
		// 計算される。それは index を正しくするためでもあり、生成領域それ
		// 自身の Include 行がユーザーが書いたものと取り違えられないようにするためでもある。
		without := withoutLines(file, start, end+1)
		insertAt, positionErr := regionPosition(without, groups, groupsFile)
		if positionErr != nil {
			return RegionPlan{}, positionErr
		}
		return RegionPlan{
			RemoveFrom: start, RemoveTo: end + 1, Removing: true,
			InsertAt: insertAt, Lines: lines,
		}, nil
	}
	insertAt, err := regionPosition(file, groups, groupsFile)
	if err != nil {
		return RegionPlan{}, err
	}
	return RegionPlan{InsertAt: insertAt, Lines: lines}, nil
}

// withoutLines は、1 個の半開区間を取り除いてファイルをコピーする。
func withoutLines(file *config.File, from, to int) *config.File {
	lines := make([]config.Line, 0, len(file.Lines)-(to-from))
	lines = append(lines, file.Lines[:from]...)
	lines = append(lines, file.Lines[to:]...)
	return &config.File{Lines: lines}
}

func groupPatterns(groups []string) []string {
	patterns := make([]string, 0, len(groups))
	for _, group := range groups {
		patterns = append(patterns, GroupIncludePattern(group))
	}
	return patterns
}

// regionPosition は、生成領域がどこに属するかを計算する。最初の Host
// または Match 行の上、あるいはどちらも無いファイルの末尾である。
//
// ここに選択の余地は無い。Include は他のあらゆるディレクティブと同様のディレクティブ
// なので、それが書かれているブロックに属し、OpenSSH はそのブロックが match
// するときにのみ include されたファイルの option を適用する。無条件に読まれる
// 行は最初のブロックヘッダーより上にある行だけなので、宣言はそこに置かなければならない。
// 以前のバージョンは、ユーザー自身のブロックを勝たせ続けるために、
// 代わりに生成領域を最初の catch-all の手前に置いていた。
// その代償は、Include が、catch-all の手前にあるどんな具体的なブロックの内側にも——
// あるいは catch-all の無いファイルではファイル内の最後のブロックの内側に——着地して
// しまい、グループをその 1 個のホストだけに宣言し、他の何にも宣言しないことだった。
//
// 結果として、グループファイルはエントリファイル自身のブロックより前に
// 読まれるので、両方の場所に書かれた alias はグループファイルの方に
// 解決される。これはここで決めていることではなく、推測でもない。
//
// とはいえ、これは今のところ十分に報告されておらず、この
// コメントはそうではないと言っているのではない。今のところ
// ファイルをまたぐ重複を報告するのは/api/v1/diagnostics/effective
// だけであり、しかも両方ではなく負けたブロックだけを名指す。connections overview
// はそれをしない。ProjectHosts は重複チェックの key をファイルの絶対 path にしているので、
// 1 個のファイル内の 2 個のブロックにしか発火しない——助けの要らないケースだ。
// 直るまでは、2 個のファイルをまたぐ重複はユーザーが気づく画面上で沈黙している。
//
// 挿入位置は最初のブロックのコメントの連なりの先頭なので、生成領域は
// コメントとそれが説明するヘッダーの間にではなく、そのコメントの
// 上に置かれる。
func regionPosition(file *config.File, groups []string, groupsFile string) (int, error) {
	if err := checkExistingIncludes(file, groups, groupsFile); err != nil {
		return 0, err
	}
	for index, line := range file.Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		if config.EqualKeyword(line.Keyword, "Host") || config.EqualKeyword(line.Keyword, "Match") {
			return file.CommentRun(index), nil
		}
	}
	return len(file.Lines), nil
}

// checkExistingIncludes は、生成領域が include しようとしている
// ファイルをユーザーが既に include している場合に拒否する。
//
// 同じファイルへの 2 回目の Include は無害ではない。OpenSSH は最初に読んだものを
// 適用し、graph は include_duplicate を報告するので、生成領域は黙って無用の重荷に
// なってしまう——あるいはもっと悪いことに、優先順位を変えてしまう。
// ユーザーが書いた Include が名指されるのは、意図的に置き換えられるようにするためである。
//
// top-level の Include だけが数えられる。Host または Match ブロックの
// 内側に書かれたものは条件付きである。それはそのホストに接続するときにしか読まれず、
// それ以外のときには読まれないのであり、これはまったく別の主張である。
// 以前の planner は、governing block を確認していなかったため、まさにそれに騙されていた。
func checkExistingIncludes(file *config.File, groups []string, groupsFile string) error {
	claimed := make(map[string]bool, len(groups)+1)
	for _, pattern := range append(groupPatterns(groups), groupsFile) {
		claimed[pattern] = true
	}
	for index, line := range file.Lines {
		if line.Kind != config.LineDirective || !config.EqualKeyword(line.Keyword, "Include") {
			continue
		}
		if file.Condition(file.BlockAt(index)) != "" {
			continue
		}
		for _, value := range line.Values() {
			if claimed[value] || strings.HasPrefix(value, ConnectionsDirectory+"/") {
				return ErrRegionIncludeAlreadyPresent
			}
		}
	}
	return nil
}

// ApplyRegion は、計画された行をファイルに書き込み、生成領域以外は
// 何も変更しない。
func ApplyRegion(file *config.File, plan RegionPlan) error {
	if plan.Removing {
		if plan.RemoveFrom < 0 || plan.RemoveTo > len(file.Lines) || plan.RemoveFrom > plan.RemoveTo {
			return ErrEditLineOutsideBlock
		}
		rest := append([]config.Line(nil), file.Lines[plan.RemoveTo:]...)
		file.Lines = append(file.Lines[:plan.RemoveFrom:plan.RemoveFrom], rest...)
	}
	if plan.Replacing {
		if plan.ReplaceFrom < 0 || plan.ReplaceTo > len(file.Lines) || plan.ReplaceFrom > plan.ReplaceTo {
			return ErrEditLineOutsideBlock
		}
		rest := append([]config.Line(nil), file.Lines[plan.ReplaceTo:]...)
		file.Lines = append(append(file.Lines[:plan.ReplaceFrom:plan.ReplaceFrom], plan.Lines...), rest...)
		return nil
	}
	if plan.InsertAt < 0 || plan.InsertAt > len(file.Lines) {
		return ErrEditLineOutsideBlock
	}
	for offset, line := range plan.Lines {
		insertLine(file, plan.InsertAt+offset, line)
	}
	return nil
}
