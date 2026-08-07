package effective

import (
	"strings"

	"sshc/internal/config"
)

// 出所をどれだけ確信をもって説明できるか。
const (
	SourceExact    = "exact"
	SourceWildcard = "wildcard"
	SourceGlobal   = "global"
)

// 射影を、ひとつの整った継承の連鎖として示せない理由。
const (
	ComplexityWildcardPattern   = "wildcard_pattern"
	ComplexityNegatedPattern    = "negated_pattern"
	ComplexityMatchBlock        = "match_block"
	ComplexityDuplicateAlias    = "duplicate_alias"
	ComplexityUnresolvedInclude = "unresolved_include"
	ComplexityJumpInvalid       = "jump_invalid"
	ComplexityJumpCycle         = "jump_cycle"
	ComplexityJumpDepth         = "jump_depth_exceeded"
)

// Source は、値の出どころひとつ。Winner は OpenSSH が採用する値を示す。最初に
// 読まれた値が勝つからだ。他のものも列挙するのは、何が影に隠れているかを読み手が
// 見られるようにするためである。
type Source struct {
	Keyword   string
	Value     string
	Path      string
	Line      int
	Condition string
	Kind      string
	Winner    bool
}

// Complexity は、エンジンが自身の射影を全体の真実として提示することを拒む理由を
// 記録する。UI はこれらを複雑な外部ルールとして示し、権威ある値については
// `ssh -G` に委ねる。
type Complexity struct {
	Code      string
	Path      string
	Line      int
	Condition string
	Detail    string
}

// Projection は、ひとつの alias に対するエンジン自身の設定の読み。
type Projection struct {
	Alias        string
	Sources      []Source
	Complexities []Complexity
}

// Simple は、すべての値が但し書きなしに帰属できたかを報告する。
func (p Projection) Simple() bool { return len(p.Complexities) == 0 }

// Value は、keyword について勝った出所を返す。
func (p Projection) Value(keyword string) (Source, bool) {
	wanted := strings.ToLower(keyword)
	for _, source := range p.Sources {
		if source.Winner && strings.ToLower(source.Keyword) == wanted {
			return source, true
		}
	}
	return Source{}, false
}

// Project は設定を読み込み順に走査し、各キーワードを、それを最初に設定した
// ブロックへ帰属させる。これは OpenSSH がしていることである。
//
// 読み込み順はファイル順ではない。OpenSSH は Include をその行のある位置で読むので、
// Include より下に書かれたブロックは、include されたファイル全体のあとで読まれる —
// そして最初の値が勝つので、include されたファイルの方が勝つ。ファイル単位でグラフ
// を走査すると、エントリファイルのすべてのブロックが include された側のすべてより
// 前に来てしまい、生成されたグループのリージョンが依存しているまさにその場合を
// 逆転させる。Include はユーザーの catch-all の上に置かれ、グループの値が既定に
// 勝つようになっているのに、ファイル順の帰属は既定を報告してしまう。
//
// Match ブロックが値を寄与することは決してない。その条件は、接続中にしか存在しない
// 状態に依存するからである。代わりに、グラフのどこかにある Match ブロックは
// complexity として記録される。それは、この射影があとの Host ブロックへ帰属させた
// 値を、影に隠すこともできるからだ。
func Project(graph *config.Graph, alias string) Projection {
	projection := Projection{Alias: alias}
	if graph == nil {
		return projection
	}
	claimed := make(map[string]bool)
	matchedHostBlocks := 0
	kind, applies, condition := SourceGlobal, true, ""

	enterBlock := func(filePath string, file *config.File, block config.Block) {
		condition = file.Condition(block)
		kind, applies = blockApplies(block, alias)
		if block.Kind == config.BlockMatch {
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityMatchBlock,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "Match criteria are evaluated while connecting, so this block may override values shown here",
			})
			return
		}
		if !applies || block.Kind != config.BlockHost {
			return
		}
		matchedHostBlocks++
		if matchedHostBlocks > 1 {
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityDuplicateAlias,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "more than one Host block claims this alias",
			})
		}
		if kind == SourceWildcard {
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityWildcardPattern,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "this block matched through a wildcard pattern",
			})
		}
		for _, pattern := range block.Patterns {
			if !pattern.Negated {
				continue
			}
			projection.Complexities = append(projection.Complexities, Complexity{
				Code:      ComplexityNegatedPattern,
				Path:      filePath,
				Line:      block.Header + 1,
				Condition: condition,
				Detail:    "this block excludes hosts through " + pattern.Raw,
			})
			break
		}
	}

	directive := func(filePath string, index int, line config.Line) {
		if !applies {
			return
		}
		keyword := strings.ToLower(line.Keyword)
		projection.Sources = append(projection.Sources, Source{
			Keyword:   line.Keyword,
			Value:     argumentText(line),
			Path:      filePath,
			Line:      index + 1,
			Condition: condition,
			Kind:      kind,
			Winner:    !claimed[keyword],
		})
		claimed[keyword] = true
	}

	walkLoadOrder(graph, graph.Root, map[string]bool{}, enterBlock, directive)

	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Severity == config.SeverityInfo {
			continue
		}
		projection.Complexities = append(projection.Complexities, Complexity{
			Code:   ComplexityUnresolvedInclude,
			Path:   diagnostic.Path,
			Line:   diagnostic.Line,
			Detail: diagnostic.Code,
		})
	}
	return projection
}

// walkLoadOrder は、ひとつのファイルのブロックとディレクティブを OpenSSH が読む
// 順に訪れ、各 Include をその行のある位置で降りていく。
//
// chain は循環を止める。二度 include されたファイルは二度走査される。OpenSSH が
// そうするからだ。二度目の読みは何も寄与しない。最初の値がすでに取られているから
// である。
func walkLoadOrder(
	graph *config.Graph,
	filePath string,
	chain map[string]bool,
	enterBlock func(string, *config.File, config.Block),
	directive func(string, int, config.Line),
) {
	node := graph.Nodes[filePath]
	if node == nil || node.File == nil || chain[filePath] {
		return
	}
	chain[filePath] = true
	defer delete(chain, filePath)

	blocks := node.File.Blocks()
	position := 0
	enterBlock(filePath, node.File, blocks[0])
	for index, line := range node.File.Lines {
		if position+1 < len(blocks) && blocks[position+1].Header == index {
			position++
			enterBlock(filePath, node.File, blocks[position])
			continue
		}
		if line.Kind != config.LineDirective {
			continue
		}
		if config.EqualKeyword(line.Keyword, "Include") {
			for _, edge := range node.Includes {
				if edge.Line != index+1 {
					continue
				}
				for _, match := range edge.Matches {
					walkLoadOrder(graph, match, chain, enterBlock, directive)
				}
			}
			continue
		}
		directive(filePath, index, line)
	}
}

// blockApplies は、ブロックが alias を支配するか、そしてどう一致したかを報告する。
func blockApplies(block config.Block, alias string) (kind string, applies bool) {
	switch block.Kind {
	case config.BlockGlobal:
		return SourceGlobal, true
	case config.BlockMatch:
		return "", false
	}
	for _, pattern := range block.Patterns {
		if pattern.Negated && MatchPattern(pattern.Value, alias) {
			return "", false
		}
	}
	for _, pattern := range block.Patterns {
		if pattern.Negated || !MatchPattern(pattern.Value, alias) {
			continue
		}
		if pattern.Wildcard {
			return SourceWildcard, true
		}
		return SourceExact, true
	}
	return "", false
}

// MatchPattern は OpenSSH の match_pattern を実装する。'*' は任意の並びに、'?' は
// ちょうど 1 文字に一致し、比較は大文字小文字を区別せず、他のメタ文字に特別な意味は
// ない。
func MatchPattern(pattern, value string) bool {
	loweredPattern := strings.ToLower(pattern)
	loweredValue := strings.ToLower(value)

	patternIndex, valueIndex := 0, 0
	starIndex, resumeIndex := -1, 0
	for valueIndex < len(loweredValue) {
		switch {
		case patternIndex < len(loweredPattern) &&
			(loweredPattern[patternIndex] == '?' || loweredPattern[patternIndex] == loweredValue[valueIndex]):
			patternIndex++
			valueIndex++
		case patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*':
			starIndex = patternIndex
			resumeIndex = valueIndex
			patternIndex++
		case starIndex >= 0:
			patternIndex = starIndex + 1
			resumeIndex++
			valueIndex = resumeIndex
		default:
			return false
		}
	}
	for patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(loweredPattern)
}
