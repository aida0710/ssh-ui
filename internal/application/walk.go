package application

import "sshc/internal/config"

// Visit は、OpenSSH が読むのと同じ方法で設定を読む中で到達した
// 1 本のディレクティブ行である。
type Visit struct {
	// Path は、その行が属するファイルの絶対 path である。
	Path string
	// Index は、そのファイル内での 0-based の行 index である。
	Index int
	Line  config.Line
	Block config.Block
	// Condition は、その行を支配する Host または Match ヘッダーを描き
	// 出したものであり、global block では空文字列である。
	Condition string
}

// WalkDirectives は、すべてのディレクティブを読み取り順に訪れる。各
// ファイルを上から下まで、Include 行が現れるまさにその場所で、かつ
// resolver が記録した字句順で Include へ降りていく。現在の chain 上に
// 既にあるファイルはスキップされるので、循環する Include は終了する。resolver は既にその
// cycle を diagnostic として報告している。walk は、visit が false を返すと停止する。
func WalkDirectives(graph *config.Graph, visit func(Visit) bool) {
	if graph == nil || graph.Root == "" {
		return
	}
	walkNode(graph, graph.Root, map[string]bool{}, visit)
}

func walkNode(graph *config.Graph, filePath string, chain map[string]bool, visit func(Visit) bool) bool {
	node, ok := graph.Nodes[filePath]
	if !ok || node.File == nil || chain[filePath] {
		return true
	}
	chain[filePath] = true
	defer delete(chain, filePath)

	includedAtLine := make(map[int][]string, len(node.Includes))
	for _, edge := range node.Includes {
		includedAtLine[edge.Line] = append(includedAtLine[edge.Line], edge.Matches...)
	}

	blocks := node.File.Blocks()
	current := 0
	for index := range node.File.Lines {
		for current+1 < len(blocks) && blocks[current+1].Header <= index {
			current++
		}
		line := node.File.Lines[index]
		if line.Kind == config.LineDirective {
			if !visit(Visit{
				Path:      filePath,
				Index:     index,
				Line:      line,
				Block:     blocks[current],
				Condition: node.File.Condition(blocks[current]),
			}) {
				return false
			}
		}
		for _, match := range includedAtLine[index+1] {
			if !walkNode(graph, match, chain, visit) {
				return false
			}
		}
	}
	return true
}
