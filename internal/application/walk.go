package application

import "sshc/internal/config"

// Visit is one directive line reached while reading the configuration the way
// OpenSSH reads it.
type Visit struct {
	// Path is the absolute path of the file the line belongs to.
	Path string
	// Index is the 0-based line index inside that file.
	Index int
	Line  config.Line
	Block config.Block
	// Condition is the rendered Host or Match header governing the line, or
	// the empty string in the global block.
	Condition string
}

// WalkDirectives visits every directive in reading order: each file top to
// bottom, descending into an Include exactly where the Include line appears and
// in the lexical order the resolver recorded. A file already on the current
// chain is skipped, so a cyclic Include terminates; the resolver has already
// reported the cycle as a diagnostic. The walk stops when visit returns false.
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
