package main

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"sshc/internal/application"
	"sshc/internal/config"
	"sshc/internal/storage"
)

// ListSubcommand は、OpenSSH が config と Include から読み取る具体的な接続名を列挙する。
const ListSubcommand = "list"

// concreteAliases は、OpenSSH と同じ読み取り順で Host 行を訪れ、実際にコマンドの
// 宛先として使える具体名だけを返す。Host *、Host web-?、!blocked のようなパターンは
// 接続先の名前そのものではないので列挙しない。同じ名前は最初の一度だけ表示する。
func concreteAliases(graph *config.Graph) []string {
	seen := map[string]bool{}
	aliases := []string{}
	application.WalkDirectives(graph, func(visit application.Visit) bool {
		if visit.Block.Kind != config.BlockHost || visit.Block.Header != visit.Index {
			return true
		}
		for _, pattern := range visit.Block.Patterns {
			if pattern.Value == "" || pattern.Negated || pattern.Wildcard || seen[pattern.Value] {
				continue
			}
			seen[pattern.Value] = true
			aliases = append(aliases, pattern.Value)
		}
		return true
	})
	sort.Strings(aliases)
	return aliases
}

func runList(home string, stdout, stderr io.Writer) int {
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		fmt.Fprintf(stderr, "sshc: %v\n", err)
		return 1
	}
	entry := filepath.Join(workspace.Root(), "config")
	graph, err := storage.NewResolver(workspace).Resolve(entry)
	if err != nil {
		fmt.Fprintf(stderr, "sshc: read config: %v\n", err)
		return 1
	}
	// config がまだ存在しないことは空の一覧である。一方、存在するのに読めない場合は、
	// 正しい一覧を返せないので成功したふりをしない。
	if root := graph.Nodes[graph.Root]; root != nil && root.File == nil && !root.Missing {
		fmt.Fprintln(stderr, "sshc: cannot read ~/.ssh/config")
		return 1
	}
	for _, alias := range concreteAliases(graph) {
		if _, err := fmt.Fprintln(stdout, alias); err != nil {
			fmt.Fprintf(stderr, "sshc: write host list: %v\n", err)
			return 1
		}
	}
	return 0
}
