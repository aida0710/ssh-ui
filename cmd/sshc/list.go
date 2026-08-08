package main

import (
	"errors"
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

// readConfigGraph は、`~/.ssh/config` と到達できる Include を解決する。
//
// 一覧も接続の選択画面も、同じ設定について同じことを答えなければならない。
// 特に「読めなかった」については、片方が「ホストが無い」と言い換えてしまうと、
// 壊れた設定が空の設定に見える。
func readConfigGraph(home string) (*storage.Workspace, *config.Graph, error) {
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		return nil, nil, err
	}
	entry := filepath.Join(workspace.Root(), "config")
	graph, err := storage.NewResolver(workspace).Resolve(entry)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	// config がまだ存在しないことは空の一覧である。一方、存在するのに読めない場合は、
	// 正しい一覧を返せないので成功したふりをしない。
	if root := graph.Nodes[graph.Root]; root != nil && root.File == nil && !root.Missing {
		return nil, nil, errors.New("cannot read ~/.ssh/config")
	}
	return workspace, graph, nil
}

func runList(home string, stdout, stderr io.Writer) int {
	_, graph, err := readConfigGraph(home)
	if err != nil {
		fmt.Fprintf(stderr, "sshc: %v\n", err)
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
