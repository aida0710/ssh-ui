package storage

import (
	"os"
	"path/filepath"
	"testing"

	"sshc/internal/config"
)

// "~/.ssh/…" と書かれた Include は Home に対して展開されるが、それに関する判断は
// すべて Root に対して行われる。~/.ssh がリンク経由で到達される場合、両者は食い
// 違い、ユーザーが求めたファイルはルートの外にあると報告されて編集を拒まれていた
// — 自分自身の ~/.ssh にある、自分自身の設定なのに。
func TestResolverReadsATildeIncludeUnderASymlinkedHome(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real-home")
	if err := os.MkdirAll(filepath.Join(real, ".ssh", "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "linked-home")
	if err := os.Symlink(real, home); err != nil {
		t.Skipf("this filesystem does not support symbolic links: %v", err)
	}
	write := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(real, ".ssh", name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config", "Include ~/.ssh/conf.d/*.conf\nInclude %d/.ssh/extra.conf\n")
	write("conf.d/10.conf", "Host nas\n\tUser aida\n")
	write("extra.conf", "Host attic\n\tUser aida\n")

	workspace, err := NewWorkspace(OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		t.Fatal(err)
	}

	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Code == config.DiagnosticIncludeOutsideRoot {
			t.Errorf("a file inside ~/.ssh was called outside it: %#v", diagnostic)
		}
	}
	for _, name := range []string{"conf.d/10.conf", "extra.conf"} {
		absolute := filepath.Join(workspace.Root(), filepath.FromSlash(name))
		node := graph.Nodes[absolute]
		if node == nil {
			t.Errorf("%s was not reached at its resolved path", name)
			continue
		}
		if !node.Editable {
			t.Errorf("%s is inside the workspace but was refused for editing", name)
		}
	}
}
