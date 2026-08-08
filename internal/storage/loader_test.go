package storage

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"sshc/internal/config"
)

// OpenSSH は %u をローカルのユーザー名に、%i をその uid に展開する。どちらも接続先が
// 決まる前に確定しているので、'%d' と同じくここで供給できる。以前は供給されておらず、
// これらを使う Include は include_unsupported_expansion として報告されていた。理由は
// 「プラットフォーム層が後のサブシステムで提供する」であり、その層はもう存在する。
func TestResolverExpandsTheLocalUserAndUid(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("このマシンではローカルユーザーを読めない: %v", err)
	}
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config", "Include conf.d/%u.conf\nInclude conf.d/%i.conf\n")
	write("conf.d/"+current.Username+".conf", "Host by-name\n")
	write("conf.d/"+current.Uid+".conf", "Host by-uid\n")

	workspace, err := NewWorkspace(OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		t.Fatal(err)
	}

	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Code == config.DiagnosticIncludeUnsupported {
			t.Errorf("%%u か %%i が未対応の展開として報告された: %#v", diagnostic)
		}
	}
	for _, name := range []string{current.Username, current.Uid} {
		absolute := filepath.Join(workspace.Root(), "conf.d", name+".conf")
		if graph.Nodes[absolute] == nil {
			t.Errorf("conf.d/%s.conf に到達しなかった", name)
		}
	}
	if _, err := strconv.Atoi(current.Uid); err != nil {
		t.Fatalf("uid %q は数値ではない", current.Uid)
	}
}

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
