package application

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"sshc/internal/storage"
)

// mapLoader は、map に裏打ちされた config.Loader であり、filesystem
// 無しで overlay を演習できるようにする。
type mapLoader map[string][]byte

func (loader mapLoader) ReadFile(name string) ([]byte, error) {
	contents, ok := loader[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return contents, nil
}

func (loader mapLoader) Glob(pattern string) ([]string, error) {
	var matches []string
	for name := range loader {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			return nil, err
		}
		if matched {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

// overlay は、save がそれに照らして validate される対象なので、
// transaction が実際に生み出す filesystem を記述しなければならない。
// 書き込みだけを model 化することは、ファイルが両方の場所に同時に
// 存在する世界に照らして move がチェックされることを意味していた。
func TestOverlayForDescribesWhatArrivesAndWhatLeaves(t *testing.T) {
	pending, gone := overlayFor(storage.Request{
		Changes:  []storage.Change{{Path: "conf.d/20-new.conf", Contents: []byte("Host new\n")}},
		Moves:    []storage.Move{{From: "conf.d/10-old.conf", To: "connections/work/10-old.conf"}},
		Removals: []storage.Removal{{Path: "conf.d/30-dead.conf"}},
	})

	if string(pending["conf.d/20-new.conf"]) != "Host new\n" {
		t.Fatalf("pending = %#v, want the written contents", pending)
	}
	if !gone["conf.d/10-old.conf"] {
		t.Errorf("a move's source is not marked gone")
	}
	if !gone["conf.d/30-dead.conf"] {
		t.Errorf("a removal is not marked gone")
	}
	if gone["connections/work/10-old.conf"] {
		t.Errorf("a move's destination must not be marked gone")
	}
}

func TestOverlayLoaderHidesAMovedSourceFromReadsAndGlobs(t *testing.T) {
	base := mapLoader{
		"/home/tester/.ssh/conf.d/10-old.conf":           []byte("Host nas\n"),
		"/home/tester/.ssh/conf.d/keep.conf":             []byte("Host keep\n"),
		"/home/tester/.ssh/connections/work/10-old.conf": []byte("Host nas\n"),
	}
	loader := overlayLoader{
		base:    base,
		pending: map[string][]byte{"/home/tester/.ssh/connections/work/10-old.conf": []byte("Host nas\n")},
		gone:    map[string]bool{"/home/tester/.ssh/conf.d/10-old.conf": true},
	}

	if _, err := loader.ReadFile("/home/tester/.ssh/conf.d/10-old.conf"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reading a moved source error = %v, want fs.ErrNotExist", err)
	}
	if _, err := loader.ReadFile("/home/tester/.ssh/conf.d/keep.conf"); err != nil {
		t.Fatalf("reading an untouched file error = %v", err)
	}

	matches, err := loader.Glob("/home/tester/.ssh/conf.d/*.conf")
	if err != nil {
		t.Fatalf("Glob error = %v", err)
	}
	// gone が無ければ、移動したファイルはここでも依然として match
	// してしまい、Include glob はそのブロックを 2 回見て、transaction
	// が commit されれば存在しなくなるはずの重複 alias を報告してしまう。
	if len(matches) != 1 || matches[0] != "/home/tester/.ssh/conf.d/keep.conf" {
		t.Fatalf("Glob = %v, want only the untouched file", matches)
	}
}

// transaction は、あるファイルを書き込みながら同じ path を削除する
// ことがあり、これは既存の destination への move がそう見えるものである。内容の方が勝つ。
func TestOverlayLoaderPrefersPendingContentsOverARemoval(t *testing.T) {
	loader := overlayLoader{
		base:    mapLoader{},
		pending: map[string][]byte{"/home/tester/.ssh/config": []byte("Host rewritten\n")},
		gone:    map[string]bool{"/home/tester/.ssh/config": true},
	}

	contents, err := loader.ReadFile("/home/tester/.ssh/config")
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}
	if string(contents) != "Host rewritten\n" {
		t.Fatalf("contents = %q, want the pending contents", contents)
	}
}

// TestValidateLeavesApplicationStateAlone は、このプロジェクト自身の
// end-to-end スイートが local ではなく CI で見つけた欠陥に対する regression テストである。
//
// password vault はこの transaction manager を共有するので、
// この validator を通過する。validator はかつてすべての変更を
// ssh_config として parse しており、封印された vault は ciphertext で
// ある。そのランダムなバイト列がたまたま奇数個の引用符を含んだ
// とき、それは"unbalanced quoting"として拒否されていた。それは save のたびのコイン投げ
// であり、まさに 1 台のマシンでは通り別のマシンでは失敗するテストの形そのものである。
func TestValidateLeavesApplicationStateAlone(t *testing.T) {
	service, workspace := newTestService(t)
	if err := workspace.EnsureDirectory(workspace.StateDir()); err != nil {
		t.Fatal(err)
	}

	// 対になっていない引用符が 1 個。それこそが ciphertext が偶発的に
	// 生み出し続けていたものである。
	ciphertext := []byte("\x91\x2f\"\x00\xd4 not configuration at all\n")

	if _, err := service.manager.Commit(storage.Request{
		Operation: "secret.vault",
		Changes: []storage.Change{{
			Path:       filepath.Join(workspace.StateDir(), "secrets"),
			Contents:   ciphertext,
			SkipBackup: true,
		}},
	}); err != nil {
		t.Fatalf("a file under sshc/ was validated as configuration: %v", err)
	}

	// 本物の設定ファイルと同じバイト列は依然として拒否されるので、
	// これは validator を無効化するのではなく狭めるだけである。
	if _, err := service.manager.Commit(storage.Request{
		Operation: "config.file_raw",
		Changes: []storage.Change{{
			Path:     filepath.Join(workspace.Root(), "conf.d", "20-bad.conf"),
			Contents: ciphertext,
		}},
	}); err == nil {
		t.Fatal("unbalanced quoting reached a configuration file")
	}

	// そして状態ディレクトリの兄弟は、その子であると誤認されない。
	if _, err := service.manager.Commit(storage.Request{
		Operation: "config.file_raw",
		Changes: []storage.Change{{
			Path:     filepath.Join(workspace.Root(), "sshc-notes.conf"),
			Contents: ciphertext,
		}},
	}); err == nil {
		t.Fatal("a sibling of sshc/ escaped validation")
	}
}

// このアプリケーション自身の状態だけに触れる書き込みは設定の
// 変更ではなく、それが一度も触れていない設定を解決できないという
// 理由で拒否されてはならない。
//
// これは見た目以上に重要である。vault は sshc/配下にあり、
// アプリケーション全体が master password の向こう側にあり、そう
// しなければ、まだ config ファイルが無い——あるいは壊れている——
// ワークスペースは、master password を設定できないワークスペースになってしまう。
// 壊れた設定を直すためのツールが、設定が壊れているという理由で起動を拒否することになる。
func TestStateOnlyWritesDoNotNeedAResolvableGraph(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// config ファイルがまったく無い。それが最初の実行の見た目である。
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	manager := storage.NewManager(workspace, time.Now, rand.Reader)
	_ = NewService(workspace, manager)

	if err := workspace.EnsureDirectory(workspace.StateDir()); err != nil {
		t.Fatal(err)
	}
	_, err = manager.Commit(storage.Request{
		Operation: "secret.vault",
		Changes: []storage.Change{{
			Path:     filepath.Join(workspace.StateDir(), "secrets"),
			Contents: []byte("sealed bytes that are not configuration"),
		}},
	})
	if err != nil {
		t.Fatalf("writing application state with no config present = %v", err)
	}
}
