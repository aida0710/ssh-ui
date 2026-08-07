package effective_test

import (
	"os"
	"path/filepath"
	"testing"

	"sshc/internal/effective"
	"sshc/internal/storage"
)

// 差分テストは OpenSSH がないときスキップされるので、フィクスチャが壊れていても、
// それを持つマシンで誰かがスイートを走らせるまで気づかれないままになりうる。
// ここでは同じフィクスチャをエンジン自身の射影に対して表明するので、ssh -G に
// 尋ねられないときでも順序の主張が検査される。
func TestGeneratedRegionFixtureOrdersChildBeforeParent(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	files := map[string]string{
		"config": "# >>> sshc groups (generated). Child groups first: OpenSSH keeps the first value it reads.\n" +
			"# Edit through the UI; lines between these markers are replaced on the next save.\n" +
			"Include connections/work/eu/*.conf\n" +
			"Include connections/work/*.conf\n" +
			"Include groups.sshc.conf\n" +
			"# <<< sshc groups\n" +
			"Host *\n\tPort 22\n",
		"connections/work/eu/lon.conf": "Host lon-1\n\tHostName 203.0.113.11\n\tPort 2210\n",
		"connections/work/web.conf":    "Host web-1\n\tHostName 203.0.113.10\n",
		"groups.sshc.conf":             "Host lon-1 web-1\n\tUser ops\n\nHost lon-1\n\tPort 2299\n",
	}
	for relative, contents := range files {
		absolute := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(root, "config"))
	if err != nil {
		t.Fatal(err)
	}
	projection := effective.Project(graph, "lon-1")

	// connections/work/*.conf は connections/work/eu/lon.conf に到達しないので、
	// 入れ子のグループには自前の Include 行が要る — そしてそれがあることで、子自身の
	// ファイルが先に読まれ、その Port が設定ファイルのものに勝つ。
	for keyword, want := range map[string]string{"hostname": "203.0.113.11", "port": "2210", "user": "ops"} {
		source, ok := projection.Value(keyword)
		if !ok {
			t.Fatalf("engine did not project %q", keyword)
		}
		if source.Value != want {
			t.Errorf("%s = %q, want %q", keyword, source.Value, want)
		}
	}
}

// ファイル順は読み込み順ではなく、その違いは学術的なものではない。ユーザー自身の
// catch-all がどの値に勝つかを決めるからだ。これは両者を区別する最小の
// フィクスチャである。
func TestAnIncludeAboveABlockIsReadBeforeIt(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	for relative, contents := range map[string]string{
		"config":              "Include conf.d/*.conf\nHost *\n\tPort 22\n",
		"conf.d/10-home.conf": "Host nas\n\tPort 2222\n",
	} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(relative)), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(root, "config"))
	if err != nil {
		t.Fatal(err)
	}

	// include されたファイルは 1 行目、2 行目の Host * より前に読まれるので、その Port
	// が最初の値になり、catch-all のものは覆される。ファイル単位で走査すると 22 を
	// 報告し、既定値が Include より下にあるあらゆる設定について誤ることになる — そして
	// それはほとんどの設定である。
	port, ok := effective.Project(graph, "nas").Value("port")
	if !ok || port.Value != "2222" {
		t.Fatalf("port = %#v, want the included file's 2222", port)
	}
}
