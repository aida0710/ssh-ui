package effective_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"sshc/internal/config"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/platform/macos"
	"sshc/internal/storage"
)

// TestProjectionMatchesInstalledOpenSSH は、設定エンジンの計画がこのサブシステム
// に先送りした差分テストである。
//
// どのフィクスチャも構造上安全である。ProxyCommand、LocalCommand、RemoteCommand、
// KnownHostsCommand、Match exec のいずれも含まないので、評価してもプログラムは
// 実行されえない。各フィクスチャは自身の t.TempDir() の中にあり、本物の ~/.ssh が
// 読まれることはない。比較はフィクスチャが設定するキーワードに限定する。
// `ssh -G -F file` は、それ以外については依然として /etc/ssh/ssh_config を読む
// からである。
func TestProjectionMatchesInstalledOpenSSH(t *testing.T) {
	toolchain := macos.NewToolchain()
	if _, err := toolchain.SSH(); err != nil {
		t.Skip("OpenSSH ssh is not installed; skipping the differential test")
	}

	tests := []struct {
		name     string
		contents string
		// files は、ワークスペース相対のパスで、エントリファイルの隣に書かれる。
		// グループのフィクスチャにはこれが要る。主張の全体が、Include が
		// どのファイルにどの順で到達するかについてのものだからだ。
		files      map[string]string
		alias      string
		keywords   []string
		wantSimple bool
	}{
		{
			name:       "explicit host",
			contents:   "Host bastion\n\tHostName 203.0.113.10\n\tUser ops\n\tPort 2222\n",
			alias:      "bastion",
			keywords:   []string{"hostname", "user", "port"},
			wantSimple: true,
		},
		{
			name:     "wildcard defaults",
			contents: "Host web-01\n\tHostName 198.51.100.20\n\nHost *\n\tUser deploy\n\tPort 2022\n",
			alias:    "web-01",
			keywords: []string{"hostname", "user", "port"},
		},
		{
			name:     "first value wins across duplicate blocks",
			contents: "Host db\n\tPort 2200\n\nHost db\n\tPort 9999\n\tUser dba\n",
			alias:    "db",
			keywords: []string{"port", "user"},
		},
		{
			name:     "negated pattern",
			contents: "Host !legacy *.internal\n\tUser ops\n\tPort 2202\n",
			alias:    "app.internal",
			keywords: []string{"user", "port"},
		},
		{
			name:       "multi hop jump",
			contents:   "Host edge\n\tHostName 192.0.2.7\n\nHost inner\n\tHostName 10.1.1.5\n\tProxyJump ops@edge:2222\n",
			alias:      "inner",
			keywords:   []string{"hostname", "proxyjump"},
			wantSimple: true,
		},
		{
			// 生成されたリージョンを、そのまま本物の OpenSSH の前に置く。
			// 試験対象の主張は順序のルールである。グループごとに Include を
			// ひとつ、深いものから順に、そのあとにコンパイル済みの設定。lon-1
			// は入れ子のグループにあるので、自分のファイルが親グループの設定
			// ブロックに勝ち、connections/work/*.conf は到達してはならない。
			name: "generated group region",
			contents: "# >>> sshc groups (generated). Child groups first: OpenSSH keeps the first value it reads.\n" +
				"# Edit through the UI; lines between these markers are replaced on the next save.\n" +
				"Include connections/work/eu/*.conf\n" +
				"Include connections/work/*.conf\n" +
				"Include groups.sshc.conf\n" +
				"# <<< sshc groups\n" +
				"Host *\n\tPort 22\n",
			files: map[string]string{
				"connections/work/eu/lon.conf": "Host lon-1\n\tHostName 203.0.113.11\n\tPort 2210\n",
				"connections/work/web.conf":    "Host web-1\n\tHostName 203.0.113.10\n",
				"groups.sshc.conf":             "Host lon-1 web-1\n\tUser ops\n\nHost lon-1\n\tPort 2299\n",
			},
			alias:      "lon-1",
			keywords:   []string{"hostname", "port", "user"},
			wantSimple: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".ssh")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(root, "config")
			if err := os.WriteFile(configPath, []byte(test.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			for relative, contents := range test.files {
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
			graph, err := storage.NewResolver(workspace).Resolve(configPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, diagnostic := range graph.Diagnostics {
				if diagnostic.Severity == config.SeverityError {
					t.Fatalf("fixture produced an error diagnostic: %#v", diagnostic)
				}
			}

			report := effective.Scan(graph)
			if len(report.Directives) != 0 {
				t.Fatalf("fixture is not safe for automatic evaluation: %#v", report.Directives)
			}

			// ssh は相対 Include を ~/.ssh に固定する — -F に渡された
			// ファイルのディレクトリではない — そして ~ を HOME から取る。
			// このプロセスの HOME をそのまま継承させると、フィクスチャ内の
			// すべての Include が本物のユーザーの ~/.ssh に到達し、何にも
			// 一致せず、ssh -G は組み込みの既定値で答えた。alias をホスト名
			// とし、ポート 22、ログインユーザー、と。比較はそのとき、空の設定
			// と中身のある設定を突き合わせていたことになる。
			//
			// フィクスチャのホームが子プロセスの HOME である。これは
			// アプリケーションが出荷している構成と同じで、プロセス自身の
			// HOME の上に platform.MinimalEnvironment を置き、その
			// ~/.ssh/config が読まれるファイルになる。相対 Include を両者が
			// 同じディレクトリへ解決するのは、それが成り立つときだけである。
			evaluator := effective.Evaluator{
				Runner:     macos.NewOutputRunner(),
				Toolchain:  toolchain,
				ConfigPath: configPath,
				Environment: platform.MinimalEnvironment(func(name string) (string, bool) {
					if name == "HOME" {
						return home, true
					}
					return os.LookupEnv(name)
				}),
			}
			values, err := evaluator.Evaluate(context.Background(), report, test.alias, false)
			if err != nil {
				t.Fatalf("Evaluate = %v", err)
			}

			projection := effective.Project(graph, test.alias)
			for _, keyword := range test.keywords {
				source, ok := projection.Value(keyword)
				if !ok {
					t.Fatalf("engine did not project %q", keyword)
				}
				if want := values.First(keyword); source.Value != want {
					t.Errorf("%s: engine = %q, ssh -G = %q", keyword, source.Value, want)
				}
			}
			if projection.Simple() != test.wantSimple {
				t.Errorf("Simple() = %v, want %v (complexities %#v)", projection.Simple(), test.wantSimple, projection.Complexities)
			}
		})
	}
}
