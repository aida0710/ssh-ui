package effective_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"ssh-ui/internal/config"
	"ssh-ui/internal/effective"
	"ssh-ui/internal/platform/macos"
	"ssh-ui/internal/storage"
)

// TestProjectionMatchesInstalledOpenSSH is the differential test the
// config-engine plan deferred to this subsystem.
//
// Every fixture is safe by construction: none contains ProxyCommand,
// LocalCommand, RemoteCommand, KnownHostsCommand or Match exec, so evaluating
// it cannot run a program. Each fixture lives in its own t.TempDir() and the
// real ~/.ssh is never read. The comparison is limited to keywords the fixture
// sets, because `ssh -G -F file` still reads /etc/ssh/ssh_config for
// everything else.
func TestProjectionMatchesInstalledOpenSSH(t *testing.T) {
	toolchain := macos.NewToolchain()
	if _, err := toolchain.SSH(); err != nil {
		t.Skip("OpenSSH ssh is not installed; skipping the differential test")
	}

	tests := []struct {
		name     string
		contents string
		// files are written beside the entry file, by workspace-relative path.
		// A group fixture needs them: the whole claim is about which file an
		// Include reaches and in which order.
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
			// The generated region, verbatim, in front of the real OpenSSH.
			// The claim under test is the ordering rule: one Include per group,
			// deepest first, then the compiled settings. lon-1 is in the nested
			// group, so its own file wins over the parent group's settings
			// block, and connections/work/*.conf must not reach it at all.
			name: "generated group region",
			contents: "# >>> ssh-ui groups (generated). Child groups first: OpenSSH keeps the first value it reads.\n" +
				"# Edit through the UI; lines between these markers are replaced on the next save.\n" +
				"Include connections/work/eu/*.conf\n" +
				"Include connections/work/*.conf\n" +
				"Include groups.ssh-ui.conf\n" +
				"# <<< ssh-ui groups\n" +
				"Host *\n\tPort 22\n",
			files: map[string]string{
				"connections/work/eu/lon.conf": "Host lon-1\n\tHostName 203.0.113.11\n\tPort 2210\n",
				"connections/work/web.conf":    "Host web-1\n\tHostName 203.0.113.10\n",
				"groups.ssh-ui.conf":           "Host lon-1 web-1\n\tUser ops\n\nHost lon-1\n\tPort 2299\n",
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

			evaluator := effective.Evaluator{
				Runner:     macos.NewOutputRunner(),
				Toolchain:  toolchain,
				ConfigPath: configPath,
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
