package effective_test

import (
	"os"
	"path/filepath"
	"testing"

	"sshc/internal/effective"
	"sshc/internal/storage"
)

// The differential test skips when OpenSSH is absent, which would let a broken
// fixture sit unnoticed until someone ran the suite on a machine that has it.
// This asserts the same fixture against the engine's own projection, so the
// ordering claim is checked here even when ssh -G cannot be asked.
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

	// connections/work/*.conf does not reach connections/work/eu/lon.conf, so
	// the nested group needs its own Include line — and having it, the child's
	// own file is read first and its Port wins over the settings file's.
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

// File order is not load order, and the difference is not academic: it decides
// which value a user's own catch-all beats. This is the smallest fixture that
// distinguishes the two.
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

	// The included file is read at line 1, before Host * on line 2, so its Port
	// is the first value and the catch-all's is superseded. Walking file by
	// file would report 22 and be wrong about every configuration whose
	// defaults sit below its Includes — which is most of them.
	port, ok := effective.Project(graph, "nas").Value("port")
	if !ok || port.Value != "2222" {
		t.Fatalf("port = %#v, want the included file's 2222", port)
	}
}
