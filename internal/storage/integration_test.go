package storage_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ssh-ui/internal/config"
	"ssh-ui/internal/storage"
)

const mainConfig = `# personal config
Include conf.d/*.conf

Host bastion
	HostName=203.0.113.10
	Port 22

Host *
	ServerAliveInterval 30
`

func newIntegrationWorkspace(t *testing.T) *storage.Workspace {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"config":              mainConfig,
		"conf.d/20-work.conf": "Host work\n\tUser ops\n",
		"conf.d/10-home.conf": "Host home\n\tUser aida\t# personal\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestResolveEditAndCommitPreservesEveryOtherByte(t *testing.T) {
	workspace := newIntegrationWorkspace(t)
	resolver := storage.NewResolver(workspace)
	entry := filepath.Join(workspace.Root(), "config")

	graph, err := resolver.Resolve(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Severity == config.SeverityError {
			t.Fatalf("unexpected diagnostic: %#v", diagnostic)
		}
	}
	want := []string{
		entry,
		filepath.Join(workspace.Root(), "conf.d", "10-home.conf"),
		filepath.Join(workspace.Root(), "conf.d", "20-work.conf"),
	}
	if len(graph.Order) != len(want) {
		t.Fatalf("order = %#v", graph.Order)
	}
	for index := range want {
		if graph.Order[index] != want[index] {
			t.Fatalf("order[%d] = %q, want %q", index, graph.Order[index], want[index])
		}
	}
	for path, node := range graph.Nodes {
		original, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(node.File.Render(), original) {
			t.Fatalf("%s did not round-trip", path)
		}
	}

	// Change one argument through the structured model and keep everything else.
	node := graph.Nodes[entry]
	original := node.File.Render()
	changed := false
	for index := range node.File.Lines {
		line := &node.File.Lines[index]
		if line.Kind == config.LineDirective && config.EqualKeyword(line.Keyword, "Port") {
			line.Arguments[0].Raw = "2222"
			line.Arguments[0].Value = "2222"
			changed = true
		}
	}
	if !changed {
		t.Fatal("fixture no longer contains a Port directive")
	}
	updated := node.File.Render()
	if bytes.Equal(updated, original) {
		t.Fatal("edit produced no change")
	}
	if want := bytes.Replace(original, []byte("Port 22\n"), []byte("Port 2222\n"), 1); !bytes.Equal(updated, want) {
		t.Fatalf("edit changed more than the port:\n%q\n%q", updated, want)
	}

	manager := storage.NewManager(workspace, time.Now, deterministicRandom())
	result, err := manager.Commit(storage.Request{
		Operation: "config.save",
		Changes: []storage.Change{{
			Path:         entry,
			Contents:     updated,
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(original)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(entry)
	if err != nil || !bytes.Equal(after, updated) {
		t.Fatalf("config after commit = %q, %v", after, err)
	}
	for _, name := range []string{"conf.d/10-home.conf", "conf.d/20-work.conf"} {
		path := filepath.Join(workspace.Root(), name)
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(contents, graph.Nodes[path].File.Render()) {
			t.Fatalf("%s changed during an unrelated commit", name)
		}
	}
	backup, err := os.ReadFile(filepath.Join(result.BackupDir, "config"))
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup = %q, %v", backup, err)
	}

	// The engine's own state directory must never appear as configuration.
	regraph, err := resolver.Resolve(entry)
	if err != nil {
		t.Fatal(err)
	}
	for path := range regraph.Nodes {
		if filepath.Dir(path) == workspace.StateDir() {
			t.Fatalf("state directory leaked into the graph: %s", path)
		}
	}
}

func TestResolverReportsUnsupportedTokensInsteadOfGuessing(t *testing.T) {
	workspace := newIntegrationWorkspace(t)
	entry := filepath.Join(workspace.Root(), "config")
	if err := os.WriteFile(entry, []byte("Include %h/other.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := storage.NewResolver(workspace).Resolve(entry)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Code == config.DiagnosticIncludeUnsupported {
			found = true
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v", graph.Diagnostics)
	}
}

// deterministicRandom keeps transaction identifiers reproducible in tests.
func deterministicRandom() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x7f}, 4096))
}
