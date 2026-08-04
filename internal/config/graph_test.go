package config

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"testing"
)

type fakeLoader struct {
	files map[string]string
	fail  map[string]error
}

func (l fakeLoader) ReadFile(name string) ([]byte, error) {
	if err, ok := l.fail[name]; ok {
		return nil, err
	}
	contents, ok := l.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(contents), nil
}

func (l fakeLoader) Glob(pattern string) ([]string, error) {
	var matches []string
	for name := range l.files {
		if matched, err := path.Match(pattern, name); err == nil && matched {
			matches = append(matches, name)
		}
	}
	for name := range l.fail {
		if matched, err := path.Match(pattern, name); err == nil && matched {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

func resolverFor(files map[string]string) Resolver {
	resolver := newTestResolver()
	resolver.Loader = fakeLoader{files: files}
	return resolver
}

func diagnosticCodes(graph *Graph) []string {
	codes := make([]string, 0, len(graph.Diagnostics))
	for _, diagnostic := range graph.Diagnostics {
		codes = append(codes, diagnostic.Code)
	}
	return codes
}

func requireDiagnostic(t *testing.T, graph *Graph, code string) Diagnostic {
	t.Helper()
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Code == code {
			return diagnostic
		}
	}
	t.Fatalf("diagnostic %q missing, got %v", code, diagnosticCodes(graph))
	return Diagnostic{}
}

func TestResolveLoadsIncludedFilesInLexicalGlobOrder(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config":           "Include conf.d/*.conf\nHost direct\n",
		"/Users/tester/.ssh/conf.d/20-b.conf": "Host bravo\n",
		"/Users/tester/.ssh/conf.d/10-a.conf": "Host alpha\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/Users/tester/.ssh/config",
		"/Users/tester/.ssh/conf.d/10-a.conf",
		"/Users/tester/.ssh/conf.d/20-b.conf",
	}
	if len(graph.Order) != len(want) {
		t.Fatalf("order = %#v", graph.Order)
	}
	for index := range want {
		if graph.Order[index] != want[index] {
			t.Fatalf("order[%d] = %q, want %q", index, graph.Order[index], want[index])
		}
	}
	root := graph.Nodes["/Users/tester/.ssh/config"]
	if !root.Editable || root.Missing || root.File == nil {
		t.Fatalf("root node = %#v", root)
	}
	if len(root.Includes) != 1 || root.Includes[0].Line != 1 || len(root.Includes[0].Matches) != 2 {
		t.Fatalf("root includes = %#v", root.Includes)
	}
	if root.Includes[0].Condition != "" {
		t.Errorf("top-level include has condition %q", root.Includes[0].Condition)
	}
}

func TestResolveStopsAtIncludeCycle(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Include a.conf\n",
		"/Users/tester/.ssh/a.conf": "Include b.conf\n",
		"/Users/tester/.ssh/b.conf": "Include config\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	cycle := requireDiagnostic(t, graph, DiagnosticIncludeCycle)
	if cycle.Path != "/Users/tester/.ssh/b.conf" || cycle.Severity != SeverityError {
		t.Fatalf("cycle diagnostic = %#v", cycle)
	}
	if len(graph.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(graph.Nodes))
	}
}

func TestResolveCountsDuplicateIncludesWithoutWalkingTwice(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config":      "Include shared.conf\nInclude shared.conf\n",
		"/Users/tester/.ssh/shared.conf": "Host shared\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeDuplicate)
	if loads := graph.Nodes["/Users/tester/.ssh/shared.conf"].Loads; loads != 2 {
		t.Fatalf("loads = %d, want 2", loads)
	}
	if len(graph.Order) != 2 {
		t.Fatalf("order = %#v", graph.Order)
	}
}

func TestResolveFlagsConditionalIncludes(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config":    "Host work\n\tInclude work.conf\n",
		"/Users/tester/.ssh/work.conf": "User ops\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	conditional := requireDiagnostic(t, graph, DiagnosticIncludeConditional)
	if conditional.Line != 2 {
		t.Fatalf("conditional diagnostic = %#v", conditional)
	}
	edge := graph.Nodes["/Users/tester/.ssh/config"].Includes[0]
	if edge.Condition != "Host work" {
		t.Fatalf("edge condition = %q", edge.Condition)
	}
}

func TestResolveMarksFilesOutsideTheRootAsNotEditable(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Include /etc/ssh/shared.conf\n",
		"/etc/ssh/shared.conf":      "Host shared\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeOutsideRoot)
	outside := graph.Nodes["/etc/ssh/shared.conf"]
	if outside == nil || outside.Editable || outside.File == nil {
		t.Fatalf("outside node = %#v", outside)
	}
}

func TestResolveReportsPatternsItRefusesToExpand(t *testing.T) {
	graph, err := resolverFor(map[string]string{
		"/Users/tester/.ssh/config": "Include %h/config\nInclude missing/*.conf\nInclude\n",
	}).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	unsupported := requireDiagnostic(t, graph, DiagnosticIncludeUnsupported)
	if unsupported.Line != 1 || unsupported.Severity != SeverityWarning {
		t.Fatalf("unsupported diagnostic = %#v", unsupported)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeNoMatch)
	requireDiagnostic(t, graph, DiagnosticIncludeEmpty)
	edges := graph.Nodes["/Users/tester/.ssh/config"].Includes
	if len(edges) != 2 || edges[0].Expanded != "" || len(edges[0].Matches) != 0 {
		t.Fatalf("edges = %#v", edges)
	}
}

func TestResolveReportsUnreadableAndMissingRoot(t *testing.T) {
	resolver := newTestResolver()
	resolver.Loader = fakeLoader{
		files: map[string]string{"/Users/tester/.ssh/config": "Include broken.conf\n"},
		fail:  map[string]error{"/Users/tester/.ssh/broken.conf": fs.ErrPermission},
	}
	graph, err := resolver.Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	unreadable := requireDiagnostic(t, graph, DiagnosticIncludeUnreadable)
	if unreadable.Severity != SeverityError {
		t.Fatalf("unreadable diagnostic = %#v", unreadable)
	}
	if node := graph.Nodes["/Users/tester/.ssh/broken.conf"]; node == nil || node.File != nil {
		t.Fatalf("broken node = %#v", graph.Nodes["/Users/tester/.ssh/broken.conf"])
	}

	empty := resolverFor(map[string]string{})
	missing, err := empty.Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	if !missing.Nodes["/Users/tester/.ssh/config"].Missing {
		t.Fatal("missing root file was not reported as missing")
	}
}

func TestResolveStopsAtMaxDepth(t *testing.T) {
	files := map[string]string{"/Users/tester/.ssh/config": "Include chain-0.conf\n"}
	for index := 0; index < 20; index++ {
		files[fmt.Sprintf("/Users/tester/.ssh/chain-%d.conf", index)] =
			fmt.Sprintf("Include chain-%d.conf\n", index+1)
	}
	graph, err := resolverFor(files).Resolve("/Users/tester/.ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, graph, DiagnosticIncludeDepthExceeded)
	if len(graph.Nodes) != DefaultMaxDepth+1 {
		t.Fatalf("nodes = %d, want %d", len(graph.Nodes), DefaultMaxDepth+1)
	}
}

func TestResolveRejectsRelativeEntryPath(t *testing.T) {
	if _, err := resolverFor(nil).Resolve("config"); err == nil {
		t.Fatal("Resolve accepted a relative entry path")
	}
}
