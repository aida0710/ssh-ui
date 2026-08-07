package effective_test

import (
	"io/fs"
	"path"
	"sort"
	"testing"

	"sshc/internal/config"
	"sshc/internal/effective"
)

// fakeLoader serves configuration files from a map so no test reads a disk.
type fakeLoader struct{ files map[string]string }

func (l fakeLoader) ReadFile(name string) ([]byte, error) {
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
	sort.Strings(matches)
	return matches, nil
}

const testHome = "/Users/tester"
const testRoot = "/Users/tester/.ssh"
const testConfig = "/Users/tester/.ssh/config"

func graphFor(t *testing.T, files map[string]string) *config.Graph {
	t.Helper()
	resolver := config.Resolver{
		Loader: fakeLoader{files: files},
		Home:   testHome,
		Root:   testRoot,
		Tokens: map[byte]string{'d': testHome},
	}
	graph, err := resolver.Resolve(testConfig)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func TestScanFindsEveryExecutableDirectiveWithItsExactText(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Include conf.d/*.conf\n" +
			"Host jump\n" +
			"\tProxyCommand   /usr/bin/nc  -X 5 -x proxy:1080 %h %p\n" +
			"\tLocalCommand /usr/bin/say connected\n" +
			"\tPermitLocalCommand yes\n" +
			"Match exec \"test -f /tmp/at-work\"\n" +
			"\tUser office\n",
		"/Users/tester/.ssh/conf.d/10-extra.conf": "Host shell\n" +
			"\tRemoteCommand tmux attach\n" +
			"\tKnownHostsCommand /usr/local/bin/hosts %H\n",
	})

	report := effective.Scan(graph)
	if len(report.Directives) != 5 {
		t.Fatalf("directives = %#v", report.Directives)
	}

	byKeyword := make(map[string]effective.Executable, len(report.Directives))
	for _, directive := range report.Directives {
		byKeyword[directive.Keyword] = directive
	}

	proxy := byKeyword["ProxyCommand"]
	if proxy.Command != "/usr/bin/nc  -X 5 -x proxy:1080 %h %p" {
		t.Errorf("ProxyCommand text = %q, want the exact argument text", proxy.Command)
	}
	if proxy.Path != testConfig || proxy.Line != 3 || proxy.Condition != "Host jump" {
		t.Errorf("ProxyCommand location = %#v", proxy)
	}
	if !proxy.OnConnect || proxy.OnEvaluate || proxy.Overridable {
		t.Errorf("ProxyCommand flags = %#v", proxy)
	}

	matchExec := byKeyword["Match exec"]
	if matchExec.Command != "test -f /tmp/at-work" || !matchExec.OnEvaluate {
		t.Errorf("Match exec = %#v", matchExec)
	}
	if matchExec.Line != 6 {
		t.Errorf("Match exec line = %d, want 6", matchExec.Line)
	}

	if local := byKeyword["LocalCommand"]; !local.Overridable || !local.OnConnect {
		t.Errorf("LocalCommand = %#v", local)
	}
	if remote := byKeyword["RemoteCommand"]; !remote.Overridable || remote.Path != "/Users/tester/.ssh/conf.d/10-extra.conf" {
		t.Errorf("RemoteCommand = %#v", remote)
	}
	if known := byKeyword["KnownHostsCommand"]; known.Overridable || !known.OnConnect {
		t.Errorf("KnownHostsCommand = %#v", known)
	}
}

func TestReportGatesEvaluationAndConnectionSeparately(t *testing.T) {
	safe := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host plain\n\tHostName 203.0.113.10\n\tUser ops\n",
	}))
	if safe.EvaluationNeedsConfirmation() || safe.ConnectionNeedsConfirmation() {
		t.Fatalf("a configuration without executable directives needs no confirmation: %#v", safe)
	}
	if len(safe.Unavoidable()) != 0 {
		t.Errorf("unavoidable = %#v", safe.Unavoidable())
	}

	connectOnly := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tLocalCommand /usr/bin/say hi\n",
	}))
	if connectOnly.EvaluationNeedsConfirmation() {
		t.Error("LocalCommand does not run while OpenSSH evaluates a configuration")
	}
	if !connectOnly.ConnectionNeedsConfirmation() {
		t.Error("LocalCommand runs while OpenSSH connects")
	}
	if len(connectOnly.Unavoidable()) != 0 {
		t.Errorf("LocalCommand can be disabled on the command line: %#v", connectOnly.Unavoidable())
	}

	evaluation := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Match exec \"id -u\"\n\tUser root\n",
	}))
	if !evaluation.EvaluationNeedsConfirmation() || !evaluation.ConnectionNeedsConfirmation() {
		t.Errorf("Match exec gates both operations: %#v", evaluation)
	}
	if len(evaluation.Unavoidable()) != 1 {
		t.Errorf("Match exec cannot be disabled: %#v", evaluation.Unavoidable())
	}
}

func TestEvidenceChangesWhenTheDisplayedCommandChanges(t *testing.T) {
	first := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tProxyCommand /usr/bin/nc %h %p\n",
	}))
	same := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tProxyCommand /usr/bin/nc %h %p\n",
	}))
	changed := effective.Scan(graphFor(t, map[string]string{
		testConfig: "Host jump\n\tProxyCommand /usr/bin/nc -X 5 %h %p\n",
	}))

	if first.Evidence() != same.Evidence() {
		t.Error("identical configurations produced different evidence")
	}
	if first.Evidence() == changed.Evidence() {
		t.Error("an edited command produced the same evidence")
	}
	if (effective.Report{}).Evidence() == "" {
		t.Error("an empty report must still produce a stable evidence value")
	}
}
