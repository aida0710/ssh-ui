package acceptance_test

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// FuzzAPIRequestBodies は、API 背後の JSON デコーダ全部を一度に fuzz する。
//
// サーバーはキャンペーン全体で 1 つだけ構築され、各実行が
// 1 つのルートへ body を post する。不変条件は、ブラウザ内の
// 悪意あるページが破ろうとするであろうもの: プロセスは生き
// 続けて応答し、レスポンスは際限なく肥大せず、すべてのレスポンスは依然として no-store
// であり、どのレスポンスも canary を漏らさず、ワークスペース外のファイルは決して触れられない。
func FuzzAPIRequestBodies(f *testing.F) {
	fixture := newFixture(f)
	routes := []string{}
	for _, route := range fixture.apiRoutes() {
		if route.Method == http.MethodGet || route.Method == http.MethodHead {
			continue
		}
		if route.Path == "/api/v1/session/bootstrap" {
			continue
		}
		routes = append(routes, fixture.concretePath(route.Path))
	}
	if len(routes) == 0 {
		f.Fatal("no mutating API route is registered; the harness is not wiring the services")
	}

	outside := filepath.Join(fixture.home, "private-notes", "canary.txt")
	original, err := os.ReadFile(outside)
	if err != nil {
		f.Fatal(err)
	}

	seeds := []string{
		`{}`,
		`[]`,
		`null`,
		`{"kind":"file_raw","path":"config","base":"","raw":"Host seed\n"}`,
		`{"kind":"host_fields","path":"config","alias":"bastion","base":"","fields":[]}`,
		`{"alias":"bastion","acknowledgeExecutable":true}`,
		`{"host":"203.0.113.10","port":22}`,
		`{"transactionId":"seed","path":"config"}`,
		`{"transactionId":"seed","action":"complete"}`,
		`{"algorithm":"ed25519","fileName":"seed","comment":"","passphrase":"","unencrypted":true}`,
		`{"unknownField":1}`,
		`{"path":"../../etc/passwd"}`,
		`{"raw":"` + strings.Repeat("A", 4096) + `"}`,
		"{\"raw\":\"a\\u0000b\"}",
		`{"line":`,
		"\x00\x01\x02",
	}
	for index := range routes {
		for _, seed := range seeds {
			f.Add(uint8(index), []byte(seed))
		}
	}

	f.Fuzz(func(t *testing.T, index uint8, body []byte) {
		path := routes[int(index)%len(routes)]
		response := fixture.doAs(t, fixture.client, http.MethodPost, path, body)
		cache := response.Header.Get("Cache-Control")
		text := readBody(t, response)

		if cache != "no-store" {
			t.Fatalf("%s answered with Cache-Control %q", path, cache)
		}
		if len(text) > maxAcceptableResponseBytes {
			t.Fatalf("%s answered with %d bytes", path, len(text))
		}
		for name, secret := range map[string]string{
			"a file outside ~/.ssh": fixture.canaries.Outside,
			"the key passphrase":    fixture.canaries.Passphrase,
			"the bootstrap token":   fixture.canaries.Bootstrap,
			"the session id":        fixture.canaries.SessionID,
			"private key material":  fixture.canaries.PrivateKeyLine,
		} {
			if secret != "" && strings.Contains(text, secret) {
				t.Fatalf("%s leaked %s", path, name)
			}
		}

		current, err := os.ReadFile(outside)
		if err != nil || string(current) != string(original) {
			t.Fatalf("a fuzzed request changed the file outside the workspace: %v", err)
		}

		// Liveness: サーバーは、直前に読んだものが何であれ、その後も応答し続けなければならない。
		health := fixture.doAs(t, fixture.client, http.MethodGet, "/api/v1/health", nil)
		healthStatus := health.StatusCode
		readBody(t, health)
		if healthStatus != http.StatusOK {
			t.Fatalf("health after %s = %d", path, healthStatus)
		}
	})
}

// fuzzFunctionPattern は、Go の fuzz target 宣言にマッチする。
var fuzzFunctionPattern = regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]*)\(f \*testing\.F\)`)

// makefileTargetsPattern は、バックスラッシュによる継続を
// 含め、FUZZ_TARGETS の代入を抽出する。
var makefileTargetsPattern = regexp.MustCompile(`(?s)FUZZ_TARGETS\s*=\s*(.*?)\n\n`)

func TestMakefileFuzzTargetsCoverEveryFuzzFunction(t *testing.T) {
	root := filepath.Join("..", "..")

	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	match := makefileTargetsPattern.FindSubmatch(makefile)
	if match == nil {
		t.Fatal("the Makefile has no FUZZ_TARGETS list")
	}
	declared := map[string]bool{}
	for _, field := range strings.Fields(strings.ReplaceAll(string(match[1]), "\\", " ")) {
		declared[field] = true
	}

	found := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "web", "bin", "docs", ".claude", ".worktrees", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		for _, declaration := range fuzzFunctionPattern.FindAllStringSubmatch(string(contents), -1) {
			found[filepath.ToSlash(relative)+":"+declaration[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("the walk found no fuzz target at all; the coverage test is not looking in the right place")
	}

	for target := range found {
		if !declared[target] {
			t.Errorf("fuzz target %s exists but `make fuzz` does not run it", target)
		}
	}
	for target := range declared {
		if !found[target] {
			t.Errorf("`make fuzz` names %s but no such fuzz target exists", target)
		}
	}
}
