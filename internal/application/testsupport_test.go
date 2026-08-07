package application

import (
	"io/fs"
	"path"
	"sort"
	"testing"

	"sshc/internal/config"
)

const testRoot = "/home/tester/.ssh"
const testHome = "/home/tester"

// fakeLoader は、射影テストが決してディスクに触れないように、
// メモリから設定ファイルを提供する。key は絶対のスラッシュ区切り path である。
type fakeLoader struct{ files map[string]string }

func (loader fakeLoader) ReadFile(name string) ([]byte, error) {
	contents, ok := loader.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(contents), nil
}

func (loader fakeLoader) Glob(pattern string) ([]string, error) {
	var matches []string
	for name := range loader.files {
		matched, err := path.Match(pattern, name)
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

// newTestGraph は、メモリ内の設定 tree を解決する。key は testRoot
// からの相対である。
func newTestGraph(t *testing.T, files map[string]string) *config.Graph {
	t.Helper()
	absolute := make(map[string]string, len(files))
	for name, contents := range files {
		absolute[path.Join(testRoot, name)] = contents
	}
	resolver := config.Resolver{
		Loader: fakeLoader{files: absolute},
		Home:   testHome,
		Root:   testRoot,
		Tokens: map[byte]string{'d': testHome},
	}
	graph, err := resolver.Resolve(path.Join(testRoot, "config"))
	if err != nil {
		t.Fatal(err)
	}
	return graph
}
