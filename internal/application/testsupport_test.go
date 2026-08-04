package application

import (
	"io/fs"
	"path"
	"sort"
	"testing"

	"ssh-ui/internal/config"
)

const testRoot = "/home/tester/.ssh"
const testHome = "/home/tester"

// fakeLoader serves configuration files from memory so projection tests never
// touch a disk. Keys are absolute, slash-separated paths.
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

// newTestGraph resolves an in-memory configuration tree. Keys are relative to
// testRoot.
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
