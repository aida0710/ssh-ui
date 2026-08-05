package application

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"testing"

	"ssh-ui/internal/storage"
)

// mapLoader is a config.Loader backed by a map, so an overlay can be exercised
// without a filesystem.
type mapLoader map[string][]byte

func (loader mapLoader) ReadFile(name string) ([]byte, error) {
	contents, ok := loader[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return contents, nil
}

func (loader mapLoader) Glob(pattern string) ([]string, error) {
	var matches []string
	for name := range loader {
		matched, err := filepath.Match(pattern, name)
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

// The overlay is what a save is validated against, so it has to describe the
// filesystem the transaction will actually produce. Modelling only the writes
// meant a move was checked against a world where the file existed in both
// places at once.
func TestOverlayForDescribesWhatArrivesAndWhatLeaves(t *testing.T) {
	pending, gone := overlayFor(storage.Request{
		Changes:  []storage.Change{{Path: "conf.d/20-new.conf", Contents: []byte("Host new\n")}},
		Moves:    []storage.Move{{From: "conf.d/10-old.conf", To: "connections/work/10-old.conf"}},
		Removals: []storage.Removal{{Path: "conf.d/30-dead.conf"}},
	})

	if string(pending["conf.d/20-new.conf"]) != "Host new\n" {
		t.Fatalf("pending = %#v, want the written contents", pending)
	}
	if !gone["conf.d/10-old.conf"] {
		t.Errorf("a move's source is not marked gone")
	}
	if !gone["conf.d/30-dead.conf"] {
		t.Errorf("a removal is not marked gone")
	}
	if gone["connections/work/10-old.conf"] {
		t.Errorf("a move's destination must not be marked gone")
	}
}

func TestOverlayLoaderHidesAMovedSourceFromReadsAndGlobs(t *testing.T) {
	base := mapLoader{
		"/home/tester/.ssh/conf.d/10-old.conf":           []byte("Host nas\n"),
		"/home/tester/.ssh/conf.d/keep.conf":             []byte("Host keep\n"),
		"/home/tester/.ssh/connections/work/10-old.conf": []byte("Host nas\n"),
	}
	loader := overlayLoader{
		base:    base,
		pending: map[string][]byte{"/home/tester/.ssh/connections/work/10-old.conf": []byte("Host nas\n")},
		gone:    map[string]bool{"/home/tester/.ssh/conf.d/10-old.conf": true},
	}

	if _, err := loader.ReadFile("/home/tester/.ssh/conf.d/10-old.conf"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reading a moved source error = %v, want fs.ErrNotExist", err)
	}
	if _, err := loader.ReadFile("/home/tester/.ssh/conf.d/keep.conf"); err != nil {
		t.Fatalf("reading an untouched file error = %v", err)
	}

	matches, err := loader.Glob("/home/tester/.ssh/conf.d/*.conf")
	if err != nil {
		t.Fatalf("Glob error = %v", err)
	}
	// Without gone the moved file would still match here, so an Include glob
	// would see the block twice and report a duplicate alias that will not
	// exist once the transaction commits.
	if len(matches) != 1 || matches[0] != "/home/tester/.ssh/conf.d/keep.conf" {
		t.Fatalf("Glob = %v, want only the untouched file", matches)
	}
}

// A transaction may write a file and remove the same path, which is what a
// move onto an existing destination looks like. The contents win.
func TestOverlayLoaderPrefersPendingContentsOverARemoval(t *testing.T) {
	loader := overlayLoader{
		base:    mapLoader{},
		pending: map[string][]byte{"/home/tester/.ssh/config": []byte("Host rewritten\n")},
		gone:    map[string]bool{"/home/tester/.ssh/config": true},
	}

	contents, err := loader.ReadFile("/home/tester/.ssh/config")
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}
	if string(contents) != "Host rewritten\n" {
		t.Fatalf("contents = %q, want the pending contents", contents)
	}
}

// TestValidateLeavesApplicationStateAlone is the regression test for a defect
// this project's own end-to-end suite found in CI and not locally.
//
// The password vault shares this transaction manager, so it passes through
// this validator. The validator used to parse every change as ssh_config, and
// a sealed vault is ciphertext: when its random bytes happened to contain an
// odd number of quotation marks it was refused as "unbalanced quoting". That
// is a coin flip on every save, which is exactly the shape of a test that
// passes on one machine and fails on another.
func TestValidateLeavesApplicationStateAlone(t *testing.T) {
	service, workspace := newTestService(t)
	if err := workspace.EnsureDirectory(workspace.StateDir()); err != nil {
		t.Fatal(err)
	}

	// One unmatched quotation mark, which is what the ciphertext kept
	// accidentally producing.
	ciphertext := []byte("\x91\x2f\"\x00\xd4 not configuration at all\n")

	if _, err := service.manager.Commit(storage.Request{
		Operation: "secret.vault",
		Changes: []storage.Change{{
			Path:       filepath.Join(workspace.StateDir(), "secrets"),
			Contents:   ciphertext,
			SkipBackup: true,
		}},
	}); err != nil {
		t.Fatalf("a file under ssh-ui/ was validated as configuration: %v", err)
	}

	// The same bytes as a real configuration file are still refused, so this
	// narrows the validator rather than disabling it.
	if _, err := service.manager.Commit(storage.Request{
		Operation: "config.file_raw",
		Changes: []storage.Change{{
			Path:     filepath.Join(workspace.Root(), "conf.d", "20-bad.conf"),
			Contents: ciphertext,
		}},
	}); err == nil {
		t.Fatal("unbalanced quoting reached a configuration file")
	}

	// And a sibling of the state directory is not mistaken for a child of it.
	if _, err := service.manager.Commit(storage.Request{
		Operation: "config.file_raw",
		Changes: []storage.Change{{
			Path:     filepath.Join(workspace.Root(), "ssh-ui-notes.conf"),
			Contents: ciphertext,
		}},
	}); err == nil {
		t.Fatal("a sibling of ssh-ui/ escaped validation")
	}
}
