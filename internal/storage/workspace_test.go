package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newTestWorkspace builds an isolated home directory. macOS temporary
// directories are themselves reached through a symbolic link, so tests must
// compare against workspace.Root() instead of the literal path they built.
func newTestWorkspace(t *testing.T) *Workspace {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := NewWorkspace(OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestNewWorkspaceResolvesSymlinkedRootAndRejectsRelativeHome(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "real-ssh")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	workspace, err := NewWorkspace(OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Root() != resolved {
		t.Fatalf("root = %q, want %q", workspace.Root(), resolved)
	}
	if _, err := NewWorkspace(OSFileSystem{}, "relative/home"); !errors.Is(err, ErrInvalidHome) {
		t.Fatalf("relative home error = %v", err)
	}
}

func TestResolveForWriteAcceptsOnlyRealFilesInsideTheRoot(t *testing.T) {
	workspace := newTestWorkspace(t)
	root := workspace.Root()
	existing := filepath.Join(root, "config")
	if err := os.WriteFile(existing, []byte("Host example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}

	if got, err := workspace.ResolveForWrite(existing); err != nil || got != existing {
		t.Fatalf("existing file = %q, %v", got, err)
	}
	newFile := filepath.Join(root, "conf.d", "new.conf")
	if got, err := workspace.ResolveForWrite(newFile); err != nil || got != newFile {
		t.Fatalf("new file = %q, %v", got, err)
	}

	outside := filepath.Join(filepath.Dir(root), "outside.conf")
	for name, candidate := range map[string]string{
		"outside the root":  outside,
		"parent traversal":  filepath.Join(root, "..", "outside.conf"),
		"root itself":       root,
		"missing directory": filepath.Join(root, "absent", "new.conf"),
		"relative path":     "config",
	} {
		if _, err := workspace.ResolveForWrite(candidate); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestResolveForWriteRejectsSymlinkedFileAndParent(t *testing.T) {
	workspace := newTestWorkspace(t)
	root := workspace.Root()
	outsideDirectory := t.TempDir()
	outsideFile := filepath.Join(outsideDirectory, "target.conf")
	if err := os.WriteFile(outsideFile, []byte("Host elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "linked.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDirectory, filepath.Join(root, "linked.d")); err != nil {
		t.Fatal(err)
	}

	if _, err := workspace.ResolveForWrite(filepath.Join(root, "linked.conf")); !errors.Is(err, ErrSymlinkPath) {
		t.Errorf("symlinked file error = %v, want ErrSymlinkPath", err)
	}
	if _, err := workspace.ResolveForWrite(filepath.Join(root, "linked.d", "new.conf")); !errors.Is(err, ErrSymlinkPath) {
		t.Errorf("symlinked parent error = %v, want ErrSymlinkPath", err)
	}
}

func TestEnsureDirectoryCreatesPrivateDirectoriesAndRejectsSymlinks(t *testing.T) {
	workspace := newTestWorkspace(t)
	nested := filepath.Join(workspace.StateDir(), "journal")
	if err := workspace.EnsureDirectory(nested); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != DirectoryPermission {
		t.Fatalf("permission = %v, want %v", info.Mode().Perm(), DirectoryPermission)
	}
	if err := workspace.EnsureDirectory(nested); err != nil {
		t.Fatalf("second call = %v", err)
	}

	if err := os.Symlink(t.TempDir(), filepath.Join(workspace.Root(), "linked.d")); err != nil {
		t.Fatal(err)
	}
	if err := workspace.EnsureDirectory(filepath.Join(workspace.Root(), "linked.d", "child")); !errors.Is(err, ErrSymlinkPath) {
		t.Fatalf("symlinked component error = %v, want ErrSymlinkPath", err)
	}
	if err := workspace.EnsureDirectory(filepath.Join(filepath.Dir(workspace.Root()), "outside")); !errors.Is(err, ErrOutsideWorkspace) {
		t.Fatalf("outside error = %v, want ErrOutsideWorkspace", err)
	}
}

// Root is resolved through EvalSymlinks and Home deliberately is not: Home is
// what this process and its children have in HOME, which is what ssh prints and
// what SanitiseHomePaths has to match. The two therefore name the same
// directory in different ways whenever ~/.ssh is reached through a link, and a
// caller that expands "~" or "%d" and then compares against Root is told the
// path is outside the workspace when it is the workspace.
func TestNormaliseMapsAHomePathOntoTheResolvedRoot(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real-home")
	if err := os.MkdirAll(filepath.Join(real, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "linked-home")
	if err := os.Symlink(real, home); err != nil {
		t.Skipf("this filesystem does not support symbolic links: %v", err)
	}
	workspace, err := NewWorkspace(OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}

	// The premise: these are two spellings of one directory.
	if workspace.Root() == filepath.Join(home, ".ssh") {
		t.Skip("this filesystem did not produce two spellings of the root")
	}

	expanded := filepath.Join(home, ".ssh", "id_work")
	normalised := workspace.Normalise(expanded)
	if want := filepath.Join(workspace.Root(), "id_work"); normalised != want {
		t.Errorf("Normalise(%q) = %q, want %q", expanded, normalised, want)
	}
	if !workspace.Contains(normalised) {
		t.Errorf("%q is not inside the workspace it is inside", normalised)
	}
	if got := workspace.Normalise(filepath.Join(home, ".ssh")); got != workspace.Root() {
		t.Errorf("Normalise of the root itself = %q, want %q", got, workspace.Root())
	}
}

func TestNormaliseLeavesAPathThatIsNotUnderTheHomeAlone(t *testing.T) {
	workspace := newTestWorkspace(t)

	for _, path := range []string{"/etc/ssh/ssh_config", filepath.Join(workspace.Root(), "id_work")} {
		if got := workspace.Normalise(path); got != filepath.Clean(path) {
			t.Errorf("Normalise(%q) = %q, want it unchanged", path, got)
		}
	}
}
