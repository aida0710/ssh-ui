package macos_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"sshc/internal/platform"
	"sshc/internal/platform/macos"
)

var _ platform.Toolchain = macos.Toolchain{}

func writeProgram(t *testing.T, directory, name string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/usr/bin/true\n"), mode); err != nil {
		t.Fatal(err)
	}
}

func TestToolchainPrefersTheFirstDirectoryThatHoldsAnExecutable(t *testing.T) {
	preferred := t.TempDir()
	fallback := t.TempDir()
	writeProgram(t, fallback, "ssh", 0o755)
	writeProgram(t, preferred, "ssh", 0o755)
	writeProgram(t, fallback, "ssh-keyscan", 0o755)
	writeProgram(t, fallback, "ssh-keygen", 0o755)
	writeProgram(t, preferred, "ssh-keygen", 0o755)
	writeProgram(t, fallback, "ssh-add", 0o755)

	toolchain := macos.Toolchain{Directories: []string{preferred, fallback}}

	sshPath, err := toolchain.SSH()
	if err != nil {
		t.Fatalf("SSH() = %v", err)
	}
	if want := filepath.Join(preferred, "ssh"); sshPath != want {
		t.Errorf("SSH() = %q, want %q", sshPath, want)
	}

	keyscanPath, err := toolchain.KeyScan()
	if err != nil {
		t.Fatalf("KeyScan() = %v", err)
	}
	if want := filepath.Join(fallback, "ssh-keyscan"); keyscanPath != want {
		t.Errorf("KeyScan() = %q, want %q", keyscanPath, want)
	}

	keygenPath, err := toolchain.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen() = %v", err)
	}
	if want := filepath.Join(preferred, "ssh-keygen"); keygenPath != want {
		t.Errorf("KeyGen() = %q, want %q", keygenPath, want)
	}

	keyaddPath, err := toolchain.KeyAdd()
	if err != nil {
		t.Fatalf("KeyAdd() = %v", err)
	}
	if want := filepath.Join(fallback, "ssh-add"); keyaddPath != want {
		t.Errorf("KeyAdd() = %q, want %q", keyaddPath, want)
	}
}

func TestToolchainIgnoresMissingAndNonExecutableFiles(t *testing.T) {
	directory := t.TempDir()
	writeProgram(t, directory, "ssh", 0o644)
	writeProgram(t, directory, "ssh-keygen", 0o644)
	if err := os.Mkdir(filepath.Join(directory, "ssh-keyscan"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, "ssh-add"), 0o755); err != nil {
		t.Fatal(err)
	}

	toolchain := macos.Toolchain{Directories: []string{directory}}
	if _, err := toolchain.SSH(); !errors.Is(err, macos.ErrProgramNotFound) {
		t.Errorf("SSH() = %v, want ErrProgramNotFound", err)
	}
	if _, err := toolchain.KeyScan(); !errors.Is(err, macos.ErrProgramNotFound) {
		t.Errorf("KeyScan() = %v, want ErrProgramNotFound", err)
	}
	if _, err := toolchain.KeyGen(); !errors.Is(err, macos.ErrProgramNotFound) {
		t.Errorf("KeyGen() = %v, want ErrProgramNotFound", err)
	}
	if _, err := toolchain.KeyAdd(); !errors.Is(err, macos.ErrProgramNotFound) {
		t.Errorf("KeyAdd() = %v, want ErrProgramNotFound", err)
	}
}

func TestToolchainResolvesEveryProgramThroughTheInjectedStat(t *testing.T) {
	installed := fstest.MapFS{
		"sandbox/ssh":         &fstest.MapFile{Mode: 0o755},
		"sandbox/ssh-keyscan": &fstest.MapFile{Mode: 0o755},
		"sandbox/ssh-keygen":  &fstest.MapFile{Mode: 0o755},
		"sandbox/ssh-add":     &fstest.MapFile{Mode: 0o755},
	}
	var asked []string
	toolchain := macos.Toolchain{
		Directories: []string{"/sandbox"},
		Stat: func(name string) (fs.FileInfo, error) {
			asked = append(asked, name)
			return installed.Stat(strings.TrimPrefix(name, "/"))
		},
	}

	resolvers := map[string]func() (string, error){
		"ssh":         toolchain.SSH,
		"ssh-keyscan": toolchain.KeyScan,
		"ssh-keygen":  toolchain.KeyGen,
		"ssh-add":     toolchain.KeyAdd,
	}
	for program, resolve := range resolvers {
		path, err := resolve()
		if err != nil {
			t.Fatalf("resolving %s = %v", program, err)
		}
		if want := filepath.Join("/sandbox", program); path != want {
			t.Errorf("resolving %s = %q, want %q", program, path, want)
		}
	}
	if len(asked) != len(resolvers) {
		t.Errorf("injected Stat saw %#v, want one lookup per program", asked)
	}
}

func TestNewToolchainLooksAtTheSystemOpenSSHFirst(t *testing.T) {
	directories := macos.NewToolchain().Directories
	if len(directories) == 0 || directories[0] != "/usr/bin" {
		t.Fatalf("directories = %#v, want /usr/bin first", directories)
	}
}
