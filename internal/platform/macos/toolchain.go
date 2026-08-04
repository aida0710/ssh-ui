package macos

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrProgramNotFound reports that an OpenSSH program is not installed in any
// directory this application is willing to run programs from.
var ErrProgramNotFound = errors.New("OpenSSH program not found")

// Toolchain finds OpenSSH programs at fixed absolute paths.
//
// PATH is deliberately not consulted: the program this application runs must
// not depend on the environment it inherited. /usr/bin comes first because the
// design targets the OpenSSH that ships with macOS; the Homebrew prefixes are
// fallbacks for a machine where Apple's copy was removed.
type Toolchain struct {
	Directories []string
	Stat        func(string) (fs.FileInfo, error)
}

// NewToolchain returns the default macOS search order.
func NewToolchain() Toolchain {
	return Toolchain{Directories: []string{"/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"}}
}

// SSH returns the absolute path of the ssh client.
func (t Toolchain) SSH() (string, error) { return t.find("ssh") }

// KeyScan returns the absolute path of ssh-keyscan.
func (t Toolchain) KeyScan() (string, error) { return t.find("ssh-keyscan") }

// KeyGen returns the absolute path of ssh-keygen.
func (t Toolchain) KeyGen() (string, error) { return t.find("ssh-keygen") }

// KeyAdd returns the absolute path of ssh-add.
func (t Toolchain) KeyAdd() (string, error) { return t.find("ssh-add") }

func (t Toolchain) find(program string) (string, error) {
	stat := t.Stat
	if stat == nil {
		stat = os.Stat
	}
	for _, directory := range t.Directories {
		candidate := filepath.Join(directory, program)
		info, err := stat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%w: %s", ErrProgramNotFound, program)
}
