package storage

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// MaxFileSize bounds how much of one configuration file is read into
	// memory. Real client configurations are far smaller.
	MaxFileSize = 1 << 20

	// DirectoryPermission is applied to directories this application creates.
	DirectoryPermission fs.FileMode = 0o700
	// FilePermission is the maximum permission a managed file may carry. A
	// stricter existing permission is preserved.
	FilePermission fs.FileMode = 0o600
)

var (
	ErrFileTooLarge   = errors.New("file is larger than the supported maximum")
	ErrNotRegularFile = errors.New("path is not a regular file")
)

// FileSystem is the only path through which this package touches the disk.
// Tests wrap an OSFileSystem to inject a failure at a chosen stage.
type FileSystem interface {
	// ReadFile reads a regular file without following a symbolic link.
	ReadFile(path string) ([]byte, error)
	Lstat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	// Glob returns matches in lexical order.
	Glob(pattern string) ([]string, error)
	MkdirAll(path string, permission fs.FileMode) error
	// WriteTemp creates a new file in directory, writes contents, applies
	// permission, flushes it to disk and returns its path.
	WriteTemp(directory, prefix string, permission fs.FileMode, contents []byte) (string, error)
	Rename(oldPath, newPath string) error
	Remove(path string) error
	SyncDir(path string) error
	EvalSymlinks(path string) (string, error)
}

// OSFileSystem is the macOS implementation of FileSystem.
type OSFileSystem struct{}

func (OSFileSystem) ReadFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrSymlinkPath
		}
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegularFile
	}
	contents, err := io.ReadAll(io.LimitReader(file, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > MaxFileSize {
		return nil, ErrFileTooLarge
	}
	return contents, nil
}

func (OSFileSystem) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }

func (OSFileSystem) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }

func (OSFileSystem) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

func (OSFileSystem) MkdirAll(path string, permission fs.FileMode) error {
	return os.MkdirAll(path, permission)
}

func (OSFileSystem) WriteTemp(directory, prefix string, permission fs.FileMode, contents []byte) (string, error) {
	file, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := writeAndFlush(file, permission, contents); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func writeAndFlush(file *os.File, permission fs.FileMode, contents []byte) error {
	if err := file.Chmod(permission); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	return file.Sync()
}

func (OSFileSystem) Rename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

func (OSFileSystem) Remove(path string) error { return os.Remove(path) }

func (OSFileSystem) SyncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (OSFileSystem) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }
