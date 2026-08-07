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
	// MaxFileSize は、設定ファイルひとつをメモリへ読み込む量の上限。実際の
	// クライアント設定はこれよりはるかに小さい。
	MaxFileSize = 1 << 20

	// DirectoryPermission は、このアプリケーションが作るディレクトリに適用される。
	DirectoryPermission fs.FileMode = 0o700
	// FilePermission は、管理対象ファイルが持ちうる最大の権限。既存のより厳しい権限は
	// そのまま保たれる。
	FilePermission fs.FileMode = 0o600
)

var (
	ErrFileTooLarge   = errors.New("file is larger than the supported maximum")
	ErrNotRegularFile = errors.New("path is not a regular file")
)

// FileSystem は、このパッケージがディスクに触れる唯一の経路。テストは
// OSFileSystem を包み、任意の段階で失敗を注入する。
type FileSystem interface {
	// ReadFile は、シンボリックリンクをたどらずに通常ファイルを読む。
	ReadFile(path string) ([]byte, error)
	Lstat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	// Glob は辞書順で一致を返す。
	Glob(pattern string) ([]string, error)
	MkdirAll(path string, permission fs.FileMode) error
	// WriteTemp は directory に新しいファイルを作り、contents を書き、permission を
	// 適用し、ディスクへフラッシュして、そのパスを返す。
	WriteTemp(directory, prefix string, permission fs.FileMode, contents []byte) (string, error)
	Rename(oldPath, newPath string) error
	Remove(path string) error
	SyncDir(path string) error
	EvalSymlinks(path string) (string, error)
}

// OSFileSystem は FileSystem の macOS 実装。
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
