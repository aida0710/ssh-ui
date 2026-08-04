package storage

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

var (
	ErrOutsideWorkspace = errors.New("path is outside the ssh-ui workspace")
	ErrSymlinkPath      = errors.New("path contains a symbolic link")
	ErrMissingDirectory = errors.New("parent directory does not exist")
	ErrNotDirectory     = errors.New("path component is not a directory")
	ErrInvalidHome      = errors.New("home directory must be an absolute path")
)

// Workspace pins every write to the user's resolved ~/.ssh directory.
//
// The root is resolved once through EvalSymlinks so a user who keeps ~/.ssh on
// another volume still works, while every component below the root must be a
// real directory. Symbolic links below the root are shown by the UI but are
// never written through, so a link cannot widen the writable set.
type Workspace struct {
	fileSystem FileSystem
	home       string
	root       string
}

// NewWorkspace resolves home/.ssh. A missing directory is not an error; it is
// created on first write.
func NewWorkspace(fileSystem FileSystem, home string) (*Workspace, error) {
	if !filepath.IsAbs(home) {
		return nil, ErrInvalidHome
	}
	cleanedHome := filepath.Clean(home)
	root := filepath.Join(cleanedHome, ".ssh")
	resolved, err := fileSystem.EvalSymlinks(root)
	switch {
	case err == nil:
		root = filepath.Clean(resolved)
	case errors.Is(err, fs.ErrNotExist):
		// Keep the literal path; EnsureDirectory creates it later.
	default:
		return nil, err
	}
	return &Workspace{fileSystem: fileSystem, home: cleanedHome, root: root}, nil
}

func (w *Workspace) FileSystem() FileSystem { return w.fileSystem }

func (w *Workspace) Home() string { return w.home }

func (w *Workspace) Root() string { return w.root }

// StateDir is the directory holding journals, history and backups.
func (w *Workspace) StateDir() string { return filepath.Join(w.root, "ssh-ui") }

// Contains reports whether candidate is the root or lives below it.
func (w *Workspace) Contains(candidate string) bool {
	cleaned := filepath.Clean(candidate)
	return cleaned == w.root || strings.HasPrefix(cleaned, w.root+string(filepath.Separator))
}

// ResolveForWrite validates that candidate is an absolute path below the root
// whose parents are real directories and which is either absent or a regular
// file. It returns the cleaned path.
func (w *Workspace) ResolveForWrite(candidate string) (string, error) {
	cleaned := filepath.Clean(candidate)
	if !filepath.IsAbs(cleaned) || !w.Contains(cleaned) || cleaned == w.root {
		return "", ErrOutsideWorkspace
	}
	relative, err := filepath.Rel(w.root, cleaned)
	if err != nil {
		return "", ErrOutsideWorkspace
	}

	segments := strings.Split(relative, string(filepath.Separator))
	current := w.root
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, statErr := w.fileSystem.Lstat(current)
		last := index == len(segments)-1
		switch {
		case errors.Is(statErr, fs.ErrNotExist):
			if last {
				return cleaned, nil
			}
			return "", ErrMissingDirectory
		case statErr != nil:
			return "", statErr
		case info.Mode()&fs.ModeSymlink != 0:
			return "", ErrSymlinkPath
		case last && !info.Mode().IsRegular():
			return "", ErrNotRegularFile
		case !last && !info.IsDir():
			return "", ErrNotDirectory
		}
	}
	return cleaned, nil
}

// EnsureDirectory creates candidate and any missing parent below the root with
// DirectoryPermission, refusing to traverse a symbolic link.
func (w *Workspace) EnsureDirectory(candidate string) error {
	cleaned := filepath.Clean(candidate)
	if !w.Contains(cleaned) {
		return ErrOutsideWorkspace
	}
	if _, err := w.fileSystem.Lstat(w.root); errors.Is(err, fs.ErrNotExist) {
		if err := w.fileSystem.MkdirAll(w.root, DirectoryPermission); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	relative, err := filepath.Rel(w.root, cleaned)
	if err != nil {
		return ErrOutsideWorkspace
	}
	current := w.root
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, statErr := w.fileSystem.Lstat(current)
		switch {
		case errors.Is(statErr, fs.ErrNotExist):
			if err := w.fileSystem.MkdirAll(current, DirectoryPermission); err != nil {
				return err
			}
		case statErr != nil:
			return statErr
		case info.Mode()&fs.ModeSymlink != 0:
			return ErrSymlinkPath
		case !info.IsDir():
			return ErrNotDirectory
		}
	}
	return nil
}
