// Package application holds the use cases that sit between the lossless
// configuration engine and the filesystem transaction manager. It never
// performs a syscall directly: every read and write goes through the storage
// workspace it is given.
package application

import (
	"errors"
	"path/filepath"
	"strings"
)

// ErrExternalPath reports a path that is not a real location inside the
// resolved ~/.ssh directory. The UI may display files outside the root, but no
// identifier the UI sends back may address one.
var ErrExternalPath = errors.New("path is outside the ssh directory")

// RelativePath converts an absolute path inside root into the slash-separated
// identifier used by metadata and the HTTP API.
func RelativePath(root, absolute string) (string, error) {
	if !filepath.IsAbs(absolute) {
		return "", ErrExternalPath
	}
	cleaned := filepath.Clean(absolute)
	if cleaned == filepath.Clean(root) {
		return "", ErrExternalPath
	}
	relative, err := filepath.Rel(filepath.Clean(root), cleaned)
	if err != nil {
		return "", ErrExternalPath
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", ErrExternalPath
	}
	return filepath.ToSlash(relative), nil
}

// AbsolutePath converts an identifier received from the UI back into an
// absolute path inside root. It rejects absolute input, empty input and any
// path that escapes the root after cleaning.
func AbsolutePath(root, relative string) (string, error) {
	if relative == "" || strings.HasPrefix(relative, "/") || strings.Contains(relative, "\x00") {
		return "", ErrExternalPath
	}
	joined := filepath.Join(filepath.Clean(root), filepath.FromSlash(relative))
	if _, err := RelativePath(root, joined); err != nil {
		return "", err
	}
	return joined, nil
}
