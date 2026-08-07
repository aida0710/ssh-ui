// Package application は、lossless な設定 engine と filesystem transaction
// manager との間に位置する use case を保持する。syscall を直接行うことは
// 決してない。すべての読み書きは、与えられた storage workspace を
// 経由する。
package application

import (
	"errors"
	"path/filepath"
	"strings"
)

// ErrExternalPath は、解決された~/.ssh ディレクトリの内側にある実在の
// 場所ではない path を報告する。UI は root の外側にあるファイルを表示して
// もよいが、UI が送り返す識別子がそれを指し示すことは許されない。
var ErrExternalPath = errors.New("path is outside the ssh directory")

// RelativePath は、root 内側の絶対 path を、metadata と HTTP API が使う
// スラッシュ区切りの識別子に変換する。
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

// AbsolutePath は、UI から受け取った識別子を root 内側の絶対 path へ
// 変換し直す。絶対 path の入力、空の入力、そしてクリーニング後に
// root を脱出する path を拒否する。
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
