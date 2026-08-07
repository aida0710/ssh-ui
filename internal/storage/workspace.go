package storage

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

var (
	ErrOutsideWorkspace = errors.New("path is outside the sshc workspace")
	ErrSymlinkPath      = errors.New("path contains a symbolic link")
	ErrMissingDirectory = errors.New("parent directory does not exist")
	ErrNotDirectory     = errors.New("path component is not a directory")
	ErrInvalidHome      = errors.New("home directory must be an absolute path")
)

// Workspace は、すべての書き込みを、解決済みのユーザーの ~/.ssh ディレクトリに固定する。
//
// ルートは EvalSymlinks を通して一度だけ解決されるので、~/.ssh を別のボリューム
// に置いているユーザーでも動く。一方、ルートより下の構成要素はすべて本物の
// ディレクトリでなければならない。ルート下のシンボリックリンクは UI に表示される
// が、そこを通して書かれることはなく、リンクが書き込み可能な範囲を広げられない。
type Workspace struct {
	fileSystem FileSystem
	home       string
	root       string
}

// NewWorkspace は home/.ssh を解決する。ディレクトリがないことはエラーではない。
// 最初の書き込み時に作られる。
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
		// リテラルのパスを保つ。EnsureDirectory があとで作る。
	default:
		return nil, err
	}
	return &Workspace{fileSystem: fileSystem, home: cleanedHome, root: root}, nil
}

func (w *Workspace) FileSystem() FileSystem { return w.fileSystem }

func (w *Workspace) Home() string { return w.home }

func (w *Workspace) Root() string { return w.root }

// StateDir は、ジャーナル・履歴・バックアップを保持するディレクトリ。
func (w *Workspace) StateDir() string { return filepath.Join(w.root, "sshc") }

// Contains は、candidate がルートであるか、その下にあるかを報告する。
func (w *Workspace) Contains(candidate string) bool {
	cleaned := filepath.Clean(candidate)
	return cleaned == w.root || strings.HasPrefix(cleaned, w.root+string(filepath.Separator))
}

// Normalise は、与えられたままのホームディレクトリを基準に表現されたパスを、
// 解決済みのルートを基準に表現されたパスへ書き換える。
//
// Root は EvalSymlinks を通して解決され、Home は意図的にそうしない。Home は、
// このプロセスとその子が HOME に持つ値であり、それが ssh の表示するものであり、
// したがって SanitiseHomePaths が一致させなければならないものだからだ。そのため、
// ~/.ssh がリンク経由で到達される場合は常に、両者は同じディレクトリを二通りに
// 名指しすることになる — dotfiles のチェックアウトや、/var が private/var への
// リンクである macOS のあらゆる一時ディレクトリで、そうなる。
//
// "~" や "%d" を展開する呼び出し側は、ホームの綴りに着地する。それを Root と
// 比べると、ワークスペースそのものであるパスがワークスペースの外にあると言われて
// しまい、それを尋ねる二か所 — 鍵の参照インデックスと、IdentityFile 行を書き換える
// 再配置 — の両方が「いいえ」と答えていた。目に見える結果は、ファイルは移動する
// のにそれらを名指しするディレクティブを何ひとつ書き換えない鍵の名前変更が、黙って
// 起きることであり、そして Keys 画面が設定全体を解決不能として報告することで
// あった。
//
// ホーム配下にないパスは、正規化されたうえで、それ以外は手を触れずに返る。
func (w *Workspace) Normalise(candidate string) string {
	cleaned := filepath.Clean(candidate)
	homeRoot := filepath.Join(w.home, ".ssh")
	if cleaned == homeRoot {
		return w.root
	}
	prefix := homeRoot + string(filepath.Separator)
	if strings.HasPrefix(cleaned, prefix) {
		return filepath.Join(w.root, strings.TrimPrefix(cleaned, prefix))
	}
	return cleaned
}

// ResolveForWrite は、candidate がルートより下の絶対パスであり、その親が本物の
// ディレクトリであり、かつ存在しないか通常ファイルであることを検証する。正規化
// されたパスを返す。
func (w *Workspace) ResolveForWrite(candidate string) (string, error) {
	return w.ResolveForWriteUnder(candidate, nil)
}

// ResolveForWriteUnder は、呼び出し側が同じトランザクションでこれから作る
// ディレクトリの集合を伴う ResolveForWrite である。
//
// これがないと、connections/work/ を作り、同じコミットで connections/work/lon.conf
// を書くリクエストは拒否される。リクエストが検査される時点で、まだ親が存在しない
// からだ。代案 — トランザクションの前にディレクトリを作る — は、まさにこれが
// 取り除くために存在する、ジャーナル外の mkdir そのもので
// ある。
func (w *Workspace) ResolveForWriteUnder(candidate string, planned map[string]bool) (string, error) {
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
			if planned[current] {
				// このトランザクションがそれを作るので、残りのセグメントもすべて
				// このトランザクションの管轄である。
				continue
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

// ResolveDirectory は、candidate がルートより下の絶対パスであり、存在しないか
// 本物のディレクトリであり、かつ既存の祖先がシンボリックリンクではなく本物の
// ディレクトリであることを検証する。
//
// ファイルではなくディレクトリであるパスのための、ResolveForWrite の兄弟である。
// 親が存在しないことを意図的に許容する。ひとつのリクエストで connections/work/ と
// connections/work/eu/ を作るトランザクションがありえ、後者はリクエストが検査
// される時点でディスク上に親を持たないからだ。
func (w *Workspace) ResolveDirectory(candidate string) (string, error) {
	cleaned := filepath.Clean(candidate)
	if !filepath.IsAbs(cleaned) || !w.Contains(cleaned) || cleaned == w.root {
		return "", ErrOutsideWorkspace
	}
	relative, err := filepath.Rel(w.root, cleaned)
	if err != nil {
		return "", ErrOutsideWorkspace
	}

	current := w.root
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, segment)
		info, statErr := w.fileSystem.Lstat(current)
		switch {
		case errors.Is(statErr, fs.ErrNotExist):
			// ここから下はまだ存在しない。作成の場合はそれが普通の
			// ケースである。
			return cleaned, nil
		case statErr != nil:
			return "", statErr
		case info.Mode()&fs.ModeSymlink != 0:
			return "", ErrSymlinkPath
		case !info.IsDir():
			return "", ErrNotDirectory
		}
	}
	return cleaned, nil
}

// EnsureDirectory は、candidate と、ルートより下で欠けている親を
// DirectoryPermission で作る。シンボリックリンクをたどることは拒否する。
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
