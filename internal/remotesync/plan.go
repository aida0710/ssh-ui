package remotesync

import (
	"errors"
	"path/filepath"
	"sort"

	"sshc/internal/storage"
)

// ErrNothingToApply は、リモートのスナップショットがすでにこのディスクと一致して
// いることを報告する。これは失敗ではなく答えである。
var ErrNothingToApply = errors.New("this workspace already matches the snapshot")

// Conflict は、前回の同期以降に両側で変わったファイルひとつ。
//
// ダイジェストを運び、内容は決して運ばない。三方向のビューは、呼び出し側が自分で
// 読めるファイルから組み立てる。秘密鍵のバイト列を運ぶ衝突レコードは、レスポンス
// 本文の中にあるその鍵のコピーになってしまう。
type Conflict struct {
	Path         string
	BaseDigest   string
	LocalDigest  string
	RemoteDigest string
}

// Plan は、復号したスナップショットと現在のワークスペースから、このマシンをそれに
// 一致させるトランザクションそのもの — あるいは衝突 — を導き出す。
//
// ここは、設計の中で最もコストが低く、最も多くを買っている部分である。ひとつの
// storage.Request として表現できない pull は、このコードベースが持つあらゆる安全性
// を逃れる pull になる。表現できるからこそ、それらすべてをただで受け継ぐ。
// Manager.Validate のフックが再解析と再解決を行うので、Include グラフを壊す
// スナップショットは 1 バイトも着地する前に拒否される。鍵を除く置き換えられたすべて
// のファイルは世代ディレクトリへバックアップされるので、まずい pull は既存の
// History 画面のクリック 1 回で取り消せる。ジャーナルは、中断された pull を完了
// 可能にする。そしてユーザーが承認するプレビューは、既存のファイル単位の差分
// そのものである。
//
//   - base は、このマシンが最後に同期したスナップショットのマニフェスト。base が
//     nil なら、このマシンは一度も同期していないので、何も削除とは呼べず、
//     ファイルはひとつも取り除かれない。
//   - local は、ワークスペース相対のパスを、いまこのディスク上のダイジェストへ対応付ける。
//   - remote は、いま取得したマニフェストで、contents はそのファイル群。
func Plan(root string, base *Manifest, local map[string]string, remote Manifest, contents map[string][]byte) (storage.Request, []Conflict, error) {
	baseDigests := map[string]string{}
	if base != nil {
		for _, item := range base.Files {
			baseDigests[item.Path] = item.SHA256
		}
	}
	remoteDigests := map[string]string{}
	for _, item := range remote.Files {
		remoteDigests[item.Path] = item.SHA256
	}

	request := storage.Request{Operation: "sync.pull"}
	var conflicts []Conflict

	for _, item := range remote.Files {
		localDigest, present := local[item.Path]
		if present && localDigest == item.SHA256 {
			continue
		}
		baseDigest, hadBase := baseDigests[item.Path]
		if present && hadBase && localDigest != baseDigest {
			// ここでも変わり、あちらでも変わった。自動的な正解は存在しない — 同じ
			// Host ブロックを双方が変えた二つの ssh_config をマージすることは、
			// パーサが守るために存在するバイト保存の約束に反する — ので、これは
			// 推測せずに報告する。
			conflicts = append(conflicts, Conflict{
				Path: item.Path, BaseDigest: baseDigest,
				LocalDigest: localDigest, RemoteDigest: item.SHA256,
			})
			continue
		}
		if present && !hadBase {
			// 両側に存在し、内容が異なり、このマシンは一度も同期していない。
			// ここにはどちらが新しいかを知るものがない。
			conflicts = append(conflicts, Conflict{
				Path: item.Path, LocalDigest: localDigest, RemoteDigest: item.SHA256,
			})
			continue
		}
		precondition := storage.Precondition{}
		if present {
			precondition = storage.Precondition{Exists: true, Digest: localDigest}
		}
		request.Changes = append(request.Changes, storage.Change{
			Path:         filepath.Join(root, filepath.FromSlash(item.Path)),
			Contents:     contents[item.Path],
			Precondition: precondition,
			// この pull が上書きする秘密鍵も、他のものと同じくバックアップを残す。
			// 以前は残さなかった。そのコピーが平文の鍵になってしまうからだ。いま
			// バックアップはマスターパスワードで封じられており、ローカルの鍵を pull が
			// 置き換えるこの場面こそ、以前のものを取り戻したくなるまさにその場合で
			// ある。
		})
	}

	// ローカルに存在しスナップショットに存在しないファイルは、「別のマシンで削除
	// された」か「前回の同期以降ここで作られた」かのどちらかである。両者を区別
	// できるのは、最後に同期したマニフェストだけである。base にあって remote に
	// ないなら削除、どちらにもないならここで新しく作られたものであり、手を触れ
	// ない。
	for path, localDigest := range local {
		if _, stillRemote := remoteDigests[path]; stillRemote {
			continue
		}
		baseDigest, hadBase := baseDigests[path]
		if !hadBase {
			continue
		}
		if localDigest != baseDigest {
			// あちらで削除され、こちらで編集された。
			conflicts = append(conflicts, Conflict{
				Path: path, BaseDigest: baseDigest, LocalDigest: localDigest,
			})
			continue
		}
		request.Removals = append(request.Removals, storage.Removal{
			Path:         filepath.Join(root, filepath.FromSlash(path)),
			Precondition: storage.Precondition{Exists: true, Digest: localDigest},
		})
	}

	sort.Slice(request.Changes, func(i, j int) bool { return request.Changes[i].Path < request.Changes[j].Path })
	sort.Slice(request.Removals, func(i, j int) bool { return request.Removals[i].Path < request.Removals[j].Path })
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].Path < conflicts[j].Path })

	if len(conflicts) == 0 && len(request.Changes) == 0 && len(request.Removals) == 0 {
		return storage.Request{}, nil, ErrNothingToApply
	}
	return request, conflicts, nil
}
