// Package remotesync は、ワークスペース全体をオブジェクトストアへ運び、また戻す。
//
// このパッケージが sync ではなく remotesync という名前なのは、標準ライブラリが
// すでにその名前を持っており、ここでミューテックスが必要なファイルが、二つのうち
// どちらかに別名を付けなければならなくなるのを避けるためである。
//
// オブジェクトひとつ、スナップショットひとつ、原子的な PUT ひとつ。オブジェクトを
// ファイルごとに分ければファイル単位の衝突検出がただで手に入るが、それは誤りだ。
// 設定は集合としてしか意味を持たないからである。~/.ssh/config は
// "Include connections/work/*.conf" と言い、metadata.json はディレクトリを持たねば
// ならないグループを名指しし、IdentityFile 行は鍵ファイルを名指しする。ファイルを
// 独立にアップロードすれば、どのマシンにも存在しなかった状態 — まだ存在しない
// ファイルに到達する Include — をリモートが保持する窓ができ、その窓の中で pull
// したマシンは、単に古いだけでなく整合してもいない設定を受け取ることに
// なる。
package remotesync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// ManifestName は、すべてのスナップショットの最初のエントリ。
const ManifestName = "manifest.json"

// SchemaVersion は、マニフェスト文書のバージョン。
const SchemaVersion = 1

// MaxSnapshotBytes は、Read が展開する量に上限を設ける。スナップショットは ~/.ssh
// である。これに近づくものは、ワークスペースではなく展開爆弾だ。
const MaxSnapshotBytes = 64 << 20

// MaxEntries は、ひとつのスナップショットが運べるファイル数に上限を設ける。
const MaxEntries = 4096

var (
	// ErrNotASnapshot は、そもそもスナップショットでないバイト列を報告する。
	ErrNotASnapshot = errors.New("these bytes are not an sshc snapshot")
	// ErrUnsupportedVersion は、より新しいビルドが作ったスナップショットを報告する。
	ErrUnsupportedVersion = errors.New("this snapshot was written by a newer version of sshc")
	// ErrUnsafePath は、ワークスペースから抜け出すパスを持つエントリを報告する。
	// スナップショットは信用できない入力であり、tar の中の "../" は最も古い手口で
	// ある。
	ErrUnsafePath = errors.New("a snapshot entry names a path outside the workspace")
	// ErrUnsafeMode は、このアプリケーションが書かない権限ビットを持つエントリを報告
	// する。スナップショットが秘密鍵の権限を広げられてはならない。
	ErrUnsafeMode = errors.New("a snapshot entry has permissions this application does not write")
	// ErrSnapshotTooLarge は、上限を超えるスナップショットを報告する。
	ErrSnapshotTooLarge = errors.New("the snapshot is larger than this application will read")
	// ErrManifestMismatch は、ダイジェストがマニフェストと一致しないファイル、または
	// マニフェストに載っていないファイルを報告する。
	ErrManifestMismatch = errors.New("the snapshot's files do not match its manifest")
)

// Entry は、スナップショット内のファイルひとつを記述する。
type Entry struct {
	// Path はワークスペース相対でスラッシュ区切り。storage.Workspace がすでに使って
	// いる語彙である。
	Path string `json:"path"`
	// SHA256 は内容の 16 進ダイジェスト。これにより pull は、すべてのファイルを二度
	// 展開せずに、どれが異なるかを判別できる。
	SHA256 string `json:"sha256"`
	// Mode を運ぶのは、ビットの誤った秘密鍵が、OpenSSH の拒む秘密鍵になるからで
	// ある。受け付けるのは 0600 と 0700 だけ。
	Mode string `json:"mode"`
	// Secret は秘密鍵であることを示す。これにより pull は、それを SkipBackup 付きで
	// 適用する。そのフィールドがストレージ層に存在する理由はまさにこれだ。設計は
	// 鍵素材の二つ目のコピーを ~/.ssh/sshc/backups/ に残すことを拒んでおり、これを
	// 無視する pull は、その判断を新しい方向から台無しにすることに
	// なる。
	Secret bool `json:"secret,omitempty"`
}

// Manifest は、スナップショットの索引。
type Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	CreatedAt     string `json:"createdAt"`
	// Origin は、これを書いたインストールを識別する。インターフェースが「これは別の
	// マシンから来た」と言えるようにするためだ。不透明な ID であって、決してホスト名
	// ではない。バケットを読める者なら誰でも見られるオブジェクトの中のホスト名は、
	// 不要な開示である。
	Origin string  `json:"origin"`
	Files  []Entry `json:"files"`
}

// Build は、与えられたファイルを圧縮アーカイブに詰める。
//
// contents は、ワークスペース相対のパスをキーとする。何を含めるかは呼び出し側が
// 決める。このパッケージは推測を拒む。「どのファイルが設定の一部なのか」は Include
// グラフの答える問いであり、このパッケージからはそれが見えないからで
// ある。
func Build(manifest Manifest, contents map[string][]byte) ([]byte, error) {
	manifest.SchemaVersion = SchemaVersion
	if len(manifest.Files) > MaxEntries {
		return nil, ErrSnapshotTooLarge
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	for _, entry := range manifest.Files {
		if err := checkPath(entry.Path); err != nil {
			return nil, err
		}
		if err := checkMode(entry.Mode); err != nil {
			return nil, err
		}
		if _, ok := contents[entry.Path]; !ok {
			return nil, ErrManifestMismatch
		}
	}

	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(zip)

	document, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if err := writeEntry(archive, ManifestName, document, 0o600); err != nil {
		return nil, err
	}
	for _, entry := range manifest.Files {
		if err := writeEntry(archive, entry.Path, contents[entry.Path], modeBits(entry.Mode)); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	if err := zip.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

// Read はアーカイブを展開し、そのマニフェストと内容を返す。
//
// すべてのバイトを敵対的なものとして扱う。アーカイブはバケットから届き、そのバケット
// に書ける者なら誰でも、その中身を選べるからだ。
func Read(archive []byte) (Manifest, map[string][]byte, error) {
	zip, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return Manifest{}, nil, ErrNotASnapshot
	}
	defer func() { _ = zip.Close() }()

	reader := tar.NewReader(io.LimitReader(zip, MaxSnapshotBytes+1))
	var manifest Manifest
	seenManifest := false
	contents := map[string][]byte{}
	total := 0

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, nil, ErrNotASnapshot
		}
		if header.Typeflag != tar.TypeReg {
			// このアーカイブの中のディレクトリ、シンボリックリンク、デバイスは、ここでは
			// 何の意味も持たず、好意的に解釈すべきものでもない。
			return Manifest{}, nil, ErrUnsafePath
		}
		if len(contents) >= MaxEntries {
			return Manifest{}, nil, ErrSnapshotTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(reader, MaxSnapshotBytes+1))
		if err != nil {
			return Manifest{}, nil, ErrNotASnapshot
		}
		total += len(body)
		if total > MaxSnapshotBytes {
			return Manifest{}, nil, ErrSnapshotTooLarge
		}

		if header.Name == ManifestName {
			if err := json.Unmarshal(body, &manifest); err != nil {
				return Manifest{}, nil, ErrNotASnapshot
			}
			seenManifest = true
			continue
		}
		if err := checkPath(header.Name); err != nil {
			return Manifest{}, nil, err
		}
		contents[header.Name] = body
	}

	if !seenManifest {
		return Manifest{}, nil, ErrNotASnapshot
	}
	if manifest.SchemaVersion > SchemaVersion {
		return Manifest{}, nil, ErrUnsupportedVersion
	}
	if len(manifest.Files) != len(contents) {
		return Manifest{}, nil, ErrManifestMismatch
	}
	for _, entry := range manifest.Files {
		if err := checkPath(entry.Path); err != nil {
			return Manifest{}, nil, err
		}
		if err := checkMode(entry.Mode); err != nil {
			return Manifest{}, nil, err
		}
		body, ok := contents[entry.Path]
		if !ok {
			return Manifest{}, nil, ErrManifestMismatch
		}
		if Digest(body) != entry.SHA256 {
			return Manifest{}, nil, ErrManifestMismatch
		}
	}
	return manifest, contents, nil
}

// checkPath は、ワークスペース内の素朴な相対パスでないものをすべて拒否する。
// filepath.Clean より意図的に厳しい。整形が必要なパスとは、誰かが組み立てたパスで
// あり、ここはそれについて好意的になる場所では
// ない。
func checkPath(name string) error {
	if name == "" || name == "." {
		return ErrUnsafePath
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return ErrUnsafePath
	}
	if name != path.Clean(name) {
		return ErrUnsafePath
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrUnsafePath
		}
	}
	return nil
}

// checkMode は、このアプリケーションが書く二つの権限セットだけを受け付ける。それ
// 以外は正規化せずに拒否する。これにより、スナップショットが秘密鍵の権限を、
// OpenSSH はまだ読むが他人も読める程度にまで広げることはできない。
func checkMode(mode string) error {
	if mode != "0600" && mode != "0700" {
		return ErrUnsafeMode
	}
	return nil
}

func modeBits(mode string) fs.FileMode {
	if mode == "0700" {
		return 0o700
	}
	return 0o600
}

func writeEntry(archive *tar.Writer, name string, body []byte, mode fs.FileMode) error {
	if err := archive.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     int64(mode),
		Size:     int64(len(body)),
		// 更新時刻も、所有者も、グループも運ばない。それらを運ぶスナップショットは、
		// 理由もなくマシンごとに異なることになり、それを書いたマシンについて少しばかり
		// 開示してしまう。
	}); err != nil {
		return err
	}
	_, err := archive.Write(body)
	return err
}
