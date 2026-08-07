package application

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"sshc/internal/storage"
)

const (
	// MetadataSchemaVersion はこのビルドが書き込む唯一のバージョンである。
	// より高いバージョンを持つファイルは黙ってダウングレードされず拒否される。
	//
	// バージョン 2 でグループメンバーシップを廃止した。グループは ~/.ssh/connections
	// 配下のディレクトリであり、エントリファイルの生成領域がどのグループが
	// 存在するかを宣言するので、hosts[].group にも groups[].parent にも
	// 語ることはもう何も残っていない。バージョン 1 の文書はデコードされ、その
	// 2 つのフィールドを単に失う。json.Unmarshal は構造体にもう存在しないものを無視するからだ。
	MetadataSchemaVersion = 2
	// MetadataFileName はワークスペースの状態ディレクトリに置かれ、設定ツリーには
	// 置かれないので、SSH 設定として読まれることは決してない。
	MetadataFileName = "metadata.json"
	// DefaultGroupsFile はグループ継承がコンパイルされる先の設定ファイルで
	// ある。設定ツリーの内側にとどまるので、手で編集できる普通の
	// OpenSSH 設定である。
	DefaultGroupsFile = "groups.sshc.conf"
)

var (
	ErrMetadataVersion = errors.New("metadata schema version is newer than this build supports")
	ErrMetadataSecret  = errors.New("metadata may not contain key material")
	ErrMetadataPath    = errors.New("metadata host path must be relative to the ssh directory")
	ErrMetadataGroup   = errors.New("metadata group definition is invalid")
)

// secretMarkers は、整理用のフィールドに鍵材料を保存しようとした痕跡を示す
// 部分文字列である。metadata には鍵のためのフィールドは無いので、出現した
// こと自体が大声で拒否する価値のある間違いである。
var secretMarkers = []string{"-----BEGIN", "PRIVATE KEY", "ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-"}

// HostIdentity はホストの UI 上の識別子である。正規化された設定ファイル
// のパスと、そこで宣言された具体的な主 Host alias を組にしたものだ。
type HostIdentity struct {
	Path  string `json:"path"`
	Alias string `json:"alias"`
}

// NewHostIdentity は絶対設定パスを識別子へと正規化する。
func NewHostIdentity(root, absolute, alias string) (HostIdentity, error) {
	relative, err := RelativePath(root, absolute)
	if err != nil {
		return HostIdentity{}, err
	}
	if alias == "" {
		return HostIdentity{}, ErrMetadataPath
	}
	return HostIdentity{Path: relative, Alias: alias}, nil
}

func (identity HostIdentity) IsZero() bool { return identity.Path == "" || identity.Alias == "" }

// Setting は、グループがメンバーに提供する 1 個のディレクティブである。
type Setting struct {
	Keyword string   `json:"keyword"`
	Values  []string `json:"values"`
}

// HostMetadata は 1 個のホストに付随する、UI 専用の情報である。
//
// 設定そのものの中に表現を持たないものだけを運ぶ。グループのメンバーシップは
// ファイルが置かれているディレクトリであり、note は Host 行の上のコメントな
// ので、どちらもここには無い。
type HostMetadata struct {
	Identity  HostIdentity `json:"identity"`
	Tags      []string     `json:"tags,omitempty"`
	Colour    string       `json:"colour,omitempty"`
	Note      string       `json:"note,omitempty"`
	Favourite bool         `json:"favourite,omitempty"`
	Order     int          `json:"order,omitempty"`
	Orphan    bool         `json:"orphan,omitempty"`
}

func (host HostMetadata) Alias() string { return host.Identity.Alias }

// GroupMetadata は 1 個のグループ名に付随する見た目（presentation）である。
// グループ自体はディレクトリであり、その階層構造がその名前そのものなので、これは
// ディレクトリが運べないものである。Settings は普通の Host ブロックへとコンパイルされる。
type GroupMetadata struct {
	Name   string `json:"name"`
	Colour string `json:"colour,omitempty"`
	Note   string `json:"note,omitempty"`
	Order  int    `json:"order,omitempty"`
	// Hidden は、他のグループを保持することが目的で、connections ツリーに
	// それ自体として示すものが何もないグループについて、その見出しを
	// connections ツリーから除く。Colour や Order と同様にこれは見た目であり、
	// このエンジンはそれを運ぶだけで決して読まない。Include 行も、
	// ディレクトリも、ssh が返すあらゆる答えも手つかずのままである。
	Hidden   bool      `json:"hidden,omitempty"`
	Settings []Setting `json:"settings,omitempty"`
}

// Metadata は~/.ssh/sshc/metadata.json の全体である。
type Metadata struct {
	SchemaVersion int             `json:"schemaVersion"`
	GroupsFile    string          `json:"groupsFile,omitempty"`
	Groups        []GroupMetadata `json:"groups,omitempty"`
	Hosts         []HostMetadata  `json:"hosts,omitempty"`
}

func NewMetadata() Metadata {
	return Metadata{SchemaVersion: MetadataSchemaVersion, GroupsFile: DefaultGroupsFile}
}

// GroupsPath は設定されたグループファイルを返し、無ければデフォルトに fallback する。
func (metadata Metadata) GroupsPath() string {
	if metadata.GroupsFile == "" {
		return DefaultGroupsFile
	}
	return metadata.GroupsFile
}

// DecodeMetadata は metadata.json をパースする。内容が無いか空であれば
// 新規の文書を作り、より新しいスキーマバージョンは書き換えず拒否する。
func DecodeMetadata(contents []byte) (Metadata, error) {
	if len(strings.TrimSpace(string(contents))) == 0 {
		return NewMetadata(), nil
	}
	var metadata Metadata
	if err := json.Unmarshal(contents, &metadata); err != nil {
		return Metadata{}, err
	}
	if metadata.SchemaVersion > MetadataSchemaVersion {
		return Metadata{}, ErrMetadataVersion
	}
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = MetadataSchemaVersion
	}
	if metadata.GroupsFile == "" {
		metadata.GroupsFile = DefaultGroupsFile
	}
	return metadata, nil
}

// EncodeMetadata は metadata を検証し、決定的にシリアライズする。
func EncodeMetadata(metadata Metadata) ([]byte, error) {
	metadata.SchemaVersion = MetadataSchemaVersion
	if metadata.GroupsFile == "" {
		metadata.GroupsFile = DefaultGroupsFile
	}
	if err := ValidateMetadata(metadata); err != nil {
		return nil, err
	}
	sorted := metadata
	sorted.Groups = append([]GroupMetadata(nil), metadata.Groups...)
	sorted.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	sort.SliceStable(sorted.Groups, func(first, second int) bool {
		return sorted.Groups[first].Name < sorted.Groups[second].Name
	})
	sort.SliceStable(sorted.Hosts, func(first, second int) bool {
		if sorted.Hosts[first].Identity.Path != sorted.Hosts[second].Identity.Path {
			return sorted.Hosts[first].Identity.Path < sorted.Hosts[second].Identity.Path
		}
		return sorted.Hosts[first].Identity.Alias < sorted.Hosts[second].Identity.Alias
	})
	encoded, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ValidateMetadata は設計の不変条件を破る文書を拒否する。
func ValidateMetadata(metadata Metadata) error {
	if _, err := checkRelative(metadata.GroupsPath()); err != nil {
		return err
	}
	names := make(map[string]bool, len(metadata.Groups))
	for _, group := range metadata.Groups {
		// 名前はディレクトリパスなので、このアプリケーションが自ら作成
		// してよいと思えるものでなければならない。ここで拒否することで、
		// 手で編集された metadata ファイルが"../escape"を名乗り、信じ込まされることを防ぐ。
		if names[strings.ToLower(group.Name)] || ValidateGroupName(group.Name) != nil {
			return ErrMetadataGroup
		}
		// 大文字小文字を区別しない。大文字小文字だけが異なる 2 つのグループ名は、
		// デフォルトの macOS ボリュームでは 1 つのディレクトリになるからだ。
		names[strings.ToLower(group.Name)] = true
		for _, setting := range group.Settings {
			if containsSecretMarker(setting.Keyword) {
				return ErrMetadataSecret
			}
			for _, value := range setting.Values {
				if containsSecretMarker(value) {
					return ErrMetadataSecret
				}
			}
		}
	}
	for _, host := range metadata.Hosts {
		if _, err := checkRelative(host.Identity.Path); err != nil {
			return err
		}
		if host.Identity.Alias == "" {
			return ErrMetadataPath
		}
		for _, text := range append([]string{host.Note, host.Colour}, host.Tags...) {
			if containsSecretMarker(text) {
				return ErrMetadataSecret
			}
		}
	}
	return nil
}

func checkRelative(candidate string) (string, error) {
	if candidate == "" || strings.HasPrefix(candidate, "/") {
		return "", ErrMetadataPath
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(candidate)))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", ErrMetadataPath
	}
	return cleaned, nil
}

func containsSecretMarker(text string) bool {
	for _, marker := range secretMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// MetadataStore はワークスペースの状態ディレクトリ内で metadata.json を
// 読み、ステージする。直接書き込むことは決してない。変更は、それが記述する
// 設定ファイルを書き込むのと同じ storage transaction によってコミットされる。
type MetadataStore struct {
	workspace *storage.Workspace
}

func NewMetadataStore(workspace *storage.Workspace) *MetadataStore {
	return &MetadataStore{workspace: workspace}
}

func (store *MetadataStore) Path() string {
	return filepath.Join(store.workspace.StateDir(), MetadataFileName)
}

// EnsureDirectory は状態ディレクトリを作成し、最初の metadata 書き込みが
// その親を解決できるようにする。
func (store *MetadataStore) EnsureDirectory() error {
	return store.workspace.EnsureDirectory(store.workspace.StateDir())
}

// Load は現在の文書と、後の commit が必要とする事前条件を読む。
func (store *MetadataStore) Load() (Metadata, storage.Precondition, error) {
	contents, err := store.workspace.FileSystem().ReadFile(store.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return NewMetadata(), storage.Precondition{}, nil
	}
	if err != nil {
		return Metadata{}, storage.Precondition{}, err
	}
	metadata, err := DecodeMetadata(contents)
	if err != nil {
		return Metadata{}, storage.Precondition{}, err
	}
	return metadata, storage.Precondition{Exists: true, Digest: storage.Digest(contents)}, nil
}

// Change は metadata を storage transaction 用の 1 個のファイル変更に変える。
func (store *MetadataStore) Change(metadata Metadata, precondition storage.Precondition) (storage.Change, error) {
	contents, err := EncodeMetadata(metadata)
	if err != nil {
		return storage.Change{}, err
	}
	return storage.Change{Path: store.Path(), Contents: contents, Precondition: precondition}, nil
}

// ReconcileMetadata はホストが消えた entry に印を付ける。entry を別の
// ホストに向け直すことは決してない。消えたターゲットは orphan となり、
// ユーザーが意図的に再関連付けしなければならない。
func ReconcileMetadata(metadata Metadata, present []HostIdentity) (Metadata, []Notice) {
	known := make(map[HostIdentity]bool, len(present))
	for _, identity := range present {
		known[identity] = true
	}
	reconciled := metadata
	reconciled.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	var notices []Notice
	for index := range reconciled.Hosts {
		host := &reconciled.Hosts[index]
		host.Orphan = !known[host.Identity]
		if !host.Orphan {
			continue
		}
		notices = appendNotice(notices, Notice{
			Code:   NoticeOrphanMetadata,
			Path:   host.Identity.Path,
			Detail: host.Identity.Alias,
		})
	}
	return reconciled, notices
}

// ClearHostNote は 1 個のホストの entry から note を取り除き、他のすべての
// フィールドと他のすべての entry は手つかずのままにする。
//
// note とコメントは 2 箇所に書かれた同じものなので、コメントを保存すると
// そのホストの note は同じ transaction で退役する。ユーザーが編集するたびに
// ホストごとにこれを行うことで、すべてのファイルを一度に書き換える
// migration を介さずに収束する。identity しか残っていない entry は
// 捨てられる。何も語らない entry は残しておく価値が無いからだ。
func ClearHostNote(metadata Metadata, identity HostIdentity) Metadata {
	cleared := metadata
	cleared.Hosts = make([]HostMetadata, 0, len(metadata.Hosts))
	for _, host := range metadata.Hosts {
		if host.Identity != identity {
			cleared.Hosts = append(cleared.Hosts, host)
			continue
		}
		host.Note = ""
		if len(host.Tags) == 0 && host.Colour == "" && !host.Favourite && host.Order == 0 {
			continue
		}
		cleared.Hosts = append(cleared.Hosts, host)
	}
	return cleared
}

// RenameHostIdentity は 1 個のホストの entry を移動し、他のすべての entry は
// 手つかずのままにする。呼び出し側は、rename を実行した設定変更と
// 同じ transaction でその結果をコミットする。
// RelocateHostIdentities は 1 個のファイルに宣言されたすべての entry の
// パスを書き換え、各 alias は保つ。これは、ちょうど 1 個の identity を
// 移動する RenameHostIdentity のファイル単位版である。
//
// 書き換えられるのは完全一致したパスだけである。前方一致にすると、"work"への rename が
// "workshop"を飲み込んでしまう。ディレクトリを移動する呼び出し側は各ファイルを渡す。
func RelocateHostIdentities(metadata Metadata, fromPath, toPath string) Metadata {
	relocated := metadata
	relocated.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	for index := range relocated.Hosts {
		if relocated.Hosts[index].Identity.Path != fromPath {
			continue
		}
		relocated.Hosts[index].Identity.Path = toPath
		relocated.Hosts[index].Orphan = false
	}
	return relocated
}

func RenameHostIdentity(metadata Metadata, from, to HostIdentity) Metadata {
	renamed := metadata
	renamed.Hosts = append([]HostMetadata(nil), metadata.Hosts...)
	for index := range renamed.Hosts {
		if renamed.Hosts[index].Identity != from {
			continue
		}
		renamed.Hosts[index].Identity = to
		renamed.Hosts[index].Orphan = false
	}
	return renamed
}
