// Package secret は、このアプリケーションが OpenSSH へ渡しうるパスワードを保持する。
//
// それらはワークスペース内のひとつの暗号化ファイル ~/.ssh/sshc/secrets の中に
// あり、macOS のキーチェーンにはない。これは意図的な選択で、理由はひとつ。
// キーチェーンの項目はマシンに属するが、これらは移動しなければならないからだ。
// 同期されるのはワークスペースなので、二台目のマシンに届かねばならないものは、
// その中のファイルでなければならない。
//
// その結果、このファイルは、同じユーザーで動くどのプロセスからも読める場所に
// ディスク上で静止することになる。だから書かれる前に暗号化される。鍵は、この
// アプリケーションが決して保存しないパスフレーズから導出される。ここにあるものは、
// そのパスフレーズが与えられない限り、何も復号できない。
package secret

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"sshc/internal/envelope"
	"sshc/internal/platform"
)

// WorkspacePath は、封をされたファイルの置き場所。ワークスペースルートからの
// 相対である。エディタに開いてくれと誘うような拡張子を持たず、読めそうに見える
// 名前も持たない。
const WorkspacePath = "sshc/secrets"

// SettingsPath は、オブジェクトストアの設定。同じマスターパスワードで封じられ、
// vault の中ではなく隣に置かれる。
//
// vault は移動する。remotesync.Collect は sshc/secrets を明示的に名指しする。
// アクセスキーをその中に入れれば、バケットへの鍵をバケットの中に入れることになり、
// 何らかの手段でスナップショットをひとつ入手し、そのパスフレーズも得た者は、すでに
// 手にしている一つ分ではなく、生きたバケットとその後のすべてのスナップショットを
// 手に入れてしまう。Collect は何を取るかを列挙するので、このファイルは、誰かが
// 覚えておくべきルールによってではなく、構造上除外される。
const SettingsPath = "sshc/sync-settings"

// SchemaVersion は、暗号化の内側にある平文文書のバージョン。ヘッダーは envelope
// 用に自前のバージョンを運ぶ。
const SchemaVersion = 2

// envelope のエラーは再エクスポートしてある。vault を扱う呼び出し側が、どの
// パッケージがそれを封じたかを知らずに済むようにするためだ。
var (
	ErrWrongPassphrase    = envelope.ErrWrongPassphrase
	ErrNotAVault          = envelope.ErrNotAnEnvelope
	ErrUnsupportedVersion = envelope.ErrUnsupportedVersion
	ErrCostRefused        = envelope.ErrCostRefused
	ErrWeakPassphrase     = envelope.ErrWeakPassphrase
)

var (
	// ErrUnsafeName は、安全な alias ではない alias を拒否する。
	ErrUnsafeName = errors.New("that is not a safe host alias")
	// ErrEmptySecret は空のパスワードを拒否する。プロンプト上では、誤ったものと
	// 区別がつかないからだ。
	ErrEmptySecret = errors.New("the password is empty")
	// ErrOldVault は、秘密に名前が付く前の文書を報告する。世界に多くともひとつしか
	// 存在せず、移行のコードは移行される対象より大きくなるので、拒否したうえで画面が
	// 最初からやり直すことを提案する。
	ErrOldVault = errors.New("this vault predates named credentials and cannot be read")
	// ErrUnknownKind は、どちらでもない名前空間を拒否する。
	ErrUnknownKind = errors.New("that is not a credential kind")
	// ErrUnknownCredential は、その名前空間に存在しない名前への参照を拒否する —
	// これは、ホストが鍵のパスフレーズを参照するのを止めている仕組みでも
	// ある。
	ErrUnknownCredential = errors.New("no credential of that kind has that name")
	// ErrCredentialInUse は、まだ何かが指している秘密の削除を拒む。
	ErrCredentialInUse = errors.New("something still uses this credential")
)

// MinPassphraseLength は、これが受け付ける最短の vault パスフレーズ長。
const MinPassphraseLength = envelope.MinPassphraseLength

// Kind は、資格情報の名前空間を表す。
//
// ホストは KindPassword のみを、鍵は KindKeyPassphrase のみを参照できる。名前空間が
// ひとつなら、ホストのパスワード選択画面が鍵のパスフレーズを提示できてしまい、それを
// 選べばそのパスフレーズがログインパスワードとしてリモートホストへ送られる。二つに
// 分ければ、それは起こりにくいどころか、表現すること自体が不可能になる。
//
// 守るものも異なる。アカウントのパスワードはひとつのアカウントへの入場を許すが、
// 鍵のパスフレーズは、多くのマシンへの入場を許しうる鍵を解錠する。共有は、それぞれ
// の中では普通のことであり、両者をまたぐと意味をなさない。
type Kind string

const (
	KindPassword      Kind = "password"
	KindKeyPassphrase Kind = "key_passphrase"
)

// ValidKind は、値が名前空間を表しているかを報告する。この集合が決まる唯一の場所
// なので、ルートとフォームがそれについて食い違うことはありえない。
func ValidKind(kind Kind) bool {
	return kind == KindPassword || kind == KindKeyPassphrase
}

// SyncSettings は、オブジェクトストアが必要とするもの。
//
// vault と同じマスターパスワードで封じられ、専用のファイルに置かれる。vault は
// 移動するからだ。Collect は sshc/secrets を明示的に名指しするので、アクセスキーを
// vault の中に入れれば、バケットへの鍵をバケットの中に入れることになる。何らかの
// 手段でスナップショットをひとつと、そのパスフレーズを入手した者は、すでに手にして
// いる一つ分ではなく、生きたバケットと今後のすべてのスナップショットを手に入れて
// しまう。
type SyncSettings struct {
	Endpoint string `json:"endpoint,omitempty"`
	Bucket   string `json:"bucket,omitempty"`
	// Path は、すべてのオブジェクトが置かれる接頭辞。空ならバケットのルート。
	Path            string `json:"path,omitempty"`
	Region          string `json:"region,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	Direction       string `json:"direction,omitempty"`
}

// document は平文であり、この形でこのパッケージの外へ出ることは決してない。
//
// 資格情報のマップが二つ、そして種別ごとに参照のマップがひとつ。ホストは alias で、
// 鍵はワークスペース相対のパスでキー付けされる。名前の付いた秘密は、いくつの
// subject が指していても一度だけ保存される。この形の理由はまさにそこにある —
// 20 台のマシンが共有するパスワードを、一か所でローテーションできる。
type document struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Passwords      map[string]string `json:"passwords"`
	KeyPassphrases map[string]string `json:"keyPassphrases"`
	Hosts          map[string]string `json:"hosts"`
	Keys           map[string]string `json:"keys"`
}

// Vault は、開かれた secrets ファイル。
//
// パスフレーズではなく導出された鍵を保持するので、再度尋ねることなく変更を封じ
// 直せる。そしてパスフレーズは、Open が返ったあとどこにも保持されて
// いない。
type Vault struct {
	key      envelope.Key
	secrets  map[Kind]map[string]string
	subjects map[Kind]map[string]string
}

func newMaps() (map[Kind]map[string]string, map[Kind]map[string]string) {
	return map[Kind]map[string]string{KindPassword: {}, KindKeyPassphrase: {}},
		map[Kind]map[string]string{KindPassword: {}, KindKeyPassphrase: {}}
}

// Create は、passphrase で封じられた空の vault を返す。
func Create(passphrase string) (*Vault, error) {
	key, err := envelope.Derive(passphrase)
	if err != nil {
		return nil, err
	}
	secrets, subjects := newMaps()
	return &Vault{key: key, secrets: secrets, subjects: subjects}, nil
}

// Open は、passphrase で sealed を復号する。
func Open(sealed []byte, passphrase string) (*Vault, error) {
	plaintext, key, err := envelope.Open(sealed, passphrase)
	if err != nil {
		return nil, err
	}
	var parsed document
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return nil, ErrWrongPassphrase
	}
	if parsed.SchemaVersion > SchemaVersion {
		return nil, ErrUnsupportedVersion
	}
	// バージョン 1 の文書は、alias ごとにパスワードを持ち、名前をまったく持たな
	// かった。世界に多くともひとつしか存在せず、そのための移行は移行する対象より
	// 大きくなるので、黙って作り変えるのではなく、画面が「もう一度設定してください」
	// に変えられるエラーで拒否する。
	if parsed.SchemaVersion < SchemaVersion {
		return nil, ErrOldVault
	}
	secrets, subjects := newMaps()
	for kind, stored := range map[Kind]map[string]string{
		KindPassword:      parsed.Passwords,
		KindKeyPassphrase: parsed.KeyPassphrases,
	} {
		for name, value := range stored {
			secrets[kind][name] = value
		}
	}
	for kind, stored := range map[Kind]map[string]string{
		KindPassword:      parsed.Hosts,
		KindKeyPassphrase: parsed.Keys,
	} {
		for subject, name := range stored {
			subjects[kind][subject] = name
		}
	}
	return &Vault{key: key, secrets: secrets, subjects: subjects}, nil
}

// SealSettings は、オブジェクトストアの設定を vault 自身の鍵で暗号化する。隣に置く
// ファイルのためである。同じマスターパスワードで、違うファイル。こちらは移動
// しない。
func (v *Vault) SealSettings(settings SyncSettings) ([]byte, error) {
	plaintext, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return v.key.Seal(plaintext)
}

// OpenSettings は、SealSettings が書いたファイルを復号する。
func (v *Vault) OpenSettings(sealed []byte) (SyncSettings, error) {
	plaintext, err := v.key.Open(sealed)
	if err != nil {
		return SyncSettings{}, err
	}
	var settings SyncSettings
	if err := json.Unmarshal(plaintext, &settings); err != nil {
		return SyncSettings{}, ErrWrongPassphrase
	}
	return settings, nil
}

// Seal は、書き込みのために vault を暗号化する。
// Rekey は passphrase から新しい鍵を導出し、それを採用する。
//
// 中身には手を触れない。変わるのは、それを開くものの方だ。古い鍵が封じたものは
// すべて、同じ流れの中で呼び出し側が封じ直さなければならない。これが新しい vault
// ではなく vault のメソッドである理由はそこにある。呼び出し側は、二つの鍵を同時に
// 必要とするからだ。
func (v *Vault) Rekey(passphrase string) (envelope.Key, error) {
	key, err := envelope.Derive(passphrase)
	if err != nil {
		return envelope.Key{}, err
	}
	previous := v.key
	v.key = key
	return previous, nil
}

// SealBytes は、任意のバイト列をこの vault の鍵で封じる。
//
// これが、世代バックアップのディレクトリを、以前のファイル内容の山 — バックアップ
// をまったく拒んでいた書き込みについては、以前の秘密鍵そのもの — から、暗号文の
// 山へと変える。
func (v *Vault) SealBytes(plaintext []byte) ([]byte, error) {
	return v.key.Seal(plaintext)
}

// OpenBytes はその逆で、巻き戻しや復元のためにある。
func (v *Vault) OpenBytes(sealed []byte) ([]byte, error) {
	return v.key.Open(sealed)
}

func (v *Vault) Seal() ([]byte, error) {
	plaintext, err := json.Marshal(document{
		SchemaVersion:  SchemaVersion,
		Passwords:      v.secrets[KindPassword],
		KeyPassphrases: v.secrets[KindKeyPassphrase],
		Hosts:          v.subjects[KindPassword],
		Keys:           v.subjects[KindKeyPassphrase],
	})
	if err != nil {
		return nil, err
	}
	return v.key.Seal(plaintext)
}

// Names は、ある種別の資格情報名をソートして返す。名前そのものは秘密ではない。
// 秘密なのは、それが表す値の方である。
func (v *Vault) Names(kind Kind) []string {
	return slices.Sorted(maps.Keys(v.secrets[kind]))
}

// Secret は、名前が表す値を返す。
func (v *Vault) Secret(kind Kind, name string) (string, bool) {
	value, ok := v.secrets[kind][name]
	return value, ok
}

// Set は、名前の下に資格情報を保存する。新規作成か、値の置き換えである。
func (v *Vault) Set(kind Kind, name, value string) error {
	if !ValidKind(kind) {
		return ErrUnknownKind
	}
	if !validCredentialName(name) {
		return ErrUnsafeName
	}
	if value == "" {
		return ErrEmptySecret
	}
	v.secrets[kind][name] = value
	return nil
}

// Delete は資格情報を忘れる。まだ何かが指しているあいだは拒否する。
//
// 秘密に名前を付ける意味は、多くの subject がひとつのエントリを共有することにある。
// だからその足元でエントリを取り除けば、あとになって、別のどこかで、すべての
// subject が一度に壊れることになる。
func (v *Vault) Delete(kind Kind, name string) error {
	if len(v.Uses(kind, name)) > 0 {
		return ErrCredentialInUse
	}
	delete(v.secrets[kind], name)
	return nil
}

// Uses は、資格情報を参照している subject をソートして列挙する。
func (v *Vault) Uses(kind Kind, name string) []string {
	var uses []string
	for subject, referenced := range v.subjects[kind] {
		if referenced == name {
			uses = append(uses, subject)
		}
	}
	slices.Sort(uses)
	return uses
}

// Assign は、subject を同じ種別の資格情報へ向ける。
//
// 種別こそが防護のすべてである。ホストは alias を名前とし、アカウントのパスワード
// だけを参照できる。鍵はワークスペース相対のパスを名前とし、鍵のパスフレーズだけを
// 参照できる。両者をまたぐことは、忘れうる検査によって拒否されるのではない —
// 他方の種別の名前が現れるマップが、そもそも存在しないのである。
func (v *Vault) Assign(kind Kind, subject, name string) error {
	if !ValidKind(kind) {
		return ErrUnknownKind
	}
	if kind == KindPassword {
		if err := platform.ValidateAlias(subject); err != nil {
			return ErrUnsafeName
		}
	} else if subject == "" || strings.ContainsAny(subject, "\x00") {
		return ErrUnsafeName
	}
	if _, ok := v.secrets[kind][name]; !ok {
		return ErrUnknownCredential
	}
	v.subjects[kind][subject] = name
	return nil
}

// Unassign は subject の参照を忘れる。subject がなくてもエラーではない。
func (v *Vault) Unassign(kind Kind, subject string) {
	delete(v.subjects[kind], subject)
}

// Assigned は、subject が参照している資格情報を返す。
func (v *Vault) Assigned(kind Kind, subject string) (string, bool) {
	name, ok := v.subjects[kind][subject]
	return name, ok
}

// Subjects は、ある資格情報を参照している、ある種別のすべての subject を返す。
func (v *Vault) Subjects(kind Kind) []string {
	return slices.Sorted(maps.Keys(v.subjects[kind]))
}

// SecretFor は、subject を、それに与えるべき値へ解決する。
func (v *Vault) SecretFor(kind Kind, subject string) (string, bool) {
	name, ok := v.subjects[kind][subject]
	if !ok {
		return "", false
	}
	return v.Secret(kind, name)
}

// Rename は、subject の参照を新しい名前へ引き継ぐ。ホストの名前変更はこれを
// しなければならず、さもなければ参照は、誰も尋ねない名前の下に黙って孤児に
// なる。
func (v *Vault) Rename(kind Kind, from, to string) error {
	name, ok := v.subjects[kind][from]
	if !ok {
		return nil
	}
	if kind == KindPassword {
		if err := platform.ValidateAlias(to); err != nil {
			return ErrUnsafeName
		}
	}
	delete(v.subjects[kind], from)
	v.subjects[kind][to] = name
	return nil
}

// RelocateSubjects は複数の subject 名を一つのスナップショットとして移す。
//
// グループ名の変更では、親と子の鍵が同時に移動する。1 件ずつ Rename すると、
// ある移動先が別の移動元でもある場合に先の値を上書きし得るため、変更前の
// map から値を集め、すべての移動元を消してから移動先へ置く。
func (v *Vault) RelocateSubjects(kind Kind, relocations map[string]string) (bool, error) {
	if !ValidKind(kind) {
		return false, ErrUnknownKind
	}
	if len(relocations) == 0 {
		return false, nil
	}
	moved := make(map[string]string)
	for from, to := range relocations {
		if from == to {
			continue
		}
		if kind == KindPassword {
			if err := platform.ValidateAlias(to); err != nil {
				return false, ErrUnsafeName
			}
		} else if to == "" || strings.ContainsRune(to, '\x00') {
			return false, ErrUnsafeName
		}
		if name, ok := v.subjects[kind][from]; ok {
			moved[to] = name
		}
	}
	if len(moved) == 0 {
		return false, nil
	}
	for from := range relocations {
		delete(v.subjects[kind], from)
	}
	for to, name := range moved {
		v.subjects[kind][to] = name
	}
	return true, nil
}

// validCredentialName は、人が打ち込み、画面が表示できる名前を受け付ける。これは
// alias ではない。資格情報は、それが何のためのものかにちなんで名付けられ、それは
// ホスト名ではなく「オフィスの VM 群」かもしれないからだ。
func validCredentialName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	return !strings.ContainsAny(name, "\x00\r\n")
}
