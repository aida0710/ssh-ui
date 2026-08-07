// Package envelope は、パスフレーズを使ってブロブを暗号化する。
//
// このパッケージがあるのは、「このバイトを、別のマシンからは読めて他のどこからも
// 読めない場所に置く」という問いに対して、このアプリケーションの二つの機能が
// まったく同じ答えを必要とするからである。すなわち、パスワード保管の vault と、
// リモート同期がアップロードするスナップショットだ。実装が二つあれば、コストの
// 上限も二つ、ヘッダー書式も二つ、追加データを取り違える機会も二つになる。
//
// 書式は意図して自己記述的にしてある。封をしたブロブは、それを書いたビルドより
// 長く生き、書かれた時点では存在しなかったビルドからも読めなければならないから
// である。
//
//	magic 16 | envelope 1 | kdf 1 | time 4 | memory 4 | threads 1 | saltLen 1 | salt | nonce 12 | AES-256-GCM(…)
//	└───────────────────────── 追加データとして認証される ─────────────────────┘
//
// ヘッダーは AEAD の追加データなので、そのパラメータを小さく書き換えて再生する
// ことはできない。1 バイトでも変えれば、安いコストで鍵を導出する代わりに open が
// 失敗する。
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"slices"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrWrongPassphrase は、与えられたパスフレーズではブロブを開けなかったことを
	// 報告する。「パスフレーズが違う」と「ブロブが改竄されている」で意図的に同じ
	// エラーにしてある。AES-GCM に両者は区別できず、区別できるふりをすればそれは
	// 当て推量になるからだ。
	ErrWrongPassphrase = errors.New("the passphrase did not open this data")
	// ErrNotAnEnvelope は、そのバイト列がそもそも封をしたブロブではないと報告する。
	ErrNotAnEnvelope = errors.New("these bytes are not an sshc envelope")
	// ErrUnsupportedVersion は、より新しいビルドが書いたブロブであることを報告する。
	// 独立したエラーにしてあるのは、「このビルドは古すぎる」と「あなたのデータは
	// 失われた」が、人に伝える内容として別物だからである。
	ErrUnsupportedVersion = errors.New("this data was written by a newer version of sshc")
	// ErrCostRefused は、このアプリケーションが書くどの envelope にも必要ないほどの
	// 作業量を要求するヘッダーを報告する。
	ErrCostRefused = errors.New("this data demands an unreasonable amount of work to open")
	// ErrWeakPassphrase は、MinPassphraseLength 未満のパスフレーズを拒否する。
	ErrWeakPassphrase = errors.New("the passphrase is too short")
)

// MinPassphraseLength は、このパッケージが封に使う最短のパスフレーズ長。
//
// 大雑把なルールであり、これが唯一のルールでもある。文字種の要件は課さない。
// それは人を、覚えられない短いパスフレーズへと追いやるからだ。封をしたブロブは
// マシンの外へコピーでき、好きなだけ時間をかけてオフラインで攻撃できる。それを
// 高くつくものにするのは長さである。
const MinPassphraseLength = 12

// Argon2id のパラメータ。すべてのヘッダーに書き込まれるので、あとで引き上げても
// 古いブロブは読めるままで、新しいものだけが強くなる。
const (
	kdfArgon2id      = 1
	defaultTime      = 3
	defaultMemoryKiB = 64 * 1024
	defaultThreads   = 4
	derivedKeyLength = 32
	saltLength       = 16
	nonceLength      = 12
	magicLength      = 16
	envelopeVersion  = 1
)

// コストの上限。
//
// 開くのにどれだけの作業がかかるかはヘッダーが述べており、封をしたブロブは外から
// やってくる。別のマシンから、バケットから、リストアから。まず妥当だと同意して
// いないパラメータから鍵を導出してよいものは何もない。
//
// これがないと、64 MiB 上で time=65539 を主張するヘッダーは、試行あたり 1 コアで
// おおよそ 90 分を要求し、open は決して戻ってこない。これは仮定の話ではない。
// vault 自身の改竄テストの初回実行が、コストのフィールドの 1 ビットを反転させる
// ことで実際にそうなり、誰かが見に来るまで 5 分間ハングしていた、という実話で
// ある。
//
// 大きなパラメータを拒否することは弱体化ではない。ヘッダーは認証されているので、
// 攻撃者が実際のコストを下げたうえでブロブを開けるようにすることはできない。
// この上限は、終わらせる価値のない作業を始めさせないだけである。
const (
	maxKDFTime      = 16
	maxKDFMemoryKiB = 1 << 20 // 1 GiB
	maxKDFThreads   = 16
	maxSaltLength   = 64
)

// Limits は、envelope が要求してよいパラメータ。
//
// 二組ある。envelope には二種類あり、そのうち自分たちのものは一方だけだからだ。
// このインストールが書いたファイルは Derive が選んだ値を要求する。バケットから
// 取ってきたスナップショットは、それを書いた誰かが選んだ値を要求し、それは他人が
// 決めた数字である。後者の上限をこちらが書くであろう値の近くに置いてあるので、
// スナップショットが、パスフレーズの誤りが判明する前にこのマシンへ 1 ギガバイトと
// 16 スレッドを費やさせることはできない。
type Limits struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// Accepted は、このインストールが書いた envelope が要求してよい値。
var Accepted = Limits{Time: maxKDFTime, MemoryKiB: maxKDFMemoryKiB, Threads: maxKDFThreads}

// AcceptedFromRemote は、ネットワーク越しに届いた envelope が要求してよい値。
// Derive が書く値を少し上回るところまでで、それ以上はない。
var AcceptedFromRemote = Limits{Time: 8, MemoryKiB: 256 << 10, Threads: 8}

var magic = [magicLength]byte{'s', 's', 'h', '-', 'u', 'i', '-', 'e', 'n', 'v', 'e', 'l', 'o', 'p', 'e', 0}

// Params は、封をしたブロブひとつ分の鍵導出パラメータ。
type Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Salt    []byte
}

// Key は導出済みの鍵。パスフレーズではなく鍵を保持するのは、変更を封じ直すときに
// パスフレーズをもう一度尋ねずに済ませるためである。
type Key struct {
	material []byte
	params   Params
}

// Derive は、新しいパラメータで passphrase を伸ばして鍵にする。
func Derive(passphrase string) (Key, error) {
	if len([]rune(passphrase)) < MinPassphraseLength {
		return Key{}, ErrWeakPassphrase
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return Key{}, err
	}
	params := Params{Time: defaultTime, Memory: defaultMemoryKiB, Threads: defaultThreads, Salt: salt}
	return Key{material: derive(passphrase, params), params: params}, nil
}

// MaxConcurrentDerivations は、同時に走ってよい鍵導出の数。
//
// 鍵導出は意図的に高価であり — 数十メガバイトと複数スレッド — アンロック、push、
// pull のいずれもが一回ずつ行う。上限がなければ、タブがいくつか開いたページが
// 一度に何十個も要求し、プロセスは理由もなくギガバイト単位を確保する。2 なら、
// 待っている人が気づくことはない。これは一人が操作するローカルのインターフェース
// だからである。
const MaxConcurrentDerivations = 2

var derivations = make(chan struct{}, MaxConcurrentDerivations)

// OnDerive は各導出を包む。同時に何個走っているかを数えるテストのためにあり、
// それ以外の場所では nil である。
var OnDerive func(step func())

func derive(passphrase string, params Params) []byte {
	derivations <- struct{}{}
	defer func() { <-derivations }()

	var key []byte
	step := func() {
		key = argon2.IDKey([]byte(passphrase), params.Salt, params.Time, params.Memory, params.Threads, derivedKeyLength)
	}
	if OnDerive != nil {
		OnDerive(step)
	} else {
		step()
	}
	return key
}

// Seal は key で plaintext を暗号化する。呼び出しごとに新しい nonce を使うので、
// 同じ内容を二度封じてもバイト列は異なり、どちらも両者が同じ内容であることを
// 明かさない。
func (k Key) Seal(plaintext []byte) ([]byte, error) {
	if len(k.material) != derivedKeyLength {
		return nil, ErrNotAnEnvelope
	}
	gcm, err := newGCM(k.material)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := writeHeader(k.params)
	sealed := make([]byte, 0, len(header)+nonceLength+len(plaintext)+gcm.Overhead())
	sealed = append(sealed, header...)
	sealed = append(sealed, nonce...)
	return gcm.Seal(sealed, nonce, plaintext, header), nil
}

// Open は、すでに保持している鍵で sealed を復号する。Seal の鏡像であり、あちらが
// 鍵だけで動くように、こちらも鍵だけで動く。
//
// これは、鍵を保持し、パスフレーズは意図的に保持しない呼び出し側 — vault — の
// ためにある。おかげで vault は自分のファイルの隣にもうひとつ封をし、ユーザーに
// 再度尋ねることなく読み戻せる。ヘッダーは認証データなので、鍵が合わない場合は
// 別途検出されるのではなくタグの検証に失敗する。
func (k Key) Open(sealed []byte) ([]byte, error) {
	if len(k.material) != derivedKeyLength {
		return nil, ErrNotAnEnvelope
	}
	header, _, rest, err := readHeader(sealed)
	if err != nil {
		return nil, err
	}
	if len(rest) < nonceLength {
		return nil, ErrNotAnEnvelope
	}
	nonce, ciphertext := rest[:nonceLength], rest[nonceLength:]
	gcm, err := newGCM(k.material)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return plaintext, nil
}

// Open は passphrase で sealed を復号し、平文とともに鍵も返す。呼び出し側が
// 導出をやり直さずに封をし直せるようにするためである。
func Open(sealed []byte, passphrase string) ([]byte, Key, error) {
	return OpenWithin(sealed, passphrase, Accepted)
}

// OpenWithin は上限を明示する Open。開こうとしている envelope を自分で書いた
// わけではない呼び出し側のためにある。
func OpenWithin(sealed []byte, passphrase string, limits Limits) ([]byte, Key, error) {
	header, params, rest, err := readHeader(sealed)
	if err != nil {
		return nil, Key{}, err
	}
	if params.Time > limits.Time || params.Memory > limits.MemoryKiB || params.Threads > limits.Threads {
		return nil, Key{}, ErrCostRefused
	}
	if len(rest) < nonceLength {
		return nil, Key{}, ErrNotAnEnvelope
	}
	nonce, ciphertext := rest[:nonceLength], rest[nonceLength:]

	material := derive(passphrase, params)
	gcm, err := newGCM(material)
	if err != nil {
		return nil, Key{}, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, Key{}, ErrWrongPassphrase
	}
	return plaintext, Key{material: material, params: params}, nil
}

func newGCM(material []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func writeHeader(params Params) []byte {
	header := make([]byte, 0, magicLength+12+len(params.Salt))
	header = append(header, magic[:]...)
	header = append(header, envelopeVersion, kdfArgon2id)
	header = binary.BigEndian.AppendUint32(header, params.Time)
	header = binary.BigEndian.AppendUint32(header, params.Memory)
	header = append(header, params.Threads, byte(len(params.Salt)))
	return append(header, params.Salt...)
}

func readHeader(sealed []byte) (header []byte, params Params, rest []byte, err error) {
	const fixed = magicLength + 12
	if len(sealed) < fixed {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	if [magicLength]byte(sealed[:magicLength]) != magic {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	if sealed[magicLength] > envelopeVersion {
		return nil, Params{}, nil, ErrUnsupportedVersion
	}
	if sealed[magicLength+1] != kdfArgon2id {
		// 未知の KDF は、壊れたブロブではなく将来のビルドが書いたブロブである。
		return nil, Params{}, nil, ErrUnsupportedVersion
	}
	params.Time = binary.BigEndian.Uint32(sealed[magicLength+2:])
	params.Memory = binary.BigEndian.Uint32(sealed[magicLength+6:])
	params.Threads = sealed[magicLength+10]
	saltLen := int(sealed[magicLength+11])
	if params.Time == 0 || params.Memory == 0 || params.Threads == 0 || saltLen == 0 {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	if params.Time > maxKDFTime || params.Memory > maxKDFMemoryKiB ||
		params.Threads > maxKDFThreads || saltLen > maxSaltLength {
		return nil, Params{}, nil, ErrCostRefused
	}
	if len(sealed) < fixed+saltLen {
		return nil, Params{}, nil, ErrNotAnEnvelope
	}
	params.Salt = slices.Clone(sealed[fixed : fixed+saltLen])
	return slices.Clone(sealed[:fixed+saltLen]), params, sealed[fixed+saltLen:], nil
}
