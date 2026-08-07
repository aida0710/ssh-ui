// Package handoff は、動作中のアプリケーションが、同じバイナリのコマンドライン
// 起動に対して自分の居場所を伝えるための仕組みである。
//
// これがあるおかげで、端末からの接続は五つの環境変数とフラグではなく
// `sshc <alias>` で済む。それらの変数は、Terminal のボタンがすでに自前でやって
// いることを手書きにした形にすぎない。そもそも人が打ち込むためのものでは
// なかった。
//
// このファイルは URL と、この実行のために発行された秘密を持つ。これを読める者は
// すでに vault の暗号文とすべての秘密鍵を読める — 同じディレクトリに同じ権限で
// 置かれているからだ — ので、境界を動かすことはない。動かすのは古くなったものの
// 到達範囲である。秘密は、それを発行した実行が終わった瞬間に無価値になる。だから
// 強制終了されたプロセスが残していったファイルは、何も待ち受けていないポートを、
// 誰も受け付けない秘密とともに指しているだけに
// なる。
package handoff

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// FileName は、アプリケーションの状態ディレクトリ内のハンドオフファイル。
const FileName = "cli"

// secretLength は、秘密の元になるランダムバイト数。
const secretLength = 32

// Handoff は、この実行がどこで待ち受けているか、そして呼び出し側が推測ではなく
// ファイルを読んだことを何が証明するかを保持する。
type Handoff struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// HeaderName は、コマンドラインからのリクエストに秘密を載せる。
//
// 独自ヘッダーは、プリフライトなしにはどのウェブページもクロスオリジンで送れない
// リクエストであり、このサーバーはプリフライトに応答しない。したがってハンドオフ
// のルートは、ブラウザからどれだけ事情を知っていても到達できない。
const HeaderName = "X-SSHC-CLI"

// Mint は、一回の実行のための秘密を返す。
//
// Write と分けてあるのは、サーバーが待ち受けを始める前に秘密を知らせる必要が
// あり、一方でファイルは URL が判明するまで書けないからである。
func Mint(random io.Reader) (string, error) {
	raw := make([]byte, secretLength)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Write は、この実行がどこで待ち受けているか、そして呼び出し側がファイルを読んだ
// ことを何が証明するかを記録し、そこにあるものを置き換える。
func Write(directory, url, secret string) (Handoff, error) {
	written := Handoff{URL: url, Secret: secret}
	body, err := json.Marshal(written)
	if err != nil {
		return Handoff{}, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Handoff{}, err
	}
	if err := os.WriteFile(filepath.Join(directory, FileName), body, 0o600); err != nil {
		return Handoff{}, err
	}
	return written, nil
}

// Read は、動作中のアプリケーションが残したものを返す。
func Read(directory string) (Handoff, error) {
	body, err := os.ReadFile(filepath.Join(directory, FileName))
	if err != nil {
		return Handoff{}, err
	}
	var read Handoff
	if err := json.Unmarshal(body, &read); err != nil {
		return Handoff{}, err
	}
	return read, nil
}

// Remove はそれを取り除く。ファイルがないことは、これが求める状態である。
func Remove(directory string) error {
	err := os.Remove(filepath.Join(directory, FileName))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Random は、呼び出し側に指定がないときに Write が引く乱数源。
var Random io.Reader = rand.Reader
