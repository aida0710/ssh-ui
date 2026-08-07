package remotesync

import (
	"crypto/sha256"
	"encoding/hex"
)

// Digest は、マニフェストで使う内容ハッシュ。ストレージ層が事前条件に使うのと同じ
// 関数だが、バイトスライスをハッシュするためだけにトランザクションマネージャを
// import しないよう、ここに書き下してある。
func Digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
