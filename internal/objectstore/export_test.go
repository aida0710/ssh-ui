package objectstore

import "time"

// SigningKeyForTest は導出済みの署名鍵を公開する。既知解テストが、AWS の公開
// 例と HMAC の連鎖を突き合わせられるようにするためである。
func SigningKeyForTest(secretAccessKey string, stamp time.Time, region, service string) []byte {
	return signingKey(secretAccessKey, stamp, region, service)
}
