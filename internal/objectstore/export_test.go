package objectstore

import "time"

// SigningKeyForTest exposes the derived signing key so a known-answer test can
// check the HMAC chain against AWS's published example.
func SigningKeyForTest(secretAccessKey string, stamp time.Time, region, service string) []byte {
	return signingKey(secretAccessKey, stamp, region, service)
}
