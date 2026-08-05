package remotesync

import (
	"crypto/sha256"
	"encoding/hex"
)

// Digest is the content hash used in the manifest. It is the same function the
// storage layer uses for preconditions, spelled out here so this package does
// not import the transaction manager to hash a byte slice.
func Digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
