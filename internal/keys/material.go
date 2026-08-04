package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Algorithm names a key algorithm family in the spelling the HTTP API uses.
type Algorithm string

const (
	AlgorithmEd25519   Algorithm = "ed25519"
	AlgorithmRSA       Algorithm = "rsa"
	AlgorithmECDSA     Algorithm = "ecdsa"
	AlgorithmEd25519SK Algorithm = "ed25519-sk"
	AlgorithmECDSASK   Algorithm = "ecdsa-sk"
)

// DefaultRSABits is used when an RSA request does not choose a size.
const DefaultRSABits = 3072

var (
	ErrNotPrivateKey        = errors.New("file does not contain a private key")
	ErrNotPublicKey         = errors.New("line does not contain a public key")
	ErrHardwareAlgorithm    = errors.New("hardware-backed keys are not generated in this process")
	ErrUnsupportedAlgorithm = errors.New("unsupported key algorithm")
	ErrUnsupportedBits      = errors.New("unsupported key size for this algorithm")
	ErrWrongPassphrase      = errors.New("passphrase does not decrypt this key")
	ErrPassphraseRequired   = errors.New("key is passphrase protected")
)

// Material describes a private key file without exposing the key itself.
//
// Fingerprint is empty when the file is encrypted in a container that does not
// carry a cleartext public key, which is the case for the legacy
// "-----BEGIN RSA PRIVATE KEY-----" form with a DEK-Info header. The caller
// recovers the fingerprint from a matching public key file or reports that it
// is unavailable; it never guesses.
type Material struct {
	Container   string
	Encrypted   bool
	Algorithm   Algorithm
	KeyType     string
	Bits        int
	Fingerprint string
}

// PublicKeyInfo describes one authorized-keys style line.
type PublicKeyInfo struct {
	KeyType                string
	Algorithm              Algorithm
	Bits                   int
	Fingerprint            string
	Comment                string
	IsCertificate          bool
	CertificateKeyID       string
	CertificatePrincipals  []string
	CertificateValidBefore uint64
	SignedKeyType          string
	SignedKeyFingerprint   string
}

// Wipe overwrites a secret buffer with zeroes.
//
// This is best effort only. Go's garbage collector may already have copied the
// bytes while growing a slice or moving a stack, and the runtime offers no way
// to find or erase those copies. Wipe shortens the window in which a secret is
// readable in this process; it does not guarantee erasure.
func Wipe(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}

// InspectPrivateKey reports what a private key file holds and whether it is
// passphrase protected, without needing the passphrase.
func InspectPrivateKey(contents []byte) (Material, error) {
	block, _ := pem.Decode(contents)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return Material{}, ErrNotPrivateKey
	}
	material := Material{Container: block.Type}

	signer, err := ssh.ParsePrivateKey(contents)
	if err == nil {
		material.KeyType = signer.PublicKey().Type()
		material.Algorithm = algorithmForKeyType(material.KeyType)
		material.Bits = publicKeyBits(signer.PublicKey())
		material.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
		return material, nil
	}

	var passphraseMissing *ssh.PassphraseMissingError
	if !errors.As(err, &passphraseMissing) {
		return Material{}, fmt.Errorf("%w: %s", ErrNotPrivateKey, err)
	}
	material.Encrypted = true
	if passphraseMissing.PublicKey != nil {
		material.KeyType = passphraseMissing.PublicKey.Type()
		material.Algorithm = algorithmForKeyType(material.KeyType)
		material.Bits = publicKeyBits(passphraseMissing.PublicKey)
		material.Fingerprint = ssh.FingerprintSHA256(passphraseMissing.PublicKey)
	}
	return material, nil
}

// InspectPublicKey reads one authorized-keys style line, which may be a plain
// public key or an OpenSSH certificate.
func InspectPublicKey(line []byte) (PublicKeyInfo, error) {
	publicKey, comment, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return PublicKeyInfo{}, fmt.Errorf("%w: %s", ErrNotPublicKey, err)
	}
	info := PublicKeyInfo{
		KeyType:     publicKey.Type(),
		Algorithm:   algorithmForKeyType(publicKey.Type()),
		Bits:        publicKeyBits(publicKey),
		Fingerprint: ssh.FingerprintSHA256(publicKey),
		Comment:     comment,
	}
	certificate, isCertificate := publicKey.(*ssh.Certificate)
	if !isCertificate {
		return info, nil
	}
	info.IsCertificate = true
	info.CertificateKeyID = certificate.KeyId
	info.CertificatePrincipals = certificate.ValidPrincipals
	info.CertificateValidBefore = certificate.ValidBefore
	info.SignedKeyType = certificate.Key.Type()
	info.SignedKeyFingerprint = ssh.FingerprintSHA256(certificate.Key)
	info.Bits = publicKeyBits(certificate.Key)
	info.Algorithm = algorithmForKeyType(certificate.Key.Type())
	return info, nil
}

// GeneratePrivateKey creates a software key pair. RSA and ECDSA keys are
// returned as pointers because ssh.MarshalPrivateKeyWithPassphrase rejects the
// value forms.
func GeneratePrivateKey(algorithm Algorithm, bits int, random io.Reader) (crypto.PrivateKey, error) {
	switch algorithm {
	case AlgorithmEd25519:
		if bits != 0 && bits != 256 {
			return nil, ErrUnsupportedBits
		}
		_, privateKey, err := ed25519.GenerateKey(random)
		if err != nil {
			return nil, err
		}
		return privateKey, nil
	case AlgorithmRSA:
		if bits == 0 {
			bits = DefaultRSABits
		}
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, ErrUnsupportedBits
		}
		return rsa.GenerateKey(random, bits)
	case AlgorithmECDSA:
		curve, err := ecdsaCurve(bits)
		if err != nil {
			return nil, err
		}
		return ecdsa.GenerateKey(curve, random)
	case AlgorithmEd25519SK, AlgorithmECDSASK:
		return nil, ErrHardwareAlgorithm
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// EncodePrivateKey serialises a key in the OpenSSH private key container. An
// empty passphrase produces the unencrypted form; the caller decides whether an
// unencrypted key is acceptable.
func EncodePrivateKey(privateKey crypto.PrivateKey, comment string, passphrase []byte) ([]byte, error) {
	var block *pem.Block
	var err error
	if len(passphrase) == 0 {
		block, err = ssh.MarshalPrivateKey(privateKey, comment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, comment, passphrase)
	}
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// EncodePublicKey renders the authorized-keys line for a private key.
func EncodePublicKey(privateKey crypto.PrivateKey, comment string) ([]byte, error) {
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	line := ssh.MarshalAuthorizedKey(signer.PublicKey())
	line = line[:len(line)-1]
	if comment != "" {
		line = append(line, ' ')
		line = append(line, comment...)
	}
	return append(line, '\n'), nil
}

// DecodePrivateKey returns the raw key from a private key file.
func DecodePrivateKey(contents []byte, passphrase []byte) (crypto.PrivateKey, error) {
	if len(passphrase) == 0 {
		privateKey, err := ssh.ParseRawPrivateKey(contents)
		if err == nil {
			return privateKey, nil
		}
		var passphraseMissing *ssh.PassphraseMissingError
		if errors.As(err, &passphraseMissing) {
			return nil, ErrPassphraseRequired
		}
		return nil, fmt.Errorf("%w: %s", ErrNotPrivateKey, err)
	}

	privateKey, err := ssh.ParseRawPrivateKeyWithPassphrase(contents, passphrase)
	switch {
	case err == nil:
		return privateKey, nil
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, ErrWrongPassphrase
	default:
		return nil, fmt.Errorf("%w: %s", ErrNotPrivateKey, err)
	}
}

func ecdsaCurve(bits int) (elliptic.Curve, error) {
	switch bits {
	case 0, 256:
		return elliptic.P256(), nil
	case 384:
		return elliptic.P384(), nil
	case 521:
		return elliptic.P521(), nil
	default:
		return nil, ErrUnsupportedBits
	}
}

func algorithmForKeyType(keyType string) Algorithm {
	base := strings.TrimSuffix(keyType, "-cert-v01@openssh.com")
	switch {
	case base == "ssh-ed25519":
		return AlgorithmEd25519
	case base == "ssh-rsa" || strings.HasPrefix(base, "rsa-sha2-"):
		return AlgorithmRSA
	case strings.HasPrefix(base, "ecdsa-sha2-"):
		return AlgorithmECDSA
	case base == "sk-ssh-ed25519@openssh.com":
		return AlgorithmEd25519SK
	case base == "sk-ecdsa-sha2-nistp256@openssh.com":
		return AlgorithmECDSASK
	default:
		return ""
	}
}

func publicKeyBits(publicKey ssh.PublicKey) int {
	converter, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch typed := converter.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return typed.N.BitLen()
	case *ecdsa.PublicKey:
		return typed.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}
