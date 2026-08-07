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

// Algorithm は、HTTP API が使う綴りで鍵アルゴリズムの系統を表す。
type Algorithm string

const (
	AlgorithmEd25519   Algorithm = "ed25519"
	AlgorithmRSA       Algorithm = "rsa"
	AlgorithmECDSA     Algorithm = "ecdsa"
	AlgorithmEd25519SK Algorithm = "ed25519-sk"
	AlgorithmECDSASK   Algorithm = "ecdsa-sk"
)

// DefaultRSABits は、RSA のリクエストがサイズを選ばなかったときに使われる。
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

// Material は、鍵そのものを露出せずに秘密鍵ファイルを記述する。
//
// Fingerprint が空になるのは、平文の公開鍵を含まないコンテナでファイルが暗号化
// されている場合である。DEK-Info ヘッダーを持つ旧来の
// "-----BEGIN RSA PRIVATE KEY-----" 形式がそれにあたる。呼び出し側は、対応する
// 公開鍵ファイルからフィンガープリントを復元するか、得られないと報告する。推測は
// 決してしない。
type Material struct {
	Container   string
	Encrypted   bool
	Algorithm   Algorithm
	KeyType     string
	Bits        int
	Fingerprint string
}

// PublicKeyInfo は、authorized-keys 形式の行ひとつを記述する。
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

// Wipe は、秘密を保持するバッファをゼロで上書きする。
//
// これはベストエフォートにすぎない。Go のガベージコレクタは、スライスの拡張や
// スタックの移動の際にすでにバイト列をコピーしているかもしれず、ランタイムには
// そのコピーを見つけたり消したりする手段がない。Wipe は、秘密がこのプロセス内で
// 読める時間の幅を縮めるだけで、消去を保証するものではない。
func Wipe(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}

// InspectPrivateKey は、パスフレーズを必要とせずに、秘密鍵ファイルが何を保持して
// いるか、そしてパスフレーズで保護されているかを報告する。
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

// InspectPublicKey は authorized-keys 形式の行をひとつ読む。素の公開鍵の場合も、
// OpenSSH の証明書の場合もある。
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

// GeneratePrivateKey はソフトウェアの鍵ペアを作る。RSA と ECDSA の鍵をポインタで
// 返すのは、ssh.MarshalPrivateKeyWithPassphrase が値の形を拒否するから
// である。
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

// EncodePrivateKey は、OpenSSH の秘密鍵コンテナに鍵を直列化する。パスフレーズが
// 空なら暗号化されない形になる。暗号化されていない鍵を許容するかは呼び出し側が
// 決める。
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

// EncodePublicKey は、秘密鍵に対応する authorized-keys の行を出力する。
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

// DecodePrivateKey は、秘密鍵ファイルから生の鍵を返す。
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
