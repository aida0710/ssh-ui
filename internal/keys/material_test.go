package keys

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEncodeAndInspectPrivateKeyRoundTrip(t *testing.T) {
	tests := []struct {
		name            string
		algorithm       Algorithm
		bits            int
		passphrase      string
		expectedKeyType string
		expectedBits    int
	}{
		{"ed25519 encrypted", AlgorithmEd25519, 0, "correct horse", "ssh-ed25519", 256},
		{"ed25519 unencrypted", AlgorithmEd25519, 0, "", "ssh-ed25519", 256},
		{"rsa encrypted", AlgorithmRSA, 2048, "correct horse", "ssh-rsa", 2048},
		{"ecdsa encrypted", AlgorithmECDSA, 256, "correct horse", "ecdsa-sha2-nistp256", 256},
		{"ecdsa unencrypted", AlgorithmECDSA, 384, "", "ecdsa-sha2-nistp384", 384},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privateKey, err := GeneratePrivateKey(test.algorithm, test.bits, rand.Reader)
			if err != nil {
				t.Fatalf("GeneratePrivateKey(%s, %d) error = %v", test.algorithm, test.bits, err)
			}
			encoded, err := EncodePrivateKey(privateKey, "sshc@test", []byte(test.passphrase))
			if err != nil {
				t.Fatalf("EncodePrivateKey error = %v", err)
			}
			if !bytes.HasPrefix(encoded, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
				t.Fatalf("encoded key does not use the OpenSSH container: %q", firstLine(encoded))
			}

			material, err := InspectPrivateKey(encoded)
			if err != nil {
				t.Fatalf("InspectPrivateKey error = %v", err)
			}
			if material.Encrypted != (test.passphrase != "") {
				t.Errorf("Encrypted = %v, want %v", material.Encrypted, test.passphrase != "")
			}
			if material.KeyType != test.expectedKeyType {
				t.Errorf("KeyType = %q, want %q", material.KeyType, test.expectedKeyType)
			}
			if material.Bits != test.expectedBits {
				t.Errorf("Bits = %d, want %d", material.Bits, test.expectedBits)
			}
			if !strings.HasPrefix(material.Fingerprint, "SHA256:") {
				t.Errorf("Fingerprint = %q, want a SHA256 fingerprint", material.Fingerprint)
			}

			decoded, err := DecodePrivateKey(encoded, []byte(test.passphrase))
			if err != nil {
				t.Fatalf("DecodePrivateKey error = %v", err)
			}
			publicKey, err := EncodePublicKey(decoded, "sshc@test")
			if err != nil {
				t.Fatalf("EncodePublicKey error = %v", err)
			}
			info, err := InspectPublicKey(publicKey)
			if err != nil {
				t.Fatalf("InspectPublicKey error = %v", err)
			}
			if info.Fingerprint != material.Fingerprint {
				t.Errorf("public fingerprint = %q, private fingerprint = %q", info.Fingerprint, material.Fingerprint)
			}
			if info.Comment != "sshc@test" {
				t.Errorf("Comment = %q, want %q", info.Comment, "sshc@test")
			}
			if info.IsCertificate {
				t.Errorf("public key was classified as a certificate")
			}
		})
	}
}

func TestDecodePrivateKeyReportsPassphraseProblemsDistinctly(t *testing.T) {
	privateKey, err := GeneratePrivateKey(AlgorithmEd25519, 0, rand.Reader)
	if err != nil {
		t.Fatalf("GeneratePrivateKey error = %v", err)
	}
	encrypted, err := EncodePrivateKey(privateKey, "sshc@test", []byte("correct horse"))
	if err != nil {
		t.Fatalf("EncodePrivateKey error = %v", err)
	}

	if _, err := DecodePrivateKey(encrypted, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("missing passphrase error = %v, want ErrPassphraseRequired", err)
	}
	if _, err := DecodePrivateKey(encrypted, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase error = %v, want ErrWrongPassphrase", err)
	}
	if _, err := DecodePrivateKey([]byte("not a key\n"), nil); !errors.Is(err, ErrNotPrivateKey) {
		t.Errorf("non-key error = %v, want ErrNotPrivateKey", err)
	}
	if _, err := InspectPrivateKey([]byte("ssh-ed25519 AAAA comment\n")); !errors.Is(err, ErrNotPrivateKey) {
		t.Errorf("public key inspected as private = %v, want ErrNotPrivateKey", err)
	}
}

func TestGeneratePrivateKeyRejectsUnsupportedRequests(t *testing.T) {
	tests := []struct {
		name      string
		algorithm Algorithm
		bits      int
		wantError error
	}{
		{"hardware ed25519", AlgorithmEd25519SK, 0, ErrHardwareAlgorithm},
		{"hardware ecdsa", AlgorithmECDSASK, 256, ErrHardwareAlgorithm},
		{"unknown algorithm", Algorithm("dsa"), 1024, ErrUnsupportedAlgorithm},
		{"rsa too small", AlgorithmRSA, 1024, ErrUnsupportedBits},
		{"ecdsa unknown curve", AlgorithmECDSA, 224, ErrUnsupportedBits},
		{"ed25519 with bits", AlgorithmEd25519, 512, ErrUnsupportedBits},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := GeneratePrivateKey(test.algorithm, test.bits, rand.Reader); !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestInspectPublicKeyReadsCertificateDetail(t *testing.T) {
	certificateLine := []byte(certificateFixture)
	info, err := InspectPublicKey(certificateLine)
	if err != nil {
		t.Fatalf("InspectPublicKey error = %v", err)
	}
	if !info.IsCertificate {
		t.Fatalf("IsCertificate = false, want true")
	}
	if info.CertificateKeyID != "probe-id" {
		t.Errorf("CertificateKeyID = %q, want %q", info.CertificateKeyID, "probe-id")
	}
	if len(info.CertificatePrincipals) != 1 || info.CertificatePrincipals[0] != "alice" {
		t.Errorf("CertificatePrincipals = %#v, want [alice]", info.CertificatePrincipals)
	}
	if info.SignedKeyType != "ssh-ed25519" {
		t.Errorf("SignedKeyType = %q, want %q", info.SignedKeyType, "ssh-ed25519")
	}
	if !strings.HasPrefix(info.SignedKeyFingerprint, "SHA256:") {
		t.Errorf("SignedKeyFingerprint = %q, want a SHA256 fingerprint", info.SignedKeyFingerprint)
	}
}

func TestWipeOverwritesTheBufferItWasGiven(t *testing.T) {
	secret := []byte("correct horse battery staple")
	Wipe(secret)
	for index, value := range secret {
		if value != 0 {
			t.Fatalf("secret[%d] = %d, want 0", index, value)
		}
	}
}

func firstLine(contents []byte) string {
	if index := bytes.IndexByte(contents, '\n'); index >= 0 {
		return string(contents[:index])
	}
	return string(contents)
}

// certificateFixture は、テスト開始時に組み立てられる自己署名の OpenSSH ユーザー
// 証明書。プロセス内で作ることで、スイートは開発者の本物のホーム配下のファイルから
// 独立していられる。
var certificateFixture = buildCertificateFixture()

func buildCertificateFixture() string {
	subjectKey, err := GeneratePrivateKey(AlgorithmEd25519, 0, rand.Reader)
	if err != nil {
		panic(err)
	}
	authorityKey, err := GeneratePrivateKey(AlgorithmEd25519, 0, rand.Reader)
	if err != nil {
		panic(err)
	}
	subjectSigner, err := ssh.NewSignerFromKey(subjectKey)
	if err != nil {
		panic(err)
	}
	authoritySigner, err := ssh.NewSignerFromKey(authorityKey)
	if err != nil {
		panic(err)
	}
	certificate := &ssh.Certificate{
		Key:             subjectSigner.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "probe-id",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := certificate.SignCert(rand.Reader, authoritySigner); err != nil {
		panic(err)
	}
	return string(ssh.MarshalAuthorizedKey(certificate))
}
