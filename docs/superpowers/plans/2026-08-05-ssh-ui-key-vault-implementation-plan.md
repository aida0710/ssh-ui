# sshc Key Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the key vault: an inventory of everything under `~/.ssh` classified by content and permissions, in-process Ed25519/RSA/ECDSA generation and passphrase change, a separated private-key reveal API guarded by one-time action tokens, ssh-agent and macOS Keychain registration behind a platform interface, and a trash that soft-deletes, restores and permanently deletes keys through the journalled transaction manager.

**Architecture:** `internal/keys` is the key vault use-case layer. It reads the disk only through the committed `storage.Workspace`/`storage.FileSystem` seam, mutates the disk only through `storage.Manager` so every change is journalled, recoverable and recorded in history, and learns which Hosts reference a key by walking the committed `config` Include graph. Cryptographic work — inspecting, generating, encrypting and decrypting OpenSSH private keys — lives in `internal/keys/material.go` on top of `golang.org/x/crypto/ssh`. Every effect that leaves the process (running `ssh -Q key`, running `ssh-add`) goes through a new shell-free `platform.CommandExecutor` and a `platform.KeyAgent` interface with a macOS adapter, so automated tests use fakes exclusively. `internal/httpserver` exposes the vault over the existing same-origin, CSRF-protected Echo v5 surface, with a second factor — a one-time, short-lived, subject-bound action token — on private-key reveal and permanent delete.

**Tech Stack:** Go 1.26.5, Echo v5.3.1, `golang.org/x/crypto` v0.54.0, oapi-codegen v2.7.0, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, OpenSSH 10.2p1 (the installed client, never invoked in automated tests).

## Global Constraints

- macOS only. The HTTP server binds only to loopback `127.0.0.1`; do not enable CORS; do not create a LaunchAgent or any background daemon.
- Pinned versions from the foundation are unchanged: Go 1.26.5, Echo v5.3.1, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1. Echo v5 handlers take `*echo.Context`.
- This plan adds exactly one new direct Go module, `golang.org/x/crypto v0.54.0`, and its single indirect requirement `golang.org/x/sys v0.47.0`. Both must be recorded in `go.mod` and `go.sum`. Add no other module.
- Automated tests must never read or write the real `~/.ssh`, the real login Keychain, a real `ssh-agent`, Terminal, or any remote host. Use `t.TempDir()`, fake `platform.CommandExecutor`s and fake `platform.KeyAgent`s only.
- A passphrase must never appear in a process argument list or in a child process's environment. It is passed to a child only on standard input, and it is held in memory only for the duration of one operation.
- The application never persists a passphrase. Retention is delegated to macOS Keychain or `ssh-agent` by an explicit user action only.
- Never log key material, passphrases, request bodies, cookies, session tokens, action tokens, or full filesystem paths. Errors returned to the caller may name a path; log lines must not.
- Managed files are written `0600`; a stricter existing permission is preserved and a looser one is tightened. Managed directories are `0700`.
- `~/.ssh/sshc/` is engine state. Every path under it — including `backups/`, `trash/`, `journal/` and `history/` — is excluded from the key inventory, from agent registration and from configuration suggestions.
- Every mutation goes through `storage.Manager` so it is journalled, backed up where a backup is appropriate, recoverable, and recorded in history. The audit fact that a private key was revealed is recorded in history without the key material.
- OpenAPI is the contract: add the endpoint and schema to `api/openapi.yaml` first, then run `make generate`. Keep the schema inside the subset `api/README.md` validated for oapi-codegen v2.7.0 — object, array, string, integer, boolean, `const`, `required`, `$ref`, response and header. Do not use `enum`, `format: date-time`, `oneOf`, `anyOf` or `nullable`; validate value sets at runtime in Go instead.
- Reads use the committed `storage.OSFileSystem`, whose `ReadFile` opens with `O_NOFOLLOW`. A symbolic link is displayed but never followed for reading key material or for editing.
- Go code follows the repository style: descriptive multi-word identifiers, no single-letter variables, table-driven tests using `t.Fatalf` and `t.Errorf`.

### Verified dependency contract

Adding `golang.org/x/crypto` is justified because writing an *encrypted* OpenSSH private key is not in the Go standard library, and the design forbids handing a passphrase to `ssh-keygen` through argv or the environment. `crypto/ed25519`, `crypto/rsa` and `crypto/ecdsa` can generate the key pair, but only `golang.org/x/crypto/ssh` can serialise it in the bcrypt-KDF OpenSSH private key format that the installed OpenSSH reads, and only it can report whether an existing key file is passphrase protected. The module was pinned at `v0.54.0` and its API verified against that exact version before this plan was written:

- `ssh.MarshalPrivateKeyWithPassphrase(key crypto.PrivateKey, comment string, passphrase []byte) (*pem.Block, error)` produces a `-----BEGIN OPENSSH PRIVATE KEY-----` block. Verified: `ssh-keygen -y -P …` from OpenSSH 10.2p1 reads the result and prints a public key whose SHA256 fingerprint equals `ssh.FingerprintSHA256` of the same key.
- `ssh.MarshalPrivateKey(key crypto.PrivateKey, comment string) (*pem.Block, error)` produces the unencrypted form.
- Accepted key values: `ed25519.PrivateKey` (value or pointer), `*rsa.PrivateKey`, `*ecdsa.PrivateKey`. An `rsa.PrivateKey` *value* is rejected with `ssh: unsupported key type rsa.PrivateKey`, so this plan always passes pointers for RSA and ECDSA.
- `ssh.ParsePrivateKey(pemBytes []byte) (ssh.Signer, error)` returns `*ssh.PassphraseMissingError` for an encrypted key, which is how encryption state is reported. Verified against keys written by `ssh-keygen` in both the modern OpenSSH container and the legacy `-m PEM` container.
- `ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase []byte) (ssh.Signer, error)` returns `x509.IncorrectPasswordError` for a wrong passphrase, matched with `errors.Is`.
- `(*ssh.PassphraseMissingError).PublicKey` is populated for the modern OpenSSH container and is `nil` for the legacy `-m PEM` container, so an encrypted legacy key's fingerprint is recovered from a matching `.pub` file or reported as unavailable.
- `ssh.ParseRawPrivateKeyWithPassphrase` returns `*ed25519.PrivateKey`, `*rsa.PrivateKey` and `*ecdsa.PrivateKey`, and those pointer values are accepted by both `ssh.NewSignerFromKey` and `ssh.MarshalPrivateKeyWithPassphrase`. The decrypt-then-re-encrypt cycle that a passphrase change performs was verified end to end for all three algorithms.
- `ssh.ParseAuthorizedKey`, `ssh.ParseKnownHosts`, `ssh.MarshalAuthorizedKey`, `ssh.FingerprintSHA256`, `ssh.NewSignerFromKey` and the `ssh.CryptoPublicKey` interface all exist at v0.54.0 with those signatures. A certificate line parses to a `*ssh.Certificate` carrying `KeyId`, `ValidPrincipals`, `ValidBefore` and `Key`.

Task 1 re-proves each of these facts as a test in this repository, so the plan does not rely on the note above staying true.

### Out of scope

These belong to other roadmap subsystems and must not appear in this plan's code:

- Remote `authorized_keys` registration, Terminal launch, `ssh -G`, connection tests, `ssh-keyscan` and Known Hosts — roadmap subsystem 5. This plan produces the exact `ssh-keygen` argument list for a FIDO key and stops there; subsystem 5 owns actually launching Terminal.
- Connections UI, Include explorer, groups and group inheritance, metadata — roadmap subsystem 3, planned in parallel and not yet committed. This plan must not consume any type from it.
- Packaging, Playwright end-to-end hardening, fuzz and race campaigns beyond `go test -race ./...` — roadmap subsystem 6.

`ssh -Q key` is *not* `ssh -G`. It prints the algorithm names the installed binary was built with, evaluates no configuration file and runs no user-supplied directive. This plan invokes it with `-F /dev/null` and states that boundary in the README.

---

## File Structure

```text
api/
├── openapi.yaml                       # + key vault, trash and action-token contract
internal/
├── keys/                              # key vault use cases; no HTTP, no UI
│   ├── material.go                    # inspect, generate, encrypt, decrypt, wipe
│   ├── inventory.go                   # classify ~/.ssh by content and permissions
│   ├── references.go                  # Hosts that reference a key file
│   ├── service.go                     # Service, generation, passphrase change, reveal
│   ├── catalogue.go                   # variants the installed OpenSSH supports
│   ├── trash.go                       # soft delete, restore, permanent delete
│   ├── material_test.go
│   ├── inventory_test.go
│   ├── references_test.go
│   ├── service_test.go
│   ├── catalogue_test.go
│   └── trash_test.go
├── platform/
│   ├── command.go                     # + shell-free CommandExecutor seam
│   ├── keyagent.go                    # + KeyAgent contract
│   └── macos/
│       ├── command.go                 # exec adapter with bounded output
│       ├── command_test.go
│       ├── keyagent.go                # ssh-add adapter, passphrase on stdin
│       └── keyagent_test.go
├── session/
│   ├── manager.go                     # + one-time, subject-bound action tokens
│   └── manager_test.go
├── storage/
│   ├── transaction.go                 # + Move, Removal, Note
│   ├── journal.go                     # + move/remove recovery, CanRollback
│   ├── transaction_test.go
│   └── journal_test.go
├── httpserver/
│   ├── keys.go                        # key vault handlers and KeyService seam
│   ├── keys_test.go
│   ├── security.go                    # + problemDetail helper
│   └── server.go                      # + key vault routes
└── app/run.go                         # + workspace, transactions, key service wiring
web/src/
├── api/client.ts                      # + authenticated read helper
├── keys/
│   ├── api.ts                         # typed key vault client with runtime checks
│   ├── KeysScreen.tsx                 # self-contained Keys screen
│   ├── RevealDialog.tsx               # separated private-key reveal dialog
│   ├── KeysScreen.test.tsx
│   └── RevealDialog.test.tsx
├── App.tsx                            # + Keys navigation target
└── App.test.tsx
README.md                              # + key vault boundary section
```

---

## Task 1: Pin `golang.org/x/crypto` and build the key material primitives

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/keys/material.go`
- Create: `internal/keys/material_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks in this plan.
- Produces: `keys.Algorithm` with constants `AlgorithmEd25519`, `AlgorithmRSA`, `AlgorithmECDSA`, `AlgorithmEd25519SK`, `AlgorithmECDSASK`.
- Produces: `keys.Material{Container, Encrypted, Algorithm, KeyType, Bits, Fingerprint}`.
- Produces: `keys.PublicKeyInfo{KeyType, Algorithm, Bits, Fingerprint, Comment, IsCertificate, CertificateKeyID, CertificatePrincipals, CertificateValidBefore, SignedKeyType, SignedKeyFingerprint}`.
- Produces: `keys.InspectPrivateKey(contents []byte) (Material, error)`.
- Produces: `keys.InspectPublicKey(line []byte) (PublicKeyInfo, error)`.
- Produces: `keys.GeneratePrivateKey(algorithm Algorithm, bits int, random io.Reader) (crypto.PrivateKey, error)`.
- Produces: `keys.EncodePrivateKey(privateKey crypto.PrivateKey, comment string, passphrase []byte) ([]byte, error)`.
- Produces: `keys.EncodePublicKey(privateKey crypto.PrivateKey, comment string) ([]byte, error)`.
- Produces: `keys.DecodePrivateKey(contents []byte, passphrase []byte) (crypto.PrivateKey, error)`.
- Produces: `keys.Wipe(secret []byte)`.
- Produces: `keys.ErrNotPrivateKey`, `keys.ErrNotPublicKey`, `keys.ErrHardwareAlgorithm`, `keys.ErrUnsupportedAlgorithm`, `keys.ErrUnsupportedBits`, `keys.ErrWrongPassphrase`, `keys.ErrPassphraseRequired`.

- [ ] **Step 1: Write the failing round-trip and inspection tests**

```go
// internal/keys/material_test.go
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
```

The certificate fixture is generated once, in-process, by the test file so the suite never reads a file the developer has to create by hand. Add it to the same file:

```go
// certificateFixture is a self-signed OpenSSH user certificate built at test
// start. Building it in-process keeps the suite independent of any file under
// the developer's real home directory.
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
```

- [ ] **Step 2: Run the test and verify the package and module are absent**

Run: `go test ./internal/keys`

Expected: FAIL — the build reports `no required module provides package golang.org/x/crypto/ssh` and `undefined: GeneratePrivateKey`.

- [ ] **Step 3: Pin the module**

```bash
go get golang.org/x/crypto@v0.54.0
go mod tidy
```

Expected: `go.mod` gains `golang.org/x/crypto v0.54.0` as a direct requirement and `golang.org/x/sys v0.47.0 // indirect`; `go.sum` gains their hashes. No other direct requirement changes.

- [ ] **Step 4: Implement the material primitives**

```go
// internal/keys/material.go
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
```

- [ ] **Step 5: Run the material tests**

Run: `go test ./internal/keys -v`

Expected: PASS for all five test functions, including both encrypted and unencrypted round trips for Ed25519, RSA-2048 and ECDSA.

- [ ] **Step 6: Prove no other direct dependency was added**

Run:

```bash
go mod tidy
git diff go.mod
go test ./... 
```

Expected: `go.mod` shows exactly two added lines, `golang.org/x/crypto v0.54.0` and `golang.org/x/sys v0.47.0 // indirect`; all existing packages still pass.

- [ ] **Step 7: Commit the pinned dependency and the primitives**

```bash
git add go.mod go.sum internal/keys/material.go internal/keys/material_test.go
git commit -m "feat: add verified OpenSSH key material primitives"
```

## Task 2: Classify the workspace and attach the Hosts that reference each file

**Files:**
- Create: `internal/keys/inventory.go`
- Create: `internal/keys/references.go`
- Create: `internal/keys/inventory_test.go`
- Create: `internal/keys/references_test.go`

**Interfaces:**
- Consumes: Task 1's `InspectPrivateKey`, `InspectPublicKey`, `Algorithm`, `Material`, `PublicKeyInfo`.
- Consumes: committed `storage.NewWorkspace`, `(*storage.Workspace).Root/Home/StateDir/FileSystem/Contains`, `storage.OSFileSystem`.
- Consumes: committed `config.Parse`, `config.EqualKeyword`, `config.LineDirective`, `(*config.File).BlockAt/Condition`, `config.Graph`, `config.Resolver`.
- Produces: `keys.Kind` with constants `KindPrivateKey`, `KindPublicKey`, `KindCertificate`, `KindKnownHosts`, `KindConfig`, `KindOther`.
- Produces: `keys.Item`, `keys.CertificateInfo`, `keys.UnreadableFile`, `keys.Inventory`.
- Produces: `keys.ItemID(relativePath string) string`.
- Produces: `keys.NewScanner(workspace *storage.Workspace) *Scanner` and `(*Scanner).Scan() (*Inventory, error)`.
- Produces: `(*Inventory).Find(id string) (*Item, bool)` and `(*Inventory).Group(item *Item) []Item`.
- Produces: `keys.Reference`, `keys.UnresolvedReference`, `keys.ReferenceIndex`.
- Produces: `keys.BuildReferenceIndex(graph *config.Graph, workspace *storage.Workspace) *ReferenceIndex`.
- Produces: `(*ReferenceIndex).For(relativePath string) []Reference`, `.AgentDelegations() []Reference`, `.Unresolved() []UnresolvedReference`.
- Produces: `(*Inventory).AttachReferences(index *ReferenceIndex)`.

- [ ] **Step 1: Write the failing classification test**

```go
// internal/keys/inventory_test.go
package keys

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/storage"
)

// newTestWorkspace builds an isolated ~/.ssh under t.TempDir(). No test in this
// package ever touches the developer's real home directory.
//
// The temporary directory is resolved with EvalSymlinks first because macOS
// puts t.TempDir() under /var, which is a symbolic link to /private/var.
// Workspace resolves its root the same way, so an unresolved home would make
// Workspace.Home() and Workspace.Root() disagree and every '~' expansion would
// look like a path outside the workspace.
func newTestWorkspace(t *testing.T) *storage.Workspace {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary home: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("create ssh directory fixture: %v", err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatalf("new workspace: %v", err)
	}
	return workspace
}

func writeFixture(t *testing.T, workspace *storage.Workspace, relativePath string, contents []byte, permission os.FileMode) {
	t.Helper()
	absolute := filepath.Join(workspace.Root(), relativePath)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatalf("create fixture directory for %s: %v", relativePath, err)
	}
	if err := os.WriteFile(absolute, contents, permission); err != nil {
		t.Fatalf("write fixture %s: %v", relativePath, err)
	}
}

func newKeyPairFixture(t *testing.T, passphrase string) (privateKey []byte, publicKey []byte, fingerprint string) {
	t.Helper()
	generated, err := GeneratePrivateKey(AlgorithmEd25519, 0, rand.Reader)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	privateKey, err = EncodePrivateKey(generated, "fixture@test", []byte(passphrase))
	if err != nil {
		t.Fatalf("encode fixture private key: %v", err)
	}
	publicKey, err = EncodePublicKey(generated, "fixture@test")
	if err != nil {
		t.Fatalf("encode fixture public key: %v", err)
	}
	info, err := InspectPublicKey(publicKey)
	if err != nil {
		t.Fatalf("inspect fixture public key: %v", err)
	}
	return privateKey, publicKey, info.Fingerprint
}

func TestScanClassifiesByContentNotByFileName(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, publicKey, fingerprint := newKeyPairFixture(t, "correct horse")

	// Deliberately misleading names: the private key is called "notes.txt" and
	// a plain text file is called "id_ed25519".
	writeFixture(t, workspace, "notes.txt", privateKey, 0o600)
	writeFixture(t, workspace, "notes.txt.pub", publicKey, 0o644)
	writeFixture(t, workspace, "id_ed25519", []byte("this is not a key at all\n"), 0o600)
	writeFixture(t, workspace, "config", []byte("Host example\n  HostName example.test\n"), 0o600)
	writeFixture(t, workspace, "known_hosts", []byte("example.test "+string(publicKey)), 0o600)
	writeFixture(t, workspace, "exposed", privateKey, 0o644)
	writeFixture(t, workspace, "sshc/trash/20260805T090000.000-aabbccdd/secret", privateKey, 0o600)
	writeFixture(t, workspace, "sshc/backups/20260805T090000.000-aabbccdd/config", []byte("Host old\n"), 0o600)
	writeFixture(t, workspace, "sshc/journal/20260805T090000.000-aabbccdd.json", []byte("{}\n"), 0o600)

	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	byPath := make(map[string]*Item, len(inventory.Items))
	for index := range inventory.Items {
		byPath[inventory.Items[index].RelativePath] = &inventory.Items[index]
	}

	tests := []struct {
		relativePath   string
		wantKind       Kind
		wantEncrypted  bool
		wantPermission string
	}{
		{"notes.txt", KindPrivateKey, true, "0600"},
		{"notes.txt.pub", KindPublicKey, false, "0644"},
		{"id_ed25519", KindOther, false, "0600"},
		{"config", KindConfig, false, "0600"},
		{"known_hosts", KindKnownHosts, false, "0600"},
		{"exposed", KindPrivateKey, true, "0644"},
	}
	for _, test := range tests {
		t.Run(test.relativePath, func(t *testing.T) {
			item, ok := byPath[test.relativePath]
			if !ok {
				t.Fatalf("%s missing from the inventory", test.relativePath)
			}
			if item.Kind != test.wantKind {
				t.Errorf("Kind = %q, want %q", item.Kind, test.wantKind)
			}
			if item.Encrypted != test.wantEncrypted {
				t.Errorf("Encrypted = %v, want %v", item.Encrypted, test.wantEncrypted)
			}
			if item.Permission != test.wantPermission {
				t.Errorf("Permission = %q, want %q", item.Permission, test.wantPermission)
			}
			if item.ID != ItemID(test.relativePath) {
				t.Errorf("ID = %q, want %q", item.ID, ItemID(test.relativePath))
			}
		})
	}

	if !byPath["exposed"].PermissionRisk {
		t.Errorf("a world-readable private key was not flagged")
	}
	if byPath["notes.txt"].PermissionRisk {
		t.Errorf("a 0600 private key was flagged as risky")
	}
	if byPath["notes.txt"].Fingerprint != fingerprint {
		t.Errorf("Fingerprint = %q, want %q", byPath["notes.txt"].Fingerprint, fingerprint)
	}
	if byPath["notes.txt"].Bits != 256 || byPath["notes.txt"].Algorithm != AlgorithmEd25519 {
		t.Errorf("algorithm detail = %q/%d", byPath["notes.txt"].Algorithm, byPath["notes.txt"].Bits)
	}

	for path := range byPath {
		if strings.HasPrefix(path, StateDirectoryName+string(filepath.Separator)) {
			t.Fatalf("engine state leaked into the inventory: %s", path)
		}
	}
}

func TestScanShowsSymbolicLinksWithoutFollowingThem(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, _, _ := newKeyPairFixture(t, "")
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(outside, privateKey, 0o600); err != nil {
		t.Fatalf("write external key: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace.Root(), "linked")); err != nil {
		t.Fatalf("create symbolic link: %v", err)
	}

	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	var found *Item
	for index := range inventory.Items {
		if inventory.Items[index].RelativePath == "linked" {
			found = &inventory.Items[index]
		}
	}
	if found == nil {
		t.Fatalf("symbolic link was hidden from the inventory")
	}
	if found.Kind != KindOther {
		t.Errorf("Kind = %q, want %q", found.Kind, KindOther)
	}
	if found.Fingerprint != "" {
		t.Errorf("Fingerprint = %q, want empty; the link must not be followed", found.Fingerprint)
	}
	if !hasNote(found.Notes, NoteSymbolicLink) {
		t.Errorf("Notes = %#v, want %q", found.Notes, NoteSymbolicLink)
	}
}

func TestGroupMatchesSiblingsByFingerprintOnly(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, publicKey, _ := newKeyPairFixture(t, "")
	_, strangerPublicKey, _ := newKeyPairFixture(t, "")

	writeFixture(t, workspace, "work", privateKey, 0o600)
	writeFixture(t, workspace, "work.pub", publicKey, 0o644)
	// Same base name, different key: it must not be grouped with "work".
	writeFixture(t, workspace, "work-old.pub", strangerPublicKey, 0o644)

	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	item, ok := inventory.Find(ItemID("work"))
	if !ok {
		t.Fatalf("private key missing from the inventory")
	}
	group := inventory.Group(item)
	if len(group) != 2 {
		t.Fatalf("group = %d members, want 2", len(group))
	}
	names := map[string]bool{group[0].RelativePath: true, group[1].RelativePath: true}
	if !names["work"] || !names["work.pub"] {
		t.Fatalf("group = %#v, want work and work.pub", names)
	}
}

func hasNote(notes []string, wanted string) bool {
	for _, note := range notes {
		if note == wanted {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run the test and verify the scanner is absent**

Run: `go test ./internal/keys -run TestScan -v`

Expected: FAIL with `undefined: NewScanner`, `undefined: ItemID` and `undefined: StateDirectoryName`.

- [ ] **Step 3: Implement the inventory**

```go
// internal/keys/inventory.go
package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"sshc/internal/config"
	"sshc/internal/storage"
)

// Kind classifies a file under ~/.ssh by what it contains, never by its name.
type Kind string

const (
	KindPrivateKey  Kind = "private_key"
	KindPublicKey   Kind = "public_key"
	KindCertificate Kind = "certificate"
	KindKnownHosts  Kind = "known_hosts"
	KindConfig      Kind = "config"
	KindOther       Kind = "other"
)

// Note codes are stable identifiers the UI maps to its own wording.
const (
	NoteSymbolicLink           = "symbolic_link"
	NoteFingerprintUnavailable = "fingerprint_unavailable"
	NoteEmptyFile              = "empty_file"
	NoteNotRegularFile         = "not_regular_file"
	NoteCommentNotPreserved    = "comment_not_preserved"
)

// Unreadable reason codes.
const (
	ReasonFileTooLarge  = "file_too_large"
	ReasonReadFailed    = "read_failed"
	ReasonDepthExceeded = "depth_exceeded"
	ReasonTooManyFiles  = "too_many_files"
)

const (
	// StateDirectoryName is the engine's own directory inside the workspace.
	// Everything below it — backups, trash, journal and history — is engine
	// state, so it never appears in the inventory, is never registered with an
	// agent and is never suggested as an IdentityFile.
	StateDirectoryName = "sshc"

	maxScanDepth   = 8
	maxScanEntries = 4096
)

// CertificateInfo carries the parts of an OpenSSH certificate a user needs to
// decide whether it is still useful.
type CertificateInfo struct {
	KeyID                string
	Principals           []string
	ValidBefore          uint64
	SignedKeyType        string
	SignedKeyFingerprint string
}

// Item is one classified file inside the workspace.
type Item struct {
	ID             string
	RelativePath   string
	Kind           Kind
	Container      string
	Algorithm      Algorithm
	KeyType        string
	Bits           int
	Encrypted      bool
	Fingerprint    string
	Comment        string
	Permission     string
	PermissionRisk bool
	SizeBytes      int64
	Certificate    *CertificateInfo
	References     []Reference
	Notes          []string
}

// UnreadableFile is a file the scanner deliberately refused to interpret.
type UnreadableFile struct {
	RelativePath string
	Reason       string
}

// Inventory is the classified content of the workspace.
type Inventory struct {
	Items                []Item
	Unreadable           []UnreadableFile
	AgentDelegations     []Reference
	UnresolvedReferences []UnresolvedReference
}

// Find returns the item with the given identifier.
func (inventory *Inventory) Find(id string) (*Item, bool) {
	for index := range inventory.Items {
		if inventory.Items[index].ID == id {
			return &inventory.Items[index], true
		}
	}
	return nil, false
}

// Group returns the item together with the public key and certificate files
// that belong to the same key pair.
//
// Membership is decided by fingerprint alone. A file that merely shares a base
// name is never grouped, so a look-alike is never moved to the trash with a key
// it does not belong to. When the fingerprint of an encrypted private key is
// unavailable, the group is the item by itself.
func (inventory *Inventory) Group(item *Item) []Item {
	group := []Item{*item}
	if item.Kind != KindPrivateKey || item.Fingerprint == "" {
		return group
	}
	for _, candidate := range inventory.Items {
		if candidate.ID == item.ID {
			continue
		}
		switch candidate.Kind {
		case KindPublicKey:
			if candidate.Fingerprint == item.Fingerprint {
				group = append(group, candidate)
			}
		case KindCertificate:
			if candidate.Certificate != nil && candidate.Certificate.SignedKeyFingerprint == item.Fingerprint {
				group = append(group, candidate)
			}
		}
	}
	return group
}

// ItemID is the stable, path-free identifier the HTTP API uses for one file.
// It is derived from the workspace-relative path, so it survives a restart, it
// carries no path into a URL, and it cannot address a file that the current
// inventory does not contain.
func ItemID(relativePath string) string {
	sum := sha256.Sum256([]byte(relativePath))
	return hex.EncodeToString(sum[:16])
}

// Scanner walks the workspace through the storage filesystem seam.
type Scanner struct {
	workspace *storage.Workspace
}

func NewScanner(workspace *storage.Workspace) *Scanner {
	return &Scanner{workspace: workspace}
}

// Scan classifies every regular file below the workspace root except the
// engine's own state directory.
func (scanner *Scanner) Scan() (*Inventory, error) {
	inventory := &Inventory{}
	visited := 0
	if err := scanner.walk(inventory, scanner.workspace.Root(), 0, &visited); err != nil {
		return nil, err
	}
	sort.Slice(inventory.Items, func(first, second int) bool {
		return inventory.Items[first].RelativePath < inventory.Items[second].RelativePath
	})
	sort.Slice(inventory.Unreadable, func(first, second int) bool {
		return inventory.Unreadable[first].RelativePath < inventory.Unreadable[second].RelativePath
	})
	return inventory, nil
}

func (scanner *Scanner) walk(inventory *Inventory, directory string, depth int, visited *int) error {
	fileSystem := scanner.workspace.FileSystem()
	entries, err := fileSystem.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		absolute := filepath.Join(directory, entry.Name())
		if absolute == scanner.workspace.StateDir() {
			continue
		}
		relative := scanner.relativePath(absolute)
		if *visited >= maxScanEntries {
			inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonTooManyFiles})
			return nil
		}
		*visited++

		info, statErr := fileSystem.Lstat(absolute)
		if statErr != nil {
			inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonReadFailed})
			continue
		}
		mode := info.Mode()
		switch {
		case mode&fs.ModeSymlink != 0:
			inventory.Items = append(inventory.Items, Item{
				ID:           ItemID(relative),
				RelativePath: relative,
				Kind:         KindOther,
				Permission:   fmt.Sprintf("%04o", mode.Perm()),
				Notes:        []string{NoteSymbolicLink},
			})
		case mode.IsDir():
			if depth+1 > maxScanDepth {
				inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonDepthExceeded})
				continue
			}
			if err := scanner.walk(inventory, absolute, depth+1, visited); err != nil {
				return err
			}
		case mode.IsRegular():
			inventory.Items = append(inventory.Items, scanner.classifyFile(inventory, absolute, relative, info))
		default:
			inventory.Items = append(inventory.Items, Item{
				ID:           ItemID(relative),
				RelativePath: relative,
				Kind:         KindOther,
				Permission:   fmt.Sprintf("%04o", mode.Perm()),
				Notes:        []string{NoteNotRegularFile},
			})
		}
	}
	return nil
}

func (scanner *Scanner) relativePath(absolute string) string {
	relative, err := filepath.Rel(scanner.workspace.Root(), absolute)
	if err != nil {
		return absolute
	}
	return relative
}

func (scanner *Scanner) classifyFile(inventory *Inventory, absolute, relative string, info fs.FileInfo) Item {
	item := Item{
		ID:           ItemID(relative),
		RelativePath: relative,
		Kind:         KindOther,
		Permission:   fmt.Sprintf("%04o", info.Mode().Perm()),
		SizeBytes:    info.Size(),
	}
	contents, err := scanner.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		reason := ReasonReadFailed
		if errors.Is(err, storage.ErrFileTooLarge) {
			reason = ReasonFileTooLarge
		}
		inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: reason})
		return item
	}
	classify(&item, contents)
	if item.Kind == KindPrivateKey && info.Mode().Perm()&0o077 != 0 {
		item.PermissionRisk = true
	}
	return item
}

// classify decides what a file is from its bytes. The order matters: a private
// key is recognised first, then an authorized-keys line, then a known_hosts
// line, then configuration syntax. A known_hosts line would otherwise be
// mistaken for a public key with options.
func classify(item *Item, contents []byte) {
	if len(contents) == 0 {
		item.Notes = append(item.Notes, NoteEmptyFile)
		return
	}
	if material, err := InspectPrivateKey(contents); err == nil {
		item.Kind = KindPrivateKey
		item.Container = material.Container
		item.Encrypted = material.Encrypted
		item.Algorithm = material.Algorithm
		item.KeyType = material.KeyType
		item.Bits = material.Bits
		item.Fingerprint = material.Fingerprint
		if item.Fingerprint == "" {
			item.Notes = append(item.Notes, NoteFingerprintUnavailable)
		}
		return
	}

	line := firstMeaningfulLine(contents)
	if len(line) == 0 {
		return
	}
	fields := strings.Fields(string(line))
	if len(fields) >= 2 && looksLikeKeyType(fields[0]) {
		if info, err := InspectPublicKey(line); err == nil {
			item.Kind = KindPublicKey
			item.Algorithm = info.Algorithm
			item.KeyType = info.KeyType
			item.Bits = info.Bits
			item.Fingerprint = info.Fingerprint
			item.Comment = info.Comment
			if info.IsCertificate {
				item.Kind = KindCertificate
				item.Certificate = &CertificateInfo{
					KeyID:                info.CertificateKeyID,
					Principals:           info.CertificatePrincipals,
					ValidBefore:          info.CertificateValidBefore,
					SignedKeyType:        info.SignedKeyType,
					SignedKeyFingerprint: info.SignedKeyFingerprint,
				}
			}
			return
		}
	}
	if _, _, _, _, _, err := ssh.ParseKnownHosts(line); err == nil {
		item.Kind = KindKnownHosts
		return
	}
	if looksLikeConfiguration(contents) {
		item.Kind = KindConfig
	}
}

func firstMeaningfulLine(contents []byte) []byte {
	for _, raw := range strings.Split(string(contents), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return []byte(trimmed + "\n")
	}
	return nil
}

func looksLikeKeyType(field string) bool {
	prefixes := []string{"ssh-", "ecdsa-sha2-", "rsa-sha2-", "sk-ssh-", "sk-ecdsa-"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return false
}

var configurationKeywords = []string{
	"Host", "Match", "Include", "HostName", "IdentityFile", "ProxyJump", "User", "Port",
}

func looksLikeConfiguration(contents []byte) bool {
	for _, line := range config.Parse(contents).Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		for _, keyword := range configurationKeywords {
			if config.EqualKeyword(line.Keyword, keyword) {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run the classification tests**

Run: `go test ./internal/keys -run "TestScan|TestGroup" -v`

Expected: PASS. The misleadingly named private key is classified as a private key, the misleadingly named text file is classified as other, the state directory contributes nothing, and the symbolic link is listed but not followed.

- [ ] **Step 5: Write the failing reference test**

```go
// internal/keys/references_test.go
package keys

import (
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/storage"
)

func TestBuildReferenceIndexFindsHostsThatNameAKey(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, publicKey, _ := newKeyPairFixture(t, "")
	writeFixture(t, workspace, "work", privateKey, 0o600)
	writeFixture(t, workspace, "work.pub", publicKey, 0o644)
	writeFixture(t, workspace, "work-cert.pub", publicKey, 0o644)
	writeFixture(t, workspace, "config", []byte(""+
		"Host build-*\n"+
		"  IdentityFile ~/.ssh/work\n"+
		"  CertificateFile ~/.ssh/work-cert.pub\n"+
		"\n"+
		"Host agent-only\n"+
		"  IdentityAgent SSH_AUTH_SOCK\n"+
		"\n"+
		"Host unknown-token\n"+
		"  IdentityFile ~/.ssh/%h.key\n"+
		"\n"+
		"Host external\n"+
		"  IdentityFile /etc/ssh/shared\n"), 0o600)

	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	index := BuildReferenceIndex(graph, workspace)

	identityReferences := index.For("work")
	if len(identityReferences) != 1 {
		t.Fatalf("references for work = %#v, want one", identityReferences)
	}
	reference := identityReferences[0]
	if reference.Directive != "IdentityFile" {
		t.Errorf("Directive = %q, want IdentityFile", reference.Directive)
	}
	if reference.Line != 2 {
		t.Errorf("Line = %d, want 2", reference.Line)
	}
	if len(reference.HostPatterns) != 1 || reference.HostPatterns[0] != "build-*" {
		t.Errorf("HostPatterns = %#v, want [build-*]", reference.HostPatterns)
	}
	if reference.Condition != "Host build-*" {
		t.Errorf("Condition = %q, want %q", reference.Condition, "Host build-*")
	}

	if got := index.For("work-cert.pub"); len(got) != 1 || got[0].Directive != "CertificateFile" {
		t.Errorf("certificate references = %#v", got)
	}
	if got := index.AgentDelegations(); len(got) != 1 || got[0].Directive != "IdentityAgent" {
		t.Errorf("agent delegations = %#v", got)
	}

	reasons := make(map[string]string, len(index.Unresolved()))
	for _, unresolved := range index.Unresolved() {
		reasons[unresolved.Value] = unresolved.Reason
	}
	if reasons["~/.ssh/%h.key"] != ReasonUnsupportedToken {
		t.Errorf("token reason = %q, want %q", reasons["~/.ssh/%h.key"], ReasonUnsupportedToken)
	}
	if reasons["/etc/ssh/shared"] != ReasonOutsideWorkspace {
		t.Errorf("external reason = %q, want %q", reasons["/etc/ssh/shared"], ReasonOutsideWorkspace)
	}
}

func TestAttachReferencesNeverPointsAtEngineState(t *testing.T) {
	workspace := newTestWorkspace(t)
	privateKey, _, _ := newKeyPairFixture(t, "")
	writeFixture(t, workspace, "work", privateKey, 0o600)
	writeFixture(t, workspace, "sshc/trash/20260805T090000.000-aabbccdd/work", privateKey, 0o600)
	writeFixture(t, workspace, "config", []byte(""+
		"Host live\n"+
		"  IdentityFile ~/.ssh/work\n"+
		"\n"+
		"Host stale\n"+
		"  IdentityFile ~/.ssh/sshc/trash/20260805T090000.000-aabbccdd/work\n"), 0o600)

	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	inventory, err := NewScanner(workspace).Scan()
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	inventory.AttachReferences(BuildReferenceIndex(graph, workspace))

	item, ok := inventory.Find(ItemID("work"))
	if !ok {
		t.Fatalf("work missing from the inventory")
	}
	if len(item.References) != 1 || item.References[0].HostPatterns[0] != "live" {
		t.Fatalf("references = %#v, want the live Host only", item.References)
	}
	for _, candidate := range inventory.Items {
		if strings.HasPrefix(candidate.RelativePath, StateDirectoryName+string(filepath.Separator)) {
			t.Fatalf("engine state was inventoried: %s", candidate.RelativePath)
		}
	}
}
```

- [ ] **Step 6: Run the reference test and verify the index is absent**

Run: `go test ./internal/keys -run "TestBuildReferenceIndex|TestAttachReferences" -v`

Expected: FAIL with `undefined: BuildReferenceIndex`.

- [ ] **Step 7: Implement the reference index**

```go
// internal/keys/references.go
package keys

import (
	"path/filepath"
	"strings"

	"sshc/internal/config"
	"sshc/internal/storage"
)

// Reference is one configuration directive that names a key file.
type Reference struct {
	Directive    string
	ConfigPath   string
	Line         int
	Condition    string
	HostPatterns []string
	Value        string
}

// UnresolvedReference is a directive whose argument the engine refuses to
// guess at, so the UI can show the real reason instead of an invented answer.
type UnresolvedReference struct {
	Directive  string
	Value      string
	ConfigPath string
	Line       int
	Reason     string
}

// Unresolved reason codes.
const (
	ReasonUnsupportedToken = "unsupported_token"
	ReasonRelativePath     = "relative_path"
	ReasonOutsideWorkspace = "outside_workspace"
)

// referencedDirectives are the client directives that name a key file or an
// agent. Every other directive is ignored by this index.
var referencedDirectives = []string{"IdentityFile", "CertificateFile", "IdentityAgent"}

// ReferenceIndex maps workspace-relative paths to the directives naming them.
type ReferenceIndex struct {
	byRelativePath map[string][]Reference
	agent          []Reference
	unresolved     []UnresolvedReference
}

func (index *ReferenceIndex) For(relativePath string) []Reference {
	return index.byRelativePath[relativePath]
}

func (index *ReferenceIndex) AgentDelegations() []Reference { return index.agent }

func (index *ReferenceIndex) Unresolved() []UnresolvedReference { return index.unresolved }

// BuildReferenceIndex walks every file the Include graph reached and records
// which Hosts name which key file.
func BuildReferenceIndex(graph *config.Graph, workspace *storage.Workspace) *ReferenceIndex {
	index := &ReferenceIndex{byRelativePath: make(map[string][]Reference)}
	for _, path := range graph.Order {
		node := graph.Nodes[path]
		if node == nil || node.File == nil {
			continue
		}
		for lineIndex, line := range node.File.Lines {
			if line.Kind != config.LineDirective {
				continue
			}
			directive, matched := matchDirective(line.Keyword)
			if !matched {
				continue
			}
			block := node.File.BlockAt(lineIndex)
			condition := node.File.Condition(block)
			patterns := make([]string, 0, len(block.Patterns))
			for _, pattern := range block.Patterns {
				patterns = append(patterns, pattern.Raw)
			}
			for _, value := range line.Values() {
				index.record(workspace, directive, value, path, lineIndex+1, condition, patterns)
			}
		}
	}
	return index
}

func matchDirective(keyword string) (string, bool) {
	for _, directive := range referencedDirectives {
		if config.EqualKeyword(keyword, directive) {
			return directive, true
		}
	}
	return "", false
}

func (index *ReferenceIndex) record(
	workspace *storage.Workspace,
	directive, value, configPath string,
	line int,
	condition string,
	patterns []string,
) {
	reference := Reference{
		Directive:    directive,
		ConfigPath:   configPath,
		Line:         line,
		Condition:    condition,
		HostPatterns: patterns,
		Value:        value,
	}
	if directive == "IdentityAgent" {
		index.agent = append(index.agent, reference)
		if value == "none" || value == "SSH_AUTH_SOCK" {
			return
		}
	}

	absolute, reason := expandKeyPath(value, workspace.Home())
	if reason != "" {
		index.unresolved = append(index.unresolved, UnresolvedReference{
			Directive: directive, Value: value, ConfigPath: configPath, Line: line, Reason: reason,
		})
		return
	}
	if !workspace.Contains(absolute) {
		index.unresolved = append(index.unresolved, UnresolvedReference{
			Directive: directive, Value: value, ConfigPath: configPath, Line: line, Reason: ReasonOutsideWorkspace,
		})
		return
	}
	relative, err := filepath.Rel(workspace.Root(), absolute)
	if err != nil {
		index.unresolved = append(index.unresolved, UnresolvedReference{
			Directive: directive, Value: value, ConfigPath: configPath, Line: line, Reason: ReasonOutsideWorkspace,
		})
		return
	}
	index.byRelativePath[relative] = append(index.byRelativePath[relative], reference)
}

// expandKeyPath resolves an IdentityFile style argument to an absolute path.
//
// Only '%d' and a leading '~/' are expanded, because they are the only forms
// whose meaning is fixed before a destination host is chosen. A relative path
// is reported rather than guessed at, because OpenSSH resolves it against the
// working directory of the ssh process, which this application cannot know.
func expandKeyPath(value, home string) (absolute string, reason string) {
	if value == "" {
		return "", ReasonUnsupportedToken
	}
	expanded := value
	if strings.ContainsRune(expanded, '%') {
		var builder strings.Builder
		for index := 0; index < len(expanded); index++ {
			if expanded[index] != '%' {
				builder.WriteByte(expanded[index])
				continue
			}
			index++
			if index >= len(expanded) {
				return "", ReasonUnsupportedToken
			}
			switch expanded[index] {
			case '%':
				builder.WriteByte('%')
			case 'd':
				builder.WriteString(home)
			default:
				return "", ReasonUnsupportedToken
			}
		}
		expanded = builder.String()
	}
	switch {
	case expanded == "~":
		expanded = home
	case strings.HasPrefix(expanded, "~/"):
		expanded = filepath.Join(home, expanded[2:])
	case strings.HasPrefix(expanded, "~"):
		return "", ReasonUnsupportedToken
	case !filepath.IsAbs(expanded):
		return "", ReasonRelativePath
	}
	return filepath.Clean(expanded), ""
}

// AttachReferences copies the Hosts that name each file onto its inventory
// item and records the directives the engine could not resolve.
func (inventory *Inventory) AttachReferences(index *ReferenceIndex) {
	for itemIndex := range inventory.Items {
		item := &inventory.Items[itemIndex]
		item.References = index.For(item.RelativePath)
	}
	inventory.AgentDelegations = index.AgentDelegations()
	inventory.UnresolvedReferences = index.Unresolved()
}
```

- [ ] **Step 8: Run the whole package and the race detector**

Run:

```bash
go test ./internal/keys -v
go test -race ./internal/keys
```

Expected: PASS. References resolve for `~/.ssh/work`, the agent delegation is recorded separately, and both the unsupported token and the external path are reported as unresolved rather than guessed.

- [ ] **Step 9: Commit the inventory**

```bash
git add internal/keys/inventory.go internal/keys/references.go internal/keys/inventory_test.go internal/keys/references_test.go
git commit -m "feat: classify the ssh workspace and index key references"
```

## Task 3: Generate keys and change passphrases in process, and draw the hardware boundary

**Files:**
- Create: `internal/platform/command.go`
- Create: `internal/platform/macos/command.go`
- Create: `internal/platform/macos/command_test.go`
- Create: `internal/keys/catalogue.go`
- Create: `internal/keys/catalogue_test.go`
- Create: `internal/keys/service.go`
- Create: `internal/keys/service_test.go`

**Interfaces:**
- Consumes: Task 1's `GeneratePrivateKey`, `EncodePrivateKey`, `EncodePublicKey`, `DecodePrivateKey`, `InspectPublicKey`, `Wipe` and the error values.
- Consumes: Task 2's `Inventory`, `Item`, `ItemID`, `NewScanner`, `BuildReferenceIndex`, `KindPrivateKey`, `KindPublicKey`, `NoteCommentNotPreserved`.
- Consumes: committed `storage.Manager.Commit`, `storage.Request`, `storage.Change`, `storage.Precondition`, `storage.Digest`, `storage.NewResolver`.
- Produces: `platform.MaxCommandOutput`, `platform.Command{Name, Args, Input}`, `platform.CommandResult{ExitCode, Stdout, Stderr, Truncated}`, `platform.CommandExecutor`.
- Produces: `macos.NewExecutor(lookup func(string) (string, bool)) Executor`, `macos.OSLookup`.
- Produces: `keys.Variant{Algorithm, Bits, Label, InProcess, Reason}`, `keys.Catalogue{Variants, Source, Diagnostic}`, `keys.CatalogueReader{Executor, Timeout}` and `(CatalogueReader).Read(ctx context.Context) Catalogue`.
- Produces: `keys.Service`, `keys.ServiceOptions{Workspace, Transactions, Resolver, Catalogue, Now, Random}`, `keys.NewService(options ServiceOptions) *Service`.
- Produces: `(*Service).Inventory() (*Inventory, error)`, `.Algorithms(ctx context.Context) Catalogue`, `.Generate(request GenerateRequest) (GenerateResult, error)`, `.ChangePassphrase(change PassphraseChange) (PassphraseResult, error)`, `.HardwareCommand(algorithm Algorithm, fileName, comment string) ([]string, error)`.
- Produces: `keys.GenerateRequest`, `keys.GenerateResult`, `keys.PassphraseChange`, `keys.PassphraseResult`.
- Produces: `keys.ValidateFileName(name string) error`, `keys.ValidateComment(comment string) error`.
- Produces: `keys.ErrUnknownKey`, `keys.ErrInvalidFileName`, `keys.ErrInvalidComment`, `keys.ErrConflictingPassphraseChoice`.
- Produces (test helpers reused by later tasks in this package): `newTestService`, `steppingClock`, `fakeExecutor`.

- [ ] **Step 1: Write the failing executor test**

```go
// internal/platform/macos/command_test.go
package macos

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"sshc/internal/platform"
)

// These tests run /bin/cat and /usr/bin/false. Neither touches ~/.ssh, the
// Keychain, an ssh-agent, Terminal or a remote host; they exist only to prove
// the adapter's own behaviour.
func TestExecutorPassesInputOnStandardInputAndKeepsEnvironmentSmall(t *testing.T) {
	executor := NewExecutor(func(name string) (string, bool) {
		switch name {
		case "PATH":
			return "/usr/bin:/bin", true
		case "SSH_AUTH_SOCK":
			return "/tmp/fake-agent.sock", true
		case "SECRET_TOKEN":
			return "must-not-be-passed", true
		default:
			return "", false
		}
	})

	result, err := executor.Execute(context.Background(), platform.Command{
		Name:  "/bin/cat",
		Input: []byte("correct horse"),
	})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if string(result.Stdout) != "correct horse" {
		t.Errorf("Stdout = %q, want %q", result.Stdout, "correct horse")
	}
	if result.Truncated {
		t.Errorf("Truncated = true, want false")
	}

	joined := strings.Join(executor.environment, "\n")
	if strings.Contains(joined, "SECRET_TOKEN") || strings.Contains(joined, "must-not-be-passed") {
		t.Fatalf("an unrelated environment variable reached the child process")
	}
	if !strings.Contains(joined, "SSH_AUTH_SOCK=/tmp/fake-agent.sock") {
		t.Fatalf("environment = %q, want the agent socket", joined)
	}
}

func TestExecutorReportsExitCodeAsDataAndBoundsOutput(t *testing.T) {
	executor := NewExecutor(func(name string) (string, bool) {
		if name == "PATH" {
			return "/usr/bin:/bin", true
		}
		return "", false
	})

	failure, err := executor.Execute(context.Background(), platform.Command{Name: "/usr/bin/false"})
	if err != nil {
		t.Fatalf("Execute error = %v, want a nil error with a non-zero exit code", err)
	}
	if failure.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", failure.ExitCode)
	}

	oversized := bytes.Repeat([]byte("x"), platform.MaxCommandOutput+4096)
	bounded, err := executor.Execute(context.Background(), platform.Command{Name: "/bin/cat", Input: oversized})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if len(bounded.Stdout) != platform.MaxCommandOutput {
		t.Errorf("len(Stdout) = %d, want %d", len(bounded.Stdout), platform.MaxCommandOutput)
	}
	if !bounded.Truncated {
		t.Errorf("Truncated = false, want true")
	}

	if _, err := executor.Execute(context.Background(), platform.Command{Name: "/nonexistent/binary"}); err == nil {
		t.Errorf("a missing executable must be reported as a Go error, not as an exit code")
	}
}
```

- [ ] **Step 2: Run the executor test and verify the adapter is absent**

Run: `go test ./internal/platform/macos -run TestExecutor -v`

Expected: FAIL with `undefined: NewExecutor`.

- [ ] **Step 3: Implement the command seam and the macOS adapter**

```go
// internal/platform/command.go
package platform

import "context"

// MaxCommandOutput bounds each captured stream of a child process so a runaway
// command can neither exhaust memory nor fill an HTTP response.
const MaxCommandOutput = 64 << 10

// Command is one shell-free child process invocation.
//
// The application never builds a shell command line, so no argument can be
// re-interpreted as shell syntax. Input is written to the child's standard
// input, and it is the only channel a secret ever travels on: argv and the
// environment are readable by every process of the same user.
type Command struct {
	Name  string
	Args  []string
	Input []byte
}

// CommandResult is the bounded outcome of a finished child process.
//
// A non-zero ExitCode is data rather than a Go error, so a caller can tell a
// rejected passphrase from a missing executable.
type CommandResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool
}

// CommandExecutor runs a child process without a shell. Tests substitute a
// fake; no automated test starts a real ssh, ssh-add or Terminal process.
type CommandExecutor interface {
	Execute(ctx context.Context, command Command) (CommandResult, error)
}
```

```go
// internal/platform/macos/command.go
package macos

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"

	"sshc/internal/platform"
)

// passthroughVariables are the only environment variables a child receives. A
// short list keeps unrelated state, and any secret an ancestor exported, out of
// the child process.
var passthroughVariables = []string{"HOME", "PATH", "SSH_AUTH_SOCK", "LANG"}

// Executor runs child processes with a deliberately small environment.
type Executor struct {
	environment []string
}

// NewExecutor builds an executor from an environment lookup function so tests
// never depend on the developer's real environment.
func NewExecutor(lookup func(string) (string, bool)) Executor {
	environment := make([]string, 0, len(passthroughVariables))
	for _, name := range passthroughVariables {
		if value, ok := lookup(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return Executor{environment: environment}
}

// OSLookup reads the real process environment.
func OSLookup(name string) (string, bool) { return os.LookupEnv(name) }

// Execute runs one command. Standard input is always a reader, even when there
// is no input, so a child can never block waiting for a terminal.
func (executor Executor) Execute(ctx context.Context, command platform.Command) (platform.CommandResult, error) {
	process := exec.CommandContext(ctx, command.Name, command.Args...)
	process.Env = executor.environment
	process.Stdin = bytes.NewReader(command.Input)
	stdout := &boundedBuffer{limit: platform.MaxCommandOutput}
	stderr := &boundedBuffer{limit: platform.MaxCommandOutput}
	process.Stdout = stdout
	process.Stderr = stderr

	runErr := process.Run()
	result := platform.CommandResult{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Truncated: stdout.truncated || stderr.truncated,
	}
	var exitError *exec.ExitError
	switch {
	case runErr == nil:
		return result, nil
	case errors.As(runErr, &exitError):
		result.ExitCode = exitError.ExitCode()
		return result, nil
	default:
		return result, runErr
	}
}

// boundedBuffer stops storing bytes at its limit and remembers that it did, so
// the caller can say the output was cut instead of presenting it as complete.
type boundedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (bounded *boundedBuffer) Write(chunk []byte) (int, error) {
	remaining := bounded.limit - bounded.buffer.Len()
	if remaining <= 0 {
		bounded.truncated = true
		return len(chunk), nil
	}
	if len(chunk) > remaining {
		bounded.truncated = true
		bounded.buffer.Write(chunk[:remaining])
		return len(chunk), nil
	}
	return bounded.buffer.Write(chunk)
}

func (bounded *boundedBuffer) Bytes() []byte { return bounded.buffer.Bytes() }
```

- [ ] **Step 4: Run the executor test**

Run: `go test ./internal/platform/... -v`

Expected: PASS, including the committed browser tests.

- [ ] **Step 5: Write the failing catalogue and hardware-boundary test**

```go
// internal/keys/catalogue_test.go
package keys

import (
	"context"
	"errors"
	"testing"
	"time"

	"sshc/internal/platform"
)

// fakeExecutor records what would have been run and returns a canned result.
// No test in this package starts a real child process.
type fakeExecutor struct {
	commands []platform.Command
	result   platform.CommandResult
	err      error
}

func (fake *fakeExecutor) Execute(_ context.Context, command platform.Command) (platform.CommandResult, error) {
	fake.commands = append(fake.commands, command)
	return fake.result, fake.err
}

const opensshQueryOutput = "ssh-ed25519\n" +
	"ssh-ed25519-cert-v01@openssh.com\n" +
	"sk-ssh-ed25519@openssh.com\n" +
	"ecdsa-sha2-nistp256\n" +
	"ecdsa-sha2-nistp384\n" +
	"ecdsa-sha2-nistp521\n" +
	"sk-ecdsa-sha2-nistp256@openssh.com\n" +
	"ssh-rsa\n"

func TestCatalogueOffersTheVariantsTheInstalledOpenSSHSupports(t *testing.T) {
	executor := &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}}
	catalogue := CatalogueReader{Executor: executor, Timeout: time.Second}.Read(context.Background())

	if catalogue.Source != "ssh -Q key" {
		t.Fatalf("Source = %q, want %q", catalogue.Source, "ssh -Q key")
	}
	if len(executor.commands) != 1 {
		t.Fatalf("commands = %#v, want exactly one", executor.commands)
	}
	command := executor.commands[0]
	wantArgs := []string{"-F", "/dev/null", "-Q", "key"}
	if command.Name != "ssh" || len(command.Args) != len(wantArgs) {
		t.Fatalf("command = %s %v", command.Name, command.Args)
	}
	for index, want := range wantArgs {
		if command.Args[index] != want {
			t.Fatalf("Args[%d] = %q, want %q", index, command.Args[index], want)
		}
	}

	tests := []struct {
		algorithm Algorithm
		bits      int
		inProcess bool
	}{
		{AlgorithmEd25519, 256, true},
		{AlgorithmRSA, 2048, true},
		{AlgorithmRSA, 3072, true},
		{AlgorithmRSA, 4096, true},
		{AlgorithmECDSA, 256, true},
		{AlgorithmECDSA, 384, true},
		{AlgorithmECDSA, 521, true},
		{AlgorithmEd25519SK, 0, false},
		{AlgorithmECDSASK, 256, false},
	}
	if len(catalogue.Variants) != len(tests) {
		t.Fatalf("variants = %#v, want %d", catalogue.Variants, len(tests))
	}
	for index, test := range tests {
		variant := catalogue.Variants[index]
		if variant.Algorithm != test.algorithm || variant.Bits != test.bits {
			t.Errorf("variant[%d] = %s/%d, want %s/%d", index, variant.Algorithm, variant.Bits, test.algorithm, test.bits)
		}
		if variant.InProcess != test.inProcess {
			t.Errorf("variant[%d].InProcess = %v, want %v", index, variant.InProcess, test.inProcess)
		}
		if !variant.InProcess && variant.Reason == "" {
			t.Errorf("variant[%d] has no reason for leaving the process", index)
		}
	}
}

func TestCatalogueFallsBackToEd25519WhenOpenSSHCannotBeQueried(t *testing.T) {
	executor := &fakeExecutor{err: errors.New("exec: \"ssh\": executable file not found in $PATH")}
	catalogue := CatalogueReader{Executor: executor, Timeout: time.Second}.Read(context.Background())

	if catalogue.Source != "fallback" {
		t.Fatalf("Source = %q, want %q", catalogue.Source, "fallback")
	}
	if catalogue.Diagnostic != DiagnosticAlgorithmQueryFailed {
		t.Fatalf("Diagnostic = %q, want %q", catalogue.Diagnostic, DiagnosticAlgorithmQueryFailed)
	}
	if len(catalogue.Variants) != 1 || catalogue.Variants[0].Algorithm != AlgorithmEd25519 {
		t.Fatalf("variants = %#v, want Ed25519 only", catalogue.Variants)
	}
}

func TestHardwareCommandProducesAnUnambiguousArgumentList(t *testing.T) {
	command, err := HardwareCommand(AlgorithmEd25519SK, "id_yubikey", "aida@laptop", "/Users/example/.ssh")
	if err != nil {
		t.Fatalf("HardwareCommand error = %v", err)
	}
	want := []string{"ssh-keygen", "-t", "ed25519-sk", "-C", "aida@laptop", "-f", "/Users/example/.ssh/id_yubikey"}
	if len(command) != len(want) {
		t.Fatalf("command = %#v, want %#v", command, want)
	}
	for index := range want {
		if command[index] != want[index] {
			t.Fatalf("command[%d] = %q, want %q", index, command[index], want[index])
		}
	}

	rejections := []struct {
		name      string
		algorithm Algorithm
		fileName  string
		comment   string
		wantError error
	}{
		{"software algorithm", AlgorithmEd25519, "id_ed25519", "aida@laptop", ErrUnsupportedAlgorithm},
		{"traversal in name", AlgorithmEd25519SK, "../escape", "aida@laptop", ErrInvalidFileName},
		{"option injection in name", AlgorithmEd25519SK, "-oProxyCommand=id", "aida@laptop", ErrInvalidFileName},
		{"shell metacharacter in comment", AlgorithmECDSASK, "id_yubikey", "aida; rm -rf /", ErrInvalidComment},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			if _, err := HardwareCommand(test.algorithm, test.fileName, test.comment, "/Users/example/.ssh"); !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
}
```

- [ ] **Step 6: Run the catalogue test and verify it is absent**

Run: `go test ./internal/keys -run "TestCatalogue|TestHardwareCommand" -v`

Expected: FAIL with `undefined: CatalogueReader` and `undefined: HardwareCommand`.

- [ ] **Step 7: Implement the catalogue and the hardware boundary**

```go
// internal/keys/catalogue.go
package keys

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"sshc/internal/platform"
)

// DiagnosticAlgorithmQueryFailed is reported when the installed OpenSSH could
// not be asked which algorithms it supports.
const DiagnosticAlgorithmQueryFailed = "algorithm_query_failed"

// Reason codes explaining why a variant is not generated inside this process.
const ReasonHardwareToken = "hardware_token_required"

// Variant is one key type the user may ask for.
type Variant struct {
	Algorithm Algorithm
	Bits      int
	Label     string
	InProcess bool
	Reason    string
}

// Catalogue is the set of variants the installed OpenSSH understands.
type Catalogue struct {
	Variants   []Variant
	Source     string
	Diagnostic string
}

// CatalogueReader asks the installed OpenSSH which key algorithms it supports.
//
// It runs `ssh -F /dev/null -Q key`, which prints a static list and exits. That
// invocation reads no configuration file, evaluates no Match block and runs no
// user-supplied directive, so it is not the `ssh -G` evaluation that roadmap
// subsystem 5 owns and that this subsystem must not perform.
type CatalogueReader struct {
	Executor platform.CommandExecutor
	Timeout  time.Duration
}

func (reader CatalogueReader) Read(ctx context.Context) Catalogue {
	timeout := reader.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := reader.Executor.Execute(queryCtx, platform.Command{
		Name: "ssh",
		Args: []string{"-F", "/dev/null", "-Q", "key"},
	})
	if err != nil || result.ExitCode != 0 {
		return Catalogue{
			Variants:   []Variant{{Algorithm: AlgorithmEd25519, Bits: 256, Label: "Ed25519", InProcess: true}},
			Source:     "fallback",
			Diagnostic: DiagnosticAlgorithmQueryFailed,
		}
	}

	supported := make(map[string]bool)
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			supported[trimmed] = true
		}
	}

	catalogue := Catalogue{Source: "ssh -Q key"}
	if supported["ssh-ed25519"] {
		catalogue.Variants = append(catalogue.Variants, Variant{Algorithm: AlgorithmEd25519, Bits: 256, Label: "Ed25519", InProcess: true})
	}
	if supported["ssh-rsa"] || supported["rsa-sha2-256"] || supported["rsa-sha2-512"] {
		for _, bits := range []int{2048, 3072, 4096} {
			catalogue.Variants = append(catalogue.Variants, Variant{Algorithm: AlgorithmRSA, Bits: bits, Label: "RSA", InProcess: true})
		}
	}
	for _, curve := range []struct {
		name string
		bits int
	}{{"ecdsa-sha2-nistp256", 256}, {"ecdsa-sha2-nistp384", 384}, {"ecdsa-sha2-nistp521", 521}} {
		if supported[curve.name] {
			catalogue.Variants = append(catalogue.Variants, Variant{Algorithm: AlgorithmECDSA, Bits: curve.bits, Label: "ECDSA", InProcess: true})
		}
	}
	if supported["sk-ssh-ed25519@openssh.com"] {
		catalogue.Variants = append(catalogue.Variants, Variant{
			Algorithm: AlgorithmEd25519SK, Label: "Ed25519 security key", InProcess: false, Reason: ReasonHardwareToken,
		})
	}
	if supported["sk-ecdsa-sha2-nistp256@openssh.com"] {
		catalogue.Variants = append(catalogue.Variants, Variant{
			Algorithm: AlgorithmECDSASK, Bits: 256, Label: "ECDSA security key", InProcess: false, Reason: ReasonHardwareToken,
		})
	}
	return catalogue
}

// HardwareCommand returns the exact argument list a user must run in Terminal
// for a hardware-backed key.
//
// This subsystem never launches Terminal; roadmap subsystem 5 owns that step.
// Every element is checked against a character set that needs no shell quoting,
// so the displayed line is unambiguous, no element can be re-read as an option,
// and nothing here can become AppleScript or shell syntax later.
func HardwareCommand(algorithm Algorithm, fileName, comment, sshDirectory string) ([]string, error) {
	var keyType string
	switch algorithm {
	case AlgorithmEd25519SK:
		keyType = "ed25519-sk"
	case AlgorithmECDSASK:
		keyType = "ecdsa-sk"
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	if err := ValidateFileName(fileName); err != nil {
		return nil, err
	}
	if err := ValidateComment(comment); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(sshDirectory) {
		return nil, ErrInvalidFileName
	}

	command := []string{"ssh-keygen", "-t", keyType}
	if comment != "" {
		command = append(command, "-C", comment)
	}
	command = append(command, "-f", filepath.Join(sshDirectory, fileName))
	for _, argument := range command {
		if !safeArgumentPattern.MatchString(argument) {
			return nil, ErrInvalidFileName
		}
	}
	return command, nil
}
```

- [ ] **Step 8: Write the failing generation and passphrase test**

```go
// internal/keys/service_test.go
package keys

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sshc/internal/platform"
	"sshc/internal/storage"
)

// steppingClock advances one second per call so two transactions in one test
// never share an identifier.
func steppingClock(start time.Time) func() time.Time {
	current := start
	return func() time.Time {
		current = current.Add(time.Second)
		return current
	}
}

func newTestService(t *testing.T, executor platform.CommandExecutor) (*Service, *storage.Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	clock := steppingClock(time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC))
	service := NewService(ServiceOptions{
		Workspace:    workspace,
		Transactions: storage.NewManager(workspace, clock, rand.Reader),
		Resolver:     storage.NewResolver(workspace),
		Catalogue:    CatalogueReader{Executor: executor, Timeout: time.Second},
		Now:          clock,
		Random:       rand.Reader,
	})
	return service, workspace
}

func TestGenerateWritesAnEncryptedPairThroughATransaction(t *testing.T) {
	service, workspace := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})

	result, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	})
	if err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if result.RelativePath != "id_work" || result.PublicRelativePath != "id_work.pub" {
		t.Fatalf("result paths = %q / %q", result.RelativePath, result.PublicRelativePath)
	}
	if !result.Encrypted {
		t.Errorf("Encrypted = false, want true")
	}
	if result.TransactionID == "" {
		t.Errorf("TransactionID is empty; the write was not journalled")
	}

	privateContents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work"))
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}
	material, err := InspectPrivateKey(privateContents)
	if err != nil {
		t.Fatalf("InspectPrivateKey error = %v", err)
	}
	if !material.Encrypted {
		t.Fatalf("the generated key on disk is not encrypted")
	}
	if material.Fingerprint != result.Fingerprint {
		t.Errorf("fingerprint on disk = %q, reported = %q", material.Fingerprint, result.Fingerprint)
	}
	if _, err := DecodePrivateKey(privateContents, []byte("correct horse")); err != nil {
		t.Fatalf("the generated key does not open with its own passphrase: %v", err)
	}

	for _, name := range []string{"id_work", "id_work.pub"} {
		info, statErr := os.Lstat(filepath.Join(workspace.Root(), name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s permission = %04o, want 0600", name, info.Mode().Perm())
		}
	}

	history, err := storage.NewManager(workspace, time.Now, rand.Reader).History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	if len(history) != 1 || history[0].Operation != "key.generate" {
		t.Fatalf("history = %#v, want one key.generate record", history)
	}
}

func TestGenerateRefusesUnsafeAndAmbiguousRequests(t *testing.T) {
	service, workspace := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})
	if err := os.WriteFile(filepath.Join(workspace.Root(), "taken"), []byte("existing\n"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	tests := []struct {
		name      string
		request   GenerateRequest
		wantError error
	}{
		{
			name:      "empty passphrase without acknowledgement",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "id_a", Comment: "aida@laptop"},
			wantError: ErrPassphraseRequired,
		},
		{
			name:      "passphrase together with the unencrypted flag",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "id_b", Comment: "aida@laptop", Passphrase: []byte("x"), Unencrypted: true},
			wantError: ErrConflictingPassphraseChoice,
		},
		{
			name:      "path traversal in the file name",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "../escape", Comment: "aida@laptop", Passphrase: []byte("x")},
			wantError: ErrInvalidFileName,
		},
		{
			name:      "hardware algorithm",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519SK, FileName: "id_c", Comment: "aida@laptop", Passphrase: []byte("x")},
			wantError: ErrHardwareAlgorithm,
		},
		{
			name:      "existing file",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "taken", Comment: "aida@laptop", Passphrase: []byte("x")},
			wantError: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Generate(test.request)
			if err == nil {
				t.Fatalf("Generate accepted %s", test.name)
			}
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}

	entries, err := os.ReadDir(workspace.Root())
	if err != nil {
		t.Fatalf("read workspace: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "taken" && entry.Name() != StateDirectoryName {
			t.Fatalf("a rejected request created %s", entry.Name())
		}
	}
}

func TestGenerateAcceptsAnExplicitlyUnencryptedKey(t *testing.T) {
	service, workspace := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})

	result, err := service.Generate(GenerateRequest{
		Algorithm:   AlgorithmEd25519,
		FileName:    "id_automation",
		Comment:     "automation@laptop",
		Unencrypted: true,
	})
	if err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if result.Encrypted {
		t.Fatalf("Encrypted = true, want false")
	}
	contents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_automation"))
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}
	if _, err := DecodePrivateKey(contents, nil); err != nil {
		t.Fatalf("the unencrypted key does not parse without a passphrase: %v", err)
	}
}

func TestChangePassphraseRewritesTheKeyAndKeepsItsComment(t *testing.T) {
	service, workspace := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("first passphrase"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}

	if _, err := service.ChangePassphrase(PassphraseChange{
		KeyID:   ItemID("id_work"),
		Current: []byte("wrong"),
		New:     []byte("second passphrase"),
	}); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong current passphrase error = %v, want ErrWrongPassphrase", err)
	}

	result, err := service.ChangePassphrase(PassphraseChange{
		KeyID:   ItemID("id_work"),
		Current: []byte("first passphrase"),
		New:     []byte("second passphrase"),
	})
	if err != nil {
		t.Fatalf("ChangePassphrase error = %v", err)
	}
	if !result.Encrypted {
		t.Errorf("Encrypted = false, want true")
	}

	contents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if _, err := DecodePrivateKey(contents, []byte("second passphrase")); err != nil {
		t.Fatalf("the key does not open with the new passphrase: %v", err)
	}
	if _, err := DecodePrivateKey(contents, []byte("first passphrase")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("the old passphrase still opens the key: %v", err)
	}

	publicContents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work.pub"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	info, err := InspectPublicKey(publicContents)
	if err != nil {
		t.Fatalf("InspectPublicKey error = %v", err)
	}
	if info.Comment != "aida@laptop" {
		t.Fatalf("public key comment = %q, want %q", info.Comment, "aida@laptop")
	}
	for _, note := range result.Notes {
		if note == NoteCommentNotPreserved {
			t.Fatalf("the comment was reported as lost even though a matching public key exists")
		}
	}
}

func TestAlgorithmsAreReadThroughTheCommandSeam(t *testing.T) {
	executor := &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}}
	service, _ := newTestService(t, executor)

	catalogue := service.Algorithms(context.Background())
	if catalogue.Source != "ssh -Q key" {
		t.Fatalf("Source = %q", catalogue.Source)
	}
	if len(executor.commands) != 1 {
		t.Fatalf("commands = %#v, want one", executor.commands)
	}
	for _, argument := range executor.commands[0].Args {
		if argument == "-G" {
			t.Fatalf("the catalogue must never run an effective-configuration evaluation")
		}
	}
}
```

- [ ] **Step 9: Run the service test and verify the service is absent**

Run: `go test ./internal/keys -run "TestGenerate|TestChangePassphrase|TestAlgorithms" -v`

Expected: FAIL with `undefined: NewService`.

- [ ] **Step 10: Implement the service, generation and passphrase change**

```go
// internal/keys/service.go
package keys

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sshc/internal/config"
	"sshc/internal/storage"
)

var (
	ErrUnknownKey                  = errors.New("no key with that identifier is in the inventory")
	ErrInvalidFileName             = errors.New("file name is not a safe single path segment")
	ErrInvalidComment              = errors.New("comment contains characters this application will not put in a command line")
	ErrConflictingPassphraseChoice = errors.New("a passphrase was supplied together with the unencrypted flag")
)

// fileNamePattern accepts one safe path segment. A leading dot, a slash and a
// '..' segment are all impossible under this pattern, so a request cannot name
// a file outside ~/.ssh even before Workspace.ResolveForWrite sees it.
var fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// commentPattern accepts only characters that need no shell quoting, because a
// comment is shown inside a copyable ssh-keygen command line.
var commentPattern = regexp.MustCompile(`^[A-Za-z0-9@._+=:,/-]{0,127}$`)

// safeArgumentPattern is the final check applied to every element of a command
// line this application displays.
var safeArgumentPattern = regexp.MustCompile(`^[A-Za-z0-9@%_+=:,./-]+$`)

// ValidateFileName rejects anything that is not a safe single path segment.
func ValidateFileName(name string) error {
	if !fileNamePattern.MatchString(name) {
		return ErrInvalidFileName
	}
	if strings.HasSuffix(name, ".pub") || name == StateDirectoryName {
		return ErrInvalidFileName
	}
	return nil
}

// ValidateComment rejects a comment this application would have to quote.
func ValidateComment(comment string) error {
	if !commentPattern.MatchString(comment) {
		return ErrInvalidComment
	}
	return nil
}

// Service is the key vault use-case layer. It owns no HTTP and no UI concern,
// reads only through the storage filesystem seam, and writes only through the
// journalled transaction manager.
type Service struct {
	workspace    *storage.Workspace
	transactions *storage.Manager
	resolver     config.Resolver
	catalogue    CatalogueReader
	now          func() time.Time
	random       io.Reader
}

type ServiceOptions struct {
	Workspace    *storage.Workspace
	Transactions *storage.Manager
	Resolver     config.Resolver
	Catalogue    CatalogueReader
	Now          func() time.Time
	Random       io.Reader
}

func NewService(options ServiceOptions) *Service {
	return &Service{
		workspace:    options.Workspace,
		transactions: options.Transactions,
		resolver:     options.Resolver,
		catalogue:    options.Catalogue,
		now:          options.Now,
		random:       options.Random,
	}
}

// entryPath is the user configuration file the Include graph starts from.
func (service *Service) entryPath() string {
	return filepath.Join(service.workspace.Root(), "config")
}

func (service *Service) absolutePath(relativePath string) string {
	return filepath.Join(service.workspace.Root(), relativePath)
}

// Inventory classifies the workspace and attaches the Hosts that name each file.
func (service *Service) Inventory() (*Inventory, error) {
	inventory, err := NewScanner(service.workspace).Scan()
	if err != nil {
		return nil, err
	}
	graph, err := service.resolver.Resolve(service.entryPath())
	if err != nil {
		return inventory, nil
	}
	inventory.AttachReferences(BuildReferenceIndex(graph, service.workspace))
	return inventory, nil
}

// Algorithms reports the variants the installed OpenSSH supports.
func (service *Service) Algorithms(ctx context.Context) Catalogue {
	return service.catalogue.Read(ctx)
}

// HardwareCommand returns the ssh-keygen argument list for a hardware method.
func (service *Service) HardwareCommand(algorithm Algorithm, fileName, comment string) ([]string, error) {
	return HardwareCommand(algorithm, fileName, comment, service.workspace.Root())
}

// GenerateRequest is one in-process key generation.
//
// Unencrypted must be set explicitly for an empty passphrase, so an accidentally
// blank field can never silently produce an unprotected key.
type GenerateRequest struct {
	Algorithm   Algorithm
	Bits        int
	FileName    string
	Comment     string
	Passphrase  []byte
	Unencrypted bool
}

type GenerateResult struct {
	ID                 string
	RelativePath       string
	PublicRelativePath string
	Fingerprint        string
	KeyType            string
	Bits               int
	Encrypted          bool
	TransactionID      string
}

// Generate creates a software key pair inside this process and commits both
// files in one journalled transaction. The passphrase never reaches argv, the
// environment or another process, and it is overwritten before Generate returns.
func (service *Service) Generate(request GenerateRequest) (GenerateResult, error) {
	defer Wipe(request.Passphrase)

	if err := ValidateFileName(request.FileName); err != nil {
		return GenerateResult{}, err
	}
	if err := ValidateComment(request.Comment); err != nil {
		return GenerateResult{}, err
	}
	if len(request.Passphrase) == 0 && !request.Unencrypted {
		return GenerateResult{}, ErrPassphraseRequired
	}
	if len(request.Passphrase) > 0 && request.Unencrypted {
		return GenerateResult{}, ErrConflictingPassphraseChoice
	}

	privateKey, err := GeneratePrivateKey(request.Algorithm, request.Bits, service.random)
	if err != nil {
		return GenerateResult{}, err
	}
	privateContents, err := EncodePrivateKey(privateKey, request.Comment, request.Passphrase)
	if err != nil {
		return GenerateResult{}, err
	}
	defer Wipe(privateContents)
	publicContents, err := EncodePublicKey(privateKey, request.Comment)
	if err != nil {
		return GenerateResult{}, err
	}
	info, err := InspectPublicKey(publicContents)
	if err != nil {
		return GenerateResult{}, err
	}

	if err := service.workspace.EnsureDirectory(service.workspace.Root()); err != nil {
		return GenerateResult{}, err
	}
	publicName := request.FileName + ".pub"
	result, err := service.transactions.Commit(storage.Request{
		Operation: "key.generate",
		Changes: []storage.Change{
			{Path: service.absolutePath(request.FileName), Contents: privateContents},
			{Path: service.absolutePath(publicName), Contents: publicContents},
		},
	})
	if err != nil {
		return GenerateResult{}, err
	}
	return GenerateResult{
		ID:                 ItemID(request.FileName),
		RelativePath:       request.FileName,
		PublicRelativePath: publicName,
		Fingerprint:        info.Fingerprint,
		KeyType:            info.KeyType,
		Bits:               info.Bits,
		Encrypted:          len(request.Passphrase) > 0,
		TransactionID:      result.ID,
	}, nil
}

// PassphraseChange re-encrypts one private key.
type PassphraseChange struct {
	KeyID       string
	Current     []byte
	New         []byte
	Unencrypted bool
}

type PassphraseResult struct {
	ID            string
	RelativePath  string
	Encrypted     bool
	Notes         []string
	TransactionID string
}

// ChangePassphrase decrypts a key with the current passphrase and writes it
// back encrypted with the new one, in one journalled transaction guarded by the
// digest of the file it read.
//
// x/crypto's parser does not expose the comment stored inside an OpenSSH
// private key, so the comment is taken from a public key file whose fingerprint
// matches. When no such file exists the new key carries no comment and the
// result says so through NoteCommentNotPreserved; the engine never invents one.
func (service *Service) ChangePassphrase(change PassphraseChange) (PassphraseResult, error) {
	defer Wipe(change.Current)
	defer Wipe(change.New)

	if len(change.New) == 0 && !change.Unencrypted {
		return PassphraseResult{}, ErrPassphraseRequired
	}
	if len(change.New) > 0 && change.Unencrypted {
		return PassphraseResult{}, ErrConflictingPassphraseChoice
	}

	inventory, err := service.Inventory()
	if err != nil {
		return PassphraseResult{}, err
	}
	item, ok := inventory.Find(change.KeyID)
	if !ok || item.Kind != KindPrivateKey {
		return PassphraseResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	contents, err := service.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		return PassphraseResult{}, err
	}
	defer Wipe(contents)
	precondition := storage.Precondition{Exists: true, Digest: storage.Digest(contents)}

	privateKey, err := DecodePrivateKey(contents, change.Current)
	if err != nil {
		return PassphraseResult{}, err
	}
	comment, notes := commentForKey(inventory, item)
	encoded, err := EncodePrivateKey(privateKey, comment, change.New)
	if err != nil {
		return PassphraseResult{}, err
	}
	defer Wipe(encoded)

	result, err := service.transactions.Commit(storage.Request{
		Operation: "key.passphrase",
		Changes:   []storage.Change{{Path: absolute, Contents: encoded, Precondition: precondition}},
	})
	if err != nil {
		return PassphraseResult{}, err
	}
	return PassphraseResult{
		ID:            item.ID,
		RelativePath:  item.RelativePath,
		Encrypted:     len(change.New) > 0,
		Notes:         notes,
		TransactionID: result.ID,
	}, nil
}

// commentForKey recovers a private key's comment from a public key file with
// the same fingerprint.
func commentForKey(inventory *Inventory, item *Item) (string, []string) {
	if item.Fingerprint != "" {
		for _, candidate := range inventory.Items {
			if candidate.Kind == KindPublicKey && candidate.Fingerprint == item.Fingerprint && candidate.Comment != "" {
				return candidate.Comment, nil
			}
		}
	}
	return "", []string{NoteCommentNotPreserved}
}
```

- [ ] **Step 11: Run the whole package with the race detector**

Run:

```bash
go test ./internal/keys -v
go test -race ./internal/keys ./internal/platform/...
```

Expected: PASS. The generated key is encrypted on disk, opens with its own passphrase, is `0600`, and appears in `Manager.History()` as `key.generate`. Every rejected request leaves the workspace untouched.

- [ ] **Step 12: Commit generation and the hardware boundary**

```bash
git add internal/platform/command.go internal/platform/macos/command.go internal/platform/macos/command_test.go internal/keys/catalogue.go internal/keys/catalogue_test.go internal/keys/service.go internal/keys/service_test.go
git commit -m "feat: generate keys in process and hand hardware methods to Terminal"
```

## Task 4: Journalled moves, removals and content-free audit notes

**Files:**
- Modify: `internal/storage/transaction.go`
- Modify: `internal/storage/journal.go`
- Modify: `internal/storage/transaction_test.go`
- Modify: `internal/storage/journal_test.go`
- Modify: `internal/keys/service.go`
- Modify: `internal/keys/service_test.go`

**Interfaces:**
- Consumes: committed `storage.Manager`, `storage.Request`, `storage.Change`, `storage.Precondition`, `storage.ConflictError`, `storage.Digest`, `storage.Pending`, `storage.Complete`, `storage.Rollback`, `storage.History`, and the test helpers `newTestManager`, `newTestWorkspace`, `writeWorkspaceFile`, `fixedClock`, `faultyFileSystem` already in the storage test files.
- Consumes: Task 3's `keys.Service`, `keys.ErrUnknownKey`, `keys.Wipe`.
- Produces: `storage.Move{From, To, Precondition}` and `storage.Removal{Path, Precondition}`.
- Produces: `storage.Request` fields `Moves []Move` and `Removals []Removal` in addition to `Changes`.
- Produces: `(*storage.Manager).Note(operation string, paths []string) (Result, error)`.
- Produces: `storage.ErrIrreversibleRemoval`, `storage.ErrMoveTargetExists`, `storage.ErrMissingSource`.
- Produces: `storage.PendingEntry` fields `Action string` and `Target string`, and `storage.Pending` field `CanRollback bool`.
- Produces: `keys.RevealResult{ID, RelativePath, Contents, Encrypted, Fingerprint, TransactionID}` and `(*keys.Service).Reveal(keyID string) (RevealResult, error)`.

Why a move rather than a copy plus a delete: the design gives private keys the trash, not the generational backup directory, precisely so key material is never duplicated. A `rename(2)` inside the same filesystem moves the file without writing its bytes anywhere new and without changing its permission bits. A `Change` plus a `Removal` would put a second copy of the key in `~/.ssh/sshc/backups/`, which is the outcome the design set out to avoid.

- [ ] **Step 1: Write the failing move and removal tests**

```go
// internal/storage/transaction_test.go  (append)

func TestCommitMovesAFileWithoutCopyingItsBytes(t *testing.T) {
	manager, workspace := newTestManager(t)
	source := writeWorkspaceFile(t, workspace, "id_work", "PRIVATE KEY BYTES\n", 0o400)
	destinationDirectory := filepath.Join(workspace.StateDir(), "trash", "entry-1")
	if err := workspace.EnsureDirectory(destinationDirectory); err != nil {
		t.Fatalf("EnsureDirectory error = %v", err)
	}
	destination := filepath.Join(destinationDirectory, "id_work")

	result, err := manager.Commit(Request{
		Operation: "key.trash",
		Moves: []Move{{
			From:         source,
			To:           destination,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("PRIVATE KEY BYTES\n"))},
		}},
	})
	if err != nil {
		t.Fatalf("Commit error = %v", err)
	}

	if _, statErr := os.Lstat(source); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("source still exists: %v", statErr)
	}
	moved, err := os.Lstat(destination)
	if err != nil {
		t.Fatalf("destination missing: %v", err)
	}
	if moved.Mode().Perm() != 0o400 {
		t.Errorf("destination permission = %04o, want 0400", moved.Mode().Perm())
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "PRIVATE KEY BYTES\n" {
		t.Fatalf("destination contents = %q, %v", contents, err)
	}

	if entries, readErr := os.ReadDir(result.BackupDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("a move copied bytes into the backup directory: %#v", entries)
	}

	history, err := manager.History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	if len(history) != 1 || history[0].Operation != "key.trash" {
		t.Fatalf("history = %#v", history)
	}
}

func TestCommitRejectsAMoveOntoAnExistingFileOrAChangedSource(t *testing.T) {
	manager, workspace := newTestManager(t)
	source := writeWorkspaceFile(t, workspace, "id_work", "ORIGINAL\n", 0o600)
	occupied := writeWorkspaceFile(t, workspace, "taken", "ALREADY HERE\n", 0o600)

	if _, err := manager.Commit(Request{
		Operation: "key.trash",
		Moves: []Move{{
			From:         source,
			To:           occupied,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("ORIGINAL\n"))},
		}},
	}); !errors.Is(err, ErrMoveTargetExists) {
		t.Fatalf("error = %v, want ErrMoveTargetExists", err)
	}

	_, err := manager.Commit(Request{
		Operation: "key.trash",
		Moves: []Move{{
			From:         source,
			To:           filepath.Join(workspace.Root(), "moved"),
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("SOMETHING ELSE\n"))},
		}},
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want a ConflictError", err)
	}
	if conflict.Current != nil {
		t.Fatalf("a conflict on a move carried file contents, which may be key material")
	}
	if contents, readErr := os.ReadFile(source); readErr != nil || string(contents) != "ORIGINAL\n" {
		t.Fatalf("source changed after a rejected move: %q, %v", contents, readErr)
	}
}

func TestCommitRemovesAFileWithoutWritingABackup(t *testing.T) {
	manager, workspace := newTestManager(t)
	target := writeWorkspaceFile(t, workspace, "sshc/trash/entry-1/id_work", "PRIVATE KEY BYTES\n", 0o600)

	result, err := manager.Commit(Request{
		Operation: "key.purge",
		Removals: []Removal{{
			Path:         target,
			Precondition: Precondition{Exists: true, Digest: Digest([]byte("PRIVATE KEY BYTES\n"))},
		}},
	})
	if err != nil {
		t.Fatalf("Commit error = %v", err)
	}
	if _, statErr := os.Lstat(target); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("removed file still exists: %v", statErr)
	}
	if entries, readErr := os.ReadDir(result.BackupDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("a permanent delete wrote a backup: %#v", entries)
	}
}

func TestNoteRecordsAnAuditFactWithoutFileContents(t *testing.T) {
	manager, workspace := newTestManager(t)
	target := writeWorkspaceFile(t, workspace, "id_work", "PRIVATE KEY BYTES\n", 0o600)

	if _, err := manager.Note("key.reveal", []string{target}); err != nil {
		t.Fatalf("Note error = %v", err)
	}

	history, err := manager.History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	if len(history) != 1 || history[0].Operation != "key.reveal" {
		t.Fatalf("history = %#v", history)
	}
	if len(history[0].Paths) != 1 || history[0].Paths[0] != target {
		t.Fatalf("history paths = %#v", history[0].Paths)
	}
	if contents, readErr := os.ReadFile(target); readErr != nil || string(contents) != "PRIVATE KEY BYTES\n" {
		t.Fatalf("Note changed the file it recorded: %q, %v", contents, readErr)
	}
	if journalEntries, readErr := os.ReadDir(filepath.Join(workspace.StateDir(), "journal")); readErr == nil && len(journalEntries) != 0 {
		t.Fatalf("Note left a pending journal: %#v", journalEntries)
	}

	records, err := os.ReadDir(filepath.Join(workspace.StateDir(), "history"))
	if err != nil {
		t.Fatalf("read history directory: %v", err)
	}
	for _, entry := range records {
		document, readErr := os.ReadFile(filepath.Join(workspace.StateDir(), "history", entry.Name()))
		if readErr != nil {
			t.Fatalf("read history record: %v", readErr)
		}
		if strings.Contains(string(document), "PRIVATE KEY BYTES") {
			t.Fatalf("the audit record contains file contents")
		}
	}
}
```

Add `"io/fs"` to the import block of `internal/storage/journal_test.go`; the other imports these tests need are already there.

```go
// internal/storage/journal_test.go  (append)

func TestRollbackReversesAnInterruptedMove(t *testing.T) {
	workspace := newTestWorkspace(t)
	source := writeWorkspaceFile(t, workspace, "id_work", "PRIVATE KEY BYTES\n", 0o600)
	other := writeWorkspaceFile(t, workspace, "id_spare", "SPARE KEY BYTES\n", 0o600)
	destinationDirectory := filepath.Join(workspace.StateDir(), "trash", "entry-1")
	if err := workspace.EnsureDirectory(destinationDirectory); err != nil {
		t.Fatalf("EnsureDirectory error = %v", err)
	}
	failure := errors.New("injected rename failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "rename" && path == filepath.Join(destinationDirectory, "id_spare") {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))

	_, err := manager.Commit(Request{
		Operation: "key.trash",
		Moves: []Move{
			{From: source, To: filepath.Join(destinationDirectory, "id_work"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("PRIVATE KEY BYTES\n"))}},
			{From: other, To: filepath.Join(destinationDirectory, "id_spare"), Precondition: Precondition{Exists: true, Digest: Digest([]byte("SPARE KEY BYTES\n"))}},
		},
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want the injected failure", err)
	}

	workspace.fileSystem = OSFileSystem{}
	pending, err := manager.Pending()
	if err != nil {
		t.Fatalf("Pending error = %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %#v, want one", pending)
	}
	if !pending[0].CanRollback {
		t.Fatalf("an interrupted move must be reversible")
	}
	if pending[0].Entries[0].Action != "move" {
		t.Fatalf("Action = %q, want move", pending[0].Entries[0].Action)
	}

	if err := manager.Rollback(pending[0].ID); err != nil {
		t.Fatalf("Rollback error = %v", err)
	}
	for path, want := range map[string]string{source: "PRIVATE KEY BYTES\n", other: "SPARE KEY BYTES\n"} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != want {
			t.Fatalf("%s = %q, %v", path, contents, readErr)
		}
	}
}

func TestRollbackRefusesToPretendACommittedRemovalCanBeUndone(t *testing.T) {
	workspace := newTestWorkspace(t)
	first := writeWorkspaceFile(t, workspace, "sshc/trash/entry-1/id_work", "FIRST\n", 0o600)
	second := writeWorkspaceFile(t, workspace, "sshc/trash/entry-1/id_work.pub", "SECOND\n", 0o600)
	failure := errors.New("injected remove failure")
	workspace.fileSystem = faultyFileSystem{
		FileSystem: OSFileSystem{},
		failOn: func(operation, path string) error {
			if operation == "remove" && path == second {
				return failure
			}
			return nil
		},
	}
	manager := NewManager(workspace, fixedClock(), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)))

	if _, err := manager.Commit(Request{
		Operation: "key.purge",
		Removals: []Removal{
			{Path: first, Precondition: Precondition{Exists: true, Digest: Digest([]byte("FIRST\n"))}},
			{Path: second, Precondition: Precondition{Exists: true, Digest: Digest([]byte("SECOND\n"))}},
		},
	}); !errors.Is(err, failure) {
		t.Fatalf("error = %v, want the injected failure", err)
	}

	workspace.fileSystem = OSFileSystem{}
	pending, err := manager.Pending()
	if err != nil {
		t.Fatalf("Pending error = %v", err)
	}
	if len(pending) != 1 || pending[0].CanRollback {
		t.Fatalf("pending = %#v, want one entry that cannot be rolled back", pending)
	}
	if !pending[0].CanComplete {
		t.Fatalf("an interrupted removal must still be completable")
	}
	if err := manager.Rollback(pending[0].ID); !errors.Is(err, ErrIrreversibleRemoval) {
		t.Fatalf("Rollback error = %v, want ErrIrreversibleRemoval", err)
	}
	if err := manager.Complete(pending[0].ID); err != nil {
		t.Fatalf("Complete error = %v", err)
	}
	for _, path := range []string{first, second} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("%s survived completion: %v", path, statErr)
		}
	}
}
```

- [ ] **Step 2: Run the storage tests and verify the primitives are absent**

Run: `go test ./internal/storage -run "TestCommitMoves|TestCommitRejectsAMove|TestCommitRemoves|TestNote|TestRollbackReverses|TestRollbackRefuses" -v`

Expected: FAIL with `undefined: Move`, `undefined: Removal`, `undefined: ErrMoveTargetExists` and `undefined: ErrIrreversibleRemoval`.

- [ ] **Step 3: Extend the transaction model**

Replace the error block, `Change` block and `Request` definition in `internal/storage/transaction.go` with:

```go
const (
	actionWrite  = "write"
	actionMove   = "move"
	actionRemove = "remove"
	actionNote   = "note"
)

var (
	ErrNoChanges           = errors.New("transaction has no changes")
	ErrDuplicatePath       = errors.New("transaction contains the same path twice")
	ErrMoveTargetExists    = errors.New("move target already exists")
	ErrMissingSource       = errors.New("file to move or remove does not exist")
	ErrIrreversibleRemoval = errors.New("a committed removal cannot be rolled back")
)

// Precondition records the state the caller based its new contents on.
type Precondition struct {
	Exists bool
	Digest string
}

// Change is one file the transaction replaces or creates.
type Change struct {
	Path         string
	Contents     []byte
	Precondition Precondition
}

// Move relocates one file with rename(2) inside the workspace.
//
// A move copies no bytes, so a private key is never duplicated into the
// generational backup directory, and rename preserves the file's existing
// permission bits exactly.
type Move struct {
	From         string
	To           string
	Precondition Precondition
}

// Removal deletes one file.
//
// A removal never writes a backup. Its only caller is a permanent delete the
// user has confirmed twice, and copying key material into the backup directory
// would defeat that decision. An interrupted removal can therefore be completed
// but not rolled back, and Rollback says so instead of pretending otherwise.
type Removal struct {
	Path         string
	Precondition Precondition
}

// Request is one logical edit spanning any number of files. Changes are applied
// first, then moves, then removals.
type Request struct {
	Operation string
	Changes   []Change
	Moves     []Move
	Removals  []Removal
}
```

Add the action fields to `journalEntry` and a reader that defaults to `write`, so a journal written by the config engine before this change still loads:

```go
type journalEntry struct {
	Action         string `json:"action,omitempty"`
	Path           string `json:"path"`
	Target         string `json:"target,omitempty"`
	Temp           string `json:"temp,omitempty"`
	Backup         string `json:"backup,omitempty"`
	HadPrevious    bool   `json:"hadPrevious"`
	Mode           uint32 `json:"mode"`
	Digest         string `json:"digest"`
	PreviousDigest string `json:"previousDigest,omitempty"`
}

// action defaults to write so a journal written before moves and removals
// existed still replays correctly.
func (e journalEntry) action() string {
	if e.Action == "" {
		return actionWrite
	}
	return e.Action
}

// zeroBytes overwrites a buffer that may hold key material. Like keys.Wipe it
// is best effort: the Go runtime may already have copied the bytes elsewhere.
func zeroBytes(contents []byte) {
	for index := range contents {
		contents[index] = 0
	}
}
```

- [ ] **Step 4: Plan and commit the three kinds of entry**

Replace `Commit` in `internal/storage/transaction.go` with:

```go
// Commit validates every change, journals the intent, stages all new contents
// durably, then applies the entries one at a time.
//
// Commit does not roll back automatically. A failure leaves a pending journal
// so the user can choose between completing and restoring, which is the only
// honest option when several files are involved.
func (m *Manager) Commit(request Request) (Result, error) {
	if len(request.Changes)+len(request.Moves)+len(request.Removals) == 0 {
		return Result{}, ErrNoChanges
	}
	fileSystem := m.workspace.FileSystem()

	capacity := len(request.Changes) + len(request.Moves) + len(request.Removals)
	entries := make([]journalEntry, 0, capacity)
	stagedContents := make([][]byte, 0, capacity)
	previousContents := make([][]byte, 0, capacity)
	written := make([]string, 0, capacity)
	claimed := make(map[string]bool, capacity)

	claim := func(path string) error {
		if claimed[path] {
			return ErrDuplicatePath
		}
		claimed[path] = true
		return nil
	}

	for _, change := range request.Changes {
		target, err := m.workspace.ResolveForWrite(change.Path)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}

		previous, mode, exists, err := m.currentState(target)
		if err != nil {
			return Result{}, err
		}
		actual := ""
		expected := ""
		if exists {
			actual = Digest(previous)
		}
		if change.Precondition.Exists {
			expected = change.Precondition.Digest
		}
		if actual != expected {
			return Result{}, &ConflictError{Path: target, Expected: expected, Actual: actual, Current: previous}
		}

		entry := journalEntry{
			Action:      actionWrite,
			Path:        target,
			HadPrevious: exists,
			Mode:        uint32(mode),
			Digest:      Digest(change.Contents),
		}
		if exists {
			entry.PreviousDigest = actual
		}
		entries = append(entries, entry)
		stagedContents = append(stagedContents, change.Contents)
		previousContents = append(previousContents, previous)
		written = append(written, target)
	}

	for _, move := range request.Moves {
		source, err := m.workspace.ResolveForWrite(move.From)
		if err != nil {
			return Result{}, err
		}
		target, err := m.workspace.ResolveForWrite(move.To)
		if err != nil {
			return Result{}, err
		}
		if err := claim(source); err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		if _, statErr := fileSystem.Lstat(target); statErr == nil {
			return Result{}, ErrMoveTargetExists
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return Result{}, statErr
		}

		digest, mode, err := m.sourceState(source, move.Precondition)
		if err != nil {
			return Result{}, err
		}
		entries = append(entries, journalEntry{
			Action:         actionMove,
			Path:           source,
			Target:         target,
			HadPrevious:    true,
			Mode:           uint32(mode),
			Digest:         digest,
			PreviousDigest: digest,
		})
		stagedContents = append(stagedContents, nil)
		previousContents = append(previousContents, nil)
		written = append(written, target)
	}

	for _, removal := range request.Removals {
		target, err := m.workspace.ResolveForWrite(removal.Path)
		if err != nil {
			return Result{}, err
		}
		if err := claim(target); err != nil {
			return Result{}, err
		}
		digest, mode, err := m.sourceState(target, removal.Precondition)
		if err != nil {
			return Result{}, err
		}
		entries = append(entries, journalEntry{
			Action:         actionRemove,
			Path:           target,
			HadPrevious:    true,
			Mode:           uint32(mode),
			Digest:         digest,
			PreviousDigest: digest,
		})
		stagedContents = append(stagedContents, nil)
		previousContents = append(previousContents, nil)
		written = append(written, target)
	}

	if m.Validate != nil {
		if err := m.Validate(request); err != nil {
			return Result{}, err
		}
	}

	identifier, err := m.newIdentifier()
	if err != nil {
		return Result{}, err
	}
	journalDirectory := filepath.Join(m.workspace.StateDir(), journalDirectoryName)
	historyDirectory := filepath.Join(m.workspace.StateDir(), historyDirectoryName)
	backupDirectory := filepath.Join(m.workspace.StateDir(), backupDirectoryName, identifier)
	for _, directory := range []string{journalDirectory, historyDirectory, backupDirectory} {
		if err := m.workspace.EnsureDirectory(directory); err != nil {
			return Result{}, err
		}
	}

	record := journalRecord{
		ID:        identifier,
		Version:   journalVersion,
		Operation: request.Operation,
		Status:    statusStaging,
		StartedAt: m.now().UTC(),
		Entries:   entries,
	}
	journalPath := filepath.Join(journalDirectory, identifier+".json")
	if err := m.writeRecord(journalPath, record); err != nil {
		return Result{}, err
	}

	// Only a replacement needs a generational backup. A move keeps the single
	// copy of the file, and a removal is deliberately irreversible.
	for index := range record.Entries {
		entry := &record.Entries[index]
		if entry.action() != actionWrite || !entry.HadPrevious {
			continue
		}
		relative, relErr := filepath.Rel(m.workspace.Root(), entry.Path)
		if relErr != nil {
			return Result{}, relErr
		}
		backupPath := filepath.Join(backupDirectory, relative)
		if err := m.workspace.EnsureDirectory(filepath.Dir(backupPath)); err != nil {
			return Result{}, err
		}
		if err := m.writeFile(backupPath, previousContents[index], fs.FileMode(entry.Mode)); err != nil {
			return Result{}, err
		}
		entry.Backup = backupPath
	}

	// Stage every new file next to its target so a later rename is atomic.
	for index := range record.Entries {
		entry := &record.Entries[index]
		if entry.action() != actionWrite {
			continue
		}
		temporaryPath, tempErr := fileSystem.WriteTemp(
			filepath.Dir(entry.Path),
			temporaryPrefix+identifier+"-",
			fs.FileMode(entry.Mode),
			stagedContents[index],
		)
		if tempErr != nil {
			return Result{}, tempErr
		}
		entry.Temp = temporaryPath
	}
	record.Status = statusStaged
	if err := m.writeRecord(journalPath, record); err != nil {
		return Result{}, err
	}

	if err := m.commitStaged(&record, journalPath); err != nil {
		return Result{}, err
	}
	if err := m.finish(&record, journalPath, statusCompleted); err != nil {
		return Result{}, err
	}
	return Result{ID: identifier, BackupDir: backupDirectory, Written: written}, nil
}

// sourceState hashes a file that is about to be moved or removed and checks the
// caller's precondition.
//
// The bytes are zeroed as soon as the digest exists, because neither a move nor
// a removal ever needs them again and the file may be a private key. The
// returned ConflictError deliberately carries no Current contents for the same
// reason; a three-way diff of key material would be useless and unsafe.
func (m *Manager) sourceState(path string, precondition Precondition) (string, fs.FileMode, error) {
	contents, mode, exists, err := m.currentState(path)
	if err != nil {
		return "", 0, err
	}
	if !exists {
		return "", 0, ErrMissingSource
	}
	digest := Digest(contents)
	zeroBytes(contents)

	expected := ""
	if precondition.Exists {
		expected = precondition.Digest
	}
	if digest != expected {
		return "", 0, &ConflictError{Path: path, Expected: expected, Actual: digest}
	}
	return digest, mode, nil
}
```

Replace `commitStaged` with:

```go
func (m *Manager) commitStaged(record *journalRecord, journalPath string) error {
	fileSystem := m.workspace.FileSystem()
	for index := record.Committed; index < len(record.Entries); index++ {
		entry := record.Entries[index]
		switch entry.action() {
		case actionMove:
			if err := fileSystem.Rename(entry.Path, entry.Target); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Target)); err != nil {
				return err
			}
		case actionRemove:
			if err := fileSystem.Remove(entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
		default:
			if err := fileSystem.Rename(entry.Temp, entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
		}
		record.Committed = index + 1
		record.Entries[index].Temp = ""
		if err := m.writeRecord(journalPath, *record); err != nil {
			return err
		}
	}
	return nil
}
```

Append `Note` to `internal/storage/transaction.go`:

```go
// Note records a completed action that changed no file, such as revealing a
// private key.
//
// A note has no staged content, no backup and no journal file, because there is
// nothing to recover. It exists so history is a complete account of what the
// application did. By construction it can hold no file contents: it stores only
// the operation name, the time and the paths involved.
func (m *Manager) Note(operation string, paths []string) (Result, error) {
	if len(paths) == 0 {
		return Result{}, ErrNoChanges
	}
	entries := make([]journalEntry, 0, len(paths))
	for _, path := range paths {
		resolved, err := m.workspace.ResolveForWrite(path)
		if err != nil {
			return Result{}, err
		}
		entries = append(entries, journalEntry{Action: actionNote, Path: resolved})
	}

	identifier, err := m.newIdentifier()
	if err != nil {
		return Result{}, err
	}
	historyDirectory := filepath.Join(m.workspace.StateDir(), historyDirectoryName)
	if err := m.workspace.EnsureDirectory(historyDirectory); err != nil {
		return Result{}, err
	}
	recorded := m.now().UTC()
	record := journalRecord{
		ID:         identifier,
		Version:    journalVersion,
		Operation:  operation,
		Status:     statusCompleted,
		StartedAt:  recorded,
		FinishedAt: &recorded,
		Committed:  len(entries),
		Entries:    entries,
	}
	if err := m.writeRecord(filepath.Join(historyDirectory, identifier+".json"), record); err != nil {
		return Result{}, err
	}
	return Result{ID: identifier}, nil
}
```

- [ ] **Step 5: Teach recovery about moves and removals**

In `internal/storage/journal.go`, replace `PendingEntry`, `Pending`, `Pending()`, `Complete` and `Rollback` with:

```go
// PendingEntry is one file inside an interrupted transaction.
type PendingEntry struct {
	Path      string
	Target    string
	Action    string
	Committed bool
	HasBackup bool
	HasStaged bool
}

// Pending is an interrupted transaction found at startup. A partial state is
// reported as it is; it is never presented as a healthy result.
type Pending struct {
	ID          string
	Operation   string
	Status      string
	StartedAt   time.Time
	Committed   int
	Entries     []PendingEntry
	CanComplete bool
	CanRollback bool
}

// Pending lists interrupted transactions, oldest first.
func (m *Manager) Pending() ([]Pending, error) {
	records, err := m.readRecords(m.journalDirectory())
	if err != nil {
		return nil, err
	}
	pending := make([]Pending, 0, len(records))
	for _, record := range records {
		item := Pending{
			ID:          record.ID,
			Operation:   record.Operation,
			Status:      record.Status,
			StartedAt:   record.StartedAt,
			Committed:   record.Committed,
			CanComplete: true,
			CanRollback: true,
		}
		for index, entry := range record.Entries {
			pendingEntry := PendingEntry{
				Path:      entry.Path,
				Target:    entry.Target,
				Action:    entry.action(),
				Committed: index < record.Committed,
				HasBackup: entry.Backup != "",
			}
			switch {
			case pendingEntry.Committed && pendingEntry.Action == actionRemove:
				item.CanRollback = false
			case !pendingEntry.Committed && pendingEntry.Action == actionWrite:
				pendingEntry.HasStaged = m.stagedMatches(entry)
				if !pendingEntry.HasStaged {
					item.CanComplete = false
				}
			}
			item.Entries = append(item.Entries, pendingEntry)
		}
		pending = append(pending, item)
	}
	return pending, nil
}

// Complete finishes an interrupted transaction. Only a replacement has staged
// contents to verify; a move and a removal carry their whole intent in the
// journal entry.
func (m *Manager) Complete(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	for index := record.Committed; index < len(record.Entries); index++ {
		if record.Entries[index].action() != actionWrite {
			continue
		}
		if !m.stagedMatches(record.Entries[index]) {
			return ErrCannotComplete
		}
	}
	if err := m.commitStaged(record, journalPath); err != nil {
		return err
	}
	return m.finish(record, journalPath, statusCompleted)
}

// Rollback restores every file the interrupted transaction had already changed
// and discards the staged contents. A transaction that already removed a file
// cannot be rolled back, and Rollback refuses rather than reporting a recovery
// it did not perform.
func (m *Manager) Rollback(identifier string) error {
	record, journalPath, err := m.loadPending(identifier)
	if err != nil {
		return err
	}
	for index := 0; index < record.Committed; index++ {
		if record.Entries[index].action() == actionRemove {
			return ErrIrreversibleRemoval
		}
	}

	fileSystem := m.workspace.FileSystem()
	for index := record.Committed - 1; index >= 0; index-- {
		entry := record.Entries[index]
		if entry.action() == actionMove {
			if err := fileSystem.Rename(entry.Target, entry.Path); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Target)); err != nil {
				return err
			}
			if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
				return err
			}
			continue
		}
		if entry.HadPrevious {
			contents, readErr := fileSystem.ReadFile(entry.Backup)
			if readErr != nil {
				return readErr
			}
			if err := m.writeFile(entry.Path, contents, fs.FileMode(entry.Mode)); err != nil {
				return err
			}
			continue
		}
		if err := fileSystem.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := fileSystem.SyncDir(filepath.Dir(entry.Path)); err != nil {
			return err
		}
	}
	for _, entry := range record.Entries {
		if entry.Temp == "" {
			continue
		}
		if err := fileSystem.Remove(entry.Temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	record.Committed = 0
	return m.finish(record, journalPath, statusRolledBack)
}
```

- [ ] **Step 6: Run the storage suite**

Run:

```bash
go test ./internal/storage -v
go test -race ./internal/storage
```

Expected: PASS, including every test the config engine plan committed. A move preserves `0400`, writes nothing into `BackupDir`, and can be rolled back; a committed removal reports `ErrIrreversibleRemoval` and can still be completed.

- [ ] **Step 7: Write the failing reveal test**

```go
// internal/keys/service_test.go  (append)

func TestRevealReturnsTheKeyAndRecordsAnAuditFact(t *testing.T) {
	service, workspace := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}

	revealed, err := service.Reveal(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Reveal error = %v", err)
	}
	if !revealed.Encrypted {
		t.Errorf("Encrypted = false, want true")
	}
	onDisk, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(revealed.Contents) != string(onDisk) {
		t.Fatalf("Reveal returned different bytes than the file holds")
	}

	if _, err := service.Reveal(ItemID("id_work.pub")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revealing a public key = %v, want ErrUnknownKey", err)
	}
	if _, err := service.Reveal("not-an-identifier"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revealing an unknown identifier = %v, want ErrUnknownKey", err)
	}

	history, err := storage.NewManager(workspace, time.Now, rand.Reader).History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	reveals := 0
	for _, record := range history {
		if record.Operation == "key.reveal" {
			reveals++
		}
	}
	if reveals != 1 {
		t.Fatalf("key.reveal records = %d, want 1", reveals)
	}

	records, err := os.ReadDir(filepath.Join(workspace.StateDir(), "history"))
	if err != nil {
		t.Fatalf("read history directory: %v", err)
	}
	for _, entry := range records {
		document, readErr := os.ReadFile(filepath.Join(workspace.StateDir(), "history", entry.Name()))
		if readErr != nil {
			t.Fatalf("read history record: %v", readErr)
		}
		if strings.Contains(string(document), "OPENSSH PRIVATE KEY") {
			t.Fatalf("an audit record contains key material")
		}
	}
}
```

Add `"strings"` to the `internal/keys/service_test.go` import block.

- [ ] **Step 8: Implement Reveal**

Append to `internal/keys/service.go`:

```go
// RevealResult is the answer to a confirmed private-key reveal.
type RevealResult struct {
	ID            string
	RelativePath  string
	Contents      []byte
	Encrypted     bool
	Fingerprint   string
	TransactionID string
}

// Reveal returns the bytes of one private key.
//
// The audit record is written before the bytes are returned, so a reveal that
// could not be recorded does not happen. The record names the file and the time
// and never contains key material. Reveal deliberately has no other caller: the
// ordinary detail API never returns private key bytes.
func (service *Service) Reveal(keyID string) (RevealResult, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return RevealResult{}, err
	}
	item, ok := inventory.Find(keyID)
	if !ok || item.Kind != KindPrivateKey {
		return RevealResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	contents, err := service.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		return RevealResult{}, err
	}
	result, err := service.transactions.Note("key.reveal", []string{absolute})
	if err != nil {
		Wipe(contents)
		return RevealResult{}, err
	}
	return RevealResult{
		ID:            item.ID,
		RelativePath:  item.RelativePath,
		Contents:      contents,
		Encrypted:     item.Encrypted,
		Fingerprint:   item.Fingerprint,
		TransactionID: result.ID,
	}, nil
}
```

- [ ] **Step 9: Run both packages**

Run:

```bash
go test ./internal/storage ./internal/keys -v
go test -race ./...
```

Expected: PASS everywhere.

- [ ] **Step 10: Commit the transaction primitives and reveal**

```bash
git add internal/storage internal/keys/service.go internal/keys/service_test.go
git commit -m "feat: add journalled moves, removals and audit notes"
```

## Task 5: Soft delete, restore and permanent delete through the trash

**Files:**
- Create: `internal/keys/trash.go`
- Create: `internal/keys/trash_test.go`

**Interfaces:**
- Consumes: Task 4's `storage.Move`, `storage.Removal`, `storage.Request.Moves/Removals`.
- Consumes: Task 3's `keys.Service`, `keys.ErrUnknownKey`, `(*Service).Inventory`, `(*Service).absolutePath`.
- Consumes: Task 2's `Inventory.Find`, `Inventory.Group`, `Item`, `Kind`, `StateDirectoryName`.
- Produces: `keys.TrashRetentionDays` (30).
- Produces: `keys.TrashFile{OriginalRelativePath, TrashRelativePath, Kind, Fingerprint, Permission}`.
- Produces: `keys.TrashEntry{ID, DeletedAt, AgeDays, Stale, Files, Restorable, Blockers}`.
- Produces: `keys.TrashResult{EntryID, Files, Skipped, TransactionID}`, `keys.RestoreResult{EntryID, Restored, Blockers, TransactionID}`, `keys.PurgeResult{EntryID, Removed, TransactionID}`.
- Produces: `(*Service).Trash(keyID string) (TrashResult, error)`, `.ListTrash() ([]TrashEntry, error)`, `.Restore(entryID string) (RestoreResult, error)`, `.Purge(entryID string) (PurgeResult, error)`.
- Produces: `keys.ErrUnknownTrashEntry`, `keys.ErrRestoreBlocked`, `keys.ErrTrashNameConflict`.
- Produces: blocker codes `keys.BlockerPathOccupied`, `keys.BlockerFingerprintPresent`, `keys.BlockerEntryIncomplete`.

- [ ] **Step 1: Write the failing trash lifecycle test**

```go
// internal/keys/trash_test.go
package keys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshc/internal/platform"
)

func newTrashService(t *testing.T) (*Service, string) {
	t.Helper()
	service, workspace := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	return service, workspace.Root()
}

func TestTrashMovesTheWholeKeyPairAndKeepsItsPermissions(t *testing.T) {
	service, root := newTrashService(t)
	if err := os.Chmod(filepath.Join(root, "id_work"), 0o400); err != nil {
		t.Fatalf("tighten permissions: %v", err)
	}

	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("files = %#v, want the private and public key", result.Files)
	}
	for _, name := range []string{"id_work", "id_work.pub"} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s is still in the workspace: %v", name, statErr)
		}
	}

	entryDirectory := filepath.Join(root, StateDirectoryName, "trash", result.EntryID)
	directoryInfo, err := os.Lstat(entryDirectory)
	if err != nil {
		t.Fatalf("trash entry missing: %v", err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Errorf("trash directory permission = %04o, want 0700", directoryInfo.Mode().Perm())
	}
	keyInfo, err := os.Lstat(filepath.Join(entryDirectory, "id_work"))
	if err != nil {
		t.Fatalf("trashed key missing: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o400 {
		t.Errorf("trashed key permission = %04o, want the original 0400", keyInfo.Mode().Perm())
	}

	backups := filepath.Join(root, StateDirectoryName, "backups")
	if err := filepath.WalkDir(backups, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(contents), "OPENSSH PRIVATE KEY") {
			t.Fatalf("key material was copied into the backup directory: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk backups: %v", err)
	}

	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 1 || entries[0].ID != result.EntryID {
		t.Fatalf("entries = %#v", entries)
	}
	if !entries[0].Restorable || len(entries[0].Blockers) != 0 {
		t.Fatalf("entry = %#v, want a restorable entry", entries[0])
	}
	if entries[0].Stale {
		t.Errorf("a key deleted moments ago was marked stale")
	}
}

func TestListTrashShowsAgeAndNeverDeletesAnything(t *testing.T) {
	service, root := newTrashService(t)
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	manifestPath := filepath.Join(root, StateDirectoryName, "trash", result.EntryID, "manifest.json")
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest["deletedAt"] = time.Now().UTC().Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	aged, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, aged, 0o600); err != nil {
		t.Fatalf("write aged manifest: %v", err)
	}

	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].AgeDays < TrashRetentionDays {
		t.Errorf("AgeDays = %d, want at least %d", entries[0].AgeDays, TrashRetentionDays)
	}
	if !entries[0].Stale {
		t.Errorf("Stale = false, want true for a 40-day-old entry")
	}
	if _, statErr := os.Lstat(filepath.Join(root, StateDirectoryName, "trash", result.EntryID, "id_work")); statErr != nil {
		t.Fatalf("listing the trash deleted a key: %v", statErr)
	}
}

func TestRestoreRefusesWhenItWouldHaveToGuess(t *testing.T) {
	service, root := newTrashService(t)
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	// A different file now occupies the original path.
	if err := os.WriteFile(filepath.Join(root, "id_work"), []byte("something else\n"), 0o600); err != nil {
		t.Fatalf("occupy the original path: %v", err)
	}
	restored, err := service.Restore(result.EntryID)
	if !errors.Is(err, ErrRestoreBlocked) {
		t.Fatalf("Restore error = %v, want ErrRestoreBlocked", err)
	}
	if len(restored.Blockers) == 0 || !strings.HasPrefix(restored.Blockers[0], BlockerPathOccupied) {
		t.Fatalf("blockers = %#v, want a path-occupied blocker", restored.Blockers)
	}
	if contents, readErr := os.ReadFile(filepath.Join(root, "id_work")); readErr != nil || string(contents) != "something else\n" {
		t.Fatalf("a blocked restore overwrote the occupying file: %q, %v", contents, readErr)
	}

	if err := os.Remove(filepath.Join(root, "id_work")); err != nil {
		t.Fatalf("clear the original path: %v", err)
	}
	if _, err := service.Restore("../escape"); !errors.Is(err, ErrUnknownTrashEntry) {
		t.Fatalf("traversal identifier = %v, want ErrUnknownTrashEntry", err)
	}

	success, err := service.Restore(result.EntryID)
	if err != nil {
		t.Fatalf("Restore error = %v", err)
	}
	if len(success.Restored) != 2 {
		t.Fatalf("restored = %#v, want two files", success.Restored)
	}
	for _, name := range []string{"id_work", "id_work.pub"} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); statErr != nil {
			t.Fatalf("%s was not restored: %v", name, statErr)
		}
	}
	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %#v, want an empty trash after a restore", entries)
	}
}

func TestRestoreRefusesWhenAnIdenticalKeyIsAlreadyPresent(t *testing.T) {
	service, root := newTrashService(t)
	original, err := os.ReadFile(filepath.Join(root, "id_work"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "id_copy"), original, 0o600); err != nil {
		t.Fatalf("write duplicate key: %v", err)
	}

	restored, err := service.Restore(result.EntryID)
	if !errors.Is(err, ErrRestoreBlocked) {
		t.Fatalf("Restore error = %v, want ErrRestoreBlocked", err)
	}
	found := false
	for _, blocker := range restored.Blockers {
		if strings.HasPrefix(blocker, BlockerFingerprintPresent) {
			found = true
		}
	}
	if !found {
		t.Fatalf("blockers = %#v, want a fingerprint-present blocker", restored.Blockers)
	}
}

func TestPurgeRemovesEveryFileAndCannotBeUndone(t *testing.T) {
	service, root := newTrashService(t)
	result, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	purged, err := service.Purge(result.EntryID)
	if err != nil {
		t.Fatalf("Purge error = %v", err)
	}
	if len(purged.Removed) != 2 {
		t.Fatalf("removed = %#v, want two files", purged.Removed)
	}
	entryDirectory := filepath.Join(root, StateDirectoryName, "trash", result.EntryID)
	for _, name := range []string{"id_work", "id_work.pub", "manifest.json"} {
		if _, statErr := os.Lstat(filepath.Join(entryDirectory, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s survived the purge: %v", name, statErr)
		}
	}
	entries, err := service.ListTrash()
	if err != nil {
		t.Fatalf("ListTrash error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %#v, want an empty trash", entries)
	}
	if _, err := service.Purge(result.EntryID); !errors.Is(err, ErrUnknownTrashEntry) {
		t.Fatalf("second purge = %v, want ErrUnknownTrashEntry", err)
	}
}
```

- [ ] **Step 2: Run the trash tests and verify the feature is absent**

Run: `go test ./internal/keys -run "TestTrash|TestListTrash|TestRestore|TestPurge" -v`

Expected: FAIL with `undefined: (*Service).Trash`.

- [ ] **Step 3: Implement the trash**

```go
// internal/keys/trash.go
package keys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"sshc/internal/storage"
)

const (
	// TrashRetentionDays is the age at which the UI marks a trashed key old.
	// Nothing is ever deleted automatically; this number is presentation only.
	TrashRetentionDays = 30

	trashDirectoryName = "trash"
	manifestFileName   = "manifest.json"
	manifestVersion    = 1
)

var (
	ErrUnknownTrashEntry = errors.New("no trash entry with that identifier")
	ErrRestoreBlocked    = errors.New("restore would overwrite or duplicate an existing key")
	ErrTrashNameConflict = errors.New("two files in one delete share a base name")
)

// Blocker codes are stable identifiers followed by ':' and the path involved.
const (
	BlockerPathOccupied       = "restore_path_occupied"
	BlockerFingerprintPresent = "restore_fingerprint_present"
	BlockerEntryIncomplete    = "restore_entry_incomplete"
)

// trashEntryPattern is the only shape a trash identifier may take. It mirrors
// the transaction identifier format, and it makes '..' and any other traversal
// attempt impossible before a path is ever built.
var trashEntryPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{3}-[0-9a-f]{8}$`)

type manifestFile struct {
	OriginalPath string `json:"originalPath"`
	TrashPath    string `json:"trashPath"`
	Kind         string `json:"kind"`
	Fingerprint  string `json:"fingerprint"`
	Permission   string `json:"permission"`
}

// trashManifest records what one soft delete moved. Paths are workspace
// relative so the entry survives a change of home directory, and no field ever
// holds file contents.
type trashManifest struct {
	SchemaVersion int            `json:"schemaVersion"`
	EntryID       string         `json:"entryId"`
	DeletedAt     string         `json:"deletedAt"`
	Files         []manifestFile `json:"files"`
}

// TrashFile is one file inside a trash entry.
type TrashFile struct {
	OriginalRelativePath string
	TrashRelativePath    string
	Kind                 Kind
	Fingerprint          string
	Permission           string
}

// TrashEntry is one soft-deleted group of files.
type TrashEntry struct {
	ID         string
	DeletedAt  time.Time
	AgeDays    int
	Stale      bool
	Files      []TrashFile
	Restorable bool
	Blockers   []string
}

type TrashResult struct {
	EntryID       string
	Files         []TrashFile
	Skipped       []string
	TransactionID string
}

type RestoreResult struct {
	EntryID       string
	Restored      []string
	Blockers      []string
	TransactionID string
}

type PurgeResult struct {
	EntryID       string
	Removed       []string
	TransactionID string
}

func (service *Service) trashRoot() string {
	return filepath.Join(service.workspace.StateDir(), trashDirectoryName)
}

func (service *Service) newEntryID() (string, error) {
	suffix := make([]byte, 4)
	if _, err := io.ReadFull(service.random, suffix); err != nil {
		return "", err
	}
	return service.now().UTC().Format("20060102T150405.000") + "-" + hex.EncodeToString(suffix), nil
}

// Trash soft-deletes a key by moving it, and the files that belong to the same
// key pair, into ~/.ssh/sshc/trash/<entry>/ in one journalled transaction.
//
// The move is a rename inside the same filesystem, so the bytes are never
// copied and the file keeps the permission bits it already had. The trash entry
// is the recovery point for a key; the generational backup directory is
// deliberately not used, because it would leave a second copy of the key.
func (service *Service) Trash(keyID string) (TrashResult, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return TrashResult{}, err
	}
	item, ok := inventory.Find(keyID)
	if !ok {
		return TrashResult{}, ErrUnknownKey
	}
	group := inventory.Group(item)

	entryID, err := service.newEntryID()
	if err != nil {
		return TrashResult{}, err
	}
	entryRelative := filepath.Join(StateDirectoryName, trashDirectoryName, entryID)
	entryDirectory := filepath.Join(service.workspace.Root(), entryRelative)
	if err := service.workspace.EnsureDirectory(entryDirectory); err != nil {
		return TrashResult{}, err
	}

	manifest := trashManifest{
		SchemaVersion: manifestVersion,
		EntryID:       entryID,
		DeletedAt:     service.now().UTC().Format(time.RFC3339),
	}
	request := storage.Request{Operation: "key.trash"}
	files := make([]TrashFile, 0, len(group))
	usedNames := make(map[string]bool, len(group))

	for _, member := range group {
		baseName := filepath.Base(member.RelativePath)
		if usedNames[baseName] {
			return TrashResult{}, ErrTrashNameConflict
		}
		usedNames[baseName] = true

		absolute := service.absolutePath(member.RelativePath)
		contents, readErr := service.workspace.FileSystem().ReadFile(absolute)
		if readErr != nil {
			return TrashResult{}, readErr
		}
		digest := storage.Digest(contents)
		Wipe(contents)

		trashRelative := filepath.Join(entryRelative, baseName)
		request.Moves = append(request.Moves, storage.Move{
			From:         absolute,
			To:           filepath.Join(service.workspace.Root(), trashRelative),
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		files = append(files, TrashFile{
			OriginalRelativePath: member.RelativePath,
			TrashRelativePath:    trashRelative,
			Kind:                 member.Kind,
			Fingerprint:          member.Fingerprint,
			Permission:           member.Permission,
		})
		manifest.Files = append(manifest.Files, manifestFile{
			OriginalPath: member.RelativePath,
			TrashPath:    trashRelative,
			Kind:         string(member.Kind),
			Fingerprint:  member.Fingerprint,
			Permission:   member.Permission,
		})
	}

	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return TrashResult{}, err
	}
	request.Changes = append(request.Changes, storage.Change{
		Path:     filepath.Join(entryDirectory, manifestFileName),
		Contents: append(document, '\n'),
	})

	result, err := service.transactions.Commit(request)
	if err != nil {
		return TrashResult{}, err
	}
	return TrashResult{
		EntryID:       entryID,
		Files:         files,
		Skipped:       skippedSiblings(inventory, item, group),
		TransactionID: result.ID,
	}, nil
}

// skippedSiblings lists files that look related by name but were left in place
// because their fingerprint could not be compared, which happens for a legacy
// PEM key that is encrypted. Nothing is ever moved on the strength of a name;
// this list exists only so the user is told what stayed behind.
func skippedSiblings(inventory *Inventory, item *Item, group []Item) []string {
	if item.Kind != KindPrivateKey || item.Fingerprint != "" {
		return nil
	}
	moved := make(map[string]bool, len(group))
	for _, member := range group {
		moved[member.RelativePath] = true
	}
	skipped := make([]string, 0)
	for _, candidate := range inventory.Items {
		if moved[candidate.RelativePath] {
			continue
		}
		if candidate.Kind != KindPublicKey && candidate.Kind != KindCertificate {
			continue
		}
		if strings.HasPrefix(candidate.RelativePath, item.RelativePath) {
			skipped = append(skipped, candidate.RelativePath)
		}
	}
	if len(skipped) == 0 {
		return nil
	}
	return skipped
}

// ListTrash returns every trash entry, newest first. It performs no write and
// deletes nothing, however old an entry is.
func (service *Service) ListTrash() ([]TrashEntry, error) {
	directories, err := service.workspace.FileSystem().ReadDir(service.trashRoot())
	if errors.Is(err, fs.ErrNotExist) {
		return []TrashEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	inventory, err := service.Inventory()
	if err != nil {
		return nil, err
	}

	entries := make([]TrashEntry, 0, len(directories))
	for _, directory := range directories {
		if !directory.IsDir() || !trashEntryPattern.MatchString(directory.Name()) {
			continue
		}
		manifest, manifestErr := service.readManifest(directory.Name())
		if manifestErr != nil {
			// A directory without a readable manifest is left-over engine
			// debris, for example from a delete that failed before it wrote
			// anything. It is not presented as a recoverable key.
			continue
		}
		entries = append(entries, service.describeEntry(inventory, manifest))
	}
	sort.Slice(entries, func(first, second int) bool { return entries[first].ID > entries[second].ID })
	return entries, nil
}

func (service *Service) readManifest(entryID string) (trashManifest, error) {
	if !trashEntryPattern.MatchString(entryID) {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	path := filepath.Join(service.trashRoot(), entryID, manifestFileName)
	contents, err := service.workspace.FileSystem().ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	if err != nil {
		return trashManifest{}, err
	}
	var manifest trashManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	if manifest.SchemaVersion != manifestVersion || manifest.EntryID != entryID {
		return trashManifest{}, ErrUnknownTrashEntry
	}
	return manifest, nil
}

func (service *Service) describeEntry(inventory *Inventory, manifest trashManifest) TrashEntry {
	entry := TrashEntry{ID: manifest.EntryID}
	if deletedAt, err := time.Parse(time.RFC3339, manifest.DeletedAt); err == nil {
		entry.DeletedAt = deletedAt
		entry.AgeDays = int(service.now().UTC().Sub(deletedAt).Hours() / 24)
		entry.Stale = entry.AgeDays >= TrashRetentionDays
	}
	for _, file := range manifest.Files {
		entry.Files = append(entry.Files, TrashFile{
			OriginalRelativePath: file.OriginalPath,
			TrashRelativePath:    file.TrashPath,
			Kind:                 Kind(file.Kind),
			Fingerprint:          file.Fingerprint,
			Permission:           file.Permission,
		})
	}
	entry.Blockers = service.restoreBlockers(inventory, manifest)
	entry.Restorable = len(entry.Blockers) == 0
	return entry
}

// restoreBlockers reports every reason a restore would have to guess.
//
// The engine never renames a restored file, never overwrites an existing one
// and never decides which of two identical keys a Host meant. When a blocker is
// present it refuses and shows the reason.
func (service *Service) restoreBlockers(inventory *Inventory, manifest trashManifest) []string {
	fileSystem := service.workspace.FileSystem()
	blockers := make([]string, 0)
	for _, file := range manifest.Files {
		if _, err := fileSystem.Lstat(filepath.Join(service.workspace.Root(), file.TrashPath)); err != nil {
			blockers = append(blockers, BlockerEntryIncomplete+":"+file.OriginalPath)
			continue
		}
		if _, err := fileSystem.Lstat(filepath.Join(service.workspace.Root(), file.OriginalPath)); err == nil {
			blockers = append(blockers, BlockerPathOccupied+":"+file.OriginalPath)
			continue
		}
		if file.Fingerprint == "" || Kind(file.Kind) != KindPrivateKey {
			continue
		}
		for _, candidate := range inventory.Items {
			if candidate.Kind == KindPrivateKey && candidate.Fingerprint == file.Fingerprint {
				blockers = append(blockers, BlockerFingerprintPresent+":"+candidate.RelativePath)
				break
			}
		}
	}
	if len(blockers) == 0 {
		return nil
	}
	return blockers
}

// Restore moves every file of a trash entry back to the path it came from and
// removes the entry's manifest, in one journalled transaction. The empty entry
// directory is left behind, because the transaction manager owns files, not
// directories; ListTrash ignores a directory without a manifest.
func (service *Service) Restore(entryID string) (RestoreResult, error) {
	manifest, err := service.readManifest(entryID)
	if err != nil {
		return RestoreResult{}, err
	}
	inventory, err := service.Inventory()
	if err != nil {
		return RestoreResult{}, err
	}
	if blockers := service.restoreBlockers(inventory, manifest); len(blockers) > 0 {
		return RestoreResult{EntryID: entryID, Blockers: blockers}, ErrRestoreBlocked
	}

	fileSystem := service.workspace.FileSystem()
	request := storage.Request{Operation: "key.restore"}
	restored := make([]string, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		trashAbsolute := filepath.Join(service.workspace.Root(), file.TrashPath)
		originalAbsolute := filepath.Join(service.workspace.Root(), file.OriginalPath)
		if err := service.workspace.EnsureDirectory(filepath.Dir(originalAbsolute)); err != nil {
			return RestoreResult{}, err
		}
		contents, readErr := fileSystem.ReadFile(trashAbsolute)
		if readErr != nil {
			return RestoreResult{}, readErr
		}
		digest := storage.Digest(contents)
		Wipe(contents)
		request.Moves = append(request.Moves, storage.Move{
			From:         trashAbsolute,
			To:           originalAbsolute,
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		restored = append(restored, file.OriginalPath)
	}

	manifestPath := filepath.Join(service.trashRoot(), entryID, manifestFileName)
	manifestContents, err := fileSystem.ReadFile(manifestPath)
	if err != nil {
		return RestoreResult{}, err
	}
	request.Removals = append(request.Removals, storage.Removal{
		Path:         manifestPath,
		Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(manifestContents)},
	})

	result, err := service.transactions.Commit(request)
	if err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{EntryID: entryID, Restored: restored, TransactionID: result.ID}, nil
}

// Purge permanently deletes a trash entry. Nothing is backed up, so the result
// cannot be undone; the HTTP layer requires a second confirmation and its own
// action token before calling it.
func (service *Service) Purge(entryID string) (PurgeResult, error) {
	manifest, err := service.readManifest(entryID)
	if err != nil {
		return PurgeResult{}, err
	}
	fileSystem := service.workspace.FileSystem()
	request := storage.Request{Operation: "key.purge"}
	removed := make([]string, 0, len(manifest.Files))

	for _, file := range manifest.Files {
		absolute := filepath.Join(service.workspace.Root(), file.TrashPath)
		contents, readErr := fileSystem.ReadFile(absolute)
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return PurgeResult{}, readErr
		}
		digest := storage.Digest(contents)
		Wipe(contents)
		request.Removals = append(request.Removals, storage.Removal{
			Path:         absolute,
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		removed = append(removed, file.OriginalPath)
	}

	manifestPath := filepath.Join(service.trashRoot(), entryID, manifestFileName)
	manifestContents, err := fileSystem.ReadFile(manifestPath)
	if err != nil {
		return PurgeResult{}, err
	}
	request.Removals = append(request.Removals, storage.Removal{
		Path:         manifestPath,
		Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(manifestContents)},
	})

	result, err := service.transactions.Commit(request)
	if err != nil {
		return PurgeResult{}, err
	}
	return PurgeResult{EntryID: entryID, Removed: removed, TransactionID: result.ID}, nil
}
```

- [ ] **Step 4: Run the trash tests**

Run:

```bash
go test ./internal/keys -v
go test -race ./internal/keys
```

Expected: PASS. The trashed key keeps `0400`, the trash directory is `0700`, no key material reaches `backups/`, a 40-day-old entry is reported as stale without being deleted, a blocked restore changes nothing, and a purge cannot be repeated.

- [ ] **Step 5: Commit the trash**

```bash
git add internal/keys/trash.go internal/keys/trash_test.go
git commit -m "feat: soft delete, restore and permanently delete keys"
```

## Task 6: Register keys with ssh-agent and the macOS Keychain

**Files:**
- Create: `internal/platform/keyagent.go`
- Create: `internal/platform/macos/keyagent.go`
- Create: `internal/platform/macos/keyagent_test.go`
- Modify: `internal/keys/service.go`
- Modify: `internal/keys/service_test.go`

**Interfaces:**
- Consumes: Task 3's `platform.Command`, `platform.CommandResult`, `platform.CommandExecutor`, `keys.Service`, `keys.ServiceOptions`, `keys.ErrUnknownKey`.
- Consumes: Task 4's `(*storage.Manager).Note`.
- Produces: `platform.AgentIdentity{Bits, Fingerprint, Comment, Algorithm}`.
- Produces: `platform.AgentAddRequest{PrivateKeyPath, Passphrase, LifetimeSeconds, StoreInKeychain}`.
- Produces: `platform.KeyAgent` with `Available(ctx) bool`, `List(ctx) ([]AgentIdentity, error)`, `Add(ctx, AgentAddRequest) error`, `Remove(ctx, publicKeyPath string) error`.
- Produces: `platform.ErrAgentUnavailable`, `platform.ErrAgentRejected`.
- Produces: `macos.NewKeyAgent(executor platform.CommandExecutor, lookup func(string) (string, bool)) KeyAgent`.
- Produces: `keys.ServiceOptions.Agent` and `keys.Service` field `agent`.
- Produces: `keys.RegisterRequest{KeyID, Passphrase, LifetimeSeconds, StoreInKeychain}`, `keys.RegisterResult{ID, RelativePath, Fingerprint, LifetimeSeconds, StoredInKeychain, Identities}`.
- Produces: `(*Service).Register(ctx context.Context, request RegisterRequest) (RegisterResult, error)` and `(*Service).AgentIdentities(ctx context.Context) ([]platform.AgentIdentity, bool)`.

Why `ssh-add` and not the agent protocol: `ssh-add` is the only supported way to reach the macOS Keychain integration, and it reads a passphrase from standard input when one is available, so nothing has to travel through argv, the environment, `SSH_ASKPASS` or a terminal. Both facts were verified against the installed OpenSSH 10.2p1 and its `ssh-add(1)` manual page, which documents `--apple-use-keychain`, before this plan was written.

- [ ] **Step 1: Write the failing agent adapter test**

```go
// internal/platform/macos/keyagent_test.go
package macos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sshc/internal/platform"
)

// recordingExecutor captures the command that would have run. No test in this
// package starts a real ssh-add or touches a real agent or Keychain.
type recordingExecutor struct {
	commands []platform.Command
	results  []platform.CommandResult
	err      error
}

func (recorder *recordingExecutor) Execute(_ context.Context, command platform.Command) (platform.CommandResult, error) {
	recorder.commands = append(recorder.commands, command)
	if recorder.err != nil {
		return platform.CommandResult{}, recorder.err
	}
	if len(recorder.results) == 0 {
		return platform.CommandResult{}, nil
	}
	result := recorder.results[0]
	recorder.results = recorder.results[1:]
	return result, nil
}

func agentLookup(name string) (string, bool) {
	switch name {
	case "SSH_AUTH_SOCK":
		return "/tmp/fake-agent.sock", true
	case "HOME":
		return "/Users/example", true
	default:
		return "", false
	}
}

func TestKeyAgentAddSendsThePassphraseOnlyOnStandardInput(t *testing.T) {
	recorder := &recordingExecutor{results: []platform.CommandResult{{}}}
	agent := NewKeyAgent(recorder, agentLookup)

	err := agent.Add(context.Background(), platform.AgentAddRequest{
		PrivateKeyPath:  "/Users/example/.ssh/id_work",
		Passphrase:      []byte("correct horse"),
		LifetimeSeconds: 3600,
		StoreInKeychain: true,
	})
	if err != nil {
		t.Fatalf("Add error = %v", err)
	}
	if len(recorder.commands) != 1 {
		t.Fatalf("commands = %#v, want one", recorder.commands)
	}
	command := recorder.commands[0]
	if command.Name != "/usr/bin/ssh-add" {
		t.Errorf("Name = %q, want /usr/bin/ssh-add", command.Name)
	}
	want := []string{"-t", "3600", "--apple-use-keychain", "/Users/example/.ssh/id_work"}
	if strings.Join(command.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("Args = %#v, want %#v", command.Args, want)
	}
	for _, argument := range command.Args {
		if strings.Contains(argument, "correct horse") {
			t.Fatalf("the passphrase appeared in an argument")
		}
	}
	if string(command.Input) != "correct horse" {
		t.Fatalf("Input = %q, want the passphrase", command.Input)
	}
}

func TestKeyAgentReportsRejectionWithoutLeakingTheHomePath(t *testing.T) {
	recorder := &recordingExecutor{results: []platform.CommandResult{{
		ExitCode: 1,
		Stderr:   []byte("Bad passphrase, try again for /Users/example/.ssh/id_work: \n"),
	}}}
	agent := NewKeyAgent(recorder, agentLookup)

	err := agent.Add(context.Background(), platform.AgentAddRequest{
		PrivateKeyPath: "/Users/example/.ssh/id_work",
		Passphrase:     []byte("wrong"),
	})
	if !errors.Is(err, platform.ErrAgentRejected) {
		t.Fatalf("error = %v, want ErrAgentRejected", err)
	}
	if strings.Contains(err.Error(), "/Users/example") {
		t.Fatalf("the error carried the absolute home path: %v", err)
	}
	if !strings.Contains(err.Error(), "~/.ssh/id_work") {
		t.Fatalf("the error lost the useful part of the message: %v", err)
	}
}

func TestKeyAgentListParsesIdentitiesAndAnEmptyAgent(t *testing.T) {
	recorder := &recordingExecutor{results: []platform.CommandResult{{
		Stdout: []byte("256 SHA256:abcdef aida@laptop (ED25519)\n2048 SHA256:012345 work key (RSA)\n"),
	}}}
	identities, err := NewKeyAgent(recorder, agentLookup).List(context.Background())
	if err != nil {
		t.Fatalf("List error = %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("identities = %#v, want two", identities)
	}
	if identities[0].Bits != 256 || identities[0].Fingerprint != "SHA256:abcdef" || identities[0].Algorithm != "ED25519" {
		t.Errorf("identities[0] = %#v", identities[0])
	}
	if identities[1].Comment != "work key" {
		t.Errorf("identities[1].Comment = %q, want %q", identities[1].Comment, "work key")
	}

	empty := &recordingExecutor{results: []platform.CommandResult{{
		ExitCode: 1,
		Stdout:   []byte("The agent has no identities.\n"),
	}}}
	none, err := NewKeyAgent(empty, agentLookup).List(context.Background())
	if err != nil {
		t.Fatalf("List error = %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("identities = %#v, want none", none)
	}
}

func TestKeyAgentRefusesWhenNoAgentSocketIsAdvertised(t *testing.T) {
	recorder := &recordingExecutor{}
	agent := NewKeyAgent(recorder, func(string) (string, bool) { return "", false })

	if agent.Available(context.Background()) {
		t.Fatalf("Available = true without SSH_AUTH_SOCK")
	}
	if err := agent.Add(context.Background(), platform.AgentAddRequest{PrivateKeyPath: "/Users/example/.ssh/id_work"}); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Fatalf("Add error = %v, want ErrAgentUnavailable", err)
	}
	if len(recorder.commands) != 0 {
		t.Fatalf("a command ran without an agent: %#v", recorder.commands)
	}
}
```

- [ ] **Step 2: Run the adapter test and verify it is absent**

Run: `go test ./internal/platform/macos -run TestKeyAgent -v`

Expected: FAIL with `undefined: NewKeyAgent`.

- [ ] **Step 3: Implement the agent contract and the macOS adapter**

```go
// internal/platform/keyagent.go
package platform

import (
	"context"
	"errors"
)

var (
	ErrAgentUnavailable = errors.New("no ssh-agent is reachable from this process")
	ErrAgentRejected    = errors.New("ssh-add rejected the request")
)

// AgentIdentity is one key currently loaded in the user's ssh-agent.
type AgentIdentity struct {
	Bits        int
	Fingerprint string
	Comment     string
	Algorithm   string
}

// AgentAddRequest asks the agent to load one private key.
//
// Passphrase travels on the child process's standard input. It is never an
// argument and never an environment variable, because both are readable by any
// process running as the same user.
type AgentAddRequest struct {
	PrivateKeyPath  string
	Passphrase      []byte
	LifetimeSeconds int
	StoreInKeychain bool
}

// KeyAgent registers private keys with the user's ssh-agent and, on macOS, with
// the login Keychain. Automated tests always substitute a fake; no test in this
// repository talks to a real agent or a real Keychain.
type KeyAgent interface {
	Available(ctx context.Context) bool
	List(ctx context.Context) ([]AgentIdentity, error)
	Add(ctx context.Context, request AgentAddRequest) error
	Remove(ctx context.Context, publicKeyPath string) error
}
```

```go
// internal/platform/macos/keyagent.go
package macos

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sshc/internal/platform"
)

const (
	sshAddPath          = "/usr/bin/ssh-add"
	defaultAgentTimeout = 30 * time.Second
	noIdentitiesMessage = "The agent has no identities."
)

// KeyAgent drives /usr/bin/ssh-add.
//
// ssh-add reads a passphrase from standard input when one is available, so this
// adapter needs neither SSH_ASKPASS nor a terminal, and the secret never
// reaches argv or the environment. The key path is always an absolute path
// inside the workspace, so it can never be read as an option.
//
// --apple-use-keychain is the documented macOS flag that also stores the
// passphrase in the login Keychain. It is used only when the user asked for it.
type KeyAgent struct {
	executor platform.CommandExecutor
	lookup   func(string) (string, bool)
	timeout  time.Duration
}

func NewKeyAgent(executor platform.CommandExecutor, lookup func(string) (string, bool)) KeyAgent {
	return KeyAgent{executor: executor, lookup: lookup, timeout: defaultAgentTimeout}
}

// Available reports whether this process was started inside an agent session.
func (agent KeyAgent) Available(_ context.Context) bool {
	socket, ok := agent.lookup("SSH_AUTH_SOCK")
	return ok && socket != ""
}

func (agent KeyAgent) List(ctx context.Context) ([]platform.AgentIdentity, error) {
	if !agent.Available(ctx) {
		return nil, platform.ErrAgentUnavailable
	}
	result, err := agent.run(ctx, platform.Command{Name: sshAddPath, Args: []string{"-l", "-E", "sha256"}})
	if err != nil {
		return nil, err
	}
	if result.ExitCode == 1 && strings.Contains(string(result.Stdout)+string(result.Stderr), noIdentitiesMessage) {
		return []platform.AgentIdentity{}, nil
	}
	if result.ExitCode != 0 {
		return nil, agent.rejected(result)
	}
	return parseIdentities(string(result.Stdout)), nil
}

func (agent KeyAgent) Add(ctx context.Context, request platform.AgentAddRequest) error {
	if !agent.Available(ctx) {
		return platform.ErrAgentUnavailable
	}
	arguments := make([]string, 0, 4)
	if request.LifetimeSeconds > 0 {
		arguments = append(arguments, "-t", strconv.Itoa(request.LifetimeSeconds))
	}
	if request.StoreInKeychain {
		arguments = append(arguments, "--apple-use-keychain")
	}
	arguments = append(arguments, request.PrivateKeyPath)

	result, err := agent.run(ctx, platform.Command{
		Name:  sshAddPath,
		Args:  arguments,
		Input: request.Passphrase,
	})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return agent.rejected(result)
	}
	return nil
}

func (agent KeyAgent) Remove(ctx context.Context, publicKeyPath string) error {
	if !agent.Available(ctx) {
		return platform.ErrAgentUnavailable
	}
	result, err := agent.run(ctx, platform.Command{Name: sshAddPath, Args: []string{"-d", publicKeyPath}})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return agent.rejected(result)
	}
	return nil
}

func (agent KeyAgent) run(ctx context.Context, command platform.Command) (platform.CommandResult, error) {
	timeout := agent.timeout
	if timeout <= 0 {
		timeout = defaultAgentTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return agent.executor.Execute(runCtx, command)
}

func (agent KeyAgent) rejected(result platform.CommandResult) error {
	message := strings.TrimSpace(string(result.Stderr))
	if message == "" {
		message = strings.TrimSpace(string(result.Stdout))
	}
	return fmt.Errorf("%w: %s", platform.ErrAgentRejected, agent.sanitize(message))
}

// sanitize replaces the user's home directory with '~' so a message shown in
// the UI, or copied out of it, carries no absolute path.
func (agent KeyAgent) sanitize(message string) string {
	home, ok := agent.lookup("HOME")
	if !ok || home == "" {
		return message
	}
	return strings.ReplaceAll(message, home, "~")
}

// parseIdentities reads `ssh-add -l` output lines of the form
// "<bits> <fingerprint> <comment> (<ALGORITHM>)".
func parseIdentities(output string) []platform.AgentIdentity {
	identities := make([]platform.AgentIdentity, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		bits, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		identities = append(identities, platform.AgentIdentity{
			Bits:        bits,
			Fingerprint: fields[1],
			Comment:     strings.Join(fields[2:len(fields)-1], " "),
			Algorithm:   strings.Trim(fields[len(fields)-1], "()"),
		})
	}
	return identities
}
```

- [ ] **Step 4: Run the adapter test**

Run: `go test ./internal/platform/... -v`

Expected: PASS. The passphrase appears only in `Command.Input`, the rejection message keeps `~/.ssh/id_work` and loses `/Users/example`, and no command runs without an advertised agent socket.

- [ ] **Step 5: Write the failing registration test**

```go
// internal/keys/service_test.go  (append)

// fakeAgent records every registration request without touching a real agent.
type fakeAgent struct {
	available  bool
	requests   []platform.AgentAddRequest
	identities []platform.AgentIdentity
	addError   error
}

func (fake *fakeAgent) Available(context.Context) bool { return fake.available }

func (fake *fakeAgent) List(context.Context) ([]platform.AgentIdentity, error) {
	if !fake.available {
		return nil, platform.ErrAgentUnavailable
	}
	return fake.identities, nil
}

func (fake *fakeAgent) Add(_ context.Context, request platform.AgentAddRequest) error {
	if !fake.available {
		return platform.ErrAgentUnavailable
	}
	fake.requests = append(fake.requests, request)
	return fake.addError
}

func (fake *fakeAgent) Remove(context.Context, string) error { return nil }

func TestRegisterSendsTheKeyPathAndPassphraseToTheAgentOnly(t *testing.T) {
	agent := &fakeAgent{
		available:  true,
		identities: []platform.AgentIdentity{{Bits: 256, Fingerprint: "SHA256:abcdef", Comment: "aida@laptop", Algorithm: "ED25519"}},
	}
	service, workspace := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})
	service.agent = agent
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}

	result, err := service.Register(context.Background(), RegisterRequest{
		KeyID:           ItemID("id_work"),
		Passphrase:      []byte("correct horse"),
		LifetimeSeconds: 3600,
		StoreInKeychain: true,
	})
	if err != nil {
		t.Fatalf("Register error = %v", err)
	}
	if len(agent.requests) != 1 {
		t.Fatalf("requests = %#v, want one", agent.requests)
	}
	request := agent.requests[0]
	if request.PrivateKeyPath != filepath.Join(workspace.Root(), "id_work") {
		t.Errorf("PrivateKeyPath = %q", request.PrivateKeyPath)
	}
	if request.LifetimeSeconds != 3600 || !request.StoreInKeychain {
		t.Errorf("request = %#v", request)
	}
	if len(result.Identities) != 1 {
		t.Errorf("Identities = %#v, want the agent listing", result.Identities)
	}

	history, err := storage.NewManager(workspace, time.Now, rand.Reader).History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	registrations := 0
	for _, record := range history {
		if record.Operation == "key.agent_add" {
			registrations++
		}
	}
	if registrations != 1 {
		t.Fatalf("key.agent_add records = %d, want 1", registrations)
	}
}

func TestRegisterRefusesTrashedAndUnknownKeys(t *testing.T) {
	agent := &fakeAgent{available: true}
	service, _ := newTestService(t, &fakeExecutor{result: platform.CommandResult{Stdout: []byte(opensshQueryOutput)}})
	service.agent = agent
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if _, err := service.Trash(ItemID("id_work")); err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	if _, err := service.Register(context.Background(), RegisterRequest{KeyID: ItemID("id_work")}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("registering a trashed key = %v, want ErrUnknownKey", err)
	}
	if len(agent.requests) != 0 {
		t.Fatalf("a trashed key reached the agent: %#v", agent.requests)
	}
}
```

- [ ] **Step 6: Wire the agent into the service**

Add the field to `Service` and `ServiceOptions` in `internal/keys/service.go` and set it in `NewService`:

```go
type Service struct {
	workspace    *storage.Workspace
	transactions *storage.Manager
	resolver     config.Resolver
	catalogue    CatalogueReader
	agent        platform.KeyAgent
	now          func() time.Time
	random       io.Reader
}

type ServiceOptions struct {
	Workspace    *storage.Workspace
	Transactions *storage.Manager
	Resolver     config.Resolver
	Catalogue    CatalogueReader
	Agent        platform.KeyAgent
	Now          func() time.Time
	Random       io.Reader
}
```

`NewService` gains `agent: options.Agent`, and the file imports `"sshc/internal/platform"`.

Append the registration use case:

```go
// RegisterRequest asks the user's ssh-agent to load one key.
type RegisterRequest struct {
	KeyID           string
	Passphrase      []byte
	LifetimeSeconds int
	StoreInKeychain bool
}

type RegisterResult struct {
	ID               string
	RelativePath     string
	Fingerprint      string
	LifetimeSeconds  int
	StoredInKeychain bool
	Identities       []platform.AgentIdentity
}

// Register loads a private key into the user's ssh-agent, optionally storing
// its passphrase in the login Keychain.
//
// Only a key the inventory currently contains can be registered, so a trashed
// key and anything under ~/.ssh/sshc are unreachable by construction. The
// passphrase is overwritten before Register returns, and the registration is
// recorded in history without it.
func (service *Service) Register(ctx context.Context, request RegisterRequest) (RegisterResult, error) {
	defer Wipe(request.Passphrase)

	if service.agent == nil {
		return RegisterResult{}, platform.ErrAgentUnavailable
	}
	inventory, err := service.Inventory()
	if err != nil {
		return RegisterResult{}, err
	}
	item, ok := inventory.Find(request.KeyID)
	if !ok || item.Kind != KindPrivateKey {
		return RegisterResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	if err := service.agent.Add(ctx, platform.AgentAddRequest{
		PrivateKeyPath:  absolute,
		Passphrase:      request.Passphrase,
		LifetimeSeconds: request.LifetimeSeconds,
		StoreInKeychain: request.StoreInKeychain,
	}); err != nil {
		return RegisterResult{}, err
	}
	if _, err := service.transactions.Note("key.agent_add", []string{absolute}); err != nil {
		return RegisterResult{}, err
	}

	identities, listErr := service.agent.List(ctx)
	if listErr != nil {
		identities = nil
	}
	return RegisterResult{
		ID:               item.ID,
		RelativePath:     item.RelativePath,
		Fingerprint:      item.Fingerprint,
		LifetimeSeconds:  request.LifetimeSeconds,
		StoredInKeychain: request.StoreInKeychain,
		Identities:       identities,
	}, nil
}

// AgentIdentities reports what the agent currently holds. The second return
// value is false when no agent is reachable, so the UI can say so instead of
// showing an empty list that looks like a working agent.
func (service *Service) AgentIdentities(ctx context.Context) ([]platform.AgentIdentity, bool) {
	if service.agent == nil || !service.agent.Available(ctx) {
		return nil, false
	}
	identities, err := service.agent.List(ctx)
	if err != nil {
		return nil, false
	}
	return identities, true
}
```

- [ ] **Step 7: Run every Go test with the race detector**

Run:

```bash
go test ./... 
go test -race ./...
```

Expected: PASS. The trashed key is unreachable from the agent, the registration is journalled as `key.agent_add`, and no test started a real `ssh-add`.

- [ ] **Step 8: Commit the agent integration**

```bash
git add internal/platform/keyagent.go internal/platform/macos/keyagent.go internal/platform/macos/keyagent_test.go internal/keys/service.go internal/keys/service_test.go
git commit -m "feat: register keys with ssh-agent and the macOS Keychain"
```

## Task 7: One-time action tokens and the key vault API contract

**Files:**
- Modify: `internal/session/manager.go`
- Modify: `internal/session/manager_test.go`
- Modify: `api/openapi.yaml`
- Modify: `api/README.md`
- Generate: `internal/api/models.gen.go`
- Generate: `web/src/api/schema.d.ts`
- Modify: `internal/api/contract_test.go`

**Interfaces:**
- Consumes: committed `session.NewManager`, `session.Manager.Authenticate/VerifyCSRF`, `session.token`.
- Produces: `session.Action{Purpose, Subject}`, `session.ActionLifetime`, `session.PurposeRevealPrivateKey`, `session.PurposePurgeTrashEntry`.
- Produces: `session.NewManagerWithClock(random io.Reader, now func() time.Time) (*Manager, string, error)`.
- Produces: `(*session.Manager).IssueAction(sessionID string, action Action) (string, time.Time, error)`.
- Produces: `(*session.Manager).ConsumeAction(sessionID, presented string, action Action) error`.
- Produces: `session.ErrActionUnknown`, `session.ErrActionExpired`, `session.ErrActionMismatch`.
- Produces: generated Go models `api.KeyItem`, `api.KeyReference`, `api.KeyCertificate`, `api.UnreadableFile`, `api.KeyInventoryResponse`, `api.KeyVariant`, `api.KeyAlgorithmsResponse`, `api.GenerateKeyRequest`, `api.GenerateKeyResponse`, `api.HardwareCommandRequest`, `api.HardwareCommandResponse`, `api.ChangePassphraseRequest`, `api.ChangePassphraseResponse`, `api.RevealPrivateKeyResponse`, `api.IssueActionRequest`, `api.IssueActionResponse`, `api.RegisterKeyRequest`, `api.RegisterKeyResponse`, `api.AgentIdentity`, `api.TrashFileSummary`, `api.TrashEntrySummary`, `api.TrashListResponse`, `api.TrashKeyResponse`, `api.RestoreTrashResponse`, `api.PurgeTrashResponse`, and the extended `api.Problem` with `Detail`.
- Produces: the matching TypeScript `components["schemas"][…]` definitions.

- [ ] **Step 1: Write the failing action-token test**

```go
// internal/session/manager_test.go  (append)

func TestActionTokenIsSingleUseShortLivedAndBoundToItsSubject(t *testing.T) {
	moment := time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return moment }
	manager, bootstrap, err := NewManagerWithClock(bytes.NewReader(bytes.Repeat([]byte{0x33}, 4096)), clock)
	if err != nil {
		t.Fatalf("NewManagerWithClock error = %v", err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatalf("Bootstrap error = %v", err)
	}
	reveal := Action{Purpose: PurposeRevealPrivateKey, Subject: "key-one"}

	value, expiresAt, err := manager.IssueAction(credentials.SessionID, reveal)
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if len(value) != 43 {
		t.Fatalf("token length = %d, want 43", len(value))
	}
	if expiresAt != moment.Add(ActionLifetime) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, moment.Add(ActionLifetime))
	}

	if err := manager.ConsumeAction(credentials.SessionID, value, Action{Purpose: PurposeRevealPrivateKey, Subject: "key-two"}); !errors.Is(err, ErrActionMismatch) {
		t.Fatalf("wrong subject = %v, want ErrActionMismatch", err)
	}
	if err := manager.ConsumeAction(credentials.SessionID, value, reveal); !errors.Is(err, ErrActionUnknown) {
		t.Fatalf("replay after a mismatch = %v, want ErrActionUnknown", err)
	}

	second, _, err := manager.IssueAction(credentials.SessionID, reveal)
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if err := manager.ConsumeAction(credentials.SessionID, second, Action{Purpose: PurposePurgeTrashEntry, Subject: "key-one"}); !errors.Is(err, ErrActionMismatch) {
		t.Fatalf("wrong purpose = %v, want ErrActionMismatch", err)
	}

	third, _, err := manager.IssueAction(credentials.SessionID, reveal)
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if err := manager.ConsumeAction(credentials.SessionID, third, reveal); err != nil {
		t.Fatalf("ConsumeAction error = %v", err)
	}
	if err := manager.ConsumeAction(credentials.SessionID, third, reveal); !errors.Is(err, ErrActionUnknown) {
		t.Fatalf("replay = %v, want ErrActionUnknown", err)
	}

	fourth, _, err := manager.IssueAction(credentials.SessionID, reveal)
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	moment = moment.Add(ActionLifetime + time.Second)
	if err := manager.ConsumeAction(credentials.SessionID, fourth, reveal); !errors.Is(err, ErrActionExpired) {
		t.Fatalf("expired token = %v, want ErrActionExpired", err)
	}
}

func TestActionTokenIsUselessWithoutItsOwnSession(t *testing.T) {
	moment := time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC)
	manager, bootstrap, err := NewManagerWithClock(bytes.NewReader(bytes.Repeat([]byte{0x44}, 4096)), func() time.Time { return moment })
	if err != nil {
		t.Fatalf("NewManagerWithClock error = %v", err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatalf("Bootstrap error = %v", err)
	}
	reveal := Action{Purpose: PurposeRevealPrivateKey, Subject: "key-one"}

	if _, _, err := manager.IssueAction("not-a-session", reveal); !errors.Is(err, ErrActionUnknown) {
		t.Fatalf("issuing without a session = %v, want ErrActionUnknown", err)
	}
	value, _, err := manager.IssueAction(credentials.SessionID, reveal)
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if err := manager.ConsumeAction("not-a-session", value, reveal); !errors.Is(err, ErrActionUnknown) {
		t.Fatalf("consuming from another session = %v, want ErrActionUnknown", err)
	}
}
```

Add `"time"` to the `internal/session/manager_test.go` import block.

- [ ] **Step 2: Run the session test and verify action tokens are absent**

Run: `go test ./internal/session -run TestActionToken -v`

Expected: FAIL with `undefined: NewManagerWithClock` and `undefined: Action`.

- [ ] **Step 3: Implement action tokens**

Replace the top of `internal/session/manager.go` and append the action methods:

```go
package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrInvalidBootstrap = errors.New("invalid bootstrap token")
	ErrBootstrapUsed    = errors.New("bootstrap token already used")
	ErrActionUnknown    = errors.New("action token is not valid for this session")
	ErrActionExpired    = errors.New("action token has expired")
	ErrActionMismatch   = errors.New("action token was issued for a different operation")
)

// Action purposes. A token minted for one purpose can never be spent on another.
const (
	PurposeRevealPrivateKey = "reveal_private_key"
	PurposePurgeTrashEntry  = "purge_trash_entry"
)

// ActionLifetime is how long a freshly issued action token stays usable. It is
// deliberately short: the token exists to prove that the user confirmed this
// operation on this target a moment ago.
const ActionLifetime = 2 * time.Minute

// Action binds a one-time token to exactly one operation on one subject.
type Action struct {
	Purpose string
	Subject string
}

type actionRecord struct {
	sessionHash [sha256.Size]byte
	action      Action
	expiresAt   time.Time
}

type Credentials struct {
	SessionID string
	CSRFToken string
}

type Session struct {
	csrfHash [sha256.Size]byte
}

type Manager struct {
	mu            sync.RWMutex
	random        io.Reader
	now           func() time.Time
	bootstrapHash [sha256.Size]byte
	bootstrapUsed bool
	sessions      map[[sha256.Size]byte]Session
	actions       map[[sha256.Size]byte]actionRecord
}

func token(random io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func NewManager(random io.Reader) (*Manager, string, error) {
	return NewManagerWithClock(random, time.Now)
}

// NewManagerWithClock lets a test drive action-token expiry deterministically.
func NewManagerWithClock(random io.Reader, now func() time.Time) (*Manager, string, error) {
	bootstrap, err := token(random)
	if err != nil {
		return nil, "", err
	}
	return &Manager{
		random:        random,
		now:           now,
		bootstrapHash: sha256.Sum256([]byte(bootstrap)),
		sessions:      make(map[[sha256.Size]byte]Session),
		actions:       make(map[[sha256.Size]byte]actionRecord),
	}, bootstrap, nil
}
```

Leave `Bootstrap`, `Authenticate` and `VerifyCSRF` exactly as they are and append:

```go
// IssueAction mints a one-time token bound to one session, one purpose and one
// subject. The token value is returned once; only its hash is kept.
func (m *Manager) IssueAction(sessionID string, action Action) (string, time.Time, error) {
	if action.Purpose == "" || action.Subject == "" {
		return "", time.Time{}, ErrActionMismatch
	}
	if _, ok := m.Authenticate(sessionID); !ok {
		return "", time.Time{}, ErrActionUnknown
	}
	value, err := token(m.random)
	if err != nil {
		return "", time.Time{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	moment := m.now()
	m.pruneActionsLocked(moment)
	expiresAt := moment.Add(ActionLifetime)
	m.actions[sha256.Sum256([]byte(value))] = actionRecord{
		sessionHash: sha256.Sum256([]byte(sessionID)),
		action:      action,
		expiresAt:   expiresAt,
	}
	return value, expiresAt, nil
}

// ConsumeAction spends a token.
//
// Presenting a token consumes it whether or not it matches, so an attacker who
// has stolen one cannot probe which operation it was minted for by replaying it
// against different targets.
func (m *Manager) ConsumeAction(sessionID, presented string, action Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	moment := m.now()
	m.pruneActionsLocked(moment)

	key := sha256.Sum256([]byte(presented))
	record, ok := m.actions[key]
	if !ok {
		return ErrActionUnknown
	}
	delete(m.actions, key)

	sessionHash := sha256.Sum256([]byte(sessionID))
	if subtle.ConstantTimeCompare(record.sessionHash[:], sessionHash[:]) != 1 {
		return ErrActionUnknown
	}
	if moment.After(record.expiresAt) {
		return ErrActionExpired
	}
	if record.action != action {
		return ErrActionMismatch
	}
	return nil
}

func (m *Manager) pruneActionsLocked(moment time.Time) {
	for key, record := range m.actions {
		if moment.After(record.expiresAt) {
			delete(m.actions, key)
		}
	}
}
```

- [ ] **Step 4: Run the session suite**

Run: `go test ./internal/session -v`

Expected: PASS, including the committed bootstrap and CSRF tests.

- [ ] **Step 5: Extend the OpenAPI contract**

Add these paths to `api/openapi.yaml` under the existing `paths:` block, after `/api/v1/health`:

```yaml
  /api/v1/actions:
    post:
      operationId: issueActionToken
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/IssueActionRequest" }
      responses:
        "201":
          description: One-time action token issued
          content:
            application/json:
              schema: { $ref: "#/components/schemas/IssueActionResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/keys:
    get:
      operationId: listKeys
      responses:
        "200":
          description: Classified contents of the ssh workspace
          content:
            application/json:
              schema: { $ref: "#/components/schemas/KeyInventoryResponse" }
        "401": { $ref: "#/components/responses/Problem" }
    post:
      operationId: generateKey
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/GenerateKeyRequest" }
      responses:
        "201":
          description: Key pair generated
          content:
            application/json:
              schema: { $ref: "#/components/schemas/GenerateKeyResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
  /api/v1/keys/algorithms:
    get:
      operationId: listKeyAlgorithms
      responses:
        "200":
          description: Variants the installed OpenSSH supports
          content:
            application/json:
              schema: { $ref: "#/components/schemas/KeyAlgorithmsResponse" }
        "401": { $ref: "#/components/responses/Problem" }
  /api/v1/keys/hardware-command:
    post:
      operationId: buildHardwareKeyCommand
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/HardwareCommandRequest" }
      responses:
        "200":
          description: Command the user runs in Terminal
          content:
            application/json:
              schema: { $ref: "#/components/schemas/HardwareCommandResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/v1/keys/{keyId}/passphrase:
    post:
      operationId: changeKeyPassphrase
      parameters:
        - name: keyId
          in: path
          required: true
          schema: { type: string, minLength: 32, maxLength: 32 }
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/ChangePassphraseRequest" }
      responses:
        "200":
          description: Passphrase changed
          content:
            application/json:
              schema: { $ref: "#/components/schemas/ChangePassphraseResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
  /api/v1/keys/{keyId}/reveal:
    post:
      operationId: revealPrivateKey
      parameters:
        - name: keyId
          in: path
          required: true
          schema: { type: string, minLength: 32, maxLength: 32 }
        - name: X-SSHC-Action
          in: header
          required: true
          schema: { type: string, minLength: 43, maxLength: 43 }
      responses:
        "200":
          description: Private key material, never cached and never logged
          headers:
            Cache-Control:
              schema: { type: string, const: no-store }
          content:
            application/json:
              schema: { $ref: "#/components/schemas/RevealPrivateKeyResponse" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
  /api/v1/keys/{keyId}/agent:
    post:
      operationId: registerKeyWithAgent
      parameters:
        - name: keyId
          in: path
          required: true
          schema: { type: string, minLength: 32, maxLength: 32 }
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RegisterKeyRequest" }
      responses:
        "200":
          description: Key registered with the ssh-agent
          content:
            application/json:
              schema: { $ref: "#/components/schemas/RegisterKeyResponse" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "502": { $ref: "#/components/responses/Problem" }
  /api/v1/keys/{keyId}/trash:
    post:
      operationId: trashKey
      parameters:
        - name: keyId
          in: path
          required: true
          schema: { type: string, minLength: 32, maxLength: 32 }
      responses:
        "200":
          description: Key moved to the trash
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TrashKeyResponse" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
  /api/v1/trash:
    get:
      operationId: listTrash
      responses:
        "200":
          description: Soft-deleted keys, newest first
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TrashListResponse" }
        "401": { $ref: "#/components/responses/Problem" }
  /api/v1/trash/{entryId}/restore:
    post:
      operationId: restoreTrashEntry
      parameters:
        - name: entryId
          in: path
          required: true
          schema: { type: string, minLength: 1, maxLength: 64 }
      responses:
        "200":
          description: Trash entry restored
          content:
            application/json:
              schema: { $ref: "#/components/schemas/RestoreTrashResponse" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "409":
          description: Restore refused because it would have to guess
          content:
            application/json:
              schema: { $ref: "#/components/schemas/RestoreTrashResponse" }
  /api/v1/trash/{entryId}:
    delete:
      operationId: purgeTrashEntry
      parameters:
        - name: entryId
          in: path
          required: true
          schema: { type: string, minLength: 1, maxLength: 64 }
        - name: X-SSHC-Action
          in: header
          required: true
          schema: { type: string, minLength: 43, maxLength: 43 }
      responses:
        "200":
          description: Trash entry permanently deleted
          content:
            application/json:
              schema: { $ref: "#/components/schemas/PurgeTrashResponse" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
```

Add these schemas to `components.schemas`, and add `detail` to the existing `Problem` schema:

```yaml
    Problem:
      type: object
      additionalProperties: false
      required: [code, message]
      properties:
        code: { type: string }
        message: { type: string }
        detail: { type: string }
    KeyReference:
      type: object
      additionalProperties: false
      required: [directive, configPath, line, condition, hostPatterns, value]
      properties:
        directive: { type: string }
        configPath: { type: string }
        line: { type: integer }
        condition: { type: string }
        hostPatterns: { type: array, items: { type: string } }
        value: { type: string }
    UnresolvedReference:
      type: object
      additionalProperties: false
      required: [directive, value, configPath, line, reason]
      properties:
        directive: { type: string }
        value: { type: string }
        configPath: { type: string }
        line: { type: integer }
        reason: { type: string }
    KeyCertificate:
      type: object
      additionalProperties: false
      required: [keyId, principals, validBefore, neverExpires, signedKeyType, signedKeyFingerprint]
      properties:
        keyId: { type: string }
        principals: { type: array, items: { type: string } }
        validBefore: { type: integer }
        neverExpires: { type: boolean }
        signedKeyType: { type: string }
        signedKeyFingerprint: { type: string }
    UnreadableFile:
      type: object
      additionalProperties: false
      required: [relativePath, reason]
      properties:
        relativePath: { type: string }
        reason: { type: string }
    KeyItem:
      type: object
      additionalProperties: false
      required:
        [id, relativePath, kind, container, algorithm, keyType, bits, encrypted,
         fingerprint, comment, permission, permissionRisk, sizeBytes, references, notes]
      properties:
        id: { type: string }
        relativePath: { type: string }
        kind: { type: string }
        container: { type: string }
        algorithm: { type: string }
        keyType: { type: string }
        bits: { type: integer }
        encrypted: { type: boolean }
        fingerprint: { type: string }
        comment: { type: string }
        permission: { type: string }
        permissionRisk: { type: boolean }
        sizeBytes: { type: integer }
        certificate: { $ref: "#/components/schemas/KeyCertificate" }
        references: { type: array, items: { $ref: "#/components/schemas/KeyReference" } }
        notes: { type: array, items: { type: string } }
    KeyInventoryResponse:
      type: object
      additionalProperties: false
      required: [items, unreadable, agentDelegations, unresolvedReferences, agentAvailable, agentIdentities]
      properties:
        items: { type: array, items: { $ref: "#/components/schemas/KeyItem" } }
        unreadable: { type: array, items: { $ref: "#/components/schemas/UnreadableFile" } }
        agentDelegations: { type: array, items: { $ref: "#/components/schemas/KeyReference" } }
        unresolvedReferences: { type: array, items: { $ref: "#/components/schemas/UnresolvedReference" } }
        agentAvailable: { type: boolean }
        agentIdentities: { type: array, items: { $ref: "#/components/schemas/AgentIdentity" } }
    AgentIdentity:
      type: object
      additionalProperties: false
      required: [bits, fingerprint, comment, algorithm]
      properties:
        bits: { type: integer }
        fingerprint: { type: string }
        comment: { type: string }
        algorithm: { type: string }
    KeyVariant:
      type: object
      additionalProperties: false
      required: [algorithm, bits, label, inProcess, reason]
      properties:
        algorithm: { type: string }
        bits: { type: integer }
        label: { type: string }
        inProcess: { type: boolean }
        reason: { type: string }
    KeyAlgorithmsResponse:
      type: object
      additionalProperties: false
      required: [variants, source, diagnostic]
      properties:
        variants: { type: array, items: { $ref: "#/components/schemas/KeyVariant" } }
        source: { type: string }
        diagnostic: { type: string }
    GenerateKeyRequest:
      type: object
      additionalProperties: false
      required: [algorithm, fileName, comment, passphrase, unencrypted]
      properties:
        algorithm: { type: string, minLength: 1, maxLength: 16 }
        bits: { type: integer }
        fileName: { type: string, minLength: 1, maxLength: 64 }
        comment: { type: string, maxLength: 127 }
        passphrase: { type: string, maxLength: 1024 }
        unencrypted: { type: boolean }
    GenerateKeyResponse:
      type: object
      additionalProperties: false
      required: [id, relativePath, publicRelativePath, fingerprint, keyType, bits, encrypted, transactionId]
      properties:
        id: { type: string }
        relativePath: { type: string }
        publicRelativePath: { type: string }
        fingerprint: { type: string }
        keyType: { type: string }
        bits: { type: integer }
        encrypted: { type: boolean }
        transactionId: { type: string }
    HardwareCommandRequest:
      type: object
      additionalProperties: false
      required: [algorithm, fileName, comment]
      properties:
        algorithm: { type: string, minLength: 1, maxLength: 16 }
        fileName: { type: string, minLength: 1, maxLength: 64 }
        comment: { type: string, maxLength: 127 }
    HardwareCommandResponse:
      type: object
      additionalProperties: false
      required: [algorithm, command, note]
      properties:
        algorithm: { type: string }
        command: { type: array, items: { type: string } }
        note: { type: string }
    ChangePassphraseRequest:
      type: object
      additionalProperties: false
      required: [currentPassphrase, newPassphrase, unencrypted]
      properties:
        currentPassphrase: { type: string, maxLength: 1024 }
        newPassphrase: { type: string, maxLength: 1024 }
        unencrypted: { type: boolean }
    ChangePassphraseResponse:
      type: object
      additionalProperties: false
      required: [id, relativePath, encrypted, notes, transactionId]
      properties:
        id: { type: string }
        relativePath: { type: string }
        encrypted: { type: boolean }
        notes: { type: array, items: { type: string } }
        transactionId: { type: string }
    RevealPrivateKeyResponse:
      type: object
      additionalProperties: false
      required: [id, relativePath, privateKey, encrypted, fingerprint, transactionId]
      properties:
        id: { type: string }
        relativePath: { type: string }
        privateKey: { type: string }
        encrypted: { type: boolean }
        fingerprint: { type: string }
        transactionId: { type: string }
    IssueActionRequest:
      type: object
      additionalProperties: false
      required: [purpose, subject]
      properties:
        purpose: { type: string, minLength: 1, maxLength: 64 }
        subject: { type: string, minLength: 1, maxLength: 64 }
    IssueActionResponse:
      type: object
      additionalProperties: false
      required: [token, expiresAt]
      properties:
        token: { type: string, minLength: 43, maxLength: 43 }
        expiresAt: { type: string, minLength: 1 }
    RegisterKeyRequest:
      type: object
      additionalProperties: false
      required: [passphrase, lifetimeSeconds, storeInKeychain]
      properties:
        passphrase: { type: string, maxLength: 1024 }
        lifetimeSeconds: { type: integer }
        storeInKeychain: { type: boolean }
    RegisterKeyResponse:
      type: object
      additionalProperties: false
      required: [id, relativePath, fingerprint, lifetimeSeconds, storedInKeychain, identities]
      properties:
        id: { type: string }
        relativePath: { type: string }
        fingerprint: { type: string }
        lifetimeSeconds: { type: integer }
        storedInKeychain: { type: boolean }
        identities: { type: array, items: { $ref: "#/components/schemas/AgentIdentity" } }
    TrashFileSummary:
      type: object
      additionalProperties: false
      required: [originalRelativePath, trashRelativePath, kind, fingerprint, permission]
      properties:
        originalRelativePath: { type: string }
        trashRelativePath: { type: string }
        kind: { type: string }
        fingerprint: { type: string }
        permission: { type: string }
    TrashEntrySummary:
      type: object
      additionalProperties: false
      required: [id, deletedAt, ageDays, stale, files, restorable, blockers]
      properties:
        id: { type: string }
        deletedAt: { type: string }
        ageDays: { type: integer }
        stale: { type: boolean }
        files: { type: array, items: { $ref: "#/components/schemas/TrashFileSummary" } }
        restorable: { type: boolean }
        blockers: { type: array, items: { type: string } }
    TrashListResponse:
      type: object
      additionalProperties: false
      required: [entries, retentionDays]
      properties:
        entries: { type: array, items: { $ref: "#/components/schemas/TrashEntrySummary" } }
        retentionDays: { type: integer }
    TrashKeyResponse:
      type: object
      additionalProperties: false
      required: [entryId, files, skipped, transactionId]
      properties:
        entryId: { type: string }
        files: { type: array, items: { $ref: "#/components/schemas/TrashFileSummary" } }
        skipped: { type: array, items: { type: string } }
        transactionId: { type: string }
    RestoreTrashResponse:
      type: object
      additionalProperties: false
      required: [entryId, restored, blockers, transactionId]
      properties:
        entryId: { type: string }
        restored: { type: array, items: { type: string } }
        blockers: { type: array, items: { type: string } }
        transactionId: { type: string }
    PurgeTrashResponse:
      type: object
      additionalProperties: false
      required: [entryId, removed, transactionId]
      properties:
        entryId: { type: string }
        removed: { type: array, items: { type: string } }
        transactionId: { type: string }
```

Timestamps are plain strings, not `format: date-time`, and value sets such as `kind` and `algorithm` are plain strings rather than `enum`, because `api/README.md` records that the pinned oapi-codegen v2.7.0 is validated only for the basic OpenAPI 3.1 subset. Every one of these values is validated at runtime in Go, which the design already requires of the API boundary.

- [ ] **Step 6: Regenerate both languages and write the failing contract test**

```go
// internal/api/contract_test.go  (append)

func TestGeneratedKeyVaultModels(t *testing.T) {
	item := KeyItem{
		Id:             "0123456789abcdef0123456789abcdef",
		RelativePath:   "id_work",
		Kind:           "private_key",
		Container:      "OPENSSH PRIVATE KEY",
		Algorithm:      "ed25519",
		KeyType:        "ssh-ed25519",
		Bits:           256,
		Encrypted:      true,
		Fingerprint:    "SHA256:abcdef",
		Comment:        "aida@laptop",
		Permission:     "0600",
		PermissionRisk: false,
		SizeBytes:      444,
		References: []KeyReference{{
			Directive:    "IdentityFile",
			ConfigPath:   "/Users/example/.ssh/config",
			Line:         2,
			Condition:    "Host build-*",
			HostPatterns: []string{"build-*"},
			Value:        "~/.ssh/id_work",
		}},
		Notes: []string{},
	}
	if item.Bits != 256 || item.References[0].Directive != "IdentityFile" {
		t.Fatalf("unexpected key item: %#v", item)
	}
	if item.Certificate != nil {
		t.Fatalf("certificate must be optional and absent by default")
	}

	inventory := KeyInventoryResponse{
		Items:                []KeyItem{item},
		Unreadable:           []UnreadableFile{{RelativePath: "huge_known_hosts", Reason: "file_too_large"}},
		AgentDelegations:     []KeyReference{},
		UnresolvedReferences: []UnresolvedReference{},
		AgentAvailable:       true,
		AgentIdentities:      []AgentIdentity{{Bits: 256, Fingerprint: "SHA256:abcdef", Comment: "aida@laptop", Algorithm: "ED25519"}},
	}
	if len(inventory.Items) != 1 || !inventory.AgentAvailable {
		t.Fatalf("unexpected inventory: %#v", inventory)
	}

	reveal := RevealPrivateKeyResponse{
		Id:            item.Id,
		RelativePath:  "id_work",
		PrivateKey:    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		Encrypted:     true,
		Fingerprint:   "SHA256:abcdef",
		TransactionId: "20260805T090000.000-aabbccdd",
	}
	if reveal.TransactionId == "" {
		t.Fatalf("unexpected reveal response: %#v", reveal)
	}

	action := IssueActionResponse{Token: "t", ExpiresAt: "2026-08-05T09:02:00Z"}
	trash := TrashListResponse{
		Entries: []TrashEntrySummary{{
			Id:         "20260805T090000.000-aabbccdd",
			DeletedAt:  "2026-08-05T09:00:00Z",
			AgeDays:    40,
			Stale:      true,
			Files:      []TrashFileSummary{{OriginalRelativePath: "id_work", TrashRelativePath: "sshc/trash/e/id_work", Kind: "private_key", Fingerprint: "SHA256:abcdef", Permission: "0600"}},
			Restorable: false,
			Blockers:   []string{"restore_path_occupied:id_work"},
		}},
		RetentionDays: 30,
	}
	if action.ExpiresAt == "" || trash.RetentionDays != 30 || !trash.Entries[0].Stale {
		t.Fatalf("unexpected trash response: %#v", trash)
	}

	problem := Problem{Code: "agent_rejected", Message: "request rejected", Detail: "Bad passphrase for ~/.ssh/id_work"}
	if problem.Detail == "" {
		t.Fatalf("Problem gained no detail field")
	}
}
```

Run:

```bash
make generate
go test ./internal/api -count=1
npm run typecheck --prefix web
```

Expected: `internal/api/models.gen.go` and `web/src/api/schema.d.ts` contain every new model; the contract test passes; TypeScript compiles.

If a generated Go field name differs from the test — for example `Id` versus `ID` — fix the *test* to match the generator's output rather than hand-editing the generated file, and record the observed convention in `api/README.md`.

- [ ] **Step 7: Record the contract decisions**

Append to `api/README.md`:

```markdown
## Key vault contract decisions

- Timestamps are plain `type: string` values in RFC 3339 form, not
  `format: date-time`. The generator's 3.1 support is validated only for the
  basic subset, and a plain string keeps both generated languages predictable.
- Value sets such as `kind`, `algorithm` and `purpose` are plain strings rather
  than `enum`, and are validated at runtime in Go at the API boundary. Type
  generation is never the only check on an input.
- `Problem.detail` carries a bounded, home-sanitised message such as `ssh-add`
  stderr. It must never contain key material, a passphrase, a token or an
  absolute path.
- `KeyCertificate.validBefore` is a signed integer plus a `neverExpires` flag.
  OpenSSH spells "never expires" as 2^64-1, which does not fit a signed integer,
  so that case is reported as `neverExpires: true` with a zero bound instead of
  being wrapped into a negative number.
- `POST /api/v1/keys/hardware-command` changes nothing on disk. It is a POST so
  it carries a validated JSON body and is covered by the CSRF requirement like
  every other non-GET request.
```

- [ ] **Step 8: Commit the contract**

```bash
git add internal/session api/openapi.yaml api/README.md internal/api/models.gen.go internal/api/contract_test.go web/src/api/schema.d.ts
git commit -m "feat: add action tokens and the key vault API contract"
```

## Task 8: Key vault HTTP handlers and process wiring

**Files:**
- Create: `internal/httpserver/keys.go`
- Create: `internal/httpserver/keys_test.go`
- Modify: `internal/httpserver/security.go`
- Modify: `internal/httpserver/server.go`
- Modify: `internal/app/run.go`
- Modify: `internal/app/run_test.go`
- Modify: `cmd/sshc/main.go`

**Interfaces:**
- Consumes: Task 7's generated `api` models and `session.Action`, `session.PurposeRevealPrivateKey`, `session.PurposePurgeTrashEntry`, `session.IssueAction`, `session.ConsumeAction`.
- Consumes: Tasks 3 to 6's `keys.Service` methods and `platform.KeyAgent`.
- Consumes: committed `httpserver.Security`, `SessionCookie`, `SessionContextKey`, `CSRFHeader`, `problem`.
- Produces: `httpserver.ActionHeader` (`X-SSHC-Action`).
- Produces: `httpserver.KeyService` interface and `httpserver.KeyHandlers{Keys, Sessions}`.
- Produces: `httpserver.problemDetail(c *echo.Context, status int, code, detail string) error`.
- Produces: `httpserver.Options.Keys KeyService`.
- Produces: `app.Dependencies` fields `Home string`, `Executor platform.CommandExecutor`, `KeyAgent platform.KeyAgent`.

- [ ] **Step 1: Write the failing handler test**

```go
// internal/httpserver/keys_test.go
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/keys"
	"sshc/internal/platform"
	"sshc/internal/session"
)

// stubKeyService answers without touching a filesystem, an agent or a process.
type stubKeyService struct {
	inventory   *keys.Inventory
	reveal      keys.RevealResult
	revealCalls int
	purgeCalls  int
	registerErr error
}

func (stub *stubKeyService) Inventory() (*keys.Inventory, error) { return stub.inventory, nil }

func (stub *stubKeyService) AgentIdentities(context.Context) ([]platform.AgentIdentity, bool) {
	return []platform.AgentIdentity{{Bits: 256, Fingerprint: "SHA256:abcdef", Comment: "aida@laptop", Algorithm: "ED25519"}}, true
}

func (stub *stubKeyService) Algorithms(context.Context) keys.Catalogue {
	return keys.Catalogue{Source: "ssh -Q key", Variants: []keys.Variant{{Algorithm: keys.AlgorithmEd25519, Bits: 256, Label: "Ed25519", InProcess: true}}}
}

func (stub *stubKeyService) Generate(keys.GenerateRequest) (keys.GenerateResult, error) {
	return keys.GenerateResult{ID: "key-one", RelativePath: "id_work", PublicRelativePath: "id_work.pub", Encrypted: true, TransactionID: "tx"}, nil
}

func (stub *stubKeyService) HardwareCommand(keys.Algorithm, string, string) ([]string, error) {
	return []string{"ssh-keygen", "-t", "ed25519-sk", "-f", "/Users/example/.ssh/id_yubikey"}, nil
}

func (stub *stubKeyService) ChangePassphrase(keys.PassphraseChange) (keys.PassphraseResult, error) {
	return keys.PassphraseResult{ID: "key-one", RelativePath: "id_work", Encrypted: true, TransactionID: "tx"}, nil
}

func (stub *stubKeyService) Reveal(keyID string) (keys.RevealResult, error) {
	if keyID != "key-one" {
		return keys.RevealResult{}, keys.ErrUnknownKey
	}
	stub.revealCalls++
	return stub.reveal, nil
}

func (stub *stubKeyService) Register(context.Context, keys.RegisterRequest) (keys.RegisterResult, error) {
	if stub.registerErr != nil {
		return keys.RegisterResult{}, stub.registerErr
	}
	return keys.RegisterResult{ID: "key-one", RelativePath: "id_work"}, nil
}

func (stub *stubKeyService) Trash(string) (keys.TrashResult, error) {
	return keys.TrashResult{EntryID: "20260805T090000.000-aabbccdd", TransactionID: "tx"}, nil
}

func (stub *stubKeyService) ListTrash() ([]keys.TrashEntry, error) {
	return []keys.TrashEntry{{ID: "20260805T090000.000-aabbccdd", DeletedAt: time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC), AgeDays: 40, Stale: true}}, nil
}

func (stub *stubKeyService) Restore(string) (keys.RestoreResult, error) {
	return keys.RestoreResult{EntryID: "20260805T090000.000-aabbccdd", Restored: []string{"id_work"}, TransactionID: "tx"}, nil
}

func (stub *stubKeyService) Purge(string) (keys.PurgeResult, error) {
	stub.purgeCalls++
	return keys.PurgeResult{EntryID: "20260805T090000.000-aabbccdd", Removed: []string{"id_work"}, TransactionID: "tx"}, nil
}

const testHost = "127.0.0.1:43123"

func newKeyServer(t *testing.T, service KeyService) (*echo.Echo, *session.Manager, session.Credentials) {
	t.Helper()
	manager, bootstrap, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x51}, 4096)))
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatalf("Bootstrap error = %v", err)
	}
	engine := echo.New()
	engine.Use((Security{ExpectedHost: testHost, ExpectedOrigin: "http://" + testHost, Sessions: manager}).Middleware)
	registerKeyRoutes(engine, KeyHandlers{Keys: service, Sessions: manager})
	return engine, manager, credentials
}

func sendKeyRequest(t *testing.T, engine *echo.Echo, credentials session.Credentials, method, target string, body []byte, actionToken string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	request.Host = testHost
	request.Header.Set(echo.HeaderContentType, "application/json")
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set(echo.HeaderOrigin, "http://"+testHost)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set(CSRFHeader, credentials.CSRFToken)
	}
	if actionToken != "" {
		request.Header.Set(ActionHeader, actionToken)
	}
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	return response
}

func TestRevealRequiresAFreshActionTokenForThatExactKey(t *testing.T) {
	service := &stubKeyService{
		inventory: &keys.Inventory{Items: []keys.Item{{ID: "key-one", RelativePath: "id_work", Kind: keys.KindPrivateKey}}},
		reveal:    keys.RevealResult{ID: "key-one", RelativePath: "id_work", Contents: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), Encrypted: true, TransactionID: "tx"},
	}
	engine, manager, credentials := newKeyServer(t, service)

	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, "").Code; got != http.StatusForbidden {
		t.Fatalf("reveal without a token = %d, want 403", got)
	}
	if service.revealCalls != 0 {
		t.Fatalf("the service was called without an action token")
	}

	otherKeyToken, _, err := manager.IssueAction(credentials.SessionID, session.Action{Purpose: session.PurposeRevealPrivateKey, Subject: "key-two"})
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, otherKeyToken).Code; got != http.StatusForbidden {
		t.Fatalf("reveal with another key's token = %d, want 403", got)
	}

	purgeToken, _, err := manager.IssueAction(credentials.SessionID, session.Action{Purpose: session.PurposePurgeTrashEntry, Subject: "key-one"})
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, purgeToken).Code; got != http.StatusForbidden {
		t.Fatalf("reveal with a purge token = %d, want 403", got)
	}

	revealToken, _, err := manager.IssueAction(credentials.SessionID, session.Action{Purpose: session.PurposeRevealPrivateKey, Subject: "key-one"})
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, revealToken)
	if response.Code != http.StatusOK {
		t.Fatalf("reveal = %d, want 200: %s", response.Code, response.Body.String())
	}
	if got := response.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var payload api.RevealPrivateKeyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode reveal: %v", err)
	}
	if payload.PrivateKey != "-----BEGIN OPENSSH PRIVATE KEY-----\n" {
		t.Fatalf("PrivateKey = %q", payload.PrivateKey)
	}

	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/reveal", nil, revealToken).Code; got != http.StatusForbidden {
		t.Fatalf("replaying an action token = %d, want 403", got)
	}
	if service.revealCalls != 1 {
		t.Fatalf("revealCalls = %d, want exactly one", service.revealCalls)
	}
}

func TestPermanentDeleteNeedsItsOwnActionToken(t *testing.T) {
	service := &stubKeyService{inventory: &keys.Inventory{}}
	engine, manager, credentials := newKeyServer(t, service)

	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/20260805T090000.000-aabbccdd", nil, "").Code; got != http.StatusForbidden {
		t.Fatalf("purge without a token = %d, want 403", got)
	}
	revealToken, _, err := manager.IssueAction(credentials.SessionID, session.Action{Purpose: session.PurposeRevealPrivateKey, Subject: "20260805T090000.000-aabbccdd"})
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/20260805T090000.000-aabbccdd", nil, revealToken).Code; got != http.StatusForbidden {
		t.Fatalf("purge with a reveal token = %d, want 403", got)
	}
	if service.purgeCalls != 0 {
		t.Fatalf("the service purged without a valid token")
	}

	purgeToken, _, err := manager.IssueAction(credentials.SessionID, session.Action{Purpose: session.PurposePurgeTrashEntry, Subject: "20260805T090000.000-aabbccdd"})
	if err != nil {
		t.Fatalf("IssueAction error = %v", err)
	}
	if got := sendKeyRequest(t, engine, credentials, http.MethodDelete, "/api/v1/trash/20260805T090000.000-aabbccdd", nil, purgeToken).Code; got != http.StatusOK {
		t.Fatalf("purge = %d, want 200", got)
	}
	if service.purgeCalls != 1 {
		t.Fatalf("purgeCalls = %d, want 1", service.purgeCalls)
	}
}

func TestKeyRoutesRejectMissingCSRFAndUnknownFields(t *testing.T) {
	service := &stubKeyService{inventory: &keys.Inventory{}}
	engine, _, credentials := newKeyServer(t, service)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader([]byte(`{}`)))
	request.Host = testHost
	request.Header.Set(echo.HeaderOrigin, "http://"+testHost)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: credentials.SessionID})
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("generate without CSRF = %d, want 403", response.Code)
	}

	body := []byte(`{"algorithm":"ed25519","fileName":"id_work","comment":"aida@laptop","passphrase":"x","unencrypted":false,"surprise":1}`)
	if got := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys", body, "").Code; got != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", got)
	}
}

func TestAgentRejectionIsReportedWithASanitisedDetail(t *testing.T) {
	service := &stubKeyService{
		inventory:   &keys.Inventory{},
		registerErr: fmt.Errorf("%w: Bad passphrase for ~/.ssh/id_work", platform.ErrAgentRejected),
	}
	engine, _, credentials := newKeyServer(t, service)

	body := []byte(`{"passphrase":"wrong","lifetimeSeconds":0,"storeInKeychain":false}`)
	response := sendKeyRequest(t, engine, credentials, http.MethodPost, "/api/v1/keys/key-one/agent", body, "")
	if response.Code != http.StatusBadGateway {
		t.Fatalf("register = %d, want 502: %s", response.Code, response.Body.String())
	}
	var problemBody api.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problemBody); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problemBody.Code != "agent_rejected" || problemBody.Detail == nil {
		t.Fatalf("problem = %#v", problemBody)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("wrong")) {
		t.Fatalf("the response echoed the passphrase")
	}
}
```

- [ ] **Step 2: Run the handler test and verify the handlers are absent**

Run: `go test ./internal/httpserver -run "TestReveal|TestPermanentDelete|TestKeyRoutes|TestAgentRejection" -v`

Expected: FAIL with `undefined: registerKeyRoutes` and `undefined: KeyHandlers`.

- [ ] **Step 3: Add the detail-carrying problem helper**

Append to `internal/httpserver/security.go`:

```go
// problemDetail returns a rejection with a bounded explanation.
//
// Callers must pass either a fixed string or a message the platform layer has
// already sanitised. A detail must never carry key material, a passphrase, a
// session or action token, or an absolute path.
func problemDetail(c *echo.Context, status int, code, detail string) error {
	const detailLimit = 512
	if len(detail) > detailLimit {
		detail = detail[:detailLimit]
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
	return c.JSON(status, api.Problem{Code: code, Message: "request rejected", Detail: &detail})
}
```

- [ ] **Step 4: Implement the key vault handlers**

```go
// internal/httpserver/keys.go
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/api"
	"sshc/internal/keys"
	"sshc/internal/platform"
	"sshc/internal/session"
	"sshc/internal/storage"
)

// ActionHeader carries the one-time token that reveal and permanent delete
// require in addition to the session cookie and the CSRF header.
const ActionHeader = "X-SSHC-Action"

// maxKeyRequestBody bounds a key vault request body.
const maxKeyRequestBody = 64 << 10

var errBodyTooLarge = errors.New("request body is larger than the supported maximum")

// KeyService is the slice of the key vault the HTTP layer needs. Handler tests
// substitute a stub, so no handler test touches a filesystem, an agent or a
// child process.
type KeyService interface {
	Inventory() (*keys.Inventory, error)
	AgentIdentities(ctx context.Context) ([]platform.AgentIdentity, bool)
	Algorithms(ctx context.Context) keys.Catalogue
	Generate(request keys.GenerateRequest) (keys.GenerateResult, error)
	HardwareCommand(algorithm keys.Algorithm, fileName, comment string) ([]string, error)
	ChangePassphrase(change keys.PassphraseChange) (keys.PassphraseResult, error)
	Reveal(keyID string) (keys.RevealResult, error)
	Register(ctx context.Context, request keys.RegisterRequest) (keys.RegisterResult, error)
	Trash(keyID string) (keys.TrashResult, error)
	ListTrash() ([]keys.TrashEntry, error)
	Restore(entryID string) (keys.RestoreResult, error)
	Purge(entryID string) (keys.PurgeResult, error)
}

type KeyHandlers struct {
	Keys     KeyService
	Sessions *session.Manager
}

func registerKeyRoutes(engine *echo.Echo, handlers KeyHandlers) {
	engine.POST("/api/v1/actions", handlers.IssueAction)
	engine.GET("/api/v1/keys", handlers.List)
	engine.POST("/api/v1/keys", handlers.Generate)
	engine.GET("/api/v1/keys/algorithms", handlers.Algorithms)
	engine.POST("/api/v1/keys/hardware-command", handlers.HardwareCommand)
	engine.POST("/api/v1/keys/:keyId/passphrase", handlers.ChangePassphrase)
	engine.POST("/api/v1/keys/:keyId/reveal", handlers.Reveal)
	engine.POST("/api/v1/keys/:keyId/agent", handlers.Register)
	engine.POST("/api/v1/keys/:keyId/trash", handlers.Trash)
	engine.GET("/api/v1/trash", handlers.ListTrash)
	engine.POST("/api/v1/trash/:entryId/restore", handlers.Restore)
	engine.DELETE("/api/v1/trash/:entryId", handlers.Purge)
}

// decodeBody reads a bounded request body and overwrites the raw bytes.
//
// A passphrase decoded out of JSON becomes a Go string, which is immutable and
// cannot be erased; only the raw buffer can be. That limit is stated here
// rather than presented as a guarantee.
func decodeBody(c *echo.Context, target any) error {
	raw, err := io.ReadAll(io.LimitReader(c.Request().Body, maxKeyRequestBody+1))
	if err != nil {
		return err
	}
	defer wipeBuffer(raw)
	if len(raw) > maxKeyRequestBody {
		return errBodyTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func wipeBuffer(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}

func (h KeyHandlers) sessionID(c *echo.Context) string {
	value, _ := c.Get(SessionContextKey).(string)
	return value
}

// consumeAction spends the one-time token this operation requires. The boolean
// reports whether the caller may continue; when it is false the response has
// already been written.
func (h KeyHandlers) consumeAction(c *echo.Context, purpose, subject string) (bool, error) {
	if h.Sessions == nil {
		return false, problem(c, http.StatusForbidden, "action_token_required")
	}
	sessionID := h.sessionID(c)
	if sessionID == "" {
		return false, problem(c, http.StatusUnauthorized, "session_required")
	}
	presented := c.Request().Header.Get(ActionHeader)
	if presented == "" {
		return false, problem(c, http.StatusForbidden, "action_token_required")
	}
	err := h.Sessions.ConsumeAction(sessionID, presented, session.Action{Purpose: purpose, Subject: subject})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, session.ErrActionExpired):
		return false, problem(c, http.StatusForbidden, "action_token_expired")
	case errors.Is(err, session.ErrActionMismatch):
		return false, problem(c, http.StatusForbidden, "action_token_mismatch")
	default:
		return false, problem(c, http.StatusForbidden, "action_token_invalid")
	}
}

func (h KeyHandlers) IssueAction(c *echo.Context) error {
	var body api.IssueActionRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	if body.Purpose != session.PurposeRevealPrivateKey && body.Purpose != session.PurposePurgeTrashEntry {
		return problem(c, http.StatusBadRequest, "unknown_purpose")
	}
	sessionID := h.sessionID(c)
	if sessionID == "" {
		return problem(c, http.StatusUnauthorized, "session_required")
	}
	value, expiresAt, err := h.Sessions.IssueAction(sessionID, session.Action{Purpose: body.Purpose, Subject: body.Subject})
	if err != nil {
		return problem(c, http.StatusForbidden, "action_token_refused")
	}
	return c.JSON(http.StatusCreated, api.IssueActionResponse{
		Token:     value,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

func (h KeyHandlers) List(c *echo.Context) error {
	inventory, err := h.Keys.Inventory()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "inventory_failed")
	}
	identities, available := h.Keys.AgentIdentities(c.Request().Context())
	return c.JSON(http.StatusOK, inventoryResponse(inventory, identities, available))
}

func (h KeyHandlers) Algorithms(c *echo.Context) error {
	catalogue := h.Keys.Algorithms(c.Request().Context())
	response := api.KeyAlgorithmsResponse{
		Variants:   make([]api.KeyVariant, 0, len(catalogue.Variants)),
		Source:     catalogue.Source,
		Diagnostic: catalogue.Diagnostic,
	}
	for _, variant := range catalogue.Variants {
		response.Variants = append(response.Variants, api.KeyVariant{
			Algorithm: string(variant.Algorithm),
			Bits:      variant.Bits,
			Label:     variant.Label,
			InProcess: variant.InProcess,
			Reason:    variant.Reason,
		})
	}
	return c.JSON(http.StatusOK, response)
}

func (h KeyHandlers) Generate(c *echo.Context) error {
	var body api.GenerateKeyRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	result, err := h.Keys.Generate(keys.GenerateRequest{
		Algorithm:   keys.Algorithm(body.Algorithm),
		Bits:        optionalInt(body.Bits),
		FileName:    body.FileName,
		Comment:     body.Comment,
		Passphrase:  []byte(body.Passphrase),
		Unencrypted: body.Unencrypted,
	})
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusCreated, api.GenerateKeyResponse{
		Id:                 result.ID,
		RelativePath:       result.RelativePath,
		PublicRelativePath: result.PublicRelativePath,
		Fingerprint:        result.Fingerprint,
		KeyType:            result.KeyType,
		Bits:               result.Bits,
		Encrypted:          result.Encrypted,
		TransactionId:      result.TransactionID,
	})
}

func (h KeyHandlers) HardwareCommand(c *echo.Context) error {
	var body api.HardwareCommandRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	command, err := h.Keys.HardwareCommand(keys.Algorithm(body.Algorithm), body.FileName, body.Comment)
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.HardwareCommandResponse{
		Algorithm: body.Algorithm,
		Command:   command,
		Note:      "run_in_terminal",
	})
}

func (h KeyHandlers) ChangePassphrase(c *echo.Context) error {
	var body api.ChangePassphraseRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	result, err := h.Keys.ChangePassphrase(keys.PassphraseChange{
		KeyID:       c.Param("keyId"),
		Current:     []byte(body.CurrentPassphrase),
		New:         []byte(body.NewPassphrase),
		Unencrypted: body.Unencrypted,
	})
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.ChangePassphraseResponse{
		Id:            result.ID,
		RelativePath:  result.RelativePath,
		Encrypted:     result.Encrypted,
		Notes:         nonNilStrings(result.Notes),
		TransactionId: result.TransactionID,
	})
}

func (h KeyHandlers) Reveal(c *echo.Context) error {
	keyID := c.Param("keyId")
	if allowed, response := h.consumeAction(c, session.PurposeRevealPrivateKey, keyID); !allowed {
		return response
	}
	result, err := h.Keys.Reveal(keyID)
	if err != nil {
		return keyProblem(c, err)
	}
	defer keys.Wipe(result.Contents)
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, api.RevealPrivateKeyResponse{
		Id:            result.ID,
		RelativePath:  result.RelativePath,
		PrivateKey:    string(result.Contents),
		Encrypted:     result.Encrypted,
		Fingerprint:   result.Fingerprint,
		TransactionId: result.TransactionID,
	})
}

func (h KeyHandlers) Register(c *echo.Context) error {
	var body api.RegisterKeyRequest
	if err := decodeBody(c, &body); err != nil {
		return problem(c, http.StatusBadRequest, "invalid_request")
	}
	result, err := h.Keys.Register(c.Request().Context(), keys.RegisterRequest{
		KeyID:           c.Param("keyId"),
		Passphrase:      []byte(body.Passphrase),
		LifetimeSeconds: body.LifetimeSeconds,
		StoreInKeychain: body.StoreInKeychain,
	})
	if err != nil {
		return keyProblem(c, err)
	}
	identities := make([]api.AgentIdentity, 0, len(result.Identities))
	for _, identity := range result.Identities {
		identities = append(identities, api.AgentIdentity{
			Bits: identity.Bits, Fingerprint: identity.Fingerprint,
			Comment: identity.Comment, Algorithm: identity.Algorithm,
		})
	}
	return c.JSON(http.StatusOK, api.RegisterKeyResponse{
		Id:               result.ID,
		RelativePath:     result.RelativePath,
		Fingerprint:      result.Fingerprint,
		LifetimeSeconds:  result.LifetimeSeconds,
		StoredInKeychain: result.StoredInKeychain,
		Identities:       identities,
	})
}

func (h KeyHandlers) Trash(c *echo.Context) error {
	result, err := h.Keys.Trash(c.Param("keyId"))
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.TrashKeyResponse{
		EntryId:       result.EntryID,
		Files:         trashFiles(result.Files),
		Skipped:       nonNilStrings(result.Skipped),
		TransactionId: result.TransactionID,
	})
}

func (h KeyHandlers) ListTrash(c *echo.Context) error {
	entries, err := h.Keys.ListTrash()
	if err != nil {
		return problem(c, http.StatusInternalServerError, "trash_unreadable")
	}
	response := api.TrashListResponse{
		Entries:       make([]api.TrashEntrySummary, 0, len(entries)),
		RetentionDays: keys.TrashRetentionDays,
	}
	for _, entry := range entries {
		response.Entries = append(response.Entries, api.TrashEntrySummary{
			Id:         entry.ID,
			DeletedAt:  entry.DeletedAt.UTC().Format(time.RFC3339),
			AgeDays:    entry.AgeDays,
			Stale:      entry.Stale,
			Files:      trashFiles(entry.Files),
			Restorable: entry.Restorable,
			Blockers:   nonNilStrings(entry.Blockers),
		})
	}
	return c.JSON(http.StatusOK, response)
}

func (h KeyHandlers) Restore(c *echo.Context) error {
	result, err := h.Keys.Restore(c.Param("entryId"))
	response := api.RestoreTrashResponse{
		EntryId:       result.EntryID,
		Restored:      nonNilStrings(result.Restored),
		Blockers:      nonNilStrings(result.Blockers),
		TransactionId: result.TransactionID,
	}
	if errors.Is(err, keys.ErrRestoreBlocked) {
		return c.JSON(http.StatusConflict, response)
	}
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, response)
}

func (h KeyHandlers) Purge(c *echo.Context) error {
	entryID := c.Param("entryId")
	if allowed, response := h.consumeAction(c, session.PurposePurgeTrashEntry, entryID); !allowed {
		return response
	}
	result, err := h.Keys.Purge(entryID)
	if err != nil {
		return keyProblem(c, err)
	}
	return c.JSON(http.StatusOK, api.PurgeTrashResponse{
		EntryId:       result.EntryID,
		Removed:       nonNilStrings(result.Removed),
		TransactionId: result.TransactionID,
	})
}

// keyProblem maps a use-case error to the status and stable code the design's
// error classification calls for. The message never carries a secret.
func keyProblem(c *echo.Context, err error) error {
	switch {
	case errors.Is(err, keys.ErrUnknownKey), errors.Is(err, keys.ErrUnknownTrashEntry):
		return problem(c, http.StatusNotFound, "not_found")
	case errors.Is(err, keys.ErrInvalidFileName), errors.Is(err, keys.ErrInvalidComment):
		return problem(c, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, keys.ErrUnsupportedAlgorithm), errors.Is(err, keys.ErrUnsupportedBits):
		return problem(c, http.StatusBadRequest, "unsupported_algorithm")
	case errors.Is(err, keys.ErrHardwareAlgorithm):
		return problem(c, http.StatusBadRequest, "hardware_algorithm")
	case errors.Is(err, keys.ErrPassphraseRequired):
		return problem(c, http.StatusBadRequest, "passphrase_required")
	case errors.Is(err, keys.ErrConflictingPassphraseChoice):
		return problem(c, http.StatusBadRequest, "conflicting_passphrase_choice")
	case errors.Is(err, keys.ErrWrongPassphrase):
		return problem(c, http.StatusForbidden, "wrong_passphrase")
	case errors.Is(err, platform.ErrAgentUnavailable):
		return problem(c, http.StatusBadGateway, "agent_unavailable")
	case errors.Is(err, platform.ErrAgentRejected):
		return problemDetail(c, http.StatusBadGateway, "agent_rejected", err.Error())
	case errors.Is(err, storage.ErrMoveTargetExists), errors.Is(err, keys.ErrTrashNameConflict):
		return problem(c, http.StatusConflict, "name_conflict")
	}
	var conflict *storage.ConflictError
	if errors.As(err, &conflict) {
		return problem(c, http.StatusConflict, "external_change")
	}
	return problem(c, http.StatusInternalServerError, "operation_failed")
}

func inventoryResponse(inventory *keys.Inventory, identities []platform.AgentIdentity, agentAvailable bool) api.KeyInventoryResponse {
	response := api.KeyInventoryResponse{
		Items:                make([]api.KeyItem, 0, len(inventory.Items)),
		Unreadable:           make([]api.UnreadableFile, 0, len(inventory.Unreadable)),
		AgentDelegations:     referenceList(inventory.AgentDelegations),
		UnresolvedReferences: make([]api.UnresolvedReference, 0, len(inventory.UnresolvedReferences)),
		AgentAvailable:       agentAvailable,
		AgentIdentities:      make([]api.AgentIdentity, 0, len(identities)),
	}
	for _, item := range inventory.Items {
		response.Items = append(response.Items, keyItem(item))
	}
	for _, unreadable := range inventory.Unreadable {
		response.Unreadable = append(response.Unreadable, api.UnreadableFile{
			RelativePath: unreadable.RelativePath, Reason: unreadable.Reason,
		})
	}
	for _, unresolved := range inventory.UnresolvedReferences {
		response.UnresolvedReferences = append(response.UnresolvedReferences, api.UnresolvedReference{
			Directive: unresolved.Directive, Value: unresolved.Value,
			ConfigPath: unresolved.ConfigPath, Line: unresolved.Line, Reason: unresolved.Reason,
		})
	}
	for _, identity := range identities {
		response.AgentIdentities = append(response.AgentIdentities, api.AgentIdentity{
			Bits: identity.Bits, Fingerprint: identity.Fingerprint,
			Comment: identity.Comment, Algorithm: identity.Algorithm,
		})
	}
	return response
}

func keyItem(item keys.Item) api.KeyItem {
	converted := api.KeyItem{
		Id:             item.ID,
		RelativePath:   item.RelativePath,
		Kind:           string(item.Kind),
		Container:      item.Container,
		Algorithm:      string(item.Algorithm),
		KeyType:        item.KeyType,
		Bits:           item.Bits,
		Encrypted:      item.Encrypted,
		Fingerprint:    item.Fingerprint,
		Comment:        item.Comment,
		Permission:     item.Permission,
		PermissionRisk: item.PermissionRisk,
		SizeBytes:      int(item.SizeBytes),
		References:     referenceList(item.References),
		Notes:          nonNilStrings(item.Notes),
	}
	if item.Certificate != nil {
		validBefore, neverExpires := certificateExpiry(item.Certificate.ValidBefore)
		converted.Certificate = &api.KeyCertificate{
			KeyId:                item.Certificate.KeyID,
			Principals:           nonNilStrings(item.Certificate.Principals),
			ValidBefore:          validBefore,
			NeverExpires:         neverExpires,
			SignedKeyType:        item.Certificate.SignedKeyType,
			SignedKeyFingerprint: item.Certificate.SignedKeyFingerprint,
		}
	}
	return converted
}

// certificateExpiry converts OpenSSH's unsigned validity bound. OpenSSH spells
// "never expires" as 2^64-1, which does not fit a signed integer, so that case
// is reported as a flag rather than wrapped into a negative number.
func certificateExpiry(validBefore uint64) (int, bool) {
	if validBefore > uint64(math.MaxInt64) {
		return 0, true
	}
	return int(validBefore), false
}

func referenceList(references []keys.Reference) []api.KeyReference {
	converted := make([]api.KeyReference, 0, len(references))
	for _, reference := range references {
		converted = append(converted, api.KeyReference{
			Directive:    reference.Directive,
			ConfigPath:   reference.ConfigPath,
			Line:         reference.Line,
			Condition:    reference.Condition,
			HostPatterns: nonNilStrings(reference.HostPatterns),
			Value:        reference.Value,
		})
	}
	return converted
}

func trashFiles(files []keys.TrashFile) []api.TrashFileSummary {
	converted := make([]api.TrashFileSummary, 0, len(files))
	for _, file := range files {
		converted = append(converted, api.TrashFileSummary{
			OriginalRelativePath: file.OriginalRelativePath,
			TrashRelativePath:    file.TrashRelativePath,
			Kind:                 string(file.Kind),
			Fingerprint:          file.Fingerprint,
			Permission:           file.Permission,
		})
	}
	return converted
}

// nonNilStrings keeps every JSON array an array instead of null.
func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func optionalInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
```

- [ ] **Step 5: Register the routes and wire the process**

In `internal/httpserver/server.go`, add `Keys KeyService` to `Options` and register the routes after the health route:

```go
	if options.Keys != nil {
		registerKeyRoutes(e, KeyHandlers{Keys: options.Keys, Sessions: options.Sessions})
	}
```

In `internal/app/run.go`, add `"time"`, `"sshc/internal/keys"` and `"sshc/internal/storage"` to the import block, then extend `Dependencies` and build the key vault when a home directory is supplied:

```go
type Dependencies struct {
	Random   io.Reader
	Browser  platform.BrowserLauncher
	Listen   ListenFunc
	UI       fs.FS
	Logger   *slog.Logger
	Home     string
	Executor platform.CommandExecutor
	KeyAgent platform.KeyAgent
}
```

```go
// buildKeyService prepares the key vault. An empty Home leaves it nil, so the
// key routes are simply absent and the process still serves the shell; the
// committed process tests rely on that.
func buildKeyService(dependencies Dependencies) (httpserver.KeyService, int, error) {
	if dependencies.Home == "" {
		return nil, 0, nil
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, dependencies.Home)
	if err != nil {
		return nil, 0, err
	}
	transactions := storage.NewManager(workspace, time.Now, dependencies.Random)
	pending, err := transactions.Pending()
	if err != nil {
		return nil, 0, err
	}
	return keys.NewService(keys.ServiceOptions{
		Workspace:    workspace,
		Transactions: transactions,
		Resolver:     storage.NewResolver(workspace),
		Catalogue:    keys.CatalogueReader{Executor: dependencies.Executor},
		Agent:        dependencies.KeyAgent,
		Now:          time.Now,
		Random:       dependencies.Random,
	}), len(pending), nil
}
```

Inside `Run`, after the session manager is created and before `httpserver.New`:

```go
	keyService, pendingCount, err := buildKeyService(dependencies)
	if err != nil {
		listener.Close()
		return fmt.Errorf("key vault: %w", err)
	}
	if pendingCount > 0 && dependencies.Logger != nil {
		// Report only the count. A partial state must never be hidden, and a
		// log line must never name a path. The recovery screen that lets the
		// user complete or roll back belongs to a later subsystem.
		dependencies.Logger.Warn("interrupted transactions found", "count", pendingCount)
	}
```

and pass `Keys: keyService` in the `httpserver.Options` literal.

In `cmd/sshc/main.go`, build the executor and agent next to the existing browser:

```go
	executor := macos.NewExecutor(macos.OSLookup)
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Error("resolve home directory", "error", err)
		os.Exit(1)
	}
	dependencies := app.Dependencies{
		Random:   rand.Reader,
		Browser:  macos.NewBrowser(macos.NewExecRunner()),
		Listen:   net.Listen,
		UI:       assets,
		Logger:   logger,
		Home:     home,
		Executor: executor,
		KeyAgent: macos.NewKeyAgent(executor, macos.OSLookup),
	}
```

- [ ] **Step 6: Add the process test for the new wiring**

```go
// internal/app/run_test.go  (append)

func TestRunExposesTheKeyVaultWhenAHomeDirectoryIsSupplied(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("create ssh directory: %v", err)
	}
	opened := make(chan string, 1)
	dependencies := Dependencies{
		Random: bytes.NewReader(bytes.Repeat([]byte{0x31}, 4096)),
		Browser: browserFunc(func(_ context.Context, target string) error {
			opened <- target
			return nil
		}),
		Listen:   net.Listen,
		UI:       fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:     home,
		Executor: stubExecutor{},
		KeyAgent: stubKeyAgent{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, dependencies, "test") }()

	target := <-opened
	base, _, _ := strings.Cut(target, "/#")
	bootstrapToken := target[strings.Index(target, "bootstrap=")+len("bootstrap="):]

	client := &http.Client{}
	bootstrapRequest, err := http.NewRequest(http.MethodPost, base+"/api/v1/session/bootstrap", nil)
	if err != nil {
		t.Fatalf("build bootstrap request: %v", err)
	}
	bootstrapRequest.Header.Set("Origin", base)
	bootstrapRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	bootstrapRequest.Header.Set("X-SSHC-Bootstrap", bootstrapToken)
	bootstrapResponse, err := client.Do(bootstrapRequest)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	cookies := bootstrapResponse.Cookies()
	bootstrapResponse.Body.Close()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}

	keysRequest, err := http.NewRequest(http.MethodGet, base+"/api/v1/keys", nil)
	if err != nil {
		t.Fatalf("build keys request: %v", err)
	}
	keysRequest.AddCookie(cookies[0])
	keysResponse, err := client.Do(keysRequest)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	defer keysResponse.Body.Close()
	if keysResponse.StatusCode != http.StatusOK {
		t.Fatalf("list keys = %d, want 200", keysResponse.StatusCode)
	}
	if got := keysResponse.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run error = %v", err)
	}
}

type stubExecutor struct{}

func (stubExecutor) Execute(context.Context, platform.Command) (platform.CommandResult, error) {
	return platform.CommandResult{Stdout: []byte("ssh-ed25519\n")}, nil
}

type stubKeyAgent struct{}

func (stubKeyAgent) Available(context.Context) bool { return false }
func (stubKeyAgent) List(context.Context) ([]platform.AgentIdentity, error) {
	return nil, platform.ErrAgentUnavailable
}
func (stubKeyAgent) Add(context.Context, platform.AgentAddRequest) error {
	return platform.ErrAgentUnavailable
}
func (stubKeyAgent) Remove(context.Context, string) error { return platform.ErrAgentUnavailable }
```

Add `os`, `path/filepath`, `strings`, `net/http` and `sshc/internal/platform` to the `internal/app/run_test.go` import block if they are not already present.

- [ ] **Step 7: Run every Go check**

Run:

```bash
go test ./... 
go test -race ./...
go vet ./...
```

Expected: PASS. Reveal and permanent delete are refused without a matching, unexpired, single-use action token; a missing CSRF header is refused before any handler runs; an unknown JSON field is refused; the agent rejection reaches the client as a `502` with a sanitised detail and no passphrase.

- [ ] **Step 8: Commit the HTTP surface**

```bash
git add internal/httpserver internal/app cmd/sshc/main.go
git commit -m "feat: expose the key vault over the localhost API"
```

## Task 9: Keys screen, documentation and subsystem verification

**Files:**
- Modify: `web/src/api/client.ts`
- Create: `web/src/keys/api.ts`
- Create: `web/src/keys/RevealDialog.tsx`
- Create: `web/src/keys/RevealDialog.test.tsx`
- Create: `web/src/keys/KeysScreen.tsx`
- Create: `web/src/keys/KeysScreen.test.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/App.test.tsx`
- Modify: `web/src/main.tsx`
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 7's generated `components["schemas"][…]` TypeScript definitions.
- Consumes: Task 8's routes and the `X-SSHC-Action` header.
- Produces: `apiClient.read<T>(path)` and `apiClient.send(path, init)` alongside the committed `health`, `mutate`, `setCSRF` and `clear`.
- Produces: `keys/api.ts` exporting `KeysApi`, `keysApi`, `GenerateKeyInput`, `REVEAL_PURPOSE`, `PURGE_PURPOSE` and the response type aliases.
- Produces: `RevealDialog` and `KeysScreen` React components.
- Produces: `App` accepting a `keysApi: KeysApi` prop and enabling only the `Keys` navigation entry.

The screen is self-contained: it renders inside the committed App shell's main panel and reads nothing from the Connections work that roadmap subsystem 3 is planning in parallel.

- [ ] **Step 1: Extend the API client**

Replace `web/src/api/client.ts` with:

```ts
import type { components } from "./schema";

export type HealthResponse = components["schemas"]["HealthResponse"];

function validateHealth(value: unknown): HealthResponse {
  if (typeof value !== "object" || value === null) {
    throw new Error("invalid_health_response");
  }

  const record = value as Record<string, unknown>;
  if (record.status !== "ok" || typeof record.version !== "string" || record.version.length === 0) {
    throw new Error("invalid_health_response");
  }
  return { status: "ok", version: record.version };
}

let csrfToken: string | null = null;

async function sendMutation(path: string, init: RequestInit): Promise<Response> {
  const target = new URL(path, window.location.origin);
  if (target.origin !== window.location.origin) {
    throw new Error("cross_origin_api_mutation");
  }
  if (!csrfToken) throw new Error("csrf_unavailable");

  const headers = new Headers(init.headers);
  headers.set("X-SSHC-CSRF", csrfToken);
  return fetch(path, { ...init, credentials: "same-origin", headers });
}

export const apiClient = {
  setCSRF(token: string) {
    csrfToken = token;
  },
  clear() {
    csrfToken = null;
  },
  async health(): Promise<HealthResponse> {
    const response = await fetch("/api/v1/health", { credentials: "same-origin" });
    if (!response.ok) throw new Error("health_failed");
    return validateHealth(await response.json());
  },
  async read<T>(path: string): Promise<T> {
    const response = await fetch(path, { credentials: "same-origin" });
    if (!response.ok) throw new Error("api_read_failed");
    return (await response.json()) as T;
  },
  // send returns the raw response so a caller can read a body that accompanies
  // a rejection, such as the blockers on a refused restore.
  send: sendMutation,
  async mutate<T>(path: string, init: RequestInit): Promise<T> {
    const response = await sendMutation(path, init);
    if (!response.ok) throw new Error("api_mutation_failed");
    return (await response.json()) as T;
  },
};
```

- [ ] **Step 2: Add the typed key vault client**

```ts
// web/src/keys/api.ts
import { apiClient } from "../api/client";
import type { components } from "../api/schema";

export type KeyItem = components["schemas"]["KeyItem"];
export type KeyInventoryResponse = components["schemas"]["KeyInventoryResponse"];
export type KeyAlgorithmsResponse = components["schemas"]["KeyAlgorithmsResponse"];
export type GenerateKeyResponse = components["schemas"]["GenerateKeyResponse"];
export type HardwareCommandResponse = components["schemas"]["HardwareCommandResponse"];
export type ChangePassphraseResponse = components["schemas"]["ChangePassphraseResponse"];
export type RevealPrivateKeyResponse = components["schemas"]["RevealPrivateKeyResponse"];
export type IssueActionResponse = components["schemas"]["IssueActionResponse"];
export type TrashListResponse = components["schemas"]["TrashListResponse"];
export type TrashKeyResponse = components["schemas"]["TrashKeyResponse"];
export type RestoreTrashResponse = components["schemas"]["RestoreTrashResponse"];
export type PurgeTrashResponse = components["schemas"]["PurgeTrashResponse"];

export const REVEAL_PURPOSE = "reveal_private_key";
export const PURGE_PURPOSE = "purge_trash_entry";

export type GenerateKeyInput = {
  algorithm: string;
  fileName: string;
  comment: string;
  passphrase: string;
  unencrypted: boolean;
  bits?: number;
};

export type HardwareCommandInput = {
  algorithm: string;
  fileName: string;
  comment: string;
};

export type PassphraseInput = {
  currentPassphrase: string;
  newPassphrase: string;
  unencrypted: boolean;
};

export type KeysApi = {
  inventory(): Promise<KeyInventoryResponse>;
  algorithms(): Promise<KeyAlgorithmsResponse>;
  generate(input: GenerateKeyInput): Promise<GenerateKeyResponse>;
  hardwareCommand(input: HardwareCommandInput): Promise<HardwareCommandResponse>;
  changePassphrase(keyId: string, input: PassphraseInput): Promise<ChangePassphraseResponse>;
  reveal(keyId: string): Promise<RevealPrivateKeyResponse>;
  trash(keyId: string): Promise<TrashKeyResponse>;
  listTrash(): Promise<TrashListResponse>;
  restore(entryId: string): Promise<RestoreTrashResponse>;
  purge(entryId: string): Promise<PurgeTrashResponse>;
};

const jsonHeaders = { "Content-Type": "application/json" } as const;

// issueAction mints the one-time token the server requires for reveal and for
// permanent delete. The token is used immediately and is never stored.
async function issueAction(purpose: string, subject: string): Promise<string> {
  const response = await apiClient.mutate<IssueActionResponse>("/api/v1/actions", {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ purpose, subject }),
  });
  return response.token;
}

export const keysApi: KeysApi = {
  inventory: () => apiClient.read<KeyInventoryResponse>("/api/v1/keys"),
  algorithms: () => apiClient.read<KeyAlgorithmsResponse>("/api/v1/keys/algorithms"),
  generate: (input) =>
    apiClient.mutate<GenerateKeyResponse>("/api/v1/keys", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify(input),
    }),
  hardwareCommand: (input) =>
    apiClient.mutate<HardwareCommandResponse>("/api/v1/keys/hardware-command", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify(input),
    }),
  changePassphrase: (keyId, input) =>
    apiClient.mutate<ChangePassphraseResponse>(`/api/v1/keys/${encodeURIComponent(keyId)}/passphrase`, {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify(input),
    }),
  async reveal(keyId) {
    const token = await issueAction(REVEAL_PURPOSE, keyId);
    return apiClient.mutate<RevealPrivateKeyResponse>(`/api/v1/keys/${encodeURIComponent(keyId)}/reveal`, {
      method: "POST",
      headers: { "X-SSHC-Action": token },
    });
  },
  trash: (keyId) =>
    apiClient.mutate<TrashKeyResponse>(`/api/v1/keys/${encodeURIComponent(keyId)}/trash`, { method: "POST" }),
  listTrash: () => apiClient.read<TrashListResponse>("/api/v1/trash"),
  async restore(entryId) {
    const response = await apiClient.send(`/api/v1/trash/${encodeURIComponent(entryId)}/restore`, { method: "POST" });
    if (!response.ok && response.status !== 409) {
      throw new Error("api_mutation_failed");
    }
    return (await response.json()) as RestoreTrashResponse;
  },
  async purge(entryId) {
    const token = await issueAction(PURGE_PURPOSE, entryId);
    return apiClient.mutate<PurgeTrashResponse>(`/api/v1/trash/${encodeURIComponent(entryId)}`, {
      method: "DELETE",
      headers: { "X-SSHC-Action": token },
    });
  },
};
```

- [ ] **Step 3: Write the failing reveal dialog test**

```tsx
// web/src/keys/RevealDialog.test.tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { RevealDialog } from "./RevealDialog";

const privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n";

describe("RevealDialog", () => {
  it("shows nothing until the user confirms and states what it cannot protect", async () => {
    const reveal = vi.fn().mockResolvedValue({
      id: "key-one",
      relativePath: "id_work",
      privateKey,
      encrypted: true,
      fingerprint: "SHA256:abcdef",
      transactionId: "tx",
    });
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={vi.fn()} />);

    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
    expect(screen.getByRole("dialog")).toHaveTextContent("browser extensions");
    expect(reveal).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));

    expect(await screen.findByLabelText("Private key")).toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
    expect(reveal).toHaveBeenCalledTimes(1);
  });

  it("drops the key material and never stores it when the dialog closes", async () => {
    const setLocal = vi.spyOn(Storage.prototype, "setItem");
    const onClose = vi.fn();
    const reveal = vi.fn().mockResolvedValue({
      id: "key-one",
      relativePath: "id_work",
      privateKey,
      encrypted: true,
      fingerprint: "SHA256:abcdef",
      transactionId: "tx",
    });
    const { unmount } = render(
      <RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={onClose} />,
    );

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));
    expect(await screen.findByLabelText("Private key")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(screen.queryByLabelText("Private key")).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");

    unmount();
    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
    expect(setLocal).not.toHaveBeenCalled();
  });

  it("reports a failed reveal without leaving stale material behind", async () => {
    const reveal = vi.fn().mockRejectedValue(new Error("api_mutation_failed"));
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("could not be shown");
    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
  });
});
```

- [ ] **Step 4: Run the dialog test and verify the component is absent**

Run: `npm test --prefix web -- RevealDialog`

Expected: FAIL — the module `./RevealDialog` cannot be resolved.

- [ ] **Step 5: Implement the reveal dialog**

```tsx
// web/src/keys/RevealDialog.tsx
import { useState } from "react";
import type { KeysApi } from "./api";

type RevealDialogProps = {
  keyId: string;
  relativePath: string;
  api: Pick<KeysApi, "reveal">;
  onClose: () => void;
};

type DialogState = "confirm" | "loading" | "shown" | "error";

// RevealDialog holds private key material in one component state value and in
// nothing else. It writes to no storage, no global object, no logger and no
// analytics sink, and it drops its reference when the dialog closes.
//
// It deliberately does not claim to protect the key from a browser extension or
// from a clipboard history tool, because it cannot.
export function RevealDialog({ keyId, relativePath, api, onClose }: RevealDialogProps) {
  const [state, setState] = useState<DialogState>("confirm");
  const [material, setMaterial] = useState("");

  function close() {
    setMaterial("");
    setState("confirm");
    onClose();
  }

  async function confirm() {
    setState("loading");
    try {
      const response = await api.reveal(keyId);
      setMaterial(response.privateKey);
      setState("shown");
    } catch {
      setMaterial("");
      setState("error");
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="reveal-heading"
      className="mt-6 rounded-xl border border-amber-700 bg-zinc-900 p-6"
    >
      <h3 id="reveal-heading" className="font-medium">
        Show private key: {relativePath}
      </h3>
      {state === "confirm" && (
        <>
          <p className="mt-2 text-sm text-zinc-300">
            The private key will be displayed in this page and can be copied by anyone who can read this
            window. This application cannot protect it from browser extensions or from clipboard history
            tools. Every reveal is recorded in history, without the key itself.
          </p>
          <button
            type="button"
            className="mt-4 rounded-md border border-amber-600 px-3 py-2"
            onClick={() => void confirm()}
          >
            Show private key
          </button>
        </>
      )}
      {state === "loading" && (
        <p role="status" className="mt-2 text-sm text-zinc-300">
          Requesting a one-time confirmation…
        </p>
      )}
      {state === "shown" && (
        <pre aria-label="Private key" className="mt-4 overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
          {material}
        </pre>
      )}
      {state === "error" && (
        <p role="alert" className="mt-2 text-sm text-red-300">
          The private key could not be shown. Close this dialog and confirm again.
        </p>
      )}
      <button type="button" className="mt-4 ml-0 rounded-md border border-zinc-700 px-3 py-2" onClick={close}>
        Close
      </button>
    </div>
  );
}
```

- [ ] **Step 6: Write the failing Keys screen test**

```tsx
// web/src/keys/KeysScreen.test.tsx
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { KeysScreen } from "./KeysScreen";
import type { KeysApi } from "./api";

function buildApi(overrides: Partial<KeysApi> = {}): KeysApi {
  return {
    inventory: vi.fn().mockResolvedValue({
      items: [
        {
          id: "key-one",
          relativePath: "id_work",
          kind: "private_key",
          container: "OPENSSH PRIVATE KEY",
          algorithm: "ed25519",
          keyType: "ssh-ed25519",
          bits: 256,
          encrypted: true,
          fingerprint: "SHA256:abcdef",
          comment: "aida@laptop",
          permission: "0600",
          permissionRisk: false,
          sizeBytes: 444,
          references: [
            {
              directive: "IdentityFile",
              configPath: "/home/.ssh/config",
              line: 2,
              condition: "Host build-*",
              hostPatterns: ["build-*"],
              value: "~/.ssh/id_work",
            },
          ],
          notes: [],
        },
        {
          id: "key-two",
          relativePath: "legacy",
          kind: "private_key",
          container: "RSA PRIVATE KEY",
          algorithm: "rsa",
          keyType: "ssh-rsa",
          bits: 2048,
          encrypted: true,
          fingerprint: "",
          comment: "",
          permission: "0644",
          permissionRisk: true,
          sizeBytes: 1700,
          references: [],
          notes: ["fingerprint_unavailable"],
        },
      ],
      unreadable: [],
      agentDelegations: [],
      unresolvedReferences: [],
      agentAvailable: false,
      agentIdentities: [],
    }),
    algorithms: vi.fn().mockResolvedValue({
      variants: [
        { algorithm: "ed25519", bits: 256, label: "Ed25519", inProcess: true, reason: "" },
        { algorithm: "ed25519-sk", bits: 0, label: "Ed25519 security key", inProcess: false, reason: "hardware_token_required" },
      ],
      source: "ssh -Q key",
      diagnostic: "",
    }),
    generate: vi.fn(),
    hardwareCommand: vi.fn().mockResolvedValue({
      algorithm: "ed25519-sk",
      command: ["ssh-keygen", "-t", "ed25519-sk", "-f", "/home/.ssh/id_yubikey"],
      note: "run_in_terminal",
    }),
    changePassphrase: vi.fn(),
    reveal: vi.fn(),
    trash: vi.fn().mockResolvedValue({ entryId: "entry-1", files: [], skipped: [], transactionId: "tx" }),
    listTrash: vi.fn().mockResolvedValue({
      entries: [
        {
          id: "20260805T090000.000-aabbccdd",
          deletedAt: "2026-08-05T09:00:00Z",
          ageDays: 40,
          stale: true,
          files: [
            {
              originalRelativePath: "id_old",
              trashRelativePath: "sshc/trash/20260805T090000.000-aabbccdd/id_old",
              kind: "private_key",
              fingerprint: "SHA256:012345",
              permission: "0600",
            },
          ],
          restorable: true,
          blockers: [],
        },
      ],
      retentionDays: 30,
    }),
    restore: vi.fn().mockResolvedValue({ entryId: "20260805T090000.000-aabbccdd", restored: ["id_old"], blockers: [], transactionId: "tx" }),
    purge: vi.fn().mockResolvedValue({ entryId: "20260805T090000.000-aabbccdd", removed: ["id_old"], transactionId: "tx" }),
    ...overrides,
  };
}

describe("KeysScreen", () => {
  it("lists classified files with fingerprint, permissions and referencing Hosts", async () => {
    render(<KeysScreen api={buildApi()} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    expect(within(workRow).getByText("SHA256:abcdef")).toBeInTheDocument();
    expect(within(workRow).getByText("ed25519 · 256")).toBeInTheDocument();
    expect(within(workRow).getByText("0600")).toBeInTheDocument();
    expect(within(workRow).getByText("build-*")).toBeInTheDocument();

    const legacyRow = screen.getByRole("row", { name: /legacy/ });
    expect(within(legacyRow).getByText("Permissions too open")).toBeInTheDocument();
    expect(within(legacyRow).getByText("Fingerprint unavailable")).toBeInTheDocument();
  });

  it("shows the exact ssh-keygen command for a hardware method instead of generating", async () => {
    const api = buildApi();
    render(<KeysScreen api={api} />);

    await screen.findByRole("row", { name: /id_work/ });
    await userEvent.selectOptions(screen.getByLabelText("Algorithm"), "ed25519-sk");
    await userEvent.type(screen.getByLabelText("File name"), "id_yubikey");
    await userEvent.click(screen.getByRole("button", { name: "Show Terminal command" }));

    expect(await screen.findByLabelText("Terminal command")).toHaveTextContent(
      "ssh-keygen -t ed25519-sk -f /home/.ssh/id_yubikey",
    );
    expect(api.generate).not.toHaveBeenCalled();
  });

  it("changes a passphrase and keeps nothing in the form afterwards", async () => {
    const changePassphrase = vi.fn().mockResolvedValue({
      id: "key-one",
      relativePath: "id_work",
      encrypted: true,
      notes: [],
      transactionId: "tx",
    });
    const api = buildApi({ changePassphrase });
    render(<KeysScreen api={api} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    await userEvent.click(within(workRow).getByRole("button", { name: "Change passphrase" }));

    await userEvent.type(screen.getByLabelText("Current passphrase"), "first passphrase");
    await userEvent.type(screen.getByLabelText("New passphrase"), "second passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Save new passphrase" }));

    await waitFor(() =>
      expect(changePassphrase).toHaveBeenCalledWith("key-one", {
        currentPassphrase: "first passphrase",
        newPassphrase: "second passphrase",
        unencrypted: false,
      }),
    );
    await waitFor(() => expect(screen.queryByLabelText("Current passphrase")).not.toBeInTheDocument());

    const reopened = await screen.findByRole("row", { name: /id_work/ });
    await userEvent.click(within(reopened).getByRole("button", { name: "Change passphrase" }));
    expect(screen.getByLabelText("Current passphrase")).toHaveValue("");
    expect(screen.getByLabelText("New passphrase")).toHaveValue("");
  });

  it("requires a second confirmation before a permanent delete", async () => {
    const api = buildApi();
    render(<KeysScreen api={api} />);

    const trashRow = await screen.findByRole("row", { name: /id_old/ });
    await userEvent.click(within(trashRow).getByRole("button", { name: "Delete permanently" }));
    expect(api.purge).not.toHaveBeenCalled();

    expect(within(trashRow).getByText(/cannot be undone/)).toBeInTheDocument();
    await userEvent.click(within(trashRow).getByRole("button", { name: "Confirm permanent delete" }));
    await waitFor(() => expect(api.purge).toHaveBeenCalledWith("20260805T090000.000-aabbccdd"));
  });

  it("shows a refused restore as blockers instead of guessing", async () => {
    const api = buildApi({
      restore: vi.fn().mockResolvedValue({
        entryId: "20260805T090000.000-aabbccdd",
        restored: [],
        blockers: ["restore_path_occupied:id_old"],
        transactionId: "",
      }),
    });
    render(<KeysScreen api={api} />);

    const trashRow = await screen.findByRole("row", { name: /id_old/ });
    await userEvent.click(within(trashRow).getByRole("button", { name: "Restore" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("restore_path_occupied:id_old");
  });

  it("marks a trash entry older than the retention window without deleting it", async () => {
    render(<KeysScreen api={buildApi()} />);

    const trashRow = await screen.findByRole("row", { name: /id_old/ });
    expect(within(trashRow).getByText("40 days · older than 30 days")).toBeInTheDocument();
    expect(within(trashRow).getByRole("button", { name: "Restore" })).toBeEnabled();
  });
});
```

- [ ] **Step 7: Implement the Keys screen**

```tsx
// web/src/keys/KeysScreen.tsx
import { useCallback, useEffect, useState } from "react";
import { RevealDialog } from "./RevealDialog";
import type { KeyInventoryResponse, KeyItem, KeysApi, TrashListResponse } from "./api";

type KeysScreenProps = { api: KeysApi };

type ScreenState = "loading" | "ready" | "error";

const noteLabels: Record<string, string> = {
  fingerprint_unavailable: "Fingerprint unavailable",
  symbolic_link: "Symbolic link, not followed",
  empty_file: "Empty file",
  not_regular_file: "Not a regular file",
  comment_not_preserved: "Comment not preserved",
};

export function KeysScreen({ api }: KeysScreenProps) {
  const [state, setState] = useState<ScreenState>("loading");
  const [inventory, setInventory] = useState<KeyInventoryResponse | null>(null);
  const [trash, setTrash] = useState<TrashListResponse | null>(null);
  const [algorithm, setAlgorithm] = useState("ed25519");
  const [fileName, setFileName] = useState("");
  const [comment, setComment] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [unencrypted, setUnencrypted] = useState(false);
  const [terminalCommand, setTerminalCommand] = useState<string[] | null>(null);
  const [revealing, setRevealing] = useState<KeyItem | null>(null);
  const [changingPassphrase, setChangingPassphrase] = useState<KeyItem | null>(null);
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [removePassphrase, setRemovePassphrase] = useState(false);
  const [pendingPurge, setPendingPurge] = useState("");
  const [failure, setFailure] = useState("");
  const [variants, setVariants] = useState<KeyInventoryVariants>([]);

  const refresh = useCallback(async () => {
    try {
      const [nextInventory, nextTrash, nextAlgorithms] = await Promise.all([
        api.inventory(),
        api.listTrash(),
        api.algorithms(),
      ]);
      setInventory(nextInventory);
      setTrash(nextTrash);
      setVariants(nextAlgorithms.variants);
      setState("ready");
    } catch {
      setState("error");
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selected = variants.find((variant) => variant.algorithm === algorithm);

  async function submitGeneration() {
    setFailure("");
    setTerminalCommand(null);
    try {
      if (selected && !selected.inProcess) {
        const response = await api.hardwareCommand({ algorithm, fileName, comment });
        setTerminalCommand(response.command);
        return;
      }
      await api.generate({
        algorithm,
        bits: selected?.bits ?? 0,
        fileName,
        comment,
        passphrase,
        unencrypted,
      });
      setPassphrase("");
      setFileName("");
      await refresh();
    } catch {
      setPassphrase("");
      setFailure("The key could not be created. Check the name, the algorithm and the passphrase.");
    }
  }

  function closePassphraseForm() {
    setCurrentPassphrase("");
    setNewPassphrase("");
    setRemovePassphrase(false);
    setChangingPassphrase(null);
  }

  // The passphrase lives in component state for the duration of one submit and
  // is cleared on success and on failure. It is never stored anywhere else.
  async function submitPassphrase(item: KeyItem) {
    setFailure("");
    try {
      await api.changePassphrase(item.id, {
        currentPassphrase,
        newPassphrase: removePassphrase ? "" : newPassphrase,
        unencrypted: removePassphrase,
      });
      closePassphraseForm();
      await refresh();
    } catch {
      setCurrentPassphrase("");
      setNewPassphrase("");
      setFailure("The passphrase could not be changed. Check the current passphrase and try again.");
    }
  }

  async function moveToTrash(keyId: string) {
    setFailure("");
    try {
      await api.trash(keyId);
      await refresh();
    } catch {
      setFailure("The key could not be moved to the trash.");
    }
  }

  async function restore(entryId: string) {
    setFailure("");
    try {
      const response = await api.restore(entryId);
      if (response.blockers.length > 0) {
        setFailure(`Restore refused: ${response.blockers.join(", ")}`);
        return;
      }
      await refresh();
    } catch {
      setFailure("The entry could not be restored.");
    }
  }

  async function purge(entryId: string) {
    setFailure("");
    try {
      await api.purge(entryId);
      setPendingPurge("");
      await refresh();
    } catch {
      setFailure("The entry could not be deleted permanently.");
    }
  }

  if (state === "loading") {
    return <p role="status">Reading the ssh directory…</p>;
  }
  if (state === "error" || inventory === null || trash === null) {
    return <p role="alert">The ssh directory could not be read. Restart sshc and try again.</p>;
  }

  return (
    <section aria-labelledby="keys-heading" className="space-y-8">
      <h2 id="keys-heading" className="text-lg font-medium">
        Keys
      </h2>
      {failure !== "" && (
        <p role="alert" className="rounded-md border border-red-800 p-3 text-sm text-red-300">
          {failure}
        </p>
      )}

      <table className="w-full text-left text-sm">
        <caption className="sr-only">Files classified by content and permissions</caption>
        <thead>
          <tr>
            <th scope="col">File</th>
            <th scope="col">Kind</th>
            <th scope="col">Algorithm</th>
            <th scope="col">Fingerprint</th>
            <th scope="col">Permissions</th>
            <th scope="col">Used by</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {inventory.items.map((item) => (
            <tr key={item.id}>
              <td>{item.relativePath}</td>
              <td>{item.kind}</td>
              <td>{item.bits > 0 ? `${item.algorithm} · ${item.bits}` : item.algorithm}</td>
              <td>
                {item.fingerprint !== "" ? item.fingerprint : null}
                {item.notes.map((note) => (
                  <span key={note} className="ml-2 text-amber-300">
                    {noteLabels[note] ?? note}
                  </span>
                ))}
              </td>
              <td>
                {item.permission}
                {item.permissionRisk && <span className="ml-2 text-red-300">Permissions too open</span>}
              </td>
              <td>{item.references.map((reference) => reference.hostPatterns.join(" ")).join(", ")}</td>
              <td>
                {item.kind === "private_key" && (
                  <>
                    <button type="button" onClick={() => setRevealing(item)}>
                      Show private key
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        closePassphraseForm();
                        setChangingPassphrase(item);
                      }}
                    >
                      Change passphrase
                    </button>
                    <button type="button" onClick={() => void moveToTrash(item.id)}>
                      Move to trash
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {revealing !== null && (
        <RevealDialog
          keyId={revealing.id}
          relativePath={revealing.relativePath}
          api={api}
          onClose={() => setRevealing(null)}
        />
      )}

      {changingPassphrase !== null && (
        <form
          aria-labelledby="passphrase-heading"
          className="space-y-3 rounded-xl border border-zinc-800 p-4"
          onSubmit={(event) => {
            event.preventDefault();
            void submitPassphrase(changingPassphrase);
          }}
        >
          <h3 id="passphrase-heading" className="font-medium">
            Change passphrase: {changingPassphrase.relativePath}
          </h3>
          <p className="text-sm text-zinc-400">
            The passphrase is used only for this change. sshc never stores it. Use agent registration if you
            want macOS to remember it.
          </p>
          <label className="block">
            Current passphrase
            <input
              type="password"
              value={currentPassphrase}
              onChange={(event) => setCurrentPassphrase(event.target.value)}
            />
          </label>
          <label className="block">
            New passphrase
            <input
              type="password"
              value={newPassphrase}
              onChange={(event) => setNewPassphrase(event.target.value)}
              disabled={removePassphrase}
            />
          </label>
          <label className="block">
            <input
              type="checkbox"
              checked={removePassphrase}
              onChange={(event) => {
                setRemovePassphrase(event.target.checked);
                setNewPassphrase("");
              }}
            />
            Remove the passphrase and leave the key unprotected on disk
          </label>
          <button type="submit">Save new passphrase</button>
          <button type="button" onClick={closePassphraseForm}>
            Cancel
          </button>
        </form>
      )}

      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          void submitGeneration();
        }}
      >
        <h3 className="font-medium">Create a key</h3>
        <label className="block">
          Algorithm
          <select value={algorithm} onChange={(event) => setAlgorithm(event.target.value)}>
            {variants.map((variant) => (
              <option key={`${variant.algorithm}-${variant.bits}`} value={variant.algorithm}>
                {variant.label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          File name
          <input value={fileName} onChange={(event) => setFileName(event.target.value)} />
        </label>
        <label className="block">
          Comment
          <input value={comment} onChange={(event) => setComment(event.target.value)} />
        </label>
        {selected?.inProcess !== false && (
          <>
            <label className="block">
              Passphrase
              <input
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                disabled={unencrypted}
              />
            </label>
            <label className="block">
              <input
                type="checkbox"
                checked={unencrypted}
                onChange={(event) => {
                  setUnencrypted(event.target.checked);
                  setPassphrase("");
                }}
              />
              Create without a passphrase, and accept that anyone who reads the file can use the key
            </label>
          </>
        )}
        <button type="submit">
          {selected?.inProcess === false ? "Show Terminal command" : "Create key"}
        </button>
      </form>

      {terminalCommand !== null && (
        <div>
          <p className="text-sm text-zinc-300">
            Hardware-backed keys need your security key, so sshc does not create them. Run this command in
            Terminal yourself:
          </p>
          <pre aria-label="Terminal command" className="overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
            {terminalCommand.join(" ")}
          </pre>
        </div>
      )}

      <div>
        <h3 className="font-medium">Trash</h3>
        <p className="text-sm text-zinc-400">
          Deleted keys stay here until you remove them. Nothing is ever deleted automatically.
        </p>
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Soft-deleted keys</caption>
          <thead>
            <tr>
              <th scope="col">Files</th>
              <th scope="col">Age</th>
              <th scope="col">Status</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {trash.entries.map((entry) => (
              <tr key={entry.id}>
                <td>{entry.files.map((file) => file.originalRelativePath).join(", ")}</td>
                <td>
                  {entry.stale
                    ? `${entry.ageDays} days · older than ${trash.retentionDays} days`
                    : `${entry.ageDays} days`}
                </td>
                <td>{entry.restorable ? "Restorable" : entry.blockers.join(", ")}</td>
                <td>
                  <button type="button" onClick={() => void restore(entry.id)}>
                    Restore
                  </button>
                  {pendingPurge === entry.id ? (
                    <>
                      <span>This cannot be undone. There is no backup of a permanently deleted key.</span>
                      <button type="button" onClick={() => void purge(entry.id)}>
                        Confirm permanent delete
                      </button>
                      <button type="button" onClick={() => setPendingPurge("")}>
                        Cancel
                      </button>
                    </>
                  ) : (
                    <button type="button" onClick={() => setPendingPurge(entry.id)}>
                      Delete permanently
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

type KeyInventoryVariants = Awaited<ReturnType<KeysApi["algorithms"]>>["variants"];
```

- [ ] **Step 8: Plug the screen into the App shell**

Replace `web/src/App.tsx` with:

```tsx
import { useEffect, useState } from "react";
import { apiClient, type HealthResponse } from "./api/client";
import { KeysScreen } from "./keys/KeysScreen";
import type { KeysApi } from "./keys/api";
import type { SessionState } from "./session/bootstrap";

type AppProps = {
  bootstrap: () => Promise<SessionState>;
  health: () => Promise<HealthResponse>;
  keysApi: KeysApi;
};

const sections = ["Connections", "Groups", "Config", "Keys", "Known Hosts", "History"] as const;
type Section = (typeof sections)[number];
const enabledSections: readonly Section[] = ["Keys"];

export function App({ bootstrap, health, keysApi }: AppProps) {
  const [state, setState] = useState<"starting" | "ready" | "error">("starting");
  const [version, setVersion] = useState("");
  const [section, setSection] = useState<Section>("Keys");

  useEffect(() => {
    let active = true;
    void bootstrap()
      .then((sessionState) => {
        if (!active) return null;
        apiClient.setCSRF(sessionState.csrfToken);
        return health();
      })
      .then((result) => {
        if (!active || result === null) return;
        setVersion(result.version);
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });

    return () => {
      active = false;
      apiClient.clear();
    };
  }, [bootstrap, health]);

  if (state === "error") {
    return (
      <main>
        <h1>sshc</h1>
        <p role="alert">Secure local session could not be started. Restart sshc and use the newly opened tab.</p>
      </main>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-800 px-6 py-4">
        <h1 className="text-xl font-semibold">sshc</h1>
      </header>
      <div className="grid grid-cols-[15rem_1fr]">
        <nav aria-label="Primary" className="border-r border-zinc-800 p-4">
          <ul>
            {sections.map((entry) => (
              <li key={entry}>
                <button
                  type="button"
                  disabled={!enabledSections.includes(entry)}
                  onClick={() => setSection(entry)}
                  className="w-full px-3 py-2 text-left text-zinc-500"
                >
                  {entry}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <main className="p-8">
          <section aria-labelledby="status-heading" className="max-w-xl rounded-xl border border-zinc-800 bg-zinc-900 p-6">
            <h2 id="status-heading" className="font-medium">
              Local process
            </h2>
            <p role="status" className="mt-2 text-sm text-zinc-300">
              {state === "ready" ? `Local session active · ${version}` : "Starting secure local session…"}
            </p>
          </section>
          {state === "ready" && section === "Keys" && (
            <div className="mt-8">
              <KeysScreen api={keysApi} />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
```

Update the committed navigation assertion in `web/src/App.test.tsx` and give every `render` a stub `keysApi`:

```tsx
const stubKeysApi: KeysApi = {
  inventory: vi.fn().mockResolvedValue({
    items: [],
    unreadable: [],
    agentDelegations: [],
    unresolvedReferences: [],
    agentAvailable: false,
    agentIdentities: [],
  }),
  algorithms: vi.fn().mockResolvedValue({ variants: [], source: "fallback", diagnostic: "" }),
  generate: vi.fn(),
  hardwareCommand: vi.fn(),
  changePassphrase: vi.fn(),
  reveal: vi.fn(),
  trash: vi.fn(),
  listTrash: vi.fn().mockResolvedValue({ entries: [], retentionDays: 30 }),
  restore: vi.fn(),
  purge: vi.fn(),
};
```

and replace the loop that expected every entry to be disabled with:

```tsx
    for (const label of ["Connections", "Groups", "Config", "Known Hosts", "History"]) {
      expect(screen.getByRole("button", { name: label })).toBeDisabled();
    }
    expect(screen.getByRole("button", { name: "Keys" })).toBeEnabled();
```

Add `import type { KeysApi } from "./keys/api";` to the test file and pass `keysApi={stubKeysApi}` to each `<App …/>`.

Finally, pass the real client in `web/src/main.tsx`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { apiClient } from "./api/client";
import { App } from "./App";
import "./index.css";
import { keysApi } from "./keys/api";
import { bootstrapSession } from "./session/bootstrap";

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");
const sessionPromise = bootstrapSession(window.location, window.history, window.fetch.bind(window));
createRoot(root).render(
  <StrictMode>
    <App bootstrap={() => sessionPromise} health={() => apiClient.health()} keysApi={keysApi} />
  </StrictMode>,
);
```

- [ ] **Step 9: Run the frontend checks**

Run:

```bash
npm test --prefix web
npm run typecheck --prefix web
```

Expected: PASS. The reveal dialog shows nothing before confirmation, drops the material on close and never calls `Storage.prototype.setItem`; permanent delete needs two clicks; a refused restore shows its blockers.

- [ ] **Step 10: Document the key vault boundary**

Append to `README.md`, in its existing Japanese style, after the config engine section:

```markdown
## 鍵管理の境界

- `~/.ssh` 配下のファイルは内容と権限で分類します。ファイル名だけで秘密鍵と断定しません。`~/.ssh/sshc/`（backups、trash、journal、history）は走査対象、agent 登録対象、config 候補のいずれからも除外します。
- 通常のソフトウェア鍵（Ed25519、RSA、ECDSA）は Go プロセス内で生成・暗号化します。パスフレーズは argv にも環境変数にも載せません。
- FIDO の `ed25519-sk` と `ecdsa-sk` はハードウェアの操作が必要なため生成しません。実行すべき `ssh-keygen` コマンドだけを表示します。Terminal の起動はロードマップのサブシステム5が担当します。
- パスフレーズは生成・変更・agent 登録の処理中だけ保持し、アプリでは保存しません。best-effort でゼロ埋めしますが、Go の GC 上メモリからの完全消去は保証できません。保持は macOS Keychain または ssh-agent へ明示操作で委ねます。
- 秘密鍵表示 API は通常の一覧・詳細 API と分離し、対象と操作へ紐付いた一回限り・短時間有効の action token を追加で要求します。レスポンスは `Cache-Control: no-store` で、フロントエンドは永続ストレージ、グローバル状態、ログ、分析イベントへ渡さず、ダイアログ終了時に参照を破棄します。ブラウザ拡張やクリップボード履歴に対しては保護できません。
- 秘密鍵を表示した事実は履歴に記録します。記録するのは操作種別、時刻、対象ファイルだけで、鍵本文は含みません。
- 鍵の削除は `~/.ssh/sshc/trash/<id>/` への同一ファイルシステム内 rename です。バイト列を複製しないため、世代バックアップに鍵本文が残りません。trash ディレクトリは `0700`、鍵は元の厳格な権限のままです。
- 30 日経過は表示するだけで、自動削除は行いません。完全削除は再確認と専用の action token を必要とし、バックアップを作らないため取り消せません。
- 復元は同名ファイルと同一 fingerprint の既存鍵を検査し、いずれかに該当する場合は推測せず拒否して理由を表示します。
- ssh-agent と Keychain への登録は `ssh-add` を経由します。パスフレーズは標準入力だけで渡します。自動テストは実 agent、実 Keychain、実 Terminal、実リモートを使いません。
- `ssh -Q key` は対応アルゴリズムの一覧取得のみに使います。設定を評価する `ssh -G` は実行しません（サブシステム5の担当）。
- 起動時に未完了トランザクションを検出した場合は件数だけを記録します。完了・復旧を選ぶ画面は後続サブシステムで追加します。
```

- [ ] **Step 11: Run the whole verification suite**

Run:

```bash
make generate
make test
make fuzz
make build
go vet ./...
git diff --stat go.mod go.sum
git status --short
```

Expected:

- `make generate` produces no diff after the committed generation;
- every Go, race, Vitest and TypeScript check passes;
- `make fuzz` finds no failing input;
- `bin/sshc` builds;
- `go.mod` and `go.sum` show exactly the two additions from Task 1;
- `git status --short` lists only the files this plan intends to add.

- [ ] **Step 12: Prove no test touched the real home directory**

Run:

```bash
grep -rn "UserHomeDir\|os.Getenv(\"HOME\")" internal/ | grep -v "_test.go" 
grep -rn "UserHomeDir\|os.Getenv(\"HOME\")\|os.LookupEnv" internal/ --include=*_test.go || echo "no environment access in tests"
ls -la ~/.ssh/sshc 2>/dev/null || echo "no state directory in the real home"
find ~/.ssh -newermt '-30 minutes' 2>/dev/null || echo "no recently modified file in the real ~/.ssh"
```

Expected: the only non-test match is `cmd/sshc/main.go` reading the home directory once at startup; tests report no environment access; the real `~/.ssh` gained no `sshc` directory and no file changed. If any check fails, fix the offending test before committing.

- [ ] **Step 13: Perform the manual isolated acceptance run**

Run: `HOME="$(mktemp -d)" ./bin/sshc`

Expected, against the throwaway home only:

- the Keys screen lists an empty workspace without error;
- creating an Ed25519 key with a passphrase writes `0600` files, and `ssh-keygen -y -P <passphrase> -f <new key>` prints a public key whose fingerprint matches the one shown;
- selecting a security-key algorithm shows an `ssh-keygen` command and creates nothing;
- revealing the private key requires the explicit confirmation, shows the same bytes as the file, and adds a `key.reveal` entry to `~/.ssh/sshc/history/` that contains no key material;
- moving the key to the trash leaves `~/.ssh` without it, the file keeps `0600` inside `~/.ssh/sshc/trash/<id>/`, and `~/.ssh/sshc/backups/` contains no key material;
- restoring puts it back; permanent delete needs the second confirmation and cannot be repeated;
- the real `~/.ssh` is untouched throughout.

- [ ] **Step 14: Commit the screen and the documentation**

```bash
git add web README.md
git commit -m "feat: add the Keys screen and document the key vault boundary"
```

---

## Key Vault Acceptance Gate

Before starting the SSH integrations plan, verify all of the following:

- `go test ./...`, `go test -race ./...` and `go vet ./...` pass.
- `npm test --prefix web` and `npm run typecheck --prefix web` pass.
- `make generate` leaves no diff, and `make build` produces `bin/sshc`.
- `go.mod` and `go.sum` gained exactly `golang.org/x/crypto v0.54.0` and `golang.org/x/sys v0.47.0 // indirect`, and no other module.
- A file is classified by its content and permissions: a private key named `notes.txt` is a private key, and a text file named `id_ed25519` is not.
- Nothing under `~/.ssh/sshc/` — backups, trash, journal or history — appears in the inventory, in agent registration or in configuration suggestions.
- A symbolic link is listed but never followed, and it never contributes a fingerprint.
- Ed25519, RSA and ECDSA keys are generated and encrypted inside the Go process; the resulting file is read by the installed `ssh-keygen`; the passphrase appears in no argument list and in no environment variable in any code path.
- `ed25519-sk` and `ecdsa-sk` are never generated in process. The API returns the exact `ssh-keygen` argument list, every element passes the safe-argument check, and launching Terminal is left to roadmap subsystem 5.
- An empty passphrase is accepted only with an explicit `unencrypted` acknowledgement, and a passphrase together with that flag is rejected.
- Reveal is a separate endpoint that requires a fresh, single-use, short-lived action token bound to that key and that purpose. A token for another key, another purpose, an expired token, or a replayed token is refused, and the service is not called.
- Reveal responses carry `Cache-Control: no-store`; the frontend writes no key material to storage, no global state, no log and no analytics event, and drops it when the dialog closes. Neither the UI nor the documentation claims protection against browser extensions or clipboard history.
- Every reveal adds a history record naming the operation, the time and the file, and containing no key material.
- ssh-agent and Keychain registration goes through `platform.KeyAgent`; the passphrase reaches `ssh-add` only on standard input; automated tests use fakes and never a real agent, Keychain, Terminal or remote host.
- A soft delete is a `rename` inside the workspace: the file keeps its original permission, the trash directory is `0700`, and `~/.ssh/sshc/backups/` receives no key material.
- Trash entries show a 30-day age and are never deleted automatically.
- Permanent delete requires a second confirmation in the UI and its own action token at the API, writes no backup, and reports honestly that an interrupted removal can be completed but not rolled back.
- Restore refuses when the original path is occupied or when an identical key already exists, changes nothing, and reports the blockers instead of guessing.
- Every mutation goes through `storage.Manager`, is journalled, and appears in `Manager.History()`.
- No log line contains key material, a passphrase, a request body, a cookie, a session or action token, or a full path.
- Managed files are `0600` or stricter and managed directories are `0700`.
- Automated tests never read or wrote the real `~/.ssh`, the real Keychain, a real ssh-agent, Terminal or a remote host.
- Remote `authorized_keys` registration, Terminal launch, `ssh -G`, connection tests and Known Hosts remain deferred to roadmap subsystem 5; Connections UI and group inheritance to subsystem 3; packaging and end-to-end hardening to subsystem 6. Each is recorded there, not silently dropped.

## Self-review notes

- Design §6.3 is covered by Tasks 1, 2, 3, 5 and 6; §6.7 by Tasks 4, 5 and the reveal audit note; §7 by Task 4; §8.2 by Tasks 7, 8 and 9; §9 by `keyProblem` and `problemDetail` in Task 8; §10.1 by the fakes in every task; §10.3 by the fault-injection tests in Task 4 and the trash tests in Task 5.
- Design §6.3's remote `authorized_keys` registration is the one bullet of that section this plan does not implement; it is listed under "Out of scope" and belongs to roadmap subsystem 5.
- `keys.Wipe` and `storage.zeroBytes` are two names for the same best-effort operation because `storage` must not import `keys`; both carry the same honest comment about the garbage collector.

