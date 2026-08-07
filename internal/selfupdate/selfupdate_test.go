package selfupdate_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ssh-ui/internal/selfupdate"
)

// A newer version is a later one, compared as numbers. Compared as strings,
// 0.10.0 is older than 0.9.0, and offering that as an update walks the user
// backwards.
func TestNewerComparesNumbersAndNotText(t *testing.T) {
	for _, test := range []struct {
		current, candidate string
		want               bool
	}{
		{"0.9.0", "0.10.0", true},
		{"0.10.0", "0.9.0", false},
		{"1.0.0", "1.0.0", false},
		{"v1.2.3", "v1.2.4", true},
		{"1.2.3", "1.2.3", false},
		// A build that is not a release is told there is one, and never told
		// how far behind it is.
		{"dev", "0.1.0", true},
		{"0.1.0", "dev", true},
	} {
		if got := selfupdate.Newer(test.current, test.candidate); got != test.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", test.current, test.candidate, got, test.want)
		}
	}
}

// signer is the project's release key, minted per test so no test needs the
// real one and no real one is ever in a test.
type signer struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{public: public, private: private}
}

// release serves a fake GitHub, so no test reaches the real one.
func release(t *testing.T, body []byte, corruptChecksum bool, key signer, sign bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	sum := sha256.Sum256(body)
	published := hex.EncodeToString(sum[:])
	if corruptChecksum {
		published = hex.EncodeToString(make([]byte, sha256.Size))
	}
	sums := fmt.Sprintf("%s  ssh-ui-darwin-arm64\n", published)
	mux.HandleFunc("/asset", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, sums)
	})
	mux.HandleFunc("/sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(ed25519.Sign(key.private, []byte(sums))))
	})
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v0.2.0",
			"html_url": server.URL + "/releases/v0.2.0",
			"assets":   assets(server.URL, sign),
		})
	})
	return server
}

// assets is what the release publishes. A release with no signature is one an
// attacker could produce by leaving the file out, so it is a case with a test.
func assets(base string, sign bool) []map[string]string {
	published := []map[string]string{
		{"name": "ssh-ui-darwin-arm64", "browser_download_url": base + "/asset"},
		{"name": "checksums.txt", "browser_download_url": base + "/sums"},
	}
	if sign {
		published = append(published, map[string]string{
			"name": "checksums.txt.sig", "browser_download_url": base + "/sig",
		})
	}
	return published
}

func checkerFor(server *httptest.Server, key signer) selfupdate.Checker {
	return selfupdate.Checker{
		API:           server.URL + "/releases/latest",
		AssetName:     "ssh-ui-darwin-arm64",
		ChecksumName:  "checksums.txt",
		SignatureName: "checksums.txt.sig",
		PublicKey:     key.public,
		HTTP:          server.Client(),
	}
}

func TestApplyReplacesTheBinaryOnlyWhenTheDownloadIsWhatWasPublished(t *testing.T) {
	key := newSigner(t)
	server := release(t, []byte("the new binary"), false, key, true)
	checker := checkerFor(server, key)

	found, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest = %v", err)
	}
	if found.Version != "v0.2.0" || found.AssetURL == "" || found.PageURL == "" {
		t.Fatalf("Latest = %+v", found)
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "ssh-ui")
	if err := os.WriteFile(path, []byte("the old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checker.Apply(context.Background(), found, path); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	replaced, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(replaced) != "the new binary" {
		t.Errorf("the binary is %q", replaced)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, %v", info, err)
	}
	// Nothing staged is left behind.
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want the binary alone", len(entries))
	}
}

// A download that is not what the release says it is leaves the working binary
// exactly where it was. It means a broken transfer; it does not mean the
// release was safe, and nothing here can tell the difference.
func TestApplyLeavesTheBinaryAloneWhenTheChecksumDoesNotMatch(t *testing.T) {
	key := newSigner(t)
	server := release(t, []byte("the new binary"), true, key, true)
	checker := checkerFor(server, key)
	found, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ssh-ui")
	if err := os.WriteFile(path, []byte("the old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checker.Apply(context.Background(), found, path); !errors.Is(err, selfupdate.ErrChecksumMismatch) {
		t.Fatalf("Apply = %v, want ErrChecksumMismatch", err)
	}
	kept, err := os.ReadFile(path)
	if err != nil || string(kept) != "the old binary" {
		t.Errorf("the binary is %q, %v", kept, err)
	}
}

func TestLatestSaysWhenNothingIsPublished(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checker := selfupdate.Checker{API: server.URL + "/releases/latest", HTTP: server.Client()}
	if _, err := checker.Latest(context.Background()); !errors.Is(err, selfupdate.ErrNoRelease) {
		t.Errorf("Latest = %v, want ErrNoRelease", err)
	}
}

// A release nobody signed is refused, not accepted with a warning: otherwise an
// attacker who takes the publishing account need only leave the file out.
func TestApplyRefusesAReleaseThatIsNotSigned(t *testing.T) {
	key := newSigner(t)
	server := release(t, []byte("the new binary"), false, key, false)
	checker := checkerFor(server, key)
	found, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ssh-ui")
	if err := os.WriteFile(path, []byte("the old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checker.Apply(context.Background(), found, path); !errors.Is(err, selfupdate.ErrUnsigned) {
		t.Fatalf("Apply = %v, want ErrUnsigned", err)
	}
	if kept, _ := os.ReadFile(path); string(kept) != "the old binary" {
		t.Errorf("the binary is %q", kept)
	}
}

// A signature from a key this binary was not built with is somebody else's
// release, whatever account published it.
func TestApplyRefusesASignatureFromAnotherKey(t *testing.T) {
	published, other := newSigner(t), newSigner(t)
	server := release(t, []byte("the new binary"), false, published, true)
	checker := checkerFor(server, other)
	found, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ssh-ui")
	if err := os.WriteFile(path, []byte("the old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checker.Apply(context.Background(), found, path); !errors.Is(err, selfupdate.ErrBadSignature) {
		t.Fatalf("Apply = %v, want ErrBadSignature", err)
	}
	if kept, _ := os.ReadFile(path); string(kept) != "the old binary" {
		t.Errorf("the binary is %q", kept)
	}
}

// A build with no key compiled in cannot tell an honest release from any other,
// and must not guess.
func TestApplyRefusesWhenThisBuildHasNoKey(t *testing.T) {
	key := newSigner(t)
	server := release(t, []byte("the new binary"), false, key, true)
	checker := checkerFor(server, signer{})
	found, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := checker.Apply(context.Background(), found, filepath.Join(t.TempDir(), "ssh-ui")); !errors.Is(err, selfupdate.ErrUnsigned) {
		t.Fatalf("Apply = %v, want ErrUnsigned", err)
	}
}
