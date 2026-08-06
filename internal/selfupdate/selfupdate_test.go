package selfupdate_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// release serves a fake GitHub, so no test reaches the real one.
func release(t *testing.T, body []byte, corruptChecksum bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	sum := sha256.Sum256(body)
	published := hex.EncodeToString(sum[:])
	if corruptChecksum {
		published = hex.EncodeToString(make([]byte, sha256.Size))
	}
	mux.HandleFunc("/asset", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  ssh-ui-darwin-arm64\n", published)
	})
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v0.2.0",
			"html_url": server.URL + "/releases/v0.2.0",
			"assets": []map[string]string{
				{"name": "ssh-ui-darwin-arm64", "browser_download_url": server.URL + "/asset"},
				{"name": "checksums.txt", "browser_download_url": server.URL + "/sums"},
			},
		})
	})
	return server
}

func checkerFor(server *httptest.Server) selfupdate.Checker {
	return selfupdate.Checker{
		API:          server.URL + "/releases/latest",
		AssetName:    "ssh-ui-darwin-arm64",
		ChecksumName: "checksums.txt",
		HTTP:         server.Client(),
	}
}

func TestApplyReplacesTheBinaryOnlyWhenTheDownloadIsWhatWasPublished(t *testing.T) {
	server := release(t, []byte("the new binary"), false)
	checker := checkerFor(server)

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
	server := release(t, []byte("the new binary"), true)
	checker := checkerFor(server)
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
