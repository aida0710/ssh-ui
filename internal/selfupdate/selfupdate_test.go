package selfupdate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

// serve is a fake GitHub, so no test reaches the real one.
func serve(t *testing.T, handler http.HandlerFunc) selfupdate.Checker {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/releases/latest", handler)
	return selfupdate.Checker{API: server.URL + "/releases/latest", HTTP: server.Client()}
}

func TestLatestReportsTheTagAndWhereToReadAboutIt(t *testing.T) {
	checker := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v0.2.0",
			"html_url": "https://example.invalid/releases/v0.2.0",
		})
	})

	found, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest = %v", err)
	}
	if found.Version != "v0.2.0" || found.PageURL != "https://example.invalid/releases/v0.2.0" {
		t.Errorf("Latest = %+v", found)
	}
}

func TestLatestSaysWhenNothingIsPublished(t *testing.T) {
	checker := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if _, err := checker.Latest(context.Background()); !errors.Is(err, selfupdate.ErrNoRelease) {
		t.Errorf("Latest = %v, want ErrNoRelease", err)
	}
}

// A draft is not published, whatever the API calls it.
func TestLatestIgnoresADraft(t *testing.T) {
	checker := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.2.0", "draft": true})
	})
	if _, err := checker.Latest(context.Background()); !errors.Is(err, selfupdate.ErrNoRelease) {
		t.Errorf("Latest = %v, want ErrNoRelease", err)
	}
}
