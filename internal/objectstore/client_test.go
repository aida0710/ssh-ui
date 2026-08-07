package objectstore_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sshc/internal/objectstore"
)

// Every test here runs against httptest. Nothing in this package reaches
// Cloudflare, or any other network.
func newClient(t *testing.T, handler http.HandlerFunc) (objectstore.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return objectstore.Client{
		HTTP:     server.Client(),
		Endpoint: server.URL,
		Bucket:   "sshc",
		Region:   "auto",
		Creds:    suiteCredentials(),
		Now:      func() time.Time { return suiteStamp },
	}, server
}

func TestPutSendsTheConditionItWasGiven(t *testing.T) {
	// The compare-and-swap is the whole reason this client exists. If the
	// condition never reached the wire, "auto" sync could clobber another
	// machine and nothing would say so.
	var ifMatch, ifNoneMatch, method, path string
	client, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		ifMatch, ifNoneMatch = r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
		w.Header().Set("ETag", `"new"`)
		w.WriteHeader(http.StatusOK)
	})

	if _, err := client.Put(context.Background(), "snapshot", []byte("body"), `"old"`, ""); err != nil {
		t.Fatalf("Put = %v", err)
	}
	if method != http.MethodPut || path != "/sshc/snapshot" {
		t.Errorf("request = %s %s", method, path)
	}
	if ifMatch != `"old"` || ifNoneMatch != "" {
		t.Errorf("If-Match = %q, If-None-Match = %q", ifMatch, ifNoneMatch)
	}

	if _, err := client.Put(context.Background(), "snapshot", []byte("body"), "", "*"); err != nil {
		t.Fatalf("Put = %v", err)
	}
	if ifNoneMatch != "*" || ifMatch != "" {
		t.Errorf("If-Match = %q, If-None-Match = %q", ifMatch, ifNoneMatch)
	}
}

func TestPutRefusesBothConditionsAtOnceWithoutSendingAnything(t *testing.T) {
	reached := false
	client, _ := newClient(t, func(http.ResponseWriter, *http.Request) { reached = true })

	if _, err := client.Put(context.Background(), "k", nil, `"a"`, "*"); !errors.Is(err, objectstore.ErrBothConditions) {
		t.Fatalf("Put = %v, want ErrBothConditions", err)
	}
	if reached {
		t.Error("a programming error still reached the network")
	}
}

func TestAFailedConditionIsItsOwnError(t *testing.T) {
	// "Somebody else got there first" is an answer, not a failure, and the
	// caller has to be able to tell it from one.
	for _, status := range []int{http.StatusPreconditionFailed, http.StatusConflict} {
		client, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})
		if _, err := client.Put(context.Background(), "k", []byte("b"), `"old"`, ""); !errors.Is(err, objectstore.ErrPreconditionFailed) {
			t.Errorf("HTTP %d gave %v, want ErrPreconditionFailed", status, err)
		}
	}
}

func TestGetMapsNotFoundAndReturnsTheETag(t *testing.T) {
	missing, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if _, err := missing.Get(context.Background(), "k"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Errorf("Get = %v, want ErrNotFound", err)
	}

	present, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("the snapshot"))
	})
	object, err := present.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get = %v", err)
	}
	if string(object.Body) != "the snapshot" || object.ETag != `"v1"` {
		t.Errorf("object = %#v", object)
	}
}

func TestEveryRequestIsSignedAndCarriesNoCredentialInTheURL(t *testing.T) {
	var seen []*http.Request
	client, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(context.Background()))
		w.Header().Set("ETag", `"v"`)
	})

	if _, err := client.Get(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Head(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put(context.Background(), "k", []byte("b"), "", "*"); err != nil {
		t.Fatal(err)
	}

	if len(seen) != 3 {
		t.Fatalf("requests = %d, want 3", len(seen))
	}
	for _, request := range seen {
		authorization := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 Credential=") {
			t.Errorf("%s %s is unsigned", request.Method, request.URL.Path)
		}
		if request.Header.Get("X-Amz-Content-Sha256") == "" {
			t.Errorf("%s %s does not sign its payload", request.Method, request.URL.Path)
		}
		if strings.Contains(request.URL.RawQuery, "Signature") ||
			strings.Contains(request.URL.String(), suiteSecretAccessKey) {
			t.Errorf("%s carries a credential in the URL", request.URL.String())
		}
	}
}

func TestAPlaintextEndpointIsRefused(t *testing.T) {
	// The body is encrypted before it gets here, but the credentials are not.
	client := objectstore.Client{
		Endpoint: "http://example.com",
		Bucket:   "sshc",
		Region:   "auto",
		Creds:    suiteCredentials(),
		Now:      func() time.Time { return suiteStamp },
	}
	if _, err := client.Get(context.Background(), "k"); !errors.Is(err, objectstore.ErrInsecureEndpoint) {
		t.Fatalf("Get = %v, want ErrInsecureEndpoint", err)
	}
}

func TestAnOversizedObjectIsRefusedBeforeItIsSent(t *testing.T) {
	reached := false
	client, _ := newClient(t, func(http.ResponseWriter, *http.Request) { reached = true })

	oversized := make([]byte, objectstore.MaxObjectBytes+1)
	if _, err := client.Put(context.Background(), "k", oversized, "", "*"); !errors.Is(err, objectstore.ErrObjectTooLarge) {
		t.Fatalf("Put = %v, want ErrObjectTooLarge", err)
	}
	if reached {
		t.Error("an oversized body was sent anyway")
	}
}

func TestAnyOtherRejectionCarriesNoResponseBody(t *testing.T) {
	// An S3 error document names the bucket and the request id. Neither
	// belongs in a message this application shows.
	client, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<Error><BucketName>private-bucket</BucketName></Error>"))
	})

	_, err := client.Get(context.Background(), "k")
	if !errors.Is(err, objectstore.ErrRefused) {
		t.Fatalf("Get = %v, want ErrRefused", err)
	}
	if strings.Contains(err.Error(), "private-bucket") {
		t.Error("the error carries the response body")
	}
}
