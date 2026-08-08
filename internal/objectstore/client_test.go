package objectstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sshc/internal/objectstore"
)

// AWS が公開している SigV4 テストスイートの資格情報。署名そのものはもう SDK の
// 責任なので既知解テストは持たないが、鍵が回線へ漏れていないことを確かめる
// テストには、探すべき具体的な文字列が要る。
const (
	suiteAccessKeyID     = "AKIDEXAMPLE"
	suiteSecretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

func suiteCredentials() objectstore.Credentials {
	return objectstore.Credentials{AccessKeyID: suiteAccessKeyID, SecretAccessKey: suiteSecretAccessKey}
}

// ここのテストはすべて httptest に対して走る。このパッケージのものが Cloudflare
// や、その他のどのネットワークにも到達することはない。
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
	}, server
}

func TestPutSendsTheConditionItWasGiven(t *testing.T) {
	// compare-and-swap こそが、このクライアントが存在する理由のすべてである。条件が
	// 回線に届いていなければ、「auto」同期は他のマシンを踏み潰しうるのに、それを
	// 告げるものは何もない。
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
	// 「誰かが先に到達した」は失敗ではなく答えであり、呼び出し側はそれを失敗と
	// 見分けられなければならない。
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
		// 空でないことだけでは足りない。"UNSIGNED-PAYLOAD" も空ではないが、それは
		// 本文に署名していないという意味である。送るものは誰かの ~/.ssh の
		// スナップショットなので、実際のハッシュが載っていなければならない。
		payloadHash := request.Header.Get("X-Amz-Content-Sha256")
		if len(payloadHash) != sha256.Size*2 {
			t.Errorf("%s %s の X-Amz-Content-Sha256 が %q で、SHA-256 の 16 進ダイジェストではない",
				request.Method, request.URL.Path, payloadHash)
		}
		if strings.Contains(request.URL.RawQuery, "Signature") ||
			strings.Contains(request.URL.String(), suiteSecretAccessKey) {
			t.Errorf("%s carries a credential in the URL", request.URL.String())
		}
	}
}

func TestAPlaintextEndpointIsRefused(t *testing.T) {
	// 本文はここへ届く前に暗号化されているが、資格情報はそうではない。
	client := objectstore.Client{
		Endpoint: "http://example.com",
		Bucket:   "sshc",
		Region:   "auto",
		Creds:    suiteCredentials(),
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
	// S3 のエラードキュメントはバケット名とリクエスト ID を名指しする。どちらも
	// このアプリケーションが表示するメッセージに入れてよいものではない。
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
