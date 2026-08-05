package objectstore_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"ssh-ui/internal/objectstore"
)

// The integration suite runs against a real S3 implementation.
//
// It exists to answer one question the unit tests cannot: what does a real
// server do with a conditional PUT. The whole sync design rests on
// If-None-Match and If-Match being honoured, and a fake that behaves as the
// specification says proves only that the fake was written from the
// specification.
//
// It skips when the endpoint is not set, so `go test ./...` stays hermetic.
// `make integration` starts SeaweedFS in a container and sets it; CI does the
// same. Any S3-compatible server will do — SeaweedFS, MinIO, or R2 itself with
// real credentials.
const (
	endpointVariable = "SSH_UI_TEST_S3_ENDPOINT"
	keyVariable      = "SSH_UI_TEST_S3_KEY"
	secretVariable   = "SSH_UI_TEST_S3_SECRET"
	bucketVariable   = "SSH_UI_TEST_S3_BUCKET"
	regionVariable   = "SSH_UI_TEST_S3_REGION"
)

func integrationClient(t *testing.T) objectstore.Client {
	t.Helper()
	endpoint := os.Getenv(endpointVariable)
	if endpoint == "" {
		t.Skipf("%s is not set; start a server with `make integration` to run this", endpointVariable)
	}
	region := os.Getenv(regionVariable)
	if region == "" {
		region = "us-east-1"
	}
	bucket := os.Getenv(bucketVariable)
	if bucket == "" {
		bucket = "ssh-ui-test"
	}
	return objectstore.Client{
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Endpoint: endpoint,
		Bucket:   bucket,
		Region:   region,
		Creds: objectstore.Credentials{
			AccessKeyID:     os.Getenv(keyVariable),
			SecretAccessKey: os.Getenv(secretVariable),
		},
	}
}

// uniqueKey keeps runs independent without needing a delete verb this client
// does not have. The test binary's own pid and the test name are enough.
func uniqueKey(t *testing.T) string {
	t.Helper()
	return "integration/" + t.Name() + "/" + time.Now().UTC().Format("20060102T150405.000000000")
}

func TestAgainstARealServerTheSignatureIsAccepted(t *testing.T) {
	// If this fails, nothing else in this file means anything: the canonical
	// request, the header set or the payload hash is wrong in a way no unit
	// test can see, because a unit test compares this client against itself.
	client := integrationClient(t)
	key := uniqueKey(t)

	etag, err := client.Put(context.Background(), key, []byte("hello"), "", "*")
	if err != nil {
		t.Fatalf("PUT = %v", err)
	}
	if etag == "" {
		t.Error("the server returned no ETag, so a conditional write has nothing to compare against")
	}

	object, err := client.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("GET = %v", err)
	}
	if string(object.Body) != "hello" {
		t.Errorf("body = %q", object.Body)
	}
}

func TestAgainstARealServerIfNoneMatchRefusesASecondCreate(t *testing.T) {
	// This is the first write's guard: a machine that has never synced must not
	// be able to replace a snapshot another machine already made.
	client := integrationClient(t)
	key := uniqueKey(t)

	if _, err := client.Put(context.Background(), key, []byte("first"), "", "*"); err != nil {
		t.Fatalf("the first PUT = %v", err)
	}
	_, err := client.Put(context.Background(), key, []byte("second"), "", "*")
	if !errors.Is(err, objectstore.ErrPreconditionFailed) {
		t.Fatalf("the second PUT = %v, want ErrPreconditionFailed", err)
	}

	object, err := client.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(object.Body) != "first" {
		t.Errorf("the object was overwritten anyway: %q", object.Body)
	}
}

func TestAgainstARealServerIfMatchRefusesAStaleWrite(t *testing.T) {
	// This is every later write's guard, and the property the word "automatic"
	// depends on: a machine that has fallen behind cannot clobber the one that
	// is ahead.
	client := integrationClient(t)
	key := uniqueKey(t)

	first, err := client.Put(context.Background(), key, []byte("one"), "", "*")
	if err != nil {
		t.Fatalf("the first PUT = %v", err)
	}
	second, err := client.Put(context.Background(), key, []byte("two"), first, "")
	if err != nil {
		t.Fatalf("a matching conditional PUT = %v", err)
	}
	if second == first {
		t.Error("the ETag did not change, so it cannot act as a generation counter")
	}

	// `first` is now stale, which is exactly the state of a machine that
	// missed somebody else's push.
	_, err = client.Put(context.Background(), key, []byte("three"), first, "")
	if !errors.Is(err, objectstore.ErrPreconditionFailed) {
		t.Fatalf("a stale conditional PUT = %v, want ErrPreconditionFailed", err)
	}

	object, err := client.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(object.Body) != "two" {
		t.Errorf("body = %q, want the value written by the machine that was up to date", object.Body)
	}
}

func TestAgainstARealServerHeadReturnsTheSameETagAsGet(t *testing.T) {
	client := integrationClient(t)
	key := uniqueKey(t)

	written, err := client.Put(context.Background(), key, []byte("x"), "", "*")
	if err != nil {
		t.Fatal(err)
	}
	head, err := client.Head(context.Background(), key)
	if err != nil {
		t.Fatalf("HEAD = %v", err)
	}
	object, err := client.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if head != written || object.ETag != written {
		t.Errorf("ETags disagree: PUT %q, HEAD %q, GET %q", written, head, object.ETag)
	}
}

func TestAgainstARealServerAMissingObjectIsNotFound(t *testing.T) {
	client := integrationClient(t)

	if _, err := client.Get(context.Background(), uniqueKey(t)); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("GET of a missing object = %v, want ErrNotFound", err)
	}
}
