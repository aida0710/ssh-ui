package objectstore_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"sshc/internal/objectstore"
)

// 統合テストのスイートは、本物の S3 実装に対して走る。
//
// これがあるのは、単体テストには答えられない問いがひとつあるからだ。すなわち、
// 本物のサーバーは条件付き PUT に何をするのか、である。同期の設計全体は
// If-None-Match と If-Match が尊重されることの上に立っており、仕様どおりに
// 振る舞う偽物は、その偽物が仕様から書かれたということを証明するだけで
// ある。
//
// エンドポイントが設定されていなければスキップするので、`go test ./...` は密閉
// されたままである。`make integration` はコンテナで SeaweedFS を起動して設定し、
// CI も同じことをする。S3 互換のサーバーなら何でもよい — SeaweedFS、MinIO、
// あるいは本物の資格情報を使った R2 そのものでも。
const (
	endpointVariable = "SSHC_TEST_S3_ENDPOINT"
	keyVariable      = "SSHC_TEST_S3_KEY"
	secretVariable   = "SSHC_TEST_S3_SECRET"
	bucketVariable   = "SSHC_TEST_S3_BUCKET"
	regionVariable   = "SSHC_TEST_S3_REGION"
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
		bucket = "sshc-test"
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

// uniqueKey は、このクライアントが持たない delete 動詞を必要とせずに、実行どうしを
// 独立に保つ。テストバイナリ自身の pid とテスト名があれば足りる。
func uniqueKey(t *testing.T) string {
	t.Helper()
	return "integration/" + t.Name() + "/" + time.Now().UTC().Format("20060102T150405.000000000")
}

func TestAgainstARealServerTheSignatureIsAccepted(t *testing.T) {
	// これが失敗するなら、このファイルの他は何の意味も持たない。正規化リクエストか、
	// ヘッダーの集合か、ペイロードのハッシュが、どの単体テストにも見えない形で
	// 誤っている。単体テストはこのクライアントを自分自身と比べているだけだからだ。
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
	// これは最初の書き込みの防護である。一度も同期していないマシンが、他のマシンが
	// すでに作ったスナップショットを置き換えられてはならない。
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
	// これはそれ以降のすべての書き込みの防護であり、「自動」という語が依存している
	// 性質でもある。遅れをとったマシンは、先を行っているマシンを踏み潰すことが
	// できない。
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

	// `first` はいまや古い。これはまさに、誰か他人の push を取り逃したマシンの
	// 状態である。
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
