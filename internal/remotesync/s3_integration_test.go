package remotesync_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshc/internal/objectstore"
	"sshc/internal/remotesync"
	"sshc/internal/storage"
)

// 二台のマシンと、本物のバケット。
//
// 密閉されたスイートは、仕様どおりに振る舞う偽物に対してこれを示すが、それは
// その偽物が仕様から書かれたことを示すにすぎない。こちらは、このリポジトリを
// 読んでいないサーバーに対して compare-and-swap が成り立つことを
// 示す。
//
// SSHC_TEST_S3_ENDPOINT がサーバーを指していなければスキップする。`make integration`
// はコンテナで SeaweedFS を起動し、それを設定する。
func integrationBucket(t *testing.T) (objectstore.Client, string) {
	t.Helper()
	endpoint := os.Getenv("SSHC_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("SSHC_TEST_S3_ENDPOINT is not set; run `make integration`")
	}
	bucket := os.Getenv("SSHC_TEST_S3_BUCKET")
	if bucket == "" {
		bucket = "sshc-test"
	}
	region := os.Getenv("SSHC_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	return objectstore.Client{
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Endpoint: endpoint,
		Bucket:   bucket,
		Region:   region,
		Creds: objectstore.Credentials{
			AccessKeyID:     os.Getenv("SSHC_TEST_S3_KEY"),
			SecretAccessKey: os.Getenv("SSHC_TEST_S3_SECRET"),
		},
	}, endpoint
}

// realInstallation は、プロセス内の偽物ではなく本物のサーバーに向けた
// newInstallation。実行どうしが衝突しないよう、各テストは自前のオブジェクトキーを持つ。
func realInstallation(t *testing.T, files map[string]string) installation {
	t.Helper()
	client, endpoint := integrationBucket(t)

	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range files {
		absolute := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	source := func() ([]string, error) {
		var paths []string
		for name := range files {
			if strings.HasPrefix(name, "keys/") || strings.HasPrefix(name, "sshc/") {
				continue
			}
			paths = append(paths, name)
		}
		return paths, nil
	}
	counter := 0
	service := remotesync.NewService(workspace,
		storage.NewManager(workspace, time.Now, rand.Reader), source,
		func() string { return time.Now().UTC().Format(time.RFC3339) },
		func() (string, error) { counter++; return "origin-integration", nil })
	service.Configure(
		remotesync.Config{Endpoint: endpoint, Bucket: client.Bucket, Region: client.Region},
		client.Creds, &client,
	)
	return installation{service: service, workspace: workspace, home: home}
}

func TestAgainstARealBucketASnapshotTravelsBetweenTwoMachines(t *testing.T) {
	first := realInstallation(t, map[string]string{
		"config":               "Host bastion\r\n\tPort 2222   \n",
		"keys/work/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\nnot really\n",
		"sshc/metadata.json":   `{"schemaVersion":2}`,
	})
	// オブジェクトキーは固定なので、以前に使われたことのあるバケットにはすでに
	// スナップショットがあり、条件付き書き込みは拒否される。それはクライアントが
	// 正しく振る舞っているということであり、以前はそのせいでこのテストがコンテナ
	// あたりちょうど一度しか通らなかった。二度目の実行は、一度目が残したオブジェクト
	// の上で失敗した。それでは誰も頻繁には走らせられない。
	//
	// 実際のマシンは、埋まっているバケットに出会えばまず pull する。これも同じことを
	// する。pull すれば ETag を知るので、push は本来あるべき If-Match になる。
	// ワークスペースがすでに一致している場合、Pull は完全な結果とともに
	// ErrNothingToApply を答える — それは API の形であって失敗ではなく、その結果を
	// apply することが ETag を記録する。
	result, err := first.service.Pull(context.Background(), syncPassphrase)
	switch {
	case err == nil, errors.Is(err, remotesync.ErrNothingToApply):
		if err := first.service.Apply(result); err != nil && !errors.Is(err, remotesync.ErrNothingToApply) {
			t.Fatalf("Apply of the snapshot already in the bucket = %v", err)
		}
	case errors.Is(err, remotesync.ErrNoSnapshot), errors.Is(err, objectstore.ErrNotFound):
		// 空のバケット — 新しいコンテナが始まる状態である。そこから学ぶものは何もなく、
		// push はオブジェクトを作る書き込みになる。サービスが答えるのは ErrNoSnapshot で、
		// その下のクライアントが答えるのは ErrNotFound。どちらもここへ届き
		// うる。
	default:
		t.Fatalf("Pull before push = %v", err)
	}
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("Push = %v", err)
	}

	second := realInstallation(t, map[string]string{})
	result, err = second.service.Pull(context.Background(), syncPassphrase)
	if err != nil {
		t.Fatalf("Pull = %v", err)
	}
	if len(result.Conflicts) != 0 {
		t.Fatalf("conflicts = %#v", result.Conflicts)
	}
	if err := second.service.Apply(result); err != nil {
		t.Fatalf("Apply = %v", err)
	}

	// 本物のネットワーク往復を通しても、CRLF と末尾の空白を含めて 1 バイト
	// 違わない。
	if got := second.read(t, "config"); got != "Host bastion\r\n\tPort 2222   \n" {
		t.Errorf("config = %q", got)
	}
	if got := second.read(t, "keys/work/id_ed25519"); !strings.HasPrefix(got, "-----BEGIN") {
		t.Errorf("the private key did not arrive: %q", got)
	}
}

func TestAgainstARealBucketAStalePushIsRefused(t *testing.T) {
	// 「自動」という語が乗っている性質を、このリポジトリを読んでいないサーバーに
	// 対して検査する。
	first := realInstallation(t, map[string]string{"config": "first\n"})
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil &&
		!errors.Is(err, remotesync.ErrRemoteMoved) {
		t.Fatalf("Push = %v", err)
	}

	behind := realInstallation(t, map[string]string{"config": "second\n"})
	if err := behind.service.Push(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrRemoteMoved) {
		t.Fatalf("a machine that has never synced pushed anyway: %v", err)
	}
}

func TestAgainstARealBucketTheObjectIsCiphertext(t *testing.T) {
	machine := realInstallation(t, map[string]string{
		"config":               "Host bastion\n\tHostName 203.0.113.10\n",
		"keys/work/id_ed25519": "PRIVATE KEY MATERIAL",
	})
	if err := machine.service.Push(context.Background(), syncPassphrase); err != nil &&
		!errors.Is(err, remotesync.ErrRemoteMoved) {
		t.Fatalf("Push = %v", err)
	}

	client, _ := integrationBucket(t)
	object, err := client.Get(context.Background(), remotesync.ObjectName)
	if err != nil {
		t.Fatalf("Get = %v", err)
	}
	for _, plaintext := range []string{"PRIVATE KEY MATERIAL", "bastion", "203.0.113.10", "manifest", "id_ed25519"} {
		if strings.Contains(string(object.Body), plaintext) {
			t.Errorf("the object in the bucket contains %q in clear", plaintext)
		}
	}
}

func TestAgainstARealBucketTheWrongPassphraseCannotRead(t *testing.T) {
	machine := realInstallation(t, map[string]string{"config": "Host bastion\n"})
	if err := machine.service.Push(context.Background(), syncPassphrase); err != nil &&
		!errors.Is(err, remotesync.ErrRemoteMoved) {
		t.Fatalf("Push = %v", err)
	}

	other := realInstallation(t, map[string]string{})
	if _, err := other.service.Pull(context.Background(), "a completely different passphrase"); err == nil {
		t.Fatal("the snapshot opened with the wrong passphrase")
	}
}
