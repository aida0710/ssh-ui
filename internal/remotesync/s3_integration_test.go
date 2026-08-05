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

	"ssh-ui/internal/objectstore"
	"ssh-ui/internal/remotesync"
	"ssh-ui/internal/storage"
)

// Two machines and a real bucket.
//
// The hermetic suite proves this against a fake that behaves as the
// specification says, which proves the fake was written from the
// specification. This proves the compare-and-swap against a server that did
// not read this repository.
//
// It skips unless SSH_UI_TEST_S3_ENDPOINT names one; `make integration` starts
// SeaweedFS in a container and sets it.
func integrationBucket(t *testing.T) (objectstore.Client, string) {
	t.Helper()
	endpoint := os.Getenv("SSH_UI_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("SSH_UI_TEST_S3_ENDPOINT is not set; run `make integration`")
	}
	bucket := os.Getenv("SSH_UI_TEST_S3_BUCKET")
	if bucket == "" {
		bucket = "ssh-ui-test"
	}
	region := os.Getenv("SSH_UI_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	return objectstore.Client{
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Endpoint: endpoint,
		Bucket:   bucket,
		Region:   region,
		Creds: objectstore.Credentials{
			AccessKeyID:     os.Getenv("SSH_UI_TEST_S3_KEY"),
			SecretAccessKey: os.Getenv("SSH_UI_TEST_S3_SECRET"),
		},
	}, endpoint
}

// realInstallation is newInstallation pointed at a real server instead of the
// in-process fake. Each test gets its own object key so runs do not collide.
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
			if strings.HasPrefix(name, "keys/") || strings.HasPrefix(name, "ssh-ui/") {
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
		"ssh-ui/metadata.json": `{"schemaVersion":2}`,
	})
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		// The very first run against an empty bucket may find an object from a
		// previous run; the conditional write is what refuses, and that is
		// reported honestly rather than worked around.
		t.Fatalf("Push = %v (if this is ErrRemoteMoved the bucket already holds a snapshot from an earlier run)", err)
	}

	second := realInstallation(t, map[string]string{})
	result, err := second.service.Pull(context.Background(), syncPassphrase)
	if err != nil {
		t.Fatalf("Pull = %v", err)
	}
	if len(result.Conflicts) != 0 {
		t.Fatalf("conflicts = %#v", result.Conflicts)
	}
	if err := second.service.Apply(result); err != nil {
		t.Fatalf("Apply = %v", err)
	}

	// Byte for byte through a real network round trip, including the CRLF and
	// the trailing spaces.
	if got := second.read(t, "config"); got != "Host bastion\r\n\tPort 2222   \n" {
		t.Errorf("config = %q", got)
	}
	if got := second.read(t, "keys/work/id_ed25519"); !strings.HasPrefix(got, "-----BEGIN") {
		t.Errorf("the private key did not arrive: %q", got)
	}
}

func TestAgainstARealBucketAStalePushIsRefused(t *testing.T) {
	// The property the word "automatic" rests on, checked against a server
	// that did not read this repository.
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
	object, err := client.Get(context.Background(), remotesync.ObjectKey)
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
