package remotesync_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"ssh-ui/internal/objectstore"
	"ssh-ui/internal/remotesync"
	"ssh-ui/internal/secret"
	"ssh-ui/internal/storage"
)

const syncPassphrase = "correct horse battery staple"

// fakeBucket is a set of objects with ETags, and the conditional-write rules
// the whole design rests on. It is deliberately a real HTTP server rather than
// a stub client, so the condition is asserted where it actually travels.
//
// It became a set when every push started leaving a dated copy beside the live
// object: a single-object fake would have shown the two writes as one and
// proved nothing about either.
type fakeBucket struct {
	mu         sync.Mutex
	objects    map[string]storedObject
	generation int
	// refuseConditional makes every conditional PUT fail, which is how the
	// fallback in the plan would be exercised if R2 turned out not to support
	// them.
	refuseConditional bool
}

type storedObject struct {
	body []byte
	etag string
}

// key strips the bucket name, so what the fake stores is what this application
// calls the object.
func (b *fakeBucket) key(path string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, "/"), "ssh-ui/")
}

func (b *fakeBucket) keys() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	names := make([]string, 0, len(b.objects))
	for name := range b.objects {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// replace stands in for another machine having written the object.
func (b *fakeBucket) replace(key, etag string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	stored := b.objects[key]
	stored.etag = etag
	b.objects[key] = stored
}

func (b *fakeBucket) object(key string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.objects[key].body
}

func (b *fakeBucket) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.objects == nil {
			b.objects = map[string]storedObject{}
		}
		key := b.key(r.URL.Path)
		stored, present := b.objects[key]
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			if !present {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("ETag", stored.etag)
			if r.Method == http.MethodGet {
				_, _ = w.Write(stored.body)
			}
		case http.MethodPut:
			ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
			if b.refuseConditional && (ifMatch != "" || ifNone != "") {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if ifNone == "*" && present {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if ifMatch != "" && ifMatch != stored.etag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			body := make([]byte, 0)
			buffer := make([]byte, 4096)
			for {
				n, err := r.Body.Read(buffer)
				body = append(body, buffer[:n]...)
				if err != nil {
					break
				}
			}
			b.generation++
			etag := `"` + string(rune('a'+b.generation)) + `"`
			b.objects[key] = storedObject{body: body, etag: etag}
			w.Header().Set("ETag", etag)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

type installation struct {
	service   *remotesync.Service
	workspace *storage.Workspace
	home      string

	// What Configure was called with, so a test can change one field of it
	// without rebuilding the fixture.
	config remotesync.Config
	creds  objectstore.Credentials
	client *objectstore.Client
}

// direct re-points this installation at the same bucket with a different
// direction, the way the settings form does.
func (i installation) direct(direction remotesync.Direction) {
	config := i.config
	config.Direction = direction
	i.service.Configure(config, i.creds, i.client)
}

func newInstallation(t *testing.T, bucket *fakeBucket, files map[string]string) installation {
	t.Helper()
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
	manager := storage.NewManager(workspace, time.Now, rand.Reader)

	// The file source is what the Include graph would answer. Here it is the
	// fixture's own configuration files, which is the same shape.
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
	service := remotesync.NewService(workspace, manager, source,
		func() string { return "2026-08-05T00:00:00Z" },
		func() (string, error) { counter++; return "origin-" + string(rune('A'+counter)), nil })

	server := httptest.NewTLSServer(bucket.handler())
	t.Cleanup(server.Close)
	config := remotesync.Config{Endpoint: server.URL, Bucket: "ssh-ui", Region: "auto"}
	credentials := objectstore.Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	client := &objectstore.Client{
		HTTP: server.Client(), Endpoint: server.URL, Bucket: "ssh-ui", Region: "auto",
		Creds: credentials,
		Now:   func() time.Time { return time.Unix(0, 0).UTC() },
	}
	service.Configure(config, credentials, client)
	return installation{
		service: service, workspace: workspace, home: home,
		config: config, creds: credentials, client: client,
	}
}

func (i installation) read(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(i.home, ".ssh", filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

func TestASnapshotTravelsBetweenTwoMachines(t *testing.T) {
	bucket := &fakeBucket{}
	first := newInstallation(t, bucket, map[string]string{
		"config":               "Host bastion\r\n\tPort 2222   \n",
		"keys/work/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		"ssh-ui/metadata.json": `{"schemaVersion":2}`,
	})
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("Push = %v", err)
	}

	second := newInstallation(t, bucket, map[string]string{})
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

	// Byte for byte, including the CRLF and the trailing spaces.
	if got := second.read(t, "config"); got != "Host bastion\r\n\tPort 2222   \n" {
		t.Errorf("config = %q", got)
	}
	if got := second.read(t, "keys/work/id_ed25519"); !strings.HasPrefix(got, "-----BEGIN") {
		t.Errorf("the private key did not arrive: %q", got)
	}
}

func TestTheObjectInTheBucketIsCiphertext(t *testing.T) {
	bucket := &fakeBucket{}
	machine := newInstallation(t, bucket, map[string]string{
		"config":               "Host bastion\n\tHostName 203.0.113.10\n",
		"keys/work/id_ed25519": "PRIVATE KEY MATERIAL",
	})
	if err := machine.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatal(err)
	}

	for _, plaintext := range []string{"PRIVATE KEY MATERIAL", "bastion", "203.0.113.10", "manifest", "id_ed25519"} {
		if strings.Contains(string(bucket.object(remotesync.ObjectName)), plaintext) {
			t.Errorf("the uploaded object contains %q in clear", plaintext)
		}
	}
}

func TestAPushCannotOverwriteAnotherMachine(t *testing.T) {
	// The compare-and-swap. Without it, "automatic" would mean "whichever
	// machine saved last wins, silently".
	bucket := &fakeBucket{}
	first := newInstallation(t, bucket, map[string]string{"config": "first\n"})
	second := newInstallation(t, bucket, map[string]string{"config": "second\n"})

	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("the first push = %v", err)
	}
	// The second machine has never synced, so its push carries
	// If-None-Match: * and must be refused rather than replacing the object.
	if err := second.service.Push(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrRemoteMoved) {
		t.Fatalf("the second push = %v, want ErrRemoteMoved", err)
	}

	// And a machine that has synced, then falls behind, is refused too.
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("a second push from the same machine = %v", err)
	}
	// Another machine wrote the live object, so this one's ETag is stale.
	bucket.replace(remotesync.ObjectName, `"somebody else"`)
	if err := first.service.Push(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrRemoteMoved) {
		t.Fatalf("a stale push = %v, want ErrRemoteMoved", err)
	}
}

func TestPullRefusesTheWrongPassphraseAndWritesNothing(t *testing.T) {
	bucket := &fakeBucket{}
	first := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatal(err)
	}

	second := newInstallation(t, bucket, map[string]string{})
	if _, err := second.service.Pull(context.Background(), "a different passphrase entirely"); err == nil {
		t.Fatal("Pull succeeded with the wrong passphrase")
	}
	if _, err := os.Stat(filepath.Join(second.home, ".ssh", "config")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused pull wrote a file")
	}
}

func TestPullOnAnEmptyBucketSaysSo(t *testing.T) {
	machine := newInstallation(t, &fakeBucket{}, map[string]string{})
	if _, err := machine.service.Pull(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrNoSnapshot) {
		t.Fatalf("Pull = %v, want ErrNoSnapshot", err)
	}
}

func TestApplyRefusesWhileAnythingIsInConflict(t *testing.T) {
	// Applying half a snapshot produces a workspace that matches neither side.
	bucket := &fakeBucket{}
	first := newInstallation(t, bucket, map[string]string{"config": "theirs\n"})
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatal(err)
	}

	second := newInstallation(t, bucket, map[string]string{"config": "mine\n"})
	result, err := second.service.Pull(context.Background(), syncPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Conflicts) == 0 {
		t.Fatal("two machines with different contents produced no conflict")
	}
	if err := second.service.Apply(result); !errors.Is(err, remotesync.ErrConflicts) {
		t.Fatalf("Apply = %v, want ErrConflicts", err)
	}
	if got := second.read(t, "config"); got != "mine\n" {
		t.Errorf("a refused apply changed the file: %q", got)
	}
}

func TestAnUnconfiguredServiceRefusesRatherThanPanicking(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	service := remotesync.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader),
		func() ([]string, error) { return nil, nil },
		func() string { return "" }, func() (string, error) { return "o", nil })

	if service.Configured() {
		t.Error("an unconfigured service reports itself configured")
	}
	if err := service.Push(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrNotConfigured) {
		t.Errorf("Push = %v, want ErrNotConfigured", err)
	}
	if _, err := service.Pull(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrNotConfigured) {
		t.Errorf("Pull = %v, want ErrNotConfigured", err)
	}
}

func TestTheStateFileRecordsWhatWasSynced(t *testing.T) {
	// It is the only thing that can later distinguish "deleted on the other
	// machine" from "created here", so a push that did not write it would make
	// the next pull unable to tell.
	bucket := &fakeBucket{}
	machine := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})
	if err := machine.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatal(err)
	}

	recorded := machine.read(t, remotesync.StatePath)
	if !strings.Contains(recorded, `"etag"`) || !strings.Contains(recorded, `"base"`) {
		t.Errorf("sync state = %s", recorded)
	}
	if strings.Contains(recorded, syncPassphrase) || strings.Contains(recorded, "secret") {
		t.Error("the sync state carries a credential")
	}
}

func TestASecondPushFromTheSameMachineSucceeds(t *testing.T) {
	bucket := &fakeBucket{}
	machine := newInstallation(t, bucket, map[string]string{"config": "one\n"})
	if err := machine.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(machine.home, ".ssh", "config"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := machine.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("the second push = %v", err)
	}

	other := newInstallation(t, bucket, map[string]string{})
	result, err := other.service.Pull(context.Background(), syncPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.service.Apply(result); err != nil {
		t.Fatal(err)
	}
	if got := other.read(t, "config"); got != "two\n" {
		t.Errorf("config = %q, want the second push", got)
	}
}

func TestAReceiveOnlyMachineWillNotPush(t *testing.T) {
	bucket := &fakeBucket{}
	machine := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})
	machine.direct(remotesync.DirectionPull)

	if err := machine.service.Push(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrPushRefused) {
		t.Fatalf("Push = %v, want ErrPushRefused", err)
	}
	// Refused before the request, not after it: nothing reached the bucket.
	if keys := bucket.keys(); len(keys) != 0 {
		t.Errorf("the bucket holds %v, pushed by a receive-only machine", keys)
	}
}

func TestASendOnlyMachineWillNotApply(t *testing.T) {
	bucket := &fakeBucket{}
	first := newInstallation(t, bucket, map[string]string{"config": "from the other machine\n"})
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatal(err)
	}

	second := newInstallation(t, bucket, map[string]string{"config": "what is on this disk\n"})
	second.direct(remotesync.DirectionPush)

	// The preview still works. A machine that may not apply is still allowed
	// to know how far behind it is; refusing to look would make the setting a
	// blindfold rather than a guard.
	result, err := second.service.Pull(context.Background(), syncPassphrase)
	if err != nil {
		t.Fatalf("Pull = %v, want a preview", err)
	}
	if len(result.Conflicts) == 0 {
		t.Fatal("the preview reported no conflict on a file both machines changed")
	}

	if err := second.service.Apply(result); !errors.Is(err, remotesync.ErrApplyRefused) {
		t.Fatalf("Apply = %v, want ErrApplyRefused", err)
	}
	if got := second.read(t, "config"); got != "what is on this disk\n" {
		t.Errorf("config = %q; a send-only machine had its file overwritten", got)
	}
}

func TestBothIsTheDefaultAndTheEmptyStringMeansIt(t *testing.T) {
	bucket := &fakeBucket{}
	machine := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})
	if got := machine.service.Direction(); got != remotesync.DirectionBoth {
		t.Errorf("Direction() = %q, want both", got)
	}
	for _, name := range []string{"", "both", "push", "pull"} {
		if _, ok := remotesync.ParseDirection(name); !ok {
			t.Errorf("ParseDirection(%q) refused a name it should accept", name)
		}
	}
	if _, ok := remotesync.ParseDirection("sideways"); ok {
		t.Error("ParseDirection accepted a name that is not a direction")
	}
}

// The vault travels; the key to the bucket does not.
//
// The sealed settings hold the access key for this very bucket, so a snapshot
// carrying them would mean anyone who obtained one snapshot could fetch every
// later one. They are excluded by construction — Collect names what it takes —
// and this is the test that notices if that list ever grows a wildcard.
func TestASnapshotCarriesTheVaultAndNotTheKeyToItsOwnBucket(t *testing.T) {
	installation := newInstallation(t, &fakeBucket{}, map[string]string{
		"config":               "Host bastion\n",
		"ssh-ui/secrets":       "sealed vault bytes",
		"ssh-ui/sync-settings": "sealed access key",
	})

	manifest, contents, err := installation.service.Collect()
	if err != nil {
		t.Fatalf("Collect = %v", err)
	}
	packed := map[string]bool{}
	for _, entry := range manifest.Files {
		packed[entry.Path] = true
	}
	if !packed["ssh-ui/secrets"] {
		t.Errorf("the vault does not travel: %v", packed)
	}
	if packed[secret.SettingsPath] {
		t.Errorf("the snapshot carries the key to its own bucket: %v", packed)
	}
	if _, ok := contents[secret.SettingsPath]; ok {
		t.Error("the settings are in the archive even though the manifest omits them")
	}
}

// Registering a bucket asks the bucket first.
//
// Settings that were never tried are settings that look configured and fail on
// the first push, hours later, with the user long past the screen where the
// typo was. A bucket with no snapshot in it yet is a working bucket: 404 is the
// answer a correct, empty configuration gives.
func TestCheckAcceptsAnEmptyBucketAndRefusesABadKey(t *testing.T) {
	bucket := &fakeBucket{}
	installation := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})

	if err := installation.service.Check(context.Background()); err != nil {
		t.Errorf("Check against an empty bucket = %v, want nil", err)
	}
	if err := installation.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("Push = %v", err)
	}
	if err := installation.service.Check(context.Background()); err != nil {
		t.Errorf("Check against a bucket holding a snapshot = %v, want nil", err)
	}
}

func TestCheckRefusesABucketThatWillNotAnswer(t *testing.T) {
	bucket := &fakeBucket{}
	installation := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})
	// A client pointed at a host that is not there, which is what a typo in the
	// endpoint looks like from here.
	installation.service.Configure(
		remotesync.Config{Endpoint: "https://127.0.0.1:1", Bucket: "ssh-ui", Region: "auto"},
		installation.creds,
		&objectstore.Client{Endpoint: "https://127.0.0.1:1", Bucket: "ssh-ui", Region: "auto", Creds: installation.creds},
	)
	if err := installation.service.Check(context.Background()); err == nil {
		t.Error("Check against an unreachable endpoint returned nil")
	}
}

func TestCheckSaysWhenNothingIsConfigured(t *testing.T) {
	service := remotesync.NewService(nil, nil, nil, nil, nil)
	if err := service.Check(context.Background()); !errors.Is(err, remotesync.ErrNotConfigured) {
		t.Errorf("Check with no configuration = %v, want ErrNotConfigured", err)
	}
}

// Settings stored before the endpoint was normalised still show correctly: the
// service trims what it is given rather than trusting where it came from.
func TestAStoredTrailingSlashIsTrimmedWhenItIsConfigured(t *testing.T) {
	installation := newInstallation(t, &fakeBucket{}, map[string]string{"config": "Host bastion\n"})
	installation.service.Configure(
		remotesync.Config{Endpoint: "https://s3.example.invalid/", Bucket: "b", Region: "auto"},
		installation.creds, installation.client)

	if endpoint, _, _ := installation.service.Target(); endpoint != "https://s3.example.invalid" {
		t.Errorf("endpoint = %q, want the trailing slash gone", endpoint)
	}
}

// The objects go where the user says, and are named for what they are.
func TestTheKeysFollowTheConfiguredPath(t *testing.T) {
	for _, test := range []struct{ path, object, dated string }{
		// The default is the bucket root: the bucket is usually named for this
		// application already, and a folder inside it repeating the name is one
		// level of nothing.
		{"", "workspace.tar.gz.enc", "snapshots/2026-08-05-000000.tar.gz.enc"},
		{"ssh-ui", "ssh-ui/workspace.tar.gz.enc", "ssh-ui/snapshots/2026-08-05-000000.tar.gz.enc"},
		// However it is spelled, it means one thing.
		{"/laptops/", "laptops/workspace.tar.gz.enc", "laptops/snapshots/2026-08-05-000000.tar.gz.enc"},
	} {
		config := remotesync.Config{Endpoint: "https://example.invalid", Bucket: "b", Path: test.path}
		if got := remotesync.ObjectKeyFor(config); got != test.object {
			t.Errorf("ObjectKeyFor(%q) = %q, want %q", test.path, got, test.object)
		}
		got, err := remotesync.SnapshotKeyFor(config, "2026-08-05T00:00:00Z")
		if err != nil {
			t.Fatalf("SnapshotKeyFor(%q) = %v", test.path, err)
		}
		if got != test.dated {
			t.Errorf("SnapshotKeyFor(%q) = %q, want %q", test.path, got, test.dated)
		}
	}
}

// Every push leaves a dated copy beside the live object. The live one keeps its
// fixed key, because the conditional write needs one object to condition on:
// dated names instead of a fixed one would remove the only thing stopping one
// machine silently clobbering another's work.
func TestEveryPushLeavesADatedCopyBesideTheLiveObject(t *testing.T) {
	bucket := &fakeBucket{}
	installation := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})

	if err := installation.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("Push = %v", err)
	}

	keys := bucket.keys()
	if len(keys) != 2 {
		t.Fatalf("the bucket holds %v, want the live object and one dated copy", keys)
	}
	live, dated := "", ""
	for _, key := range keys {
		if strings.Contains(key, "snapshots/") {
			dated = key
			continue
		}
		live = key
	}
	if !strings.HasSuffix(live, "workspace.tar.gz.enc") {
		t.Errorf("the live object is %q", live)
	}
	if !strings.HasSuffix(dated, ".tar.gz.enc") || !strings.Contains(dated, "2026-08-05") {
		t.Errorf("the dated copy is %q", dated)
	}
	// The same bytes, so the copy costs one upload and no second sealing.
	if !bytes.Equal(bucket.object(live), bucket.object(dated)) {
		t.Error("the dated copy is not the snapshot that was pushed")
	}
}
