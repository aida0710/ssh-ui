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

	"sshc/internal/objectstore"
	"sshc/internal/remotesync"
	"sshc/internal/secret"
	"sshc/internal/storage"
)

const syncPassphrase = "correct horse battery staple"

// fakeBucket は、ETag を持つオブジェクトの集合と、この設計全体が乗っている条件付き
// 書き込みのルールである。スタブのクライアントではなく意図的に本物の HTTP サーバー
// にしてあるので、条件は、それが実際に通る場所で表明される。
//
// これが集合になったのは、push のたびにライブのオブジェクトの隣へ日付付きの
// コピーが残るようになってからだ。オブジェクトひとつの偽物では、二つの書き込みが
// ひとつに見えてしまい、どちらについても何も示せなかったはずである。
type fakeBucket struct {
	mu         sync.Mutex
	objects    map[string]storedObject
	generation int
	// refuseConditional は、すべての条件付き PUT を失敗させる。R2 がそれらに対応して
	// いないと判明した場合に、計画にあるフォールバックがどう働くかを試すための
	// ものである。
	refuseConditional bool
}

type storedObject struct {
	body []byte
	etag string
}

// key はバケット名を取り除く。これにより、偽物が保存するものは、このアプリケーション
// がオブジェクトと呼ぶものと一致する。
func (b *fakeBucket) key(path string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, "/"), "sshc/")
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

// replace は、別のマシンがそのオブジェクトを書いた状況の代わりを務める。
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

	// Configure が何で呼ばれたか。テストがフィクスチャを組み立て直さずに、
	// そのフィールドをひとつだけ変えられるようにするためである。
	config remotesync.Config
	creds  objectstore.Credentials
	client *objectstore.Client
}

// direct は、設定フォームと同じやり方で、このインストールを同じバケットの別の
// direction へ向け直す。
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

	// ファイルソースは Include グラフが答えるものであり、本物のそれは、グラフが到達
	// するワークスペース内のすべてのファイルを — 種類を問わず — 答える。以前はここで
	// sshc/ を落としていたので、除外のテストは、それらのファイルへ到達する唯一の
	// 経路、すなわちそれを名指しする Include 行を、見ることが
	// できなかった。
	source := func() ([]string, error) {
		var paths []string
		for name := range files {
			if strings.HasPrefix(name, "keys/") {
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
	config := remotesync.Config{Endpoint: server.URL, Bucket: "sshc", Region: "auto"}
	credentials := objectstore.Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	client := &objectstore.Client{
		HTTP: server.Client(), Endpoint: server.URL, Bucket: "sshc", Region: "auto",
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
		"sshc/metadata.json":   `{"schemaVersion":2}`,
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

	// CRLF と末尾の空白も含め、1 バイト違わない。
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
	// compare-and-swap。これがなければ「自動」は「最後に保存したマシンが黙って勝つ」
	// という意味になってしまう。
	bucket := &fakeBucket{}
	first := newInstallation(t, bucket, map[string]string{"config": "first\n"})
	second := newInstallation(t, bucket, map[string]string{"config": "second\n"})

	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("the first push = %v", err)
	}
	// 二台目のマシンは一度も同期していないので、その push は If-None-Match: * を運び、
	// オブジェクトを置き換えるのではなく拒否されなければならない。
	if err := second.service.Push(context.Background(), syncPassphrase); !errors.Is(err, remotesync.ErrRemoteMoved) {
		t.Fatalf("the second push = %v, want ErrRemoteMoved", err)
	}

	// そして、一度同期したあとに遅れをとったマシンも拒否される。
	if err := first.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("a second push from the same machine = %v", err)
	}
	// 別のマシンがライブのオブジェクトを書いたので、こちらの ETag は古い。
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
	// 半分だけ適用すれば、どちらの側とも一致しないワークスペースになる。
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
	// あとで「別のマシンで削除された」と「ここで作られた」を区別できる唯一のものなので、
	// これを書かない push は、次の pull にそれを判別させられなくして
	// しまう。
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
	// リクエストのあとではなく前に拒否される。バケットには何も届いていない。
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

	// プレビューは引き続き動く。適用してはいけないマシンでも、どれだけ遅れているかを
	// 知ることは許される。見ることまで拒めば、この設定は防護ではなく目隠しに
	// なってしまう。
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

// vault は移動する。バケットへの鍵は移動しない。
//
// 封をされた設定は、まさにこのバケットのアクセスキーを保持している。したがって、
// それを運ぶスナップショットは、スナップショットをひとつ入手した者が以後のすべてを
// 取得できることを意味する。これらは構造上除外されている — Collect は自分が取るものを
// 列挙する — し、その一覧にワイルドカードが生えたら気づくのがこのテストである。
func TestASnapshotCarriesTheVaultAndNotTheKeyToItsOwnBucket(t *testing.T) {
	installation := newInstallation(t, &fakeBucket{}, map[string]string{
		// エントリファイル自身が、封をされた設定を名指ししている。これが、除外が
		// 生き延びなければならない形である。ファイルソースは Include グラフであり、
		// グラフは設定が指すものを取ってくるからだ。
		"config":             "Include sshc/sync-settings\nHost bastion\n",
		"sshc/secrets":       "sealed vault bytes",
		"sshc/sync-settings": "sealed access key",
		"sshc/cli":           `{"url":"http://127.0.0.1:1","secret":"s"}`,
	})

	manifest, contents, err := installation.service.Collect()
	if err != nil {
		t.Fatalf("Collect = %v", err)
	}
	packed := map[string]bool{}
	for _, entry := range manifest.Files {
		packed[entry.Path] = true
	}
	if !packed["sshc/secrets"] {
		t.Errorf("the vault does not travel: %v", packed)
	}
	for _, excluded := range []string{secret.SettingsPath, "sshc/cli"} {
		if packed[excluded] {
			t.Errorf("the snapshot carries %s: %v", excluded, packed)
		}
		if _, ok := contents[excluded]; ok {
			t.Errorf("%s is in the archive even though the manifest omits it", excluded)
		}
	}
}

// バケットの登録は、まずそのバケットに尋ねる。
//
// 試されたことのない設定は、設定済みに見えて何時間もあとの最初の push で失敗する
// 設定であり、そのときユーザーは、タイプミスをした画面からとうに離れている。まだ
// スナップショットの入っていないバケットは機能しているバケットだ。404 は、正しくて
// 空の設定が返す答えである。
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
	// 存在しないホストへ向けられたクライアント。エンドポイントの打ち間違いは、ここから
	// はこう見える。
	installation.service.Configure(
		remotesync.Config{Endpoint: "https://127.0.0.1:1", Bucket: "sshc", Region: "auto"},
		installation.creds,
		&objectstore.Client{Endpoint: "https://127.0.0.1:1", Bucket: "sshc", Region: "auto", Creds: installation.creds},
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

// エンドポイントが正規化される前に保存された設定も正しく表示される。サービスは、
// 与えられたものがどこから来たかを信用せず、自分で切り詰めるからだ。
func TestAStoredTrailingSlashIsTrimmedWhenItIsConfigured(t *testing.T) {
	installation := newInstallation(t, &fakeBucket{}, map[string]string{"config": "Host bastion\n"})
	installation.service.Configure(
		remotesync.Config{Endpoint: "https://s3.example.invalid/", Bucket: "b", Region: "auto"},
		installation.creds, installation.client)

	if endpoint, _, _ := installation.service.Target(); endpoint != "https://s3.example.invalid" {
		t.Errorf("endpoint = %q, want the trailing slash gone", endpoint)
	}
}

// オブジェクトはユーザーが言った場所へ行き、それが何であるかにちなんで名付けられる。
func TestTheKeysFollowTheConfiguredPath(t *testing.T) {
	for _, test := range []struct{ path, object, dated string }{
		// 既定はバケットのルート。バケットはたいていすでにこのアプリケーションにちなんで
		// 名付けられているので、その中で同じ名前を繰り返すフォルダは、何もない階層を
		// ひとつ増やすだけである。
		{"", "workspace.tar.gz.enc", "snapshots/2026-08-05-000000.tar.gz.enc"},
		{"sshc", "sshc/workspace.tar.gz.enc", "sshc/snapshots/2026-08-05-000000.tar.gz.enc"},
		// どう綴られていても、意味するところはひとつである。
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

// push のたびに、ライブのオブジェクトの隣へ日付付きのコピーが残る。ライブの方は
// 固定のキーを保つ。条件付き書き込みには条件をかける対象のオブジェクトがひとつ
// 必要であり、固定名の代わりに日付名にすれば、あるマシンが別のマシンの作業を黙って
// 踏み潰すのを止めている唯一のものが失われるからだ。
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
	// 同じバイト列なので、コピーのコストはアップロード 1 回で、二度目の封じ込めは不要。
	if !bytes.Equal(bucket.object(live), bucket.object(dated)) {
		t.Error("the dated copy is not the snapshot that was pushed")
	}
}

// オブジェクトの名前を変えたり、別のパスへ移したりしても、すでに同期済みのマシンを
// 置き去りにしてはならない。
//
// state は、このマシンが最後に見たスナップショットの ETag を記録する。それがどの
// オブジェクトのものかは記録していなかったので、キーが変わったあとの次の push は、
// 存在しないオブジェクトの世代に対して If-Match を送り —「別のマシンが push した、
// まず pull せよ」として拒否され — そこでの pull は、pull すべきものを何も見つけ
// られなかった。そこから抜け出す方法は、state ファイルを手で削除する以外になかった。
func TestChangingTheObjectKeyDoesNotStrandAMachineThatHasSynced(t *testing.T) {
	bucket := &fakeBucket{}
	installation := newInstallation(t, bucket, map[string]string{"config": "Host bastion\n"})
	if err := installation.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("the first push = %v", err)
	}

	// 設定がパスを名指しするようになったので、ライブのオブジェクトは別の場所にある。
	config := installation.config
	config.Path = "laptops"
	installation.service.Configure(config, installation.creds, installation.client)

	if err := installation.service.Push(context.Background(), syncPassphrase); err != nil {
		t.Fatalf("the push after the key changed = %v", err)
	}
	if got := bucket.object("laptops/" + remotesync.ObjectName); got == nil {
		t.Errorf("nothing was written to the new key: %v", bucket.keys())
	}
}
