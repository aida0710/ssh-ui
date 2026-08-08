package secret_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sshc/internal/secret"
	"sshc/internal/storage"
)

func newService(t *testing.T) (*secret.Service, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now), home
}

// newClockedService は時間を所有するので、アイドルな 1 日を、丸一日待つのでは
// なくテストの 1 行にできる。
func newClockedService(t *testing.T, now func() time.Time) (*secret.Service, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), now), home
}

func vaultPath(home string) string {
	return filepath.Join(home, ".ssh", filepath.FromSlash(secret.WorkspacePath))
}

func TestNothingIsReadableUntilTheVaultIsUnlocked(t *testing.T) {
	service, _ := newService(t)

	if service.Unlocked() {
		t.Fatal("a new service reports itself unlocked")
	}
	if err := service.Set("bastion", "hunter2"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Set while locked = %v, want ErrLocked", err)
	}
	if err := service.Remove("bastion"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Remove while locked = %v, want ErrLocked", err)
	}
	if _, err := service.IssueToken("bastion"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("IssueToken while locked = %v, want ErrLocked", err)
	}
	if service.Has("bastion") {
		t.Error("Has reported true while locked")
	}
	if service.Aliases() != nil {
		t.Error("Aliases returned something while locked")
	}
}

func TestInitialiseWritesASealedFileAndUnlockReadsItBack(t *testing.T) {
	service, home := newService(t)

	if err := service.Initialise(passphrase); err != nil {
		t.Fatalf("Initialise = %v", err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatalf("Set = %v", err)
	}

	sealed, err := os.ReadFile(vaultPath(home))
	if err != nil {
		t.Fatalf("the vault was not written: %v", err)
	}
	if strings.Contains(string(sealed), "hunter2") || strings.Contains(string(sealed), "bastion") {
		t.Error("the written file contains the password or the alias in clear")
	}

	// 同じワークスペースに対する二つ目のサービスは、アプリケーションの二度目の実行で
	// あり、それが重要な場合である。
	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock = %v", err)
	}
	if !reopened.Has("bastion") {
		t.Error("the reopened vault has no password for bastion")
	}
}

func mustReopen(t *testing.T, home string) *secret.Service {
	t.Helper()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now)
}

func TestInitialiseRefusesToReplaceAnExistingVault(t *testing.T) {
	// 置き換えれば保存済みのパスワードがすべて破壊されるし、鍵が失われた暗号化
	// ファイルに復旧の道はない。
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	second := mustReopen(t, home)
	if err := second.Initialise("a completely different passphrase"); !errors.Is(err, secret.ErrAlreadyExists) {
		t.Fatalf("Initialise = %v, want ErrAlreadyExists", err)
	}

	third := mustReopen(t, home)
	if err := third.Unlock(passphrase); err != nil {
		t.Fatalf("the original vault no longer opens: %v", err)
	}
	if !third.Has("bastion") {
		t.Error("the stored password is gone")
	}
}

func TestUnlockReportsNoVaultRatherThanAWrongPassphrase(t *testing.T) {
	service, _ := newService(t)
	if err := service.Unlock(passphrase); !errors.Is(err, secret.ErrNoVault) {
		t.Fatalf("Unlock = %v, want ErrNoVault", err)
	}
}

func TestUnlockRefusesTheWrongPassphraseAndStaysLocked(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	second := mustReopen(t, home)
	if err := second.Unlock(passphrase + "x"); !errors.Is(err, secret.ErrWrongPassphrase) {
		t.Fatalf("Unlock = %v, want ErrWrongPassphrase", err)
	}
	if second.Unlocked() {
		t.Error("a failed unlock left the service unlocked")
	}
}

func TestLockForgetsTheKeyAndEveryPendingToken(t *testing.T) {
	// ロックより長生きするトークンがあれば、ロック前に始まった接続がロック後も
	// パスワードを取得できてしまう。
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}

	service.Lock()

	if service.Unlocked() {
		t.Error("Lock left the service unlocked")
	}
	if _, err := service.Redeem(token, "bastion", "x's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Redeem after Lock = %v, want ErrLocked", err)
	}
}

func alwaysAnswerable(_, _ string) bool { return true }
func neverAnswerable(_, _ string) bool  { return false }

func TestATokenIsSpentByItsFirstUse(t *testing.T) {
	service := unlockedWithPassword(t)

	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}
	password, err := service.Redeem(token, "bastion", "ops@h's password: ", alwaysAnswerable)
	if err != nil {
		t.Fatalf("Redeem = %v", err)
	}
	if password != "hunter2" {
		t.Errorf("password = %q", password)
	}

	if _, err := service.Redeem(token, "bastion", "ops@h's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatalf("the second Redeem = %v, want ErrUnknownToken", err)
	}
}

func TestATokenIsBoundToItsAlias(t *testing.T) {
	// 盗まれたトークンの価値は、多くともユーザーがいま接続を選んだホスト一つ分で
	// あるべきで、vault 全体であってはならない。
	service := unlockedWithPassword(t)
	if err := service.Set("nas", "other-secret"); err != nil {
		t.Fatal(err)
	}

	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Redeem(token, "nas", "ops@h's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatalf("Redeem for another alias = %v, want ErrUnknownToken", err)
	}
}

func TestRedeemAppliesThePromptRuleAndSpendsTheTokenAnyway(t *testing.T) {
	// サーバー側のルールは、ヘルパーを再コンパイルしても置き換えられない。そして、
	// 拒否されたプロンプトを生き延びたトークンを、受理されるもので再試行できるなら、
	// そのルールは単なる推奨になってしまう。
	service := unlockedWithPassword(t)

	token, err := service.IssueToken("bastion")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Redeem(token, "bastion", "continue connecting?", neverAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatalf("Redeem with a refused prompt = %v", err)
	}
	if _, err := service.Redeem(token, "bastion", "ops@h's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
		t.Fatal("the token survived a refused prompt and was reusable")
	}
}

func TestAnUnknownTokenIsRefused(t *testing.T) {
	service := unlockedWithPassword(t)
	if _, err := service.IssueToken("bastion"); err != nil {
		t.Fatal(err)
	}

	for _, presented := range []string{"", "not-a-token", strings.Repeat("A", 43)} {
		if _, err := service.Redeem(presented, "bastion", "x's password: ", alwaysAnswerable); !errors.Is(err, secret.ErrUnknownToken) {
			t.Errorf("Redeem(%q) = %v, want ErrUnknownToken", presented, err)
		}
	}
}

func TestNoTokenIsIssuedForAHostWithNoStoredPassword(t *testing.T) {
	service := unlockedWithPassword(t)
	if _, err := service.IssueToken("nas"); !errors.Is(err, secret.ErrNoPassword) {
		t.Fatalf("IssueToken = %v, want ErrNoPassword", err)
	}
}

func TestRemoveWritesTheVaultBack(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := service.Remove("bastion"); err != nil {
		t.Fatalf("Remove = %v", err)
	}

	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	if reopened.Has("bastion") {
		t.Error("the password came back after a restart")
	}
}

func TestRenameCarriesThePasswordThroughAWrite(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := service.Rename("bastion", "edge"); err != nil {
		t.Fatalf("Rename = %v", err)
	}
	if err := service.Rename("absent", "elsewhere"); err != nil {
		t.Errorf("renaming a host with no password = %v, want nil", err)
	}

	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	if reopened.Has("bastion") || !reopened.Has("edge") {
		t.Errorf("aliases after rename = %#v", reopened.Aliases())
	}
}

// vault は他のすべてのファイルと同じく世代を保持し、そのどれもが
// 読めない。
//
// 以前はひとつも保持していなかった。パスワードストアの古いコピーが残されるのは
// 誰も望まないだろう、という理屈である。その代償が取り消しだった。事故で壊れた
// vault には、戻る先が何もなかったのである。いまバックアップはこの vault 自身の
// 鍵で封じられているので、古い世代が明かすものは、生きたファイルのコピーが明かす
// もの以上ではない。
func TestTheVaultKeepsGenerationsAndNoneOfThemIsReadable(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"first", "second", "third"} {
		if err := service.Set("bastion", password); err != nil {
			t.Fatal(err)
		}
	}

	backups := filepath.Join(home, ".ssh", "sshc", "backups")
	found := 0
	_ = filepath.Walk(backups, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil //nolint:nilerr // バックアップディレクトリがなければ下で失敗する
		}
		if !strings.Contains(filepath.ToSlash(path), "secrets") {
			return nil
		}
		found++
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			return nil
		}
		for _, plain := range []string{"first", "second", "bastion", passphrase} {
			if strings.Contains(string(contents), plain) {
				t.Errorf("%s carries %q in the clear", path, plain)
			}
		}
		return nil
	})
	if found == 0 {
		t.Error("the vault kept no generation, so an accident to it cannot be undone")
	}
}

func unlockedWithPassword(t *testing.T) *secret.Service {
	t.Helper()
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	return service
}

// サービスの資格情報まわりの面。すべての画面とすべてのルートが通る場所である。
// ロックされた vault は空リストではなく ErrLocked を答える。「見えない」と
// 「存在しない」は別の事実だからだ。
func TestCredentialsThroughTheService(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	if err := service.SetCredential(secret.KindPassword, "office", "s3cret"); err != nil {
		t.Fatalf("SetCredential = %v", err)
	}
	if err := service.AssignCredential(secret.KindPassword, "web-1", "office"); err != nil {
		t.Fatalf("AssignCredential = %v", err)
	}
	if err := service.AssignCredential(secret.KindPassword, "web-2", "office"); err != nil {
		t.Fatal(err)
	}

	listed, err := service.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := listed[secret.KindPassword]["office"]
	if !ok || !slices.Equal(entry, []string{"web-1", "web-2"}) {
		t.Fatalf("credentials = %#v, want office used by both", listed)
	}

	// 名前の要点そのもの。エントリはひとつ、ローテーションは一度、対象は両方のマシン。
	if err := service.SetCredential(secret.KindPassword, "office", "rotated"); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"web-1", "web-2"} {
		if got := service.PasswordFor(alias); got != "rotated" {
			t.Errorf("%s reads %q after one rotation", alias, got)
		}
	}

	if err := service.DeleteCredential(secret.KindPassword, "office"); !errors.Is(err, secret.ErrCredentialInUse) {
		t.Errorf("DeleteCredential of a used name = %v, want ErrCredentialInUse", err)
	}

	service.Lock()
	if _, err := service.Credentials(); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("Credentials while locked = %v, want ErrLocked", err)
	}
	if err := service.SetCredential(secret.KindPassword, "x", "y"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SetCredential while locked = %v, want ErrLocked", err)
	}
}

// 分離を、今度はサービスで確かめる。ルートが到達するのは vault 直接ではなく
// ここだからである。
func TestTheServiceWillNotCrossTheNamespaces(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	_ = service.SetCredential(secret.KindKeyPassphrase, "build", "phrase")

	if err := service.AssignCredential(secret.KindPassword, "web-1", "build"); err == nil {
		t.Error("a host was pointed at a key passphrase through the service")
	}
}

func TestKeyPassphraseRelocationPersists(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.SetCredential(secret.KindKeyPassphrase, "work", "phrase"); err != nil {
		t.Fatal(err)
	}
	if err := service.AssignCredential(secret.KindKeyPassphrase, "keys/work/id_work", "work"); err != nil {
		t.Fatal(err)
	}
	if err := service.RelocateKeyPassphrases(map[string]string{
		"keys/work/id_work": "keys/client-a/id_work",
	}); err != nil {
		t.Fatalf("RelocateKeyPassphrases = %v", err)
	}

	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.KeyPassphraseFor("keys/work/id_work"); ok {
		t.Error("the old key path still resolves")
	}
	if value, ok := reopened.KeyPassphraseFor("keys/client-a/id_work"); !ok || value != "phrase" {
		t.Errorf("relocated key passphrase = %q, %v", value, ok)
	}
}

// オブジェクトストアの設定は同じマスターパスワードで封じられ、vault の中ではなく
// 隣に置かれる。vault は移動する — remotesync.Collect は sshc/secrets を明示的に
// 名指しする — のであり、バケットへの鍵がバケットの中にあってはならない。
func TestSyncSettingsAreSealedBesideTheVaultAndNotInIt(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	settings := secret.SyncSettings{
		Endpoint: "https://s3.example", Bucket: "b", Region: "auto",
		AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s3cret-key", Direction: "both",
	}
	if err := service.SetSyncSettings(settings); err != nil {
		t.Fatalf("SetSyncSettings = %v", err)
	}

	read, err := service.SyncSettings()
	if err != nil {
		t.Fatalf("SyncSettings = %v", err)
	}
	if read != settings {
		t.Errorf("settings = %#v, want %#v", read, settings)
	}

	// vault の中にはなく、どちらのファイルからも読めない。
	vault, err := os.ReadFile(vaultPath(home))
	if err != nil {
		t.Fatal(err)
	}
	sealedSettings, err := os.ReadFile(filepath.Join(home, ".ssh", filepath.FromSlash(secret.SettingsPath)))
	if err != nil {
		t.Fatalf("the settings file is not there: %v", err)
	}
	for _, absent := range []string{"AKIAEXAMPLE", "s3cret-key", "s3.example"} {
		if strings.Contains(string(vault), absent) {
			t.Errorf("the vault carries %q", absent)
		}
		if strings.Contains(string(sealedSettings), absent) {
			t.Errorf("the settings file carries %q in the clear", absent)
		}
	}
}

// 一度も設定されていないことは失敗ではなく状態である。設定を与えられていない
// マシンはゼロ値を答えるので、画面はエラーではなく空のフォームを表示
// できる。
func TestSyncSettingsAnswerEmptyBeforeTheyAreEverSet(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	settings, err := service.SyncSettings()
	if err != nil {
		t.Fatalf("SyncSettings = %v", err)
	}
	if settings != (secret.SyncSettings{}) {
		t.Errorf("settings = %#v, want the zero value", settings)
	}
}

func TestSyncSettingsRefuseAShutVault(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	service.Lock()

	if _, err := service.SyncSettings(); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SyncSettings while locked = %v, want ErrLocked", err)
	}
	if err := service.SetSyncSettings(secret.SyncSettings{Bucket: "b"}); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SetSyncSettings while locked = %v, want ErrLocked", err)
	}
}

// プロセスの寿命のあいだ開いたままの vault は、ノートパソコンが鞄の中にあるあいだも
// 開いている vault である。起動時には何も尋ねないので、閉じることの代償は次に使う
// ときのマスターパスワード 1 回であり、開いたままにすることが及ぶ範囲は、すべての
// パスワードとすべての鍵のパスフレーズである。
func TestAVaultLeftUntouchedShutsItself(t *testing.T) {
	clock := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	service, _ := newClockedService(t, func() time.Time { return clock })
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(secret.IdleTimeout + time.Minute)
	if service.Unlocked() {
		t.Error("the vault is still open after a whole idle day")
	}
	if _, err := service.IssueToken("bastion"); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("IssueToken after the idle timeout = %v, want ErrLocked", err)
	}
	// そして再び開けるのはマスターパスワードであって、単に尋ねることではない。
	if err := service.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock = %v", err)
	}
	if !service.Has("bastion") {
		t.Error("the reopened vault lost what it held")
	}
}

func TestUsingASecretPutsTheClockBackToZero(t *testing.T) {
	clock := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	service, _ := newClockedService(t, func() time.Time { return clock })
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	// 4 分の 3 まで進んだところを 4 回。使われている 1 日は、合計でどれだけ経とうと
	// アイドルな 1 日ではない。
	for range 4 {
		clock = clock.Add(secret.IdleTimeout - secret.IdleTimeout/4)
		if got := service.PasswordFor("bastion"); got != "hunter2" {
			t.Fatalf("PasswordFor = %q after %v, want the password", got, clock)
		}
	}
	if !service.Unlocked() {
		t.Error("a vault used all day shut itself anyway")
	}
}

// 開いたブラウザタブは、画面がマウントされるたびにステータスを読む。それが使用と
// 数えられるなら、忘れられたタブひとつが、マシンの電源が入っているあいだじゅう
// vault を開いたままにしてしまう。タイムアウトはまさにそれを止めるためにある。
func TestReadingTheStatusDoesNotHoldTheVaultOpen(t *testing.T) {
	clock := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	service, _ := newClockedService(t, func() time.Time { return clock })
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.Set("bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	for range 4 {
		clock = clock.Add(secret.IdleTimeout - secret.IdleTimeout/4)
		service.Unlocked()
		service.Aliases()
		service.Has("bastion")
	}
	if service.Unlocked() {
		t.Error("polling the status held the vault open")
	}
}

// Verify は「これはマスターパスワードか」に、何も変えずに答える。
//
// スナップショットが二つ目のパスワードではなくマスターパスワードを使えるのは、
// これのおかげだ。打ち込まれたパスワードは、鍵として使う前に検査できる。だから
// 打ち間違いは、誰にも開けないアーカイブではなく、ここでの拒否になる。
func TestVerifyAnswersWhetherThatIsTheMasterPassword(t *testing.T) {
	service, _ := newService(t)
	if _, err := service.Verify(passphrase); !errors.Is(err, secret.ErrNoVault) {
		t.Errorf("Verify with no vault = %v, want ErrNoVault", err)
	}

	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	ok, err := service.Verify(passphrase)
	if err != nil || !ok {
		t.Errorf("Verify with the right password = %v, %v", ok, err)
	}
	ok, err = service.Verify("not the master password at all")
	if err != nil || ok {
		t.Errorf("Verify with the wrong password = %v, %v, want false and no error", ok, err)
	}

	// そしてファイルから答えるので、閉じた vault にも尋ねられる。尋ねる画面は、
	// vault が閉じていると告げられたばかりの画面である。
	service.Lock()
	if ok, err := service.Verify(passphrase); err != nil || !ok {
		t.Errorf("Verify on a locked vault = %v, %v", ok, err)
	}
}

// すべての世代バックアップは暗号文であり、それを開くのが vault である。
//
// 秘密鍵のバックアップは、以前はその鍵のコピーが ~/.ssh/sshc/backups/ に置かれる
// ことを意味していた。だからこそ、それを生みうる書き込みはバックアップをまったく
// 求めず、その結果、決して取り消せなかった。封をすることが、その取り消しを買い
// 戻している。
func TestBackupsAreSealedWithTheMasterPasswordAndOpenedWithIt(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	plain := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot really\n")
	sealed, err := service.SealBackup(plain)
	if err != nil {
		t.Fatalf("SealBackup = %v", err)
	}
	if bytes.Contains(sealed, []byte("BEGIN OPENSSH")) {
		t.Error("the sealed backup carries the key in the clear")
	}

	opened, err := service.OpenBackup(sealed)
	if err != nil {
		t.Fatalf("OpenBackup = %v", err)
	}
	if !bytes.Equal(opened, plain) {
		t.Errorf("OpenBackup returned %q", opened)
	}

	// 閉じた vault は何も封じず、何も開かない。アプリケーションがマスターパスワードの
	// 後ろにあるのは、まさに何かが書かれている最中にこれが起きないようにするためで
	// あり、平文で書く代わりに大きな音を立てて失敗する。
	service.Lock()
	if _, err := service.SealBackup(plain); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("SealBackup while shut = %v, want ErrLocked", err)
	}
	if _, err := service.OpenBackup(sealed); !errors.Is(err, secret.ErrLocked) {
		t.Errorf("OpenBackup while shut = %v, want ErrLocked", err)
	}
}

// マスターパスワードの変更は、古いパスワードが保持していたすべてを封じ直す。
//
// vault も、封をされた同期設定も、すべての世代バックアップも、そこから導出された
// 鍵で封じられている。したがって vault だけを置き換える変更は、残りを、もう誰も
// 使わないパスワードで開ける状態のまま残す — それは失うのと同じ
// ことだ。
func TestChangingTheMasterPasswordReSealsTheVaultTheSettingsAndTheBackups(t *testing.T) {
	service, home := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.SetCredential(secret.KindPassword, "office-vm", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSyncSettings(secret.SyncSettings{Bucket: "b", AccessKeyID: "AKID"}); err != nil {
		t.Fatal(err)
	}
	// 二度目の書き込み。これにより、封じ直すべき vault の世代バックアップが存在する。
	if err := service.SetCredential(secret.KindPassword, "office-vm", "hunter3"); err != nil {
		t.Fatal(err)
	}

	const next = "a different master password"
	if err := service.ChangeMasterPassword(passphrase, next); err != nil {
		t.Fatalf("ChangeMasterPassword = %v", err)
	}

	// 古いものは何も開かず、新しいものはすべてを開く。
	reopened := mustReopen(t, home)
	if err := reopened.Unlock(passphrase); !errors.Is(err, secret.ErrWrongPassphrase) {
		t.Errorf("the old password still opens the vault: %v", err)
	}
	if err := reopened.Unlock(next); err != nil {
		t.Fatalf("the new password does not open the vault: %v", err)
	}
	listed, err := reopened.Credentials()
	if err != nil {
		t.Fatalf("Credentials = %v", err)
	}
	if _, ok := listed[secret.KindPassword]["office-vm"]; !ok {
		t.Errorf("the credential did not survive: %#v", listed)
	}
	settings, err := reopened.SyncSettings()
	if err != nil || settings.AccessKeyID != "AKID" {
		t.Errorf("the settings did not survive: %+v, %v", settings, err)
	}

	// そしてすべてのバックアップが新しいもので開く。
	backups := filepath.Join(home, ".ssh", "sshc", "backups")
	found := 0
	if err := filepath.Walk(backups, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() {
			return nil //nolint:nilerr // ディレクトリがなければ下のカウントで失敗する
		}
		found++
		sealed, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if _, openErr := reopened.OpenBackup(sealed); openErr != nil {
			t.Errorf("%s cannot be opened with the new master password: %v", path, openErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Error("no backup was there to re-seal, so this proved nothing")
	}
}

func TestChangingTheMasterPasswordRefusesTheWrongCurrentOne(t *testing.T) {
	service, _ := newService(t)
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}
	if err := service.ChangeMasterPassword("not the master password", "a new master password"); !errors.Is(err, secret.ErrWrongPassphrase) {
		t.Errorf("ChangeMasterPassword with the wrong current = %v, want ErrWrongPassphrase", err)
	}
	// そして、それが持っていた鍵でいまも開く。
	if err := service.Unlock(passphrase); err != nil {
		t.Errorf("the vault was disturbed by a refused change: %v", err)
	}
}

// 誤った推測は、だんだん遅くなる。
//
// vault ファイルはコピーしてオフラインで攻撃できるので、これは攻撃者と中身の
// あいだに立つものではない — それは Argon2id である。これが止めるのは安価な場合、
// すなわち、動作中のアプリケーションに対して、答えられる限りの速さでパスワードを
// 試すローカルのプロセスである。
func TestWrongMasterPasswordsAreAnsweredMoreSlowly(t *testing.T) {
	clock := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	var waited []time.Duration
	service, _ := newClockedService(t, func() time.Time { return clock })
	service.SetSleep(func(d time.Duration) { waited = append(waited, d) })
	if err := service.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	for range 4 {
		if err := service.Unlock("not the master password"); !errors.Is(err, secret.ErrWrongPassphrase) {
			t.Fatalf("Unlock = %v", err)
		}
	}
	if len(waited) != 4 {
		t.Fatalf("waits = %v, want one per refusal", waited)
	}
	// 各拒否は前回より長く待つ。上限まで。
	for index := 1; index < len(waited); index++ {
		if waited[index] < waited[index-1] {
			t.Errorf("wait %d (%v) is shorter than wait %d (%v)", index, waited[index], index-1, waited[index-1])
		}
	}
	if waited[len(waited)-1] > secret.MaxUnlockDelay {
		t.Errorf("the wait grew past its ceiling: %v", waited[len(waited)-1])
	}

	// 正しいものは即座に答えられ、誤ったものが積み上げたものを消し去る。
	waited = nil
	if err := service.Unlock(passphrase); err != nil {
		t.Fatalf("Unlock with the right password = %v", err)
	}
	if len(waited) != 0 {
		t.Errorf("a correct password waited: %v", waited)
	}
}
