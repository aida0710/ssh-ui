package secret_test

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"sshc/internal/envelope"
	"sshc/internal/secret"
)

const passphrase = "correct horse battery staple"

func sealedVault(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	for alias, password := range entries {
		// 「このホストのためにパスワードを保存する」とは、alias にちなんで名付けられた
		// 資格情報と、その alias がそれを指すこと、の組である。
		if err := vault.Set(secret.KindPassword, alias, password); err != nil {
			t.Fatalf("Set(%q) = %v", alias, err)
		}
		if err := vault.Assign(secret.KindPassword, alias, alias); err != nil {
			t.Fatalf("Assign(%q) = %v", alias, err)
		}
	}
	sealed, err := vault.Seal()
	if err != nil {
		t.Fatalf("Seal = %v", err)
	}
	return sealed
}

func TestSealThenOpenRoundTrips(t *testing.T) {
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2 ", "nas": "p@ss word"})

	vault, err := secret.Open(sealed, passphrase)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	// パスワードは正当に空白で終わりうる。ここにあるものがそれを削ってはならない。
	if got, ok := vault.SecretFor(secret.KindPassword, "bastion"); !ok || got != "hunter2 " {
		t.Errorf("Password(bastion) = %q, %v", got, ok)
	}
	if got, _ := vault.SecretFor(secret.KindPassword, "nas"); got != "p@ss word" {
		t.Errorf("Password(nas) = %q", got)
	}
	if !slices.Equal(vault.Subjects(secret.KindPassword), []string{"bastion", "nas"}) {
		t.Errorf("Aliases = %#v", vault.Subjects(secret.KindPassword))
	}
}

func TestSealedBytesContainNoPasswordAndNoAlias(t *testing.T) {
	// このファイルは同期される。それを入手した観測者が、どのホストにパスワードが
	// 保存されているかを知ってはならないし、まして中身を知ってはならない。
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	for _, plaintext := range []string{"hunter2", "bastion", "passwords", "schemaVersion"} {
		if bytes.Contains(sealed, []byte(plaintext)) {
			t.Errorf("the sealed vault contains %q in clear", plaintext)
		}
	}
}

func TestOpenRefusesTheWrongPassphrase(t *testing.T) {
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	_, err := secret.Open(sealed, passphrase+"x")
	if !errors.Is(err, secret.ErrWrongPassphrase) {
		t.Fatalf("Open = %v, want ErrWrongPassphrase", err)
	}
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Error("the error carries the plaintext")
	}
}

func TestOpenRefusesATamperedFileIncludingItsHeader(t *testing.T) {
	// ヘッダーは KDF のコストを運ぶ。それが認証されていなければ、攻撃者はそれを
	// 可能な限り安いパラメータへ書き換え、封じられたときのコストではなくそのコストで
	// パスフレーズを攻撃できてしまう。
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	// 27 バイト目はソルト長、28 バイト目はソルトの先頭バイトで、最後のバイトはタグの
	// 中にある。コストのフィールドには上に専用のテストがある。それらは AEAD ではなく、
	// 鍵が導出される前に拒否されるからだ。
	for _, index := range []int{27, 28, 31, len(sealed) - 1} {
		tampered := slices.Clone(sealed)
		tampered[index] ^= 0x01
		if _, err := secret.Open(tampered, passphrase); err == nil {
			t.Errorf("a vault with byte %d flipped opened successfully", index)
		}
	}
}

func TestSealUsesAFreshNonceEveryTime(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	if err := vault.Set(secret.KindPassword, "bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for range 50 {
		sealed, err := vault.Seal()
		if err != nil {
			t.Fatalf("Seal = %v", err)
		}
		key := string(sealed)
		if seen[key] {
			t.Fatal("two seals of the same content produced the same bytes")
		}
		seen[key] = true
	}
}

func TestOpenRefusesSomethingThatIsNotAVault(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"short":        []byte("sshc"),
		"wrong magic":  append([]byte("not-an-sshc-en"), make([]byte, 64)...),
		"zero cost":    zeroCostVault(t),
		"truncated":    sealedVault(t, map[string]string{"a": "b"})[:20],
		"only header":  headerOf(t),
		"random bytes": bytes.Repeat([]byte{0xAB}, 128),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := secret.Open(input, passphrase); err == nil {
				t.Fatal("Open succeeded")
			}
		})
	}
}

func TestOpenRefusesAHeaderDemandingAbsurdWork(t *testing.T) {
	// このファイルは他のマシンから届く。64 MiB 上で time=65539 を主張するヘッダーは、
	// 試行あたり 1 コアで約 90 分を要求するので、ロック解除は単に戻ってこなくなる。
	// このパッケージ自身の改竄テストが見つけた。誰かが見に来るまで 5 分間ハングして
	// いたのである。
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})

	expensiveTime := slices.Clone(sealed)
	expensiveTime[19] = 0x01 // time が 65539 になる
	if _, err := secret.Open(expensiveTime, passphrase); !errors.Is(err, secret.ErrCostRefused) {
		t.Fatalf("Open = %v, want ErrCostRefused", err)
	}

	expensiveMemory := slices.Clone(sealed)
	expensiveMemory[22] = 0xFF // memory が約 4 TiB になる
	if _, err := secret.Open(expensiveMemory, passphrase); !errors.Is(err, secret.ErrCostRefused) {
		t.Fatalf("Open = %v, want ErrCostRefused", err)
	}

	manyThreads := slices.Clone(sealed)
	manyThreads[26] = 0xFF
	if _, err := secret.Open(manyThreads, passphrase); !errors.Is(err, secret.ErrCostRefused) {
		t.Fatalf("Open = %v, want ErrCostRefused", err)
	}
}

func TestOpenSaysUpgradeRatherThanCorruptForAFutureFile(t *testing.T) {
	// 「あなたのデータは失われた」と「このビルドは古すぎる」は別のメッセージであり、
	// 後者が真であるときに前者を見せてはならない。
	sealed := sealedVault(t, map[string]string{"bastion": "hunter2"})
	future := slices.Clone(sealed)
	future[16] = 99 // envelope のバージョン

	if _, err := secret.Open(future, passphrase); !errors.Is(err, secret.ErrUnsupportedVersion) {
		t.Fatalf("Open = %v, want ErrUnsupportedVersion", err)
	}

	futureKDF := slices.Clone(sealed)
	futureKDF[17] = 99 // KDF の ID
	if _, err := secret.Open(futureKDF, passphrase); !errors.Is(err, secret.ErrUnsupportedVersion) {
		t.Fatalf("Open = %v, want ErrUnsupportedVersion", err)
	}
}

func TestCreateRefusesAShortPassphrase(t *testing.T) {
	// このファイルはマシンの外へコピーでき、好きなだけ時間をかけてオフラインで攻撃
	// できる。それを高くつくものにする唯一のものが長さである。
	if _, err := secret.Create("short"); !errors.Is(err, secret.ErrWeakPassphrase) {
		t.Fatalf("Create = %v, want ErrWeakPassphrase", err)
	}
	if _, err := secret.Create(strings.Repeat("あ", secret.MinPassphraseLength)); err != nil {
		t.Errorf("a passphrase of %d runes was refused: %v", secret.MinPassphraseLength, err)
	}
}

func TestSetRefusesAnUnsafeAliasAndAnEmptyPassword(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	// alias のルールは、それが記述する対象と一緒に移った。資格情報は、それが何のため
	// のものかにちなんで名付けられる —「オフィスの VM 群」でよい — ので、Set はもはや
	// alias を判定しない。判定するのは Assign である。alias が現れるのはそこだからだ。
	if err := vault.Set(secret.KindPassword, "shared", "x"); err != nil {
		t.Fatalf("Set = %v", err)
	}
	for _, alias := range []string{"", "has space", "has\nnewline", "-U"} {
		if err := vault.Assign(secret.KindPassword, alias, "shared"); !errors.Is(err, secret.ErrUnsafeName) {
			t.Errorf("Assign(%q) = %v, want ErrUnsafeName", alias, err)
		}
	}
	if err := vault.Set(secret.KindPassword, "bastion", ""); !errors.Is(err, secret.ErrEmptySecret) {
		t.Errorf("Set with an empty password = %v, want ErrEmptySecret", err)
	}
}

func TestRenameCarriesThePasswordAndLeavesNothingBehind(t *testing.T) {
	// パスワードを古い alias の下に残したままホストの名前を変えれば、それは孤児に
	// なる。その名前を尋ねるものは二度と現れず、ユーザーからは、パスワードが黙って
	// 効かなくなったように見える。
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Set(secret.KindPassword, "bastion", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Assign(secret.KindPassword, "bastion", "bastion"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Rename(secret.KindPassword, "bastion", "edge"); err != nil {
		t.Fatalf("Rename = %v", err)
	}

	if func() bool { _, ok := vault.SecretFor(secret.KindPassword, "bastion"); return ok }() {
		t.Error("the old alias still has a password")
	}
	if got, ok := vault.SecretFor(secret.KindPassword, "edge"); !ok || got != "hunter2" {
		t.Errorf("Password(edge) = %q, %v", got, ok)
	}
	if err := vault.Rename(secret.KindPassword, "absent", "elsewhere"); err != nil {
		t.Errorf("renaming an alias with no password = %v, want nil", err)
	}
}

func TestPackageImportsNoLogger(t *testing.T) {
	// このアプリケーションのすべてのパスワードはこのパッケージを通る。ここにある
	// ログ出力は、どれほど善意でも、パスワードをファイルに残しうる唯一のものであり、
	// 「追加しないでください」というコメントは防護ではない。
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	forbidden := []string{`"log"`, `"log/slog"`}
	set := token.NewFileSet()
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(set, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imported := range file.Imports {
			if slices.Contains(forbidden, imported.Path.Value) {
				t.Errorf("%s imports %s", name, imported.Path.Value)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no package file was checked, so this assertion proves nothing")
	}
}

func zeroCostVault(t *testing.T) []byte {
	t.Helper()
	sealed := sealedVault(t, map[string]string{"a": "b"})
	zeroed := slices.Clone(sealed)
	// memory = 0。これでは KDF が無料になってしまう。
	zeroed[22], zeroed[23], zeroed[24], zeroed[25] = 0, 0, 0, 0
	return zeroed
}

func headerOf(t *testing.T) []byte {
	t.Helper()
	sealed := sealedVault(t, map[string]string{"a": "b"})
	return sealed[:44]
}

// 名前空間がひとつなら、ホストのパスワード選択画面が鍵のパスフレーズを提示でき、
// それを選べばそのパスフレーズがログインパスワードとしてリモートホストへ送られて
// しまう。分離はコメントではなく表明で示す。コメントは何も拒否できないから
// である。
func TestVaultKeepsTheTwoNamespacesApart(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Set(secret.KindPassword, "office", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Set(secret.KindKeyPassphrase, "build", "phrase"); err != nil {
		t.Fatal(err)
	}

	if err := vault.Assign(secret.KindPassword, "web-1", "build"); err == nil {
		t.Error("a host referenced a key passphrase")
	}
	if err := vault.Assign(secret.KindKeyPassphrase, "keys/id_work", "office"); err == nil {
		t.Error("a key referenced an account password")
	}
	if err := vault.Assign(secret.KindPassword, "web-1", "office"); err != nil {
		t.Errorf("a host could not reference an account password: %v", err)
	}
	if err := vault.Assign(secret.KindKeyPassphrase, "keys/id_work", "build"); err != nil {
		t.Errorf("a key could not reference a key passphrase: %v", err)
	}
}

func TestVaultRelocatesKeySubjectsFromOneSnapshot(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	_ = vault.Set(secret.KindKeyPassphrase, "work", "phrase")
	_ = vault.Assign(secret.KindKeyPassphrase, "keys/work/id_a", "work")
	_ = vault.Assign(secret.KindKeyPassphrase, "keys/work/id_b", "work")

	changed, err := vault.RelocateSubjects(secret.KindKeyPassphrase, map[string]string{
		"keys/work/id_a": "keys/client/id_a",
		"keys/work/id_b": "keys/client/id_b",
	})
	if err != nil || !changed {
		t.Fatalf("RelocateSubjects = %v, %v", changed, err)
	}
	for _, old := range []string{"keys/work/id_a", "keys/work/id_b"} {
		if _, ok := vault.SecretFor(secret.KindKeyPassphrase, old); ok {
			t.Errorf("old subject %q still resolves", old)
		}
	}
	for _, next := range []string{"keys/client/id_a", "keys/client/id_b"} {
		if value, ok := vault.SecretFor(secret.KindKeyPassphrase, next); !ok || value != "phrase" {
			t.Errorf("new subject %q = %q, %v", next, value, ok)
		}
	}
}

// 秘密に名前を付ける意味は、20 台のマシンがひとつのエントリを共有することにある。
// だからそのエントリは、まだどれかが指しているあいだは取り除けない。
func TestVaultRefusesToDeleteACredentialInUseAndSaysWhatUsesIt(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	_ = vault.Set(secret.KindPassword, "office", "s3cret")
	_ = vault.Assign(secret.KindPassword, "web-1", "office")
	_ = vault.Assign(secret.KindPassword, "web-2", "office")

	err = vault.Delete(secret.KindPassword, "office")
	if !errors.Is(err, secret.ErrCredentialInUse) {
		t.Fatalf("Delete error = %v, want ErrCredentialInUse", err)
	}
	if uses := vault.Uses(secret.KindPassword, "office"); !slices.Equal(uses, []string{"web-1", "web-2"}) {
		t.Errorf("uses = %#v, want both aliases", uses)
	}

	vault.Unassign(secret.KindPassword, "web-1")
	vault.Unassign(secret.KindPassword, "web-2")
	if err := vault.Delete(secret.KindPassword, "office"); err != nil {
		t.Errorf("Delete of an unused credential = %v", err)
	}
}

// バージョン 1 の文書は、alias ごとにパスワードを持ち、名前は持たなかった。世界に
// 多くともひとつしか存在せず、移行は移行する対象より大きくなるので、画面が「もう
// 一度設定してください」に変えられるエラーで拒否する。
func TestAVersionOneDocumentIsRefused(t *testing.T) {
	key, err := envelope.Derive(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte(`{"schemaVersion":1,"passwords":{"web-1":"s3cret"}}`))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := secret.Open(sealed, passphrase); !errors.Is(err, secret.ErrOldVault) {
		t.Fatalf("Open error = %v, want ErrOldVault", err)
	}
}

func TestSealedBytesCarryNothingFromEitherNamespace(t *testing.T) {
	vault, err := secret.Create(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	_ = vault.Set(secret.KindPassword, "office-vm", "s3cret-password")
	_ = vault.Assign(secret.KindPassword, "web-1", "office-vm")
	_ = vault.Set(secret.KindKeyPassphrase, "build-key", "s3cret-phrase")
	_ = vault.Assign(secret.KindKeyPassphrase, "keys/id_work", "build-key")
	sealed, err := vault.Seal()
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{
		"office-vm", "s3cret-password", "web-1",
		"build-key", "s3cret-phrase", "keys/id_work",
	} {
		if bytes.Contains(sealed, []byte(absent)) {
			t.Errorf("the sealed file carries %q", absent)
		}
	}
}
