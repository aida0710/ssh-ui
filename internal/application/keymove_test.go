package application

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/keys"
	"sshc/internal/storage"
)

// 本物の Ed25519 鍵ペアを一度だけ生成し、定数として保持する。テストごとに
// 1 つ作るとしたら、このパッケージで唯一遅い処理になってしまう。そしてこのバイト
// 列こそが、スキャナーがこのファイルを "other" ではなく秘密鍵として分類する根拠である。
const (
	relocateTestPrivate = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBLBQZBkOLcHOKZDGnDlOfyJTPuKQpVE5MOZaSNPWy5xQAAAJBhMS0aYTEt
GgAAAAtzc2gtZWQyNTUxOQAAACBLBQZBkOLcHOKZDGnDlOfyJTPuKQpVE5MOZaSNPWy5xQ
AAAEBGD9wRSuRSCLDMHTmDzJqJDBNPo5Y6dCLLIsG6UhTKWksFBkGQ4twc4pkMacOU5/Il
M+4pClUTkw5lpI09bLnFAAAADWFpZGFAZXhhbXBsZQECAwQ=
-----END OPENSSH PRIVATE KEY-----
`
	relocateTestPublic = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEsFBkGQ4twc4pkMacOU5/IlM+4pClUTkw5lpI09bLnF aida@example\n"
)

// keyInventory は鍵 vault と同じやり方でワークスペースを読むので、
// relocation のテストは実際に動くアプリケーションが使うのと同じ分類を行使する。
func keyInventory(t *testing.T, workspace *storage.Workspace) *keys.Inventory {
	t.Helper()
	service := keys.NewService(keys.ServiceOptions{
		Workspace:    workspace,
		Transactions: storage.NewManager(workspace, nil, rand.Reader),
		Resolver:     storage.NewResolver(workspace),
	})
	inventory, err := service.Inventory()
	if err != nil {
		t.Fatalf("Inventory error = %v", err)
	}
	return inventory
}

func writeKeyPair(t *testing.T, workspace *storage.Workspace, relative string) {
	t.Helper()
	absolute := filepath.Join(workspace.Root(), filepath.FromSlash(relative))
	if err := workspace.EnsureDirectory(filepath.Dir(absolute)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, []byte(relocateTestPrivate), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute+".pub", []byte(relocateTestPublic), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stringPointer(value string) *string { return &value }

func TestRelocateKeyRewritesEveryDirectiveThatNamesIt(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// 2 つのファイル、3 通りの綴り、そのうち 1 つには行末コメントが
	// 付く: パス自体を除くすべてのバイトが生き残らなければならない。
	const source = "Host build\n\tIdentityFile ~/.ssh/id_work  # the build key\n" +
		"Host deploy\n\tIdentityFile=%d/.ssh/id_work\n\tCertificateFile ~/.ssh/id_work.pub\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if result.RelativePath != "keys/work/id_work" || result.Group != "work" {
		t.Errorf("result = %#v", result)
	}

	for _, name := range []string{"keys/work/id_work", "keys/work/id_work.pub"} {
		if _, statErr := os.Lstat(filepath.Join(workspace.Root(), filepath.FromSlash(name))); statErr != nil {
			t.Errorf("%s was not created: %v", name, statErr)
		}
	}
	// ユーザーが書いた綴りこそ OpenSSH が解決し、ユーザーが
	// 認識するものなので、~/.ssh より下の部分だけが変わった。
	want := strings.ReplaceAll(source, "/.ssh/id_work", "/.ssh/keys/work/id_work")
	if got := readFile(t, workspace, "conf.d/30-keys.conf"); got != want {
		t.Errorf("configuration =\n%q\nwant\n%q", got, want)
	}
	if len(result.References) != 3 {
		t.Errorf("references = %#v, want all three directives", result.References)
	}
}

func TestRelocateKeyRenamesWithoutChangingGroup(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"),
		[]byte("Host build\n\tIdentityFile ~/.ssh/id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work"),
		NewName: stringPointer("id_build"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if result.RelativePath != "id_build" {
		t.Errorf("relative path = %q, want id_build", result.RelativePath)
	}
	if got := readFile(t, workspace, "conf.d/30-keys.conf"); got != "Host build\n\tIdentityFile ~/.ssh/id_build\n" {
		t.Errorf("configuration = %q", got)
	}
	// ログイン Keychain のパスフレーズは古い絶対パスの下に登録
	// されており、macOS がそのエントリを所有しているので、結果は毎回そう述べる。
	if len(result.Notes) != 1 || result.Notes[0] != NoteKeychainEntryStale {
		t.Errorf("notes = %#v, want the Keychain warning", result.Notes)
	}
}

func TestRelocateKeyMovesTheWholeFingerprintGroupAndLeavesALookAlike(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// 同じ鍵だが、ユーザーが選んだ名前である。それは "id_work" に拡張子を足した
	// ものではないので、移動すればこのアプリケーションがその名前の意味を決めつけることになる。
	if err := os.WriteFile(filepath.Join(workspace.Root(), "backup_copy.pub"), []byte(relocateTestPublic), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if len(result.Files) != 2 {
		t.Errorf("files = %#v, want the private key and its public half", result.Files)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "backup_copy.pub" {
		t.Errorf("skipped = %#v", result.Skipped)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "backup_copy.pub")); statErr != nil {
		t.Errorf("the look-alike was moved: %v", statErr)
	}
}

func TestRelocateKeyRefusesAnUndeclaredGroup(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("marketing"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerKeyGroupNotDeclared) {
		t.Errorf("blockers = %#v", result.Blockers)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "keys")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a refused relocation created the keys directory: %v", statErr)
	}
}

func TestRelocateKeyRefusesWhileADirectiveCannotBeResolved(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// 相対 IdentityFile は ssh 自身の working directory に対して
	// 解決されるが、それはこのアプリケーションには分からない。
	// それは "id_work" を名指ししているので、この鍵である可能性は十分にある。
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"),
		[]byte("Host build\n\tIdentityFile id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerKeyUnresolved) {
		t.Errorf("blockers = %#v", result.Blockers)
	}
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "id_work")); statErr != nil {
		t.Errorf("a blocked relocation moved the key: %v", statErr)
	}
}

func TestRelocateKeyRefusesADestinationAnIncludeWouldRead(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	// keys/ の下に届く手書きの Include は、destination を設定
	// ファイルにしてしまう。秘密鍵が ssh_config としてパースされる
	// のはあり得る中で最悪の結果なので、これは警告ではなく拒否する。
	entry := readFile(t, workspace, "config")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"),
		[]byte("Include keys/work/*\n"+entry), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	found := false
	for _, blocker := range result.Blockers {
		if strings.HasPrefix(blocker, BlockerKeyDestinationRead) {
			found = true
		}
	}
	if !found {
		t.Errorf("blockers = %#v, want key_destination_is_config", result.Blockers)
	}
}

func TestRelocateKeyRefusesADestinationThatIsOccupied(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "id_build.pub"), []byte("occupied\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work"),
		NewName: stringPointer("id_build"),
	})
	if !errors.Is(err, ErrKeyRelocateBlocked) {
		t.Fatalf("RelocateKey error = %v, want ErrKeyRelocateBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerKeyTargetOccupied) {
		t.Errorf("blockers = %#v", result.Blockers)
	}
}

func TestRelocateKeyRefusesHalfOfAPairAndTheNameItAlreadyHas(t *testing.T) {
	service, workspace := newTestService(t)
	writeKeyPair(t, workspace, "id_work")
	inventory := keyInventory(t, workspace)

	if _, err := service.RelocateKey(inventory, KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work.pub"),
		NewName: stringPointer("id_build"),
	}); !errors.Is(err, ErrKeyRelocateNotSupported) {
		t.Errorf("public half error = %v, want ErrKeyRelocateNotSupported", err)
	}
	if _, err := service.RelocateKey(inventory, KeyRelocateRequest{
		KeyID:   keys.ItemID("id_work"),
		NewName: stringPointer("id_work"),
	}); !errors.Is(err, ErrKeyRelocateUnchanged) {
		t.Errorf("unchanged error = %v, want ErrKeyRelocateUnchanged", err)
	}
}

func TestRelocateKeyIsOneTransactionThatCopiesNoKeyMaterial(t *testing.T) {
	service, workspace := newTestService(t)
	declareGroup(t, service, "work")
	writeKeyPair(t, workspace, "id_work")
	if err := os.Chmod(filepath.Join(workspace.Root(), "id_work"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Root(), "conf.d", "30-keys.conf"),
		[]byte("Host build\n\tIdentityFile ~/.ssh/id_work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.RelocateKey(keyInventory(t, workspace), KeyRelocateRequest{
		KeyID: keys.ItemID("id_work"),
		Group: stringPointer("work"),
	})
	if err != nil {
		t.Fatalf("RelocateKey error = %v", err)
	}
	if result.TransactionID == "" {
		t.Fatal("the relocation reported no transaction")
	}

	// 移動は rename(2) である: バイト列がこのプロセスを通って運ばれることは
	// 決してないので、mode は生き残り、コピーが世代バックアップディレクトリに届くこともない。
	info, err := os.Lstat(filepath.Join(workspace.Root(), "keys", "work", "id_work"))
	if err != nil {
		t.Fatalf("relocated key missing: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("permission = %04o, want the original 0400", info.Mode().Perm())
	}
	backups := filepath.Join(workspace.StateDir(), "backups")
	err = filepath.WalkDir(backups, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(contents), "OPENSSH PRIVATE KEY") {
			t.Fatalf("key material was copied into the backup directory: %s", path)
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("walk backups: %v", err)
	}
}
