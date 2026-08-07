package keys

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshc/internal/platform"
	"sshc/internal/storage"
)

// steppingClock は呼び出しごとに 1 秒進めるので、ひとつのテスト内の二つの
// トランザクションが識別子を共有することはない。
func steppingClock(start time.Time) func() time.Time {
	current := start
	return func() time.Time {
		current = current.Add(time.Second)
		return current
	}
}

// newQueryRunner は、実物の OpenSSH 10.2p1 の出力でアルゴリズムの問い合わせに
// 答える。一度取得して定数として保持したものである。
func newQueryRunner() *fakeRunner {
	return &fakeRunner{output: platform.Output{Stdout: []byte(opensshQueryOutput)}}
}

func newTestService(t *testing.T, runner platform.OutputRunner) (*Service, *storage.Workspace) {
	t.Helper()
	return newServiceWithAgent(t, runner, nil)
}

// newServiceWithAgent は、アプリケーションと同じやり方で、ServiceOptions を通して
// サービスを組み立てる。これにより、エージェントの継ぎ目が、テストが非公開フィールド
// へ代入したものではなく、実際に Service へ届いていることが示される。
func newServiceWithAgent(t *testing.T, runner platform.OutputRunner, agent platform.KeyAgent) (*Service, *storage.Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	clock := steppingClock(time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC))
	manager := storage.NewManager(workspace, clock, rand.Reader)
	// アプリケーションはすべての世代バックアップをマスターパスワードで封じるので、
	// これらのテストもそうする。そうしないと、アプリケーションがもう書かない形の
	// バックアップについて何かを示すだけになってしまう。
	manager.Seal = sealForTest
	manager.Unseal = unsealForTest
	service := NewService(ServiceOptions{
		Workspace:    workspace,
		Transactions: manager,
		Resolver:     storage.NewResolver(workspace),
		Catalogue:    newFakeCatalogue(runner, fakeToolchain{}),
		Agent:        agent,
		Now:          clock,
		Random:       rand.Reader,
	})
	return service, workspace
}

// assertNoKeyMaterialInBackups は世代バックアップのディレクトリを走査し、そこに
// 平文の秘密鍵を持つファイルがあれば失敗させる。
//
// 以前はディレクトリがコピーをまったく持たないことを意味していた。だからこそ
// パスフレーズの変更を取り消せなかったのである。いまは封をしたコピーを持ち、それを
// 安全に保つのがこれだ。ディスク上のバイト列は、マスターパスワードなしでは読めて
// はならない。変わったのは封をすることであって、平文についてのルールではない。
func assertNoKeyMaterialInBackups(t *testing.T, workspace *storage.Workspace) {
	t.Helper()
	backups := filepath.Join(workspace.StateDir(), "backups")
	err := filepath.WalkDir(backups, func(path string, entry os.DirEntry, walkErr error) error {
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
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("walk backups: %v", err)
	}
}

func TestGenerateWritesAnEncryptedPairThroughATransaction(t *testing.T) {
	runner := newQueryRunner()
	service, workspace := newTestService(t, runner)

	result, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	})
	if err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if result.RelativePath != "id_work" || result.PublicRelativePath != "id_work.pub" {
		t.Fatalf("result paths = %q / %q", result.RelativePath, result.PublicRelativePath)
	}
	if !result.Encrypted {
		t.Errorf("Encrypted = false, want true")
	}
	if result.TransactionID == "" {
		t.Errorf("TransactionID is empty; the write was not journalled")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("generation started a child process: %#v", runner.commands)
	}

	privateContents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work"))
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}
	material, err := InspectPrivateKey(privateContents)
	if err != nil {
		t.Fatalf("InspectPrivateKey error = %v", err)
	}
	if !material.Encrypted {
		t.Fatalf("the generated key on disk is not encrypted")
	}
	if material.Fingerprint != result.Fingerprint {
		t.Errorf("fingerprint on disk = %q, reported = %q", material.Fingerprint, result.Fingerprint)
	}
	if _, err := DecodePrivateKey(privateContents, []byte("correct horse")); err != nil {
		t.Fatalf("the generated key does not open with its own passphrase: %v", err)
	}

	for _, name := range []string{"id_work", "id_work.pub"} {
		info, statErr := os.Lstat(filepath.Join(workspace.Root(), name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s permission = %04o, want 0600", name, info.Mode().Perm())
		}
	}
	assertNoKeyMaterialInBackups(t, workspace)

	history, err := storage.NewManager(workspace, time.Now, rand.Reader).History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	if len(history) != 1 || history[0].Operation != "key.generate" {
		t.Fatalf("history = %#v, want one key.generate record", history)
	}
}

func TestGenerateRefusesUnsafeAndAmbiguousRequests(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())
	if err := os.WriteFile(filepath.Join(workspace.Root(), "taken"), []byte("existing\n"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	tests := []struct {
		name      string
		request   GenerateRequest
		wantError error
	}{
		{
			name:      "empty passphrase without acknowledgement",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "id_a", Comment: "aida@laptop"},
			wantError: ErrPassphraseRequired,
		},
		{
			name:      "passphrase together with the unencrypted flag",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "id_b", Comment: "aida@laptop", Passphrase: []byte("x"), Unencrypted: true},
			wantError: ErrConflictingPassphraseChoice,
		},
		{
			name:      "path traversal in the file name",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "../escape", Comment: "aida@laptop", Passphrase: []byte("x")},
			wantError: ErrInvalidFileName,
		},
		{
			name:      "hardware algorithm",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519SK, FileName: "id_c", Comment: "aida@laptop", Passphrase: []byte("x")},
			wantError: ErrHardwareAlgorithm,
		},
		{
			name:      "existing file",
			request:   GenerateRequest{Algorithm: AlgorithmEd25519, FileName: "taken", Comment: "aida@laptop", Passphrase: []byte("x")},
			wantError: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Generate(test.request)
			if err == nil {
				t.Fatalf("Generate accepted %s", test.name)
			}
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}

	entries, err := os.ReadDir(workspace.Root())
	if err != nil {
		t.Fatalf("read workspace: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "taken" && entry.Name() != StateDirectoryName {
			t.Fatalf("a rejected request created %s", entry.Name())
		}
	}
}

func TestGenerateAcceptsAnExplicitlyUnencryptedKey(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())

	result, err := service.Generate(GenerateRequest{
		Algorithm:   AlgorithmEd25519,
		FileName:    "id_automation",
		Comment:     "automation@laptop",
		Unencrypted: true,
	})
	if err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if result.Encrypted {
		t.Fatalf("Encrypted = true, want false")
	}
	contents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_automation"))
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}
	if _, err := DecodePrivateKey(contents, nil); err != nil {
		t.Fatalf("the unencrypted key does not parse without a passphrase: %v", err)
	}
}

func TestChangePassphraseRewritesTheKeyAndKeepsItsComment(t *testing.T) {
	runner := newQueryRunner()
	service, workspace := newTestService(t, runner)
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("first passphrase"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}

	if _, err := service.ChangePassphrase(PassphraseChange{
		KeyID:   ItemID("id_work"),
		Current: []byte("wrong"),
		New:     []byte("second passphrase"),
	}); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong current passphrase error = %v, want ErrWrongPassphrase", err)
	}

	result, err := service.ChangePassphrase(PassphraseChange{
		KeyID:   ItemID("id_work"),
		Current: []byte("first passphrase"),
		New:     []byte("second passphrase"),
	})
	if err != nil {
		t.Fatalf("ChangePassphrase error = %v", err)
	}
	if !result.Encrypted {
		t.Errorf("Encrypted = false, want true")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("a passphrase change started a child process: %#v", runner.commands)
	}

	contents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if _, err := DecodePrivateKey(contents, []byte("second passphrase")); err != nil {
		t.Fatalf("the key does not open with the new passphrase: %v", err)
	}
	if _, err := DecodePrivateKey(contents, []byte("first passphrase")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("the old passphrase still opens the key: %v", err)
	}

	publicContents, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work.pub"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	info, err := InspectPublicKey(publicContents)
	if err != nil {
		t.Fatalf("InspectPublicKey error = %v", err)
	}
	if info.Comment != "aida@laptop" {
		t.Fatalf("public key comment = %q, want %q", info.Comment, "aida@laptop")
	}
	for _, note := range result.Notes {
		if note == NoteCommentNotPreserved {
			t.Fatalf("the comment was reported as lost even though a matching public key exists")
		}
	}
}

// パスフレーズの変更は秘密鍵を置き換えるものであり、トランザクションマネージャは
// 置き換えるすべてについて世代バックアップを保持する。そのバックアップはユーザーの
// 秘密鍵の二つ目のコピーになり、設計はそれを禁じている。鍵素材が複製される場所は
// ごみ箱だけである。
func TestChangePassphraseKeepsKeyMaterialOutOfTheBackupDirectory(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("first passphrase"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if _, err := service.ChangePassphrase(PassphraseChange{
		KeyID:   ItemID("id_work"),
		Current: []byte("first passphrase"),
		New:     []byte("second passphrase"),
	}); err != nil {
		t.Fatalf("ChangePassphrase error = %v", err)
	}
	assertNoKeyMaterialInBackups(t, workspace)
}

func TestRevealReturnsTheKeyAndRecordsAnAuditFact(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}

	revealed, err := service.Reveal(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Reveal error = %v", err)
	}
	if !revealed.Encrypted {
		t.Errorf("Encrypted = false, want true")
	}
	onDisk, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(revealed.Contents) != string(onDisk) {
		t.Fatalf("Reveal returned different bytes than the file holds")
	}

	if _, err := service.Reveal(ItemID("id_work.pub")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revealing a public key = %v, want ErrUnknownKey", err)
	}
	if _, err := service.Reveal("not-an-identifier"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revealing an unknown identifier = %v, want ErrUnknownKey", err)
	}

	history, err := storage.NewManager(workspace, time.Now, rand.Reader).History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	reveals := 0
	for _, record := range history {
		if record.Operation == "key.reveal" {
			reveals++
		}
	}
	if reveals != 1 {
		t.Fatalf("key.reveal records = %d, want 1", reveals)
	}

	records, err := os.ReadDir(filepath.Join(workspace.StateDir(), "history"))
	if err != nil {
		t.Fatalf("read history directory: %v", err)
	}
	for _, entry := range records {
		document, readErr := os.ReadFile(filepath.Join(workspace.StateDir(), "history", entry.Name()))
		if readErr != nil {
			t.Fatalf("read history record: %v", readErr)
		}
		if strings.Contains(string(document), "OPENSSH PRIVATE KEY") {
			t.Fatalf("an audit record contains key material")
		}
	}
}

func TestAlgorithmsAreReadThroughTheCommandSeam(t *testing.T) {
	runner := newQueryRunner()
	service, _ := newTestService(t, runner)

	catalogue := service.Algorithms(context.Background())
	if catalogue.Source != "ssh -Q key" {
		t.Fatalf("Source = %q", catalogue.Source)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v, want one", runner.commands)
	}
	for _, argument := range runner.commands[0].Arguments {
		if argument == "-G" {
			t.Fatalf("the catalogue must never run an effective-configuration evaluation")
		}
	}
}

// 確認は、ダイアログが表示した内容のダイジェストに結び付けられる。ディスク上の鍵が
// 変われば、そのダイジェストも変わらなければならない。さもなければ、ある鍵を確認
// したユーザーが、それを置き換えた何かを承認したことになってしまう。
func TestConfirmationEvidenceTracksWhatTheUserWasShown(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())
	generateWorkKey(t, service)

	first, err := service.ConfirmationEvidence(ConfirmRevealKey, ItemID("id_work"))
	if err != nil {
		t.Fatalf("ConfirmationEvidence error = %v", err)
	}
	if first == "" {
		t.Fatalf("evidence is empty, so a token would be bound to nothing")
	}
	again, err := service.ConfirmationEvidence(ConfirmRevealKey, ItemID("id_work"))
	if err != nil {
		t.Fatalf("ConfirmationEvidence error = %v", err)
	}
	if again != first {
		t.Fatalf("evidence is not stable for an unchanged key: %q then %q", first, again)
	}

	// 同じフィンガープリントでもパスが違えば、別の確認である。
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_other",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	other, err := service.ConfirmationEvidence(ConfirmRevealKey, ItemID("id_other"))
	if err != nil {
		t.Fatalf("ConfirmationEvidence error = %v", err)
	}
	if other == first {
		t.Fatalf("two different keys produced the same evidence")
	}

	// 同じパスの背後にあるファイルを置き換えたら、evidence は無効にならなければならない。
	replacement, _, _ := newKeyPairFixture(t, "different passphrase")
	if err := os.WriteFile(filepath.Join(workspace.Root(), "id_work"), replacement, 0o600); err != nil {
		t.Fatalf("replace key: %v", err)
	}
	changed, err := service.ConfirmationEvidence(ConfirmRevealKey, ItemID("id_work"))
	if err != nil {
		t.Fatalf("ConfirmationEvidence error = %v", err)
	}
	if changed == first {
		t.Fatalf("the key was replaced but the evidence did not change")
	}

	if _, err := service.ConfirmationEvidence(ConfirmRevealKey, "not-an-identifier"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("evidence for an unknown key = %v, want ErrUnknownKey", err)
	}
	if _, err := service.ConfirmationEvidence(ConfirmRevealKey, ItemID("id_work.pub")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("evidence for a public key = %v, want ErrUnknownKey", err)
	}
	if _, err := service.ConfirmationEvidence(ConfirmationSubject("nonsense"), ItemID("id_work")); err == nil {
		t.Fatalf("an unknown confirmation subject was accepted")
	}
}

func TestConfirmationEvidenceForATrashEntryTracksItsListing(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())
	generateWorkKey(t, service)
	trashed, err := service.Trash(ItemID("id_work"))
	if err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	first, err := service.ConfirmationEvidence(ConfirmPurgeEntry, trashed.EntryID)
	if err != nil {
		t.Fatalf("ConfirmationEvidence error = %v", err)
	}
	if first == "" {
		t.Fatalf("evidence is empty")
	}

	// エントリからファイルをひとつ取り除けば、ダイアログが列挙する内容が変わる。
	if err := os.Remove(filepath.Join(workspace.Root(), StateDirectoryName, "trash", trashed.EntryID, "id_work.pub")); err != nil {
		t.Fatalf("remove trashed public key: %v", err)
	}
	changed, err := service.ConfirmationEvidence(ConfirmPurgeEntry, trashed.EntryID)
	if err != nil {
		t.Fatalf("ConfirmationEvidence error = %v", err)
	}
	if changed == first {
		t.Fatalf("the entry changed but the evidence did not")
	}

	if _, err := service.ConfirmationEvidence(ConfirmPurgeEntry, "../escape"); !errors.Is(err, ErrUnknownTrashEntry) {
		t.Fatalf("evidence for a traversal identifier = %v, want ErrUnknownTrashEntry", err)
	}
}

// fakeAgent は、本物のエージェントに触れずにすべての登録リクエストを記録する。
// パスフレーズは到着時にコピーする。Register は返る前に呼び出し側のバッファを
// 消去するからである。
type fakeAgent struct {
	available   bool
	requests    []platform.AgentAddRequest
	passphrases [][]byte
	identities  []platform.AgentIdentity
	addError    error
	removed     []string
	removeError error
}

func (fake *fakeAgent) Available(context.Context) bool { return fake.available }

func (fake *fakeAgent) List(context.Context) ([]platform.AgentIdentity, error) {
	if !fake.available {
		return nil, platform.ErrAgentUnavailable
	}
	return fake.identities, nil
}

func (fake *fakeAgent) Add(_ context.Context, request platform.AgentAddRequest) error {
	if !fake.available {
		return platform.ErrAgentUnavailable
	}
	fake.requests = append(fake.requests, request)
	fake.passphrases = append(fake.passphrases, append([]byte(nil), request.Passphrase...))
	return fake.addError
}

func (fake *fakeAgent) Remove(_ context.Context, publicKeyPath string) error {
	if !fake.available {
		return platform.ErrAgentUnavailable
	}
	fake.removed = append(fake.removed, publicKeyPath)
	return fake.removeError
}

func generateWorkKey(t *testing.T, service *Service) {
	t.Helper()
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
}

func TestRegisterSendsTheKeyPathAndPassphraseToTheAgentOnly(t *testing.T) {
	agent := &fakeAgent{
		available:  true,
		identities: []platform.AgentIdentity{{Bits: 256, Fingerprint: "SHA256:abcdef", Comment: "aida@laptop", Algorithm: "ED25519"}},
	}
	service, workspace := newServiceWithAgent(t, newQueryRunner(), agent)
	generateWorkKey(t, service)

	passphrase := []byte("correct horse")
	result, err := service.Register(context.Background(), RegisterRequest{
		KeyID:           ItemID("id_work"),
		Passphrase:      passphrase,
		LifetimeSeconds: 3600,
		StoreInKeychain: true,
	})
	if err != nil {
		t.Fatalf("Register error = %v", err)
	}
	if len(agent.requests) != 1 {
		t.Fatalf("requests = %#v, want one", agent.requests)
	}
	request := agent.requests[0]
	if request.PrivateKeyPath != filepath.Join(workspace.Root(), "id_work") {
		t.Errorf("PrivateKeyPath = %q", request.PrivateKeyPath)
	}
	if request.LifetimeSeconds != 3600 || !request.StoreInKeychain {
		t.Errorf("request = %#v", request)
	}
	if string(agent.passphrases[0]) != "correct horse" {
		t.Errorf("the agent received %q, want the passphrase", agent.passphrases[0])
	}
	for index, value := range passphrase {
		if value != 0 {
			t.Fatalf("the caller's passphrase buffer was not wiped at byte %d", index)
		}
	}
	if len(result.Identities) != 1 {
		t.Errorf("Identities = %#v, want the agent listing", result.Identities)
	}
	if result.Fingerprint == "" || !result.StoredInKeychain || result.LifetimeSeconds != 3600 {
		t.Errorf("result = %#v", result)
	}

	history, err := storage.NewManager(workspace, time.Now, rand.Reader).History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	registrations := 0
	for _, record := range history {
		if record.Operation == "key.agent_add" {
			registrations++
		}
	}
	if registrations != 1 {
		t.Fatalf("key.agent_add records = %d, want 1", registrations)
	}

	records, err := os.ReadDir(filepath.Join(workspace.StateDir(), "history"))
	if err != nil {
		t.Fatalf("read history directory: %v", err)
	}
	for _, entry := range records {
		document, readErr := os.ReadFile(filepath.Join(workspace.StateDir(), "history", entry.Name()))
		if readErr != nil {
			t.Fatalf("read history record: %v", readErr)
		}
		if strings.Contains(string(document), "correct horse") {
			t.Fatalf("the registration record contains the passphrase")
		}
	}
}

func TestRegisterRefusesTrashedAndUnknownKeys(t *testing.T) {
	agent := &fakeAgent{available: true}
	service, _ := newServiceWithAgent(t, newQueryRunner(), agent)
	generateWorkKey(t, service)
	if _, err := service.Trash(ItemID("id_work")); err != nil {
		t.Fatalf("Trash error = %v", err)
	}

	if _, err := service.Register(context.Background(), RegisterRequest{KeyID: ItemID("id_work")}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("registering a trashed key = %v, want ErrUnknownKey", err)
	}
	if _, err := service.Register(context.Background(), RegisterRequest{KeyID: "not-an-identifier"}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("registering an unknown identifier = %v, want ErrUnknownKey", err)
	}
	if len(agent.requests) != 0 {
		t.Fatalf("a trashed or unknown key reached the agent: %#v", agent.requests)
	}
}

func TestRegisterAndIdentitiesReportAnUnreachableAgentHonestly(t *testing.T) {
	withoutAgent, _ := newTestService(t, newQueryRunner())
	generateWorkKey(t, withoutAgent)
	if _, err := withoutAgent.Register(context.Background(), RegisterRequest{KeyID: ItemID("id_work")}); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Fatalf("Register without an agent = %v, want ErrAgentUnavailable", err)
	}
	if identities, reachable := withoutAgent.AgentIdentities(context.Background()); reachable || identities != nil {
		t.Fatalf("AgentIdentities = %#v, %v, want no agent", identities, reachable)
	}

	stopped := &fakeAgent{available: false}
	withStoppedAgent, _ := newServiceWithAgent(t, newQueryRunner(), stopped)
	generateWorkKey(t, withStoppedAgent)
	if _, err := withStoppedAgent.Register(context.Background(), RegisterRequest{KeyID: ItemID("id_work")}); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Fatalf("Register with a stopped agent = %v, want ErrAgentUnavailable", err)
	}
	if _, reachable := withStoppedAgent.AgentIdentities(context.Background()); reachable {
		t.Fatalf("AgentIdentities reported a stopped agent as reachable")
	}

	running := &fakeAgent{
		available:  true,
		identities: []platform.AgentIdentity{{Bits: 256, Fingerprint: "SHA256:abcdef", Algorithm: "ED25519"}},
	}
	withRunningAgent, _ := newServiceWithAgent(t, newQueryRunner(), running)
	identities, reachable := withRunningAgent.AgentIdentities(context.Background())
	if !reachable || len(identities) != 1 {
		t.Fatalf("AgentIdentities = %#v, %v, want the one loaded identity", identities, reachable)
	}
}

// エージェントが拒否した登録が、起きた登録として記録されてはならない。
func TestRegisterRecordsNothingWhenTheAgentRefuses(t *testing.T) {
	agent := &fakeAgent{available: true, addError: platform.ErrAgentRejected}
	service, workspace := newServiceWithAgent(t, newQueryRunner(), agent)
	generateWorkKey(t, service)

	if _, err := service.Register(context.Background(), RegisterRequest{
		KeyID:      ItemID("id_work"),
		Passphrase: []byte("wrong"),
	}); !errors.Is(err, platform.ErrAgentRejected) {
		t.Fatalf("Register error = %v, want ErrAgentRejected", err)
	}

	history, err := storage.NewManager(workspace, time.Now, rand.Reader).History()
	if err != nil {
		t.Fatalf("History error = %v", err)
	}
	for _, record := range history {
		if record.Operation == "key.agent_add" {
			t.Fatalf("a refused registration was recorded in history")
		}
	}
}

func TestValidateFileNameRefusesNamesTheApplicationDependsOn(t *testing.T) {
	reserved := []string{"config", "known_hosts", "authorized_keys", "sshc", "environment", "rc"}
	for _, name := range reserved {
		if err := ValidateFileName(name); !errors.Is(err, ErrInvalidFileName) {
			t.Errorf("ValidateFileName(%q) = %v, want ErrInvalidFileName", name, err)
		}
		if err := ValidateFileName(strings.ToUpper(name)); !errors.Is(err, ErrInvalidFileName) {
			t.Errorf("ValidateFileName(%q) = %v, want ErrInvalidFileName", strings.ToUpper(name), err)
		}
	}
	for _, name := range []string{"id_ed25519", "work", "config_backup", "known_hosts_old"} {
		if err := ValidateFileName(name); err != nil {
			t.Errorf("ValidateFileName(%q) = %v, want nil", name, err)
		}
	}
}

// PublicKey は、背後に確認を持たない唯一の鍵ルートである。したがって、これが秘密鍵
// を読む手段になるのを止めているのは kind の検査であって、それ以外の何物でもない。
// ここのテストは、その検査を、ファイル名ではなく分類器の判断に対して
// 縛る。
func TestPublicKeyReadsThePublicHalfAndRefusesThePrivateOne(t *testing.T) {
	service, _ := newTestService(t, newQueryRunner())

	generated, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	})
	if err != nil {
		t.Fatalf("Generate error = %v", err)
	}

	inventory, err := service.Inventory()
	if err != nil {
		t.Fatalf("Inventory error = %v", err)
	}
	var publicID string
	for _, item := range inventory.Items {
		if item.Kind == KindPublicKey && item.RelativePath == "id_work.pub" {
			publicID = item.ID
		}
	}
	if publicID == "" {
		t.Fatalf("the generated public key is not in the inventory")
	}

	result, err := service.PublicKey(publicID)
	if err != nil {
		t.Fatalf("PublicKey error = %v", err)
	}
	if !strings.HasPrefix(result.Contents, "ssh-ed25519 ") {
		t.Fatalf("contents = %q, want the public key line", result.Contents)
	}
	if strings.Contains(result.Contents, "PRIVATE KEY") {
		t.Fatalf("the public route returned private key material")
	}

	// 同じペアの秘密鍵は拒否される。したがって、別の識別子を渡すことで、確認のない
	// ルートを表示に変えることはできない。
	if _, err := service.PublicKey(generated.ID); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("PublicKey(private key) error = %v, want ErrUnknownKey", err)
	}
}

func TestPublicKeyRefusesAPrivateKeyWearingAPublicName(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())

	// 分類は内容と権限によるもので、接尾辞によることは決してない。id_decoy.pub として
	// 保存された秘密鍵も、ここでは拒否されなければならない。
	generated, err := service.Generate(GenerateRequest{
		Algorithm:   AlgorithmEd25519,
		FileName:    "id_decoy",
		Unencrypted: true,
	})
	if err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	private, err := os.ReadFile(filepath.Join(workspace.Root(), generated.RelativePath))
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}
	decoy := filepath.Join(workspace.Root(), "id_decoy.pub")
	if err := os.WriteFile(decoy, private, 0o600); err != nil {
		t.Fatalf("write decoy: %v", err)
	}

	inventory, err := service.Inventory()
	if err != nil {
		t.Fatalf("Inventory error = %v", err)
	}
	for _, item := range inventory.Items {
		if item.RelativePath != "id_decoy.pub" {
			continue
		}
		if item.Kind == KindPublicKey {
			t.Fatalf("a private key named .pub was classified as a public key")
		}
		if _, err := service.PublicKey(item.ID); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("PublicKey(decoy) error = %v, want ErrUnknownKey", err)
		}
		return
	}
	t.Fatalf("the decoy file is not in the inventory")
}

// declaredGroups は、動作中のアプリケーションが設定エンジンの答えで埋める継ぎ目。
// テストは自前のものを供給するので、このパッケージが自分で決めるのではなく尋ねて
// いることが示される。
func declaredGroups(names ...string) func(string) error {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	return func(name string) error {
		if !allowed[name] {
			return ErrUnknownGroup
		}
		return nil
	}
}

func newGroupKeyService(t *testing.T, groups ...string) (*Service, *storage.Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	clock := steppingClock(time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC))
	service := NewService(ServiceOptions{
		Workspace:     workspace,
		Transactions:  storage.NewManager(workspace, clock, rand.Reader),
		Resolver:      storage.NewResolver(workspace),
		Catalogue:     newFakeCatalogue(newQueryRunner(), fakeToolchain{}),
		Now:           clock,
		Random:        rand.Reader,
		ValidateGroup: declaredGroups(groups...),
	})
	return service, workspace
}

func TestGenerateWritesIntoTheGroupDirectory(t *testing.T) {
	service, workspace := newGroupKeyService(t, "work")

	result, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Group:      "work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	})
	if err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if result.RelativePath != "keys/work/id_work" || result.PublicRelativePath != "keys/work/id_work.pub" {
		t.Fatalf("result = %#v", result)
	}
	for _, name := range []string{"keys/work/id_work", "keys/work/id_work.pub"} {
		info, statErr := os.Lstat(filepath.Join(workspace.Root(), filepath.FromSlash(name)))
		if statErr != nil {
			t.Fatalf("%s missing: %v", name, statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s permission = %04o, want 0600", name, info.Mode().Perm())
		}
	}
	// 識別子はパスに従うので、グループ内の鍵も、ルートにあるものと同じやり方で
	// 指定できる。
	if result.ID != ItemID("keys/work/id_work") {
		t.Errorf("id = %q, want the identifier of its path", result.ID)
	}
}

func TestGenerateRefusesAGroupNothingDeclares(t *testing.T) {
	service, workspace := newGroupKeyService(t, "work")

	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Group:      "marketing",
		Passphrase: []byte("correct horse"),
	}); !errors.Is(err, ErrUnknownGroup) {
		t.Fatalf("Generate error = %v, want ErrUnknownGroup", err)
	}
	// 拒否は何も残さない。必要になったはずのディレクトリすら残さない。
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "keys")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("a refused generation created the keys directory: %v", statErr)
	}
}

func TestGenerateStillRefusesAReservedFileNameInsideAGroup(t *testing.T) {
	service, _ := newGroupKeyService(t, "work")

	// 予約名のルールは、このアプリケーションが依存する名前についてのものであり、
	// どの深さでも適用される。keys/work/config も、やはり config という名前のファイルだ。
	for _, name := range []string{"config", "known_hosts", "id_work.pub"} {
		if _, err := service.Generate(GenerateRequest{
			Algorithm:  AlgorithmEd25519,
			FileName:   name,
			Group:      "work",
			Passphrase: []byte("correct horse"),
		}); !errors.Is(err, ErrInvalidFileName) {
			t.Errorf("Generate(%q) error = %v, want ErrInvalidFileName", name, err)
		}
	}
}

func TestHardwareCommandNamesTheGroupDirectory(t *testing.T) {
	service, workspace := newGroupKeyService(t, "work")

	command, err := service.HardwareCommand(AlgorithmEd25519SK, "id_yubikey", "work", "aida@laptop")
	if err != nil {
		t.Fatalf("HardwareCommand error = %v", err)
	}
	// ユーザーがこれを手で実行するので、このアプリケーションが置いたであろう場所に
	// 鍵を置かなければならない。
	want := filepath.Join(workspace.Root(), "keys", "work", "id_yubikey")
	found := false
	for _, argument := range command {
		if argument == want {
			found = true
		}
	}
	if !found {
		t.Errorf("command = %#v, want it to name %q", command, want)
	}
}

// ソフトウェア鍵のコメントは ssh.MarshalPrivateKey が埋め込むもので、コマンドライン
// には届かない。したがって、ハードウェアの経路が必要とするシェル引用のルールは
// これには当てはまらない。"work laptop" は、人が実際に打ち込むものである。
func TestValidateCommentAcceptsAnOrdinaryComment(t *testing.T) {
	for _, comment := range []string{"work laptop", "aida@mbp", "", "backup key 2026"} {
		if err := ValidateComment(comment); err != nil {
			t.Errorf("ValidateComment(%q) = %v, want nil", comment, err)
		}
	}
}

func TestValidateCommentStillRefusesWhatWouldBreakAFile(t *testing.T) {
	for _, comment := range []string{"two\nlines", "nul\x00byte", "carriage\rreturn"} {
		if err := ValidateComment(comment); err == nil {
			t.Errorf("ValidateComment(%q) = nil, want a refusal", comment)
		}
	}
}

// ハードウェアの経路は、ユーザーが実行するための ssh-keygen コマンドラインを
// 組み立てるので、より厳しいルールを保つ。
func TestHardwareCommentKeepsTheShellSafeRule(t *testing.T) {
	if err := ValidateHardwareComment("work laptop"); err == nil {
		t.Error("ValidateHardwareComment accepted a space, which would need quoting in the shown command")
	}
	if err := ValidateHardwareComment("aida@mbp"); err != nil {
		t.Errorf("ValidateHardwareComment(aida@mbp) = %v, want nil", err)
	}
}

// 鍵をエージェントに渡したまま取り戻せないことがありえた。鍵を完全削除しても
// その identity は読み込まれたままで、ユーザーがたったいま破棄した素材が依然として
// そこにあって認証に使え、エージェントの保持内容を並べる画面には、その一覧を出す
// こと以外にできることがなかった。
func TestDeregisterTakesTheKeyBackOutOfTheAgent(t *testing.T) {
	agent := &fakeAgent{available: true}
	service, _ := newServiceWithAgent(t, newQueryRunner(), agent)
	generateWorkKey(t, service)

	inventory, err := service.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	item, ok := inventory.Find(ItemID("id_work"))
	if !ok {
		t.Fatal("the generated key is not in the inventory")
	}

	if err := service.Deregister(context.Background(), item.ID); err != nil {
		t.Fatalf("Deregister error = %v", err)
	}
	if len(agent.removed) != 1 || !strings.HasSuffix(agent.removed[0], "id_work.pub") {
		t.Errorf("removed = %#v, want the public key path ssh-add -d needs", agent.removed)
	}
}

func TestDeregisterRefusesAKeyThatIsNotThere(t *testing.T) {
	agent := &fakeAgent{available: true}
	service, _ := newServiceWithAgent(t, newQueryRunner(), agent)

	if err := service.Deregister(context.Background(), ItemID("nope")); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Deregister error = %v, want ErrUnknownKey", err)
	}
}

func TestDeregisterSaysSoWhenThereIsNoAgent(t *testing.T) {
	agent := &fakeAgent{available: false}
	service, _ := newServiceWithAgent(t, newQueryRunner(), agent)
	generateWorkKey(t, service)

	inventory, _ := service.Inventory()
	item, _ := inventory.Find(ItemID("id_work"))
	if err := service.Deregister(context.Background(), item.ID); !errors.Is(err, platform.ErrAgentUnavailable) {
		t.Errorf("Deregister error = %v, want ErrAgentUnavailable", err)
	}
}

// パスフレーズが保存されている鍵は、二段階ではなく一度の操作でエージェントに追加
// される。この参照関数は validateGroup と同じやり方で注入される。秘密がどこにある
// かは secret パッケージの領分であり、このパッケージはそれを尋ねるために import
// してはならない。
func TestRegisterUsesAStoredPassphraseWhenNoneIsTyped(t *testing.T) {
	agent := &fakeAgent{available: true}
	service, workspace := newServiceWithAgent(t, newQueryRunner(), agent)
	_ = workspace
	generateWorkKey(t, service)
	stored := map[string]string{"id_work": "correct horse"}
	service.SetStoredPassphrase(func(relative string) (string, bool) {
		value, ok := stored[relative]
		return value, ok
	})

	if _, err := service.Register(context.Background(), RegisterRequest{KeyID: ItemID("id_work")}); err != nil {
		t.Fatalf("Register = %v", err)
	}
	if len(agent.passphrases) != 1 || string(agent.passphrases[0]) != "correct horse" {
		t.Errorf("the agent was given %q, want the stored passphrase", agent.passphrases)
	}
}

// 打ち込まれたパスフレーズが常に勝つ。キーボードの前にいる人の方が、ファイルよりも
// 新しいからだ。
func TestATypedPassphraseBeatsTheStoredOne(t *testing.T) {
	agent := &fakeAgent{available: true}
	service, _ := newServiceWithAgent(t, newQueryRunner(), agent)
	generateWorkKey(t, service)
	service.SetStoredPassphrase(func(string) (string, bool) { return "the stale one", true })

	if _, err := service.Register(context.Background(), RegisterRequest{
		KeyID: ItemID("id_work"), Passphrase: []byte("typed just now"),
	}); err != nil {
		t.Fatalf("Register = %v", err)
	}
	if string(agent.passphrases[0]) != "typed just now" {
		t.Errorf("the agent was given %q, want the typed passphrase", agent.passphrases[0])
	}
}

// 何も保存されていない状態の振る舞いは、何も保存できなかった頃と同じで、いまもそうだ。
func TestRegisterWithoutAStoredPassphraseSendsWhatItWasGiven(t *testing.T) {
	agent := &fakeAgent{available: true}
	service, _ := newServiceWithAgent(t, newQueryRunner(), agent)
	generateWorkKey(t, service)

	if _, err := service.Register(context.Background(), RegisterRequest{
		KeyID: ItemID("id_work"), Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Register = %v", err)
	}
	if string(agent.passphrases[0]) != "correct horse" {
		t.Errorf("the agent was given %q", agent.passphrases[0])
	}
}

// パスフレーズの変更は、いまでは取り消せる。
//
// 以前はバックアップを取らなかった。置き換える内容が秘密鍵であり、そのコピーが
// ~/.ssh/sshc/backups/ にあることは、取り消しを失うことより悪かったからだ。いま
// バックアップはマスターパスワードで封じられるので、その理由は消えた — そして
// ここは、事故が最も回復しにくい書き込みでもある。新しいパスフレーズを打ち間違え
// れば、その鍵は誰にも開けない鍵になる。
func TestChangingAPassphraseKeepsASealedBackup(t *testing.T) {
	workspace := newTestWorkspace(t)
	clock := steppingClock(time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC))
	manager := storage.NewManager(workspace, clock, rand.Reader)
	manager.Seal = sealForTest
	manager.Unseal = unsealForTest
	service := NewService(ServiceOptions{
		Workspace:    workspace,
		Transactions: manager,
		Resolver:     storage.NewResolver(workspace),
		Catalogue:    newFakeCatalogue(&fakeRunner{}, fakeToolchain{}),
		Now:          clock,
		Random:       rand.Reader,
	})

	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("first passphrase"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	before, err := os.ReadFile(filepath.Join(workspace.Root(), "id_work"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.ChangePassphrase(PassphraseChange{
		KeyID:   ItemID("id_work"),
		Current: []byte("first passphrase"),
		New:     []byte("second passphrase"),
	}); err != nil {
		t.Fatalf("ChangePassphrase error = %v", err)
	}

	records, err := manager.History()
	if err != nil {
		t.Fatal(err)
	}
	found := ""
	for _, record := range records {
		candidate := filepath.Join(record.BackupDir, "id_work")
		if _, statErr := os.Stat(candidate); statErr == nil {
			found = candidate
		}
	}
	if found == "" {
		t.Fatal("the passphrase change kept no backup, so it still cannot be undone")
	}
	opened, err := manager.ReadBackup(found)
	if err != nil {
		t.Fatalf("ReadBackup = %v", err)
	}
	if !bytes.Equal(opened, before) {
		t.Error("the backup is not the key the change replaced")
	}
}

// sealForTest は vault の鍵の代役である。可逆であり、かつ明らかに恒等写像では
// ない。ディスク上のバイト列は入ってきたバイト列と違わねばならず、さもなければ
// バックアップを鍵素材で grep する検査が平文の上を素通りしてしまう。
func sealForTest(plaintext []byte) ([]byte, error) {
	sealed := make([]byte, 0, len(plaintext)+len(testSealMarker))
	sealed = append(sealed, testSealMarker...)
	for _, b := range plaintext {
		sealed = append(sealed, b^0x5a)
	}
	return sealed, nil
}

func unsealForTest(sealed []byte) ([]byte, error) {
	if !bytes.HasPrefix(sealed, testSealMarker) {
		return nil, errors.New("that backup was not sealed")
	}
	body := sealed[len(testSealMarker):]
	plaintext := make([]byte, 0, len(body))
	for _, b := range body {
		plaintext = append(plaintext, b^0x5a)
	}
	return plaintext, nil
}

var testSealMarker = []byte("sealed:")
