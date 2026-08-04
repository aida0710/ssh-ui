package keys

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssh-ui/internal/platform"
	"ssh-ui/internal/storage"
)

// steppingClock advances one second per call so two transactions in one test
// never share an identifier.
func steppingClock(start time.Time) func() time.Time {
	current := start
	return func() time.Time {
		current = current.Add(time.Second)
		return current
	}
}

// newQueryRunner answers the algorithm query with the output of a real
// OpenSSH 10.2p1 installation, captured once and kept as a constant.
func newQueryRunner() *fakeRunner {
	return &fakeRunner{output: platform.Output{Stdout: []byte(opensshQueryOutput)}}
}

func newTestService(t *testing.T, runner platform.OutputRunner) (*Service, *storage.Workspace) {
	t.Helper()
	return newServiceWithAgent(t, runner, nil)
}

// newServiceWithAgent builds the service the way the application does, through
// ServiceOptions, so the agent seam is proven to reach the Service rather than
// being assigned to an unexported field by the test.
func newServiceWithAgent(t *testing.T, runner platform.OutputRunner, agent platform.KeyAgent) (*Service, *storage.Workspace) {
	t.Helper()
	workspace := newTestWorkspace(t)
	clock := steppingClock(time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC))
	service := NewService(ServiceOptions{
		Workspace:    workspace,
		Transactions: storage.NewManager(workspace, clock, rand.Reader),
		Resolver:     storage.NewResolver(workspace),
		Catalogue:    newFakeCatalogue(runner, fakeToolchain{}),
		Agent:        agent,
		Now:          clock,
		Random:       rand.Reader,
	})
	return service, workspace
}

// assertNoKeyMaterialInBackups walks the generational backup directory and
// fails if any file there holds a private key. The trash is the recovery point
// for key material; the backup directory must never hold a second copy of it.
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

// A passphrase change replaces a private key, and the transaction manager keeps
// a generational backup of everything it replaces. That backup would be a
// second copy of the user's private key, which the design forbids: the trash is
// the only place key material is ever duplicated to.
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

// fakeAgent records every registration request without touching a real agent.
// The passphrase is copied on arrival because Register wipes the caller's
// buffer before it returns.
type fakeAgent struct {
	available   bool
	requests    []platform.AgentAddRequest
	passphrases [][]byte
	identities  []platform.AgentIdentity
	addError    error
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

func (fake *fakeAgent) Remove(context.Context, string) error { return nil }

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

// A registration the agent refused must not be recorded as one that happened.
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
