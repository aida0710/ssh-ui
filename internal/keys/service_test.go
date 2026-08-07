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
	manager := storage.NewManager(workspace, clock, rand.Reader)
	// The application seals every generational backup with the master
	// password, so these tests do too: without it they would prove things
	// about a shape of backup the application no longer writes.
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

// assertNoKeyMaterialInBackups walks the generational backup directory and
// fails if any file there holds a private key in the clear.
//
// It used to mean the directory held no copy at all, which is why a passphrase
// change could not be undone. It now holds a sealed copy, and this is what
// keeps that safe: the bytes on disk must be unreadable without the master
// password. Sealing is what changed, not the rule about plaintext.
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

// A confirmation is bound to a digest of what the dialog displayed. The digest
// must change when the key on disk changes, or a user who confirmed one key
// would be authorising whatever replaced it.
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

	// The same fingerprint at a different path is a different confirmation.
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

	// Replacing the file behind the same path must invalidate the evidence.
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

	// Removing a file from the entry changes what the dialog would list.
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

// fakeAgent records every registration request without touching a real agent.
// The passphrase is copied on arrival because Register wipes the caller's
// buffer before it returns.
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

// PublicKey is the one key route with no confirmation behind it, so what stops
// it being a way to read a private key is the kind check and nothing else.
// These tests hold that check to the classifier's judgement rather than to the
// file's name.
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

	// The private key of the same pair is refused, so the unconfirmed route
	// cannot be turned into a reveal by passing the other identifier.
	if _, err := service.PublicKey(generated.ID); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("PublicKey(private key) error = %v, want ErrUnknownKey", err)
	}
}

func TestPublicKeyRefusesAPrivateKeyWearingAPublicName(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())

	// Classification is by content and permissions, never by the suffix. A
	// private key saved as id_decoy.pub must still be refused here.
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

// declaredGroups is the seam the running application fills with the
// configuration engine's answer. A test supplies its own, so this package
// proves it asks rather than deciding.
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
	// The identifier follows the path, so a key in a group is addressable the
	// same way as one at the root.
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
	// A refusal leaves nothing behind, not even the directory it would need.
	if _, statErr := os.Lstat(filepath.Join(workspace.Root(), "keys")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("a refused generation created the keys directory: %v", statErr)
	}
}

func TestGenerateStillRefusesAReservedFileNameInsideAGroup(t *testing.T) {
	service, _ := newGroupKeyService(t, "work")

	// The reserved-name rule is about names this application depends on, and it
	// applies at every depth: keys/work/config is still a file called config.
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
	// The user runs this by hand, so it has to put the key where this
	// application would have put it.
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

// A software key's comment is embedded by ssh.MarshalPrivateKey and reaches no
// command line, so the shell-quoting rule the hardware path needs does not
// apply to it. "work laptop" is what people actually type.
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

// The hardware path builds an ssh-keygen command line for the user to run, so
// it keeps the stricter rule.
func TestHardwareCommentKeepsTheShellSafeRule(t *testing.T) {
	if err := ValidateHardwareComment("work laptop"); err == nil {
		t.Error("ValidateHardwareComment accepted a space, which would need quoting in the shown command")
	}
	if err := ValidateHardwareComment("aida@mbp"); err != nil {
		t.Errorf("ValidateHardwareComment(aida@mbp) = %v, want nil", err)
	}
}

// A key can be handed to the agent and could not be taken back. Purging the key
// left its identity loaded, so the material the user had just destroyed was
// still there to authenticate with, and the screen that lists what the agent
// holds had nothing to offer but the list.
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

// A key whose passphrase is stored is added to the agent in one action rather
// than two. The lookup is injected, the same way validateGroup is: where a
// secret lives belongs to the secret package, and this one must not import it
// to ask.
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

// A typed passphrase always wins: the person at the keyboard is more current
// than the file.
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

// Nothing stored is how this behaved before anything was, and still does.
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

// A passphrase change can be undone now.
//
// It kept no backup because the previous contents are a private key and a copy
// of one in ~/.ssh/sshc/backups/ was worse than the lost undo. The backups
// are sealed with the master password now, so that reason is gone — and this is
// the write where an accident is least recoverable: get the new passphrase
// wrong and the key is a key nobody can open.
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

// sealForTest stands in for the vault's key. It is reversible and obviously not
// the identity: the bytes on disk must not be the bytes that went in, or a
// guard that greps a backup for key material would pass on plaintext.
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
