package session

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// distinctReader is a deterministic random source whose reads never repeat.
// A bytes.Repeat source hands back the same 32 bytes forever, so every issued
// token would be identical and the per-token bookkeeping under test — single
// use, the outstanding-token cap — would silently collapse to one record.
type distinctReader struct{ sequence uint64 }

func (r *distinctReader) Read(destination []byte) (int, error) {
	for written := 0; written < len(destination); {
		r.sequence++
		block := sha256.Sum256(binary.BigEndian.AppendUint64(nil, r.sequence))
		written += copy(destination[written:], block[:])
	}
	return len(destination), nil
}

func newTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	manager, bootstrap, err := NewManager(&distinctReader{})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	return manager, credentials.SessionID
}

// addSession registers a second authenticated session directly. Bootstrap is
// deliberately single use, so this is the only way to prove that one session
// cannot spend another session's confirmation.
func addSession(t *testing.T, manager *Manager, sessionID string) {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.sessions[sha256.Sum256([]byte(sessionID))] = Session{
		csrfHash: sha256.Sum256([]byte("csrf-" + sessionID)),
		actions:  make(map[[sha256.Size]byte]actionRecord),
	}
}

func TestActionTokenIsSingleUseAndBoundToKindTargetAndEvidence(t *testing.T) {
	manager, sessionID := newTestManager(t)
	request := ActionRequest{Kind: ActionAuthentication, Target: "bastion", Evidence: "digest-a"}

	issued, err := manager.IssueAction(sessionID, request)
	if err != nil {
		t.Fatalf("IssueAction = %v", err)
	}
	if len(issued) != 43 {
		t.Fatalf("token length = %d, want 43", len(issued))
	}
	if err := manager.ConsumeAction(sessionID, issued, request); err != nil {
		t.Fatalf("ConsumeAction = %v", err)
	}
	replay := manager.ConsumeAction(sessionID, issued, request)
	if !errors.Is(replay, ErrInvalidAction) {
		t.Fatalf("replay = %v, want ErrInvalidAction", replay)
	}
	if strings.Contains(replay.Error(), issued) {
		t.Error("the rejection message disclosed the presented token")
	}

	mismatches := []ActionRequest{
		{Kind: ActionTerminalLaunch, Target: "bastion", Evidence: "digest-a"},
		{Kind: ActionAuthentication, Target: "other", Evidence: "digest-a"},
		{Kind: ActionAuthentication, Target: "bastion", Evidence: "digest-b"},
	}
	for _, mismatch := range mismatches {
		token, err := manager.IssueAction(sessionID, request)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.ConsumeAction(sessionID, token, mismatch); !errors.Is(err, ErrInvalidAction) {
			t.Errorf("ConsumeAction(%#v) = %v, want ErrInvalidAction", mismatch, err)
		}
		// A rejected presentation still burns the token.
		if err := manager.ConsumeAction(sessionID, token, request); !errors.Is(err, ErrInvalidAction) {
			t.Errorf("a rejected token stayed usable: %v", err)
		}
	}
}

func TestActionTokenExpiresAndIsScopedToOneSession(t *testing.T) {
	manager, sessionID := newTestManager(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	manager.Now = func() time.Time { return now }
	request := ActionRequest{Kind: ActionEvaluate, Target: "bastion", Evidence: "digest"}

	token, err := manager.IssueAction(sessionID, request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(ActionTokenTTL + time.Second)
	if err := manager.ConsumeAction(sessionID, token, request); !errors.Is(err, ErrActionExpired) {
		t.Fatalf("expired token = %v, want ErrActionExpired", err)
	}
	// An expired token is gone, not quietly renewed.
	if err := manager.ConsumeAction(sessionID, token, request); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("expired token was reissued: %v", err)
	}

	if _, err := manager.IssueAction("not-a-session", request); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("unknown session = %v, want ErrUnknownSession", err)
	}
	if err := manager.ConsumeAction("not-a-session", token, request); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("unknown session = %v, want ErrUnknownSession", err)
	}
}

func TestActionTokenCannotBeConsumedByAnotherSession(t *testing.T) {
	manager, sessionID := newTestManager(t)
	const otherSessionID = "another-authenticated-session"
	addSession(t, manager, otherSessionID)
	request := ActionRequest{Kind: ActionTerminalLaunch, Target: "bastion", Evidence: "digest"}

	issued, err := manager.IssueAction(sessionID, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ConsumeAction(otherSessionID, issued, request); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("cross-session consume = %v, want ErrInvalidAction", err)
	}
	// The failed attempt must not have burned the owner's confirmation either.
	if err := manager.ConsumeAction(sessionID, issued, request); err != nil {
		t.Fatalf("the owning session lost its confirmation: %v", err)
	}
}

func TestIssueActionRejectsUnknownKindsAndBoundsStoredTokens(t *testing.T) {
	manager, sessionID := newTestManager(t)

	if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: "shell.exec", Target: "bastion"}); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("unknown kind = %v, want ErrInvalidAction", err)
	}
	if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: ActionEvaluate}); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("empty target = %v, want ErrInvalidAction", err)
	}

	for index := 0; index < MaxActionTokensPerSession; index++ {
		if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: ActionEvaluate, Target: "bastion"}); err != nil {
			t.Fatalf("IssueAction %d = %v", index, err)
		}
	}
	if _, err := manager.IssueAction(sessionID, ActionRequest{Kind: ActionEvaluate, Target: "bastion"}); !errors.Is(err, ErrTooManyActions) {
		t.Fatalf("exceeded limit = %v, want ErrTooManyActions", err)
	}
}

func TestActionTokenCapRefusesInsteadOfEvictingAConfirmation(t *testing.T) {
	manager, sessionID := newTestManager(t)
	request := ActionRequest{Kind: ActionRevealPrivateKey, Target: "key-one", Evidence: "digest"}

	first, err := manager.IssueAction(sessionID, request)
	if err != nil {
		t.Fatal(err)
	}
	flood := ActionRequest{Kind: ActionPurgeTrashEntry, Target: "trash-entry", Evidence: "digest"}
	for index := 1; index < MaxActionTokensPerSession; index++ {
		if _, err := manager.IssueAction(sessionID, flood); err != nil {
			t.Fatalf("IssueAction %d = %v", index, err)
		}
	}
	// Flooding a full table must be refused rather than make room by discarding
	// a confirmation the user has already given.
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := manager.IssueAction(sessionID, flood); !errors.Is(err, ErrTooManyActions) {
			t.Fatalf("attempt %d past the cap = %v, want ErrTooManyActions", attempt, err)
		}
	}
	if err := manager.ConsumeAction(sessionID, first, request); err != nil {
		t.Fatalf("the oldest confirmation was evicted: %v", err)
	}
	// Burning one confirmation releases exactly one slot.
	if _, err := manager.IssueAction(sessionID, flood); err != nil {
		t.Fatalf("IssueAction after a consume = %v", err)
	}
	if _, err := manager.IssueAction(sessionID, flood); !errors.Is(err, ErrTooManyActions) {
		t.Fatalf("the cap was not restored = %v", err)
	}
}

func TestExpiredActionTokensReleaseCapacity(t *testing.T) {
	manager, sessionID := newTestManager(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	manager.Now = func() time.Time { return now }
	request := ActionRequest{Kind: ActionKnownHostsScan, Target: "bastion", Evidence: "digest"}

	for index := 0; index < MaxActionTokensPerSession; index++ {
		if _, err := manager.IssueAction(sessionID, request); err != nil {
			t.Fatalf("IssueAction %d = %v", index, err)
		}
	}
	if _, err := manager.IssueAction(sessionID, request); !errors.Is(err, ErrTooManyActions) {
		t.Fatalf("full table = %v, want ErrTooManyActions", err)
	}

	now = now.Add(ActionTokenTTL + time.Second)
	if _, err := manager.IssueAction(sessionID, request); err != nil {
		t.Fatalf("IssueAction once every token expired = %v", err)
	}
}

func TestActionTokensAreSafeForConcurrentUse(t *testing.T) {
	manager, sessionID := newTestManager(t)

	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			request := ActionRequest{
				Kind:     ActionReachability,
				Target:   "bastion-" + strconv.Itoa(worker),
				Evidence: "digest",
			}
			issued, err := manager.IssueAction(sessionID, request)
			if err != nil {
				t.Errorf("worker %d IssueAction = %v", worker, err)
				return
			}
			if err := manager.ConsumeAction(sessionID, issued, request); err != nil {
				t.Errorf("worker %d ConsumeAction = %v", worker, err)
			}
		}()
	}
	workers.Wait()
}

func TestKnownActionKindListsEveryConfirmedOperation(t *testing.T) {
	for _, kind := range []string{
		ActionEvaluate, ActionReachability, ActionAuthentication, ActionTerminalLaunch,
		ActionKnownHostsDelete, ActionKnownHostsScan, ActionKnownHostsAdd, ActionRemoteKeyRegister,
		ActionRevealPrivateKey, ActionPurgeTrashEntry,
	} {
		if !KnownActionKind(kind) {
			t.Errorf("KnownActionKind(%q) = false", kind)
		}
	}
	if KnownActionKind("") || KnownActionKind("anything") {
		t.Error("KnownActionKind accepted an unknown kind")
	}
}
