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

// distinctReader は、読み出しが決して繰り返さない決定的な乱数源。
// bytes.Repeat による乱数源は同じ 32 バイトをいつまでも返すので、発行される
// トークンはすべて同一になり、テスト対象であるトークンごとの管理 — 単回使用、
// 未使用トークンの上限 — が、黙ってレコードひとつ分に潰れてしまう。
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

// addSession は、認証済みの二つ目のセッションを直接登録する。Bootstrap は意図的に
// 単回使用なので、あるセッションが別のセッションの確認を使えないことを示すには
// これしか方法がない。
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
		// 提示が拒否されても、トークンは焼き捨てられる。
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
	// 期限切れのトークンは消えるのであって、こっそり延長されるのではない。
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
	// 失敗した試行が、持ち主の確認まで焼き捨ててしまってもならない。
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
	// 満杯の表に殺到した場合は、ユーザーがすでに与えた確認を捨てて場所を空けるのでは
	// なく、拒否しなければならない。
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := manager.IssueAction(sessionID, flood); !errors.Is(err, ErrTooManyActions) {
			t.Fatalf("attempt %d past the cap = %v, want ErrTooManyActions", attempt, err)
		}
	}
	if err := manager.ConsumeAction(sessionID, first, request); err != nil {
		t.Fatalf("the oldest confirmation was evicted: %v", err)
	}
	// 確認をひとつ焼き捨てると、ちょうどひとつ分の空きが解放される。
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
