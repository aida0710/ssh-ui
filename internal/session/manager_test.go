package session

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestBootstrapCreatesAuthenticatedSessionOnce(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 96))
	manager, bootstrap, err := NewManager(random)
	if err != nil {
		t.Fatal(err)
	}
	if len(bootstrap) != 43 {
		t.Fatalf("bootstrap length = %d", len(bootstrap))
	}

	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if ok := manager.Authenticate(credentials.SessionID); !ok {
		t.Fatal("new session was not authenticated")
	}
	if !manager.VerifyCSRF(credentials.SessionID, credentials.CSRFToken) {
		t.Fatal("csrf token was rejected")
	}
	if _, err := manager.Bootstrap(bootstrap); !errors.Is(err, ErrBootstrapUsed) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestBootstrapRejectsWrongTokenWithoutConsumingRealToken(t *testing.T) {
	manager, bootstrap, err := NewManager(bytes.NewReader(bytes.Repeat([]byte{0x21}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bootstrap("wrong"); !errors.Is(err, ErrInvalidBootstrap) {
		t.Fatalf("wrong-token error = %v", err)
	}
	if _, err := manager.Bootstrap(bootstrap); err != nil {
		t.Fatalf("valid bootstrap after rejection: %v", err)
	}
}

var errRandom = errors.New("random source failed")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errRandom }

func TestNewManagerPropagatesRandomFailure(t *testing.T) {
	if _, _, err := NewManager(errReader{}); !errors.Is(err, errRandom) {
		t.Fatalf("NewManager error = %v", err)
	}
}

func TestBootstrapPropagatesSessionRandomFailure(t *testing.T) {
	initial := bytes.NewReader(bytes.Repeat([]byte{0x31}, 32))
	manager, bootstrap, err := NewManager(io.MultiReader(initial, errReader{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bootstrap(bootstrap); !errors.Is(err, errRandom) {
		t.Fatalf("Bootstrap error = %v", err)
	}
	if ok := manager.Authenticate(""); ok {
		t.Fatal("failed bootstrap created a session")
	}
}

// A reload loses the CSRF token, because it lived in the page. The cookie
// survives, so the session does; without a way to get a token for it the
// application was dead until the binary was started again, which is not what a
// reload should cost.
//
// The token is re-minted rather than returned: the manager keeps a hash and not
// the token, which is the property that stops a leak of its memory being a leak
// of every session's token, and re-minting keeps it.
// countingReader never repeats a byte pattern, so two tokens drawn from it
// differ for the reason tokens differ in production.
type countingReader struct{ next byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for index := range p {
		r.next++
		p[index] = r.next
	}
	return len(p), nil
}

func TestRenewCSRFIssuesAWorkingTokenAndRetiresTheOld(t *testing.T) {
	// A varying source: a constant one makes every token identical, which would
	// let this test pass on an implementation that handed the old token back.
	manager, bootstrap, err := NewManager(&countingReader{})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	renewed, ok := manager.RenewCSRF(credentials.SessionID)
	if !ok || renewed == "" {
		t.Fatalf("RenewCSRF = %q, %v", renewed, ok)
	}
	if renewed == credentials.CSRFToken {
		t.Error("the renewed token is the old one")
	}
	if !manager.VerifyCSRF(credentials.SessionID, renewed) {
		t.Error("the renewed token does not verify")
	}
	if manager.VerifyCSRF(credentials.SessionID, credentials.CSRFToken) {
		t.Error("the retired token still verifies")
	}
}

func TestRenewCSRFRefusesASessionThatIsNotThere(t *testing.T) {
	manager, _, err := NewManager(bytes.NewReader(bytes.Repeat([]byte{0x32}, 4096)))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := manager.RenewCSRF("not a session"); ok {
		t.Error("RenewCSRF answered for a session that does not exist")
	}
}

// A bootstrap is spent on first use. Reissuing is what lets a browser in when
// the process that printed the first one is a background agent whose standard
// output goes nowhere.
func TestReissueMintsAWayInWithoutDisturbingTheSessions(t *testing.T) {
	manager, first, err := NewManager(&countingReader{})
	if err != nil {
		t.Fatal(err)
	}
	established, err := manager.Bootstrap(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bootstrap(first); !errors.Is(err, ErrBootstrapUsed) {
		t.Fatalf("the first bootstrap is still spendable: %v", err)
	}

	second, err := manager.Reissue()
	if err != nil {
		t.Fatalf("Reissue = %v", err)
	}
	if second == first {
		t.Error("the reissued bootstrap is the one that was spent")
	}
	if _, err := manager.Bootstrap(first); err == nil {
		t.Error("the old bootstrap still works after a reissue")
	}
	if _, err := manager.Bootstrap(second); err != nil {
		t.Fatalf("the reissued bootstrap does not work: %v", err)
	}
	// The session that already existed is untouched: this is a way in for a
	// browser that has none, not a way to end the ones that do.
	if ok := manager.Authenticate(established.SessionID); !ok {
		t.Error("an established session was lost")
	}
}
