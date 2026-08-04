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
	if _, ok := manager.Authenticate(credentials.SessionID); !ok {
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
	if _, ok := manager.Authenticate(""); ok {
		t.Fatal("failed bootstrap created a session")
	}
}
