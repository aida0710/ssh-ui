package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrInvalidBootstrap = errors.New("invalid bootstrap token")
	ErrBootstrapUsed    = errors.New("bootstrap token already used")
)

type Credentials struct {
	SessionID string
	CSRFToken string
}

type Session struct {
	csrfHash [sha256.Size]byte
	// actions holds this session's outstanding confirmations, keyed by the
	// digest of the token that was handed out, exactly as sessions themselves
	// are keyed. The map is shared with every copy of the Session value, which
	// is what lets the action helpers reach it without another lookup.
	actions map[[sha256.Size]byte]actionRecord
}

type Manager struct {
	mu            sync.RWMutex
	random        io.Reader
	bootstrapHash [sha256.Size]byte
	bootstrapUsed bool
	sessions      map[[sha256.Size]byte]Session

	// Now is the clock used for action token expiry. It is nil in production,
	// where time.Now is used; tests set it once before the manager is shared.
	Now func() time.Time
}

func token(random io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func NewManager(random io.Reader) (*Manager, string, error) {
	bootstrap, err := token(random)
	if err != nil {
		return nil, "", err
	}

	return &Manager{
		random:        random,
		bootstrapHash: sha256.Sum256([]byte(bootstrap)),
		sessions:      make(map[[sha256.Size]byte]Session),
	}, bootstrap, nil
}

// Reissue mints a fresh bootstrap token, replacing the one this manager holds.
//
// A bootstrap is spent on first use, and until this existed only a new process
// printed another — which is fine when the user starts the application and it
// prints a URL, and useless when it runs as a background agent whose standard
// output goes nowhere. The reissue is asked for by the command line, which had
// to read a file only this user can read to ask at all.
//
// Any session already established stays established. What this replaces is the
// way in for a browser that has none.
func (m *Manager) Reissue() (string, error) {
	fresh, err := token(m.random)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bootstrapHash = sha256.Sum256([]byte(fresh))
	m.bootstrapUsed = false
	return fresh, nil
}

func (m *Manager) Bootstrap(presented string) (Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.bootstrapUsed {
		return Credentials{}, ErrBootstrapUsed
	}

	presentedHash := sha256.Sum256([]byte(presented))
	if subtle.ConstantTimeCompare(presentedHash[:], m.bootstrapHash[:]) != 1 {
		return Credentials{}, ErrInvalidBootstrap
	}

	sessionID, err := token(m.random)
	if err != nil {
		return Credentials{}, err
	}
	csrf, err := token(m.random)
	if err != nil {
		return Credentials{}, err
	}

	m.bootstrapUsed = true
	m.sessions[sha256.Sum256([]byte(sessionID))] = Session{
		csrfHash: sha256.Sum256([]byte(csrf)),
		actions:  make(map[[sha256.Size]byte]actionRecord),
	}
	return Credentials{SessionID: sessionID, CSRFToken: csrf}, nil
}

// RenewCSRF mints a fresh CSRF token for a session that already exists.
//
// A reload loses the token, because it lived in the page; the cookie survives,
// so the session does. Without this the application was dead until the binary
// was started again, since a bootstrap fragment is spent on first use and only
// a new process prints another.
//
// The token is minted rather than returned. This manager keeps a hash and never
// the token, which is what stops a leak of its memory being a leak of every
// session's token, and re-minting keeps that property. The old token stops
// verifying, which is correct: there is one page per session, and a token still
// working after another was issued for it would be a second key nobody is
// holding on purpose.
func (m *Manager) RenewCSRF(sessionID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := sha256.Sum256([]byte(sessionID))
	existing, ok := m.sessions[key]
	if !ok {
		return "", false
	}
	csrf, err := token(m.random)
	if err != nil {
		return "", false
	}
	existing.csrfHash = sha256.Sum256([]byte(csrf))
	m.sessions[key] = existing
	return csrf, true
}

func (m *Manager) Authenticate(sessionID string) (Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessionValue, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	return sessionValue, ok
}

func (m *Manager) VerifyCSRF(sessionID, csrf string) bool {
	sessionValue, ok := m.Authenticate(sessionID)
	if !ok {
		return false
	}

	presentedHash := sha256.Sum256([]byte(csrf))
	return subtle.ConstantTimeCompare(presentedHash[:], sessionValue.csrfHash[:]) == 1
}
