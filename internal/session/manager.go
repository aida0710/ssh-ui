package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
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
}

type Manager struct {
	mu            sync.RWMutex
	random        io.Reader
	bootstrapHash [sha256.Size]byte
	bootstrapUsed bool
	sessions      map[[sha256.Size]byte]Session
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
	}
	return Credentials{SessionID: sessionID, CSRFToken: csrf}, nil
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
