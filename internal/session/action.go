package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"
)

const (
	// ActionTokenTTL is how long one confirmation stays usable. It is short
	// because a confirmation is answered by a person who is looking at the
	// dialog right now.
	ActionTokenTTL = 2 * time.Minute
	// MaxActionTokensPerSession bounds the memory one session can pin.
	MaxActionTokensPerSession = 32
)

// Action kinds. A token issued for one kind is useless for any other.
const (
	ActionEvaluate          = "diagnostics.evaluate"
	ActionReachability      = "diagnostics.reachability"
	ActionAuthentication    = "diagnostics.authentication"
	ActionTerminalLaunch    = "terminal.launch"
	ActionKnownHostsDelete  = "known_hosts.delete"
	ActionKnownHostsScan    = "known_hosts.scan"
	ActionKnownHostsAdd     = "known_hosts.add"
	ActionRemoteKeyRegister = "remote_key.register"
	ActionRevealPrivateKey  = "private_key.reveal"
	ActionPurgeTrashEntry   = "trash.purge"
)

var (
	ErrInvalidAction  = errors.New("action token is not valid for this operation")
	ErrActionExpired  = errors.New("action token has expired")
	ErrUnknownSession = errors.New("session does not exist")
	ErrTooManyActions = errors.New("too many pending confirmations for this session")
)

var knownActionKinds = map[string]bool{
	ActionEvaluate:          true,
	ActionReachability:      true,
	ActionAuthentication:    true,
	ActionTerminalLaunch:    true,
	ActionKnownHostsDelete:  true,
	ActionKnownHostsScan:    true,
	ActionKnownHostsAdd:     true,
	ActionRemoteKeyRegister: true,
	ActionRevealPrivateKey:  true,
	ActionPurgeTrashEntry:   true,
}

// KnownActionKind reports whether kind is an operation this application will
// ever confirm.
func KnownActionKind(kind string) bool { return knownActionKinds[kind] }

// ActionRequest identifies exactly one confirmed operation.
//
// Evidence is a digest of what the confirmation dialog displayed — usually the
// executable directives, or the current contents of the file being edited — so
// a change between the confirmation and the execution invalidates the token
// instead of silently applying to something else.
type ActionRequest struct {
	Kind     string
	Target   string
	Evidence string
}

type actionRecord struct {
	tokenHash [sha256.Size]byte
	kind      string
	target    string
	evidence  string
	expiresAt time.Time
}

func (m *Manager) clock() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// IssueAction stores one confirmation and returns its token. The token is
// returned once and only its hash is kept, exactly like the session secrets.
//
// A full table is refused rather than made room in: evicting an outstanding
// record would let anyone who can ask for a token flush a confirmation the
// user has already given, and replace it with one of their own choosing.
func (m *Manager) IssueAction(sessionID string, request ActionRequest) (string, error) {
	if !KnownActionKind(request.Kind) || request.Target == "" {
		return "", ErrInvalidAction
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sessionValue, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	if !ok {
		return "", ErrUnknownSession
	}
	now := m.clock()
	expireLocked(sessionValue, now)
	if len(sessionValue.actions) >= MaxActionTokensPerSession {
		return "", ErrTooManyActions
	}

	value, err := token(m.random)
	if err != nil {
		return "", err
	}
	valueHash := sha256.Sum256([]byte(value))
	sessionValue.actions[valueHash] = actionRecord{
		tokenHash: valueHash,
		kind:      request.Kind,
		target:    request.Target,
		evidence:  request.Evidence,
		expiresAt: now.Add(ActionTokenTTL),
	}
	return value, nil
}

// ConsumeAction verifies and burns one confirmation.
//
// The token is removed before it is checked, so a presentation that does not
// match cannot be retried against a different operation. No error mentions the
// token, and a token belonging to another session is simply not in this
// session's table.
func (m *Manager) ConsumeAction(sessionID, presented string, request ActionRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionValue, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	if !ok {
		return ErrUnknownSession
	}

	// The presented token is looked up before the expired records are swept,
	// so a confirmation that ran out of time is reported as expired instead of
	// being indistinguishable from one that was never issued.
	presentedHash := sha256.Sum256([]byte(presented))
	record, found := sessionValue.actions[presentedHash]
	if !found {
		return ErrInvalidAction
	}
	delete(sessionValue.actions, presentedHash)

	now := m.clock()
	expireLocked(sessionValue, now)
	if now.After(record.expiresAt) {
		return ErrActionExpired
	}

	// The secret itself is compared in constant time against the stored hash,
	// the same shape Bootstrap and VerifyCSRF use, so the verification does not
	// rest on how the map compares its keys. Kind, target and evidence must all
	// match the operation now being asked for.
	matched := subtle.ConstantTimeCompare(presentedHash[:], record.tokenHash[:]) &
		subtle.ConstantTimeCompare([]byte(record.kind), []byte(request.Kind)) &
		subtle.ConstantTimeCompare([]byte(record.target), []byte(request.Target)) &
		subtle.ConstantTimeCompare([]byte(record.evidence), []byte(request.Evidence))
	if matched != 1 {
		return ErrInvalidAction
	}
	return nil
}

func expireLocked(sessionValue Session, now time.Time) {
	for hash, record := range sessionValue.actions {
		if now.After(record.expiresAt) {
			delete(sessionValue.actions, hash)
		}
	}
}
