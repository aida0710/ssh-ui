package platform

import (
	"context"
	"errors"
)

var (
	ErrAgentUnavailable = errors.New("no ssh-agent is reachable from this process")
	ErrAgentRejected    = errors.New("ssh-add rejected the request")
)

// AgentIdentity is one key currently loaded in the user's ssh-agent.
type AgentIdentity struct {
	Bits        int
	Fingerprint string
	Comment     string
	Algorithm   string
}

// AgentAddRequest asks the agent to load one private key.
//
// Passphrase travels on the child process's standard input. It is never an
// argument and never an environment variable, because both are readable by any
// process running as the same user.
type AgentAddRequest struct {
	PrivateKeyPath  string
	Passphrase      []byte
	LifetimeSeconds int
	StoreInKeychain bool
}

// KeyAgent registers private keys with the user's ssh-agent and, on macOS, with
// the login Keychain. Automated tests always substitute a fake; no test in this
// repository talks to a real agent or a real Keychain.
type KeyAgent interface {
	Available(ctx context.Context) bool
	List(ctx context.Context) ([]AgentIdentity, error)
	Add(ctx context.Context, request AgentAddRequest) error
	Remove(ctx context.Context, publicKeyPath string) error
}
