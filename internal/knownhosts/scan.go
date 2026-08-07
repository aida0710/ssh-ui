package knownhosts

import (
	"context"
	"strconv"
	"strings"
	"time"

	"sshc/internal/platform"
)

// UnverifiedNotice accompanies every scan result.
const UnverifiedNotice = "ssh-keyscan proves only that something answered at this address. It does not prove the host's identity. Compare the fingerprint with one you obtained another way before trusting it."

// DefaultScanTimeout bounds one ssh-keyscan run.
const DefaultScanTimeout = 15 * time.Second

// Candidate is one key ssh-keyscan reported. Verified is always false here;
// only the user can decide that a key is genuine.
type Candidate struct {
	Host        string
	Port        int
	KeyType     string
	Key         string
	Fingerprint string
	Verified    bool
}

// Scanner fetches host key candidates.
type Scanner struct {
	Runner    platform.OutputRunner
	Toolchain platform.Toolchain
	Timeout   time.Duration
	// Environment is the child's complete environment, normally
	// platform.MinimalEnvironment. A nil value inherits this process's.
	Environment []string
}

// Scan asks ssh-keyscan for the keys of one host.
//
// The result is never marked Verified: reaching an address proves only that
// something answered there, so the decision to trust a key stays with the user.
func (s Scanner) Scan(ctx context.Context, host string, port int) ([]Candidate, error) {
	if err := platform.ValidateHostname(host); err != nil {
		return nil, err
	}
	if err := platform.ValidatePort(port); err != nil {
		return nil, err
	}
	program, err := s.Toolchain.KeyScan()
	if err != nil {
		return nil, err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultScanTimeout
	}
	output, err := s.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-T", "5", "-p", strconv.Itoa(port), host},
		Timeout:   timeout,
		Env:       s.Environment,
	})
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	for _, line := range strings.Split(string(output.Stdout), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		fingerprint, fingerprintErr := Fingerprint(fields[2])
		if fingerprintErr != nil {
			continue
		}
		candidates = append(candidates, Candidate{
			Host:        host,
			Port:        port,
			KeyType:     fields[1],
			Key:         fields[2],
			Fingerprint: fingerprint,
		})
	}
	return candidates, nil
}
