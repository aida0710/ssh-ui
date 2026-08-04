// Package diagnostics runs the separately triggered checks of the design:
// a configuration check, a direct TCP reachability check, and an SSH
// authentication test. Each is an independent operation the user starts on
// purpose; nothing here runs as a side effect of opening a screen.
package diagnostics

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// ProxyJumpNotice accompanies every reachability result. The check dials the
// destination itself, so a host that is only reachable through a jump host is
// expected to fail here, and the UI must say so rather than imply the host is
// down.
const ProxyJumpNotice = "This check dialled the destination directly. ProxyJump, ProxyCommand and any jump-host firewall were not used."

// DefaultReachabilityTimeout bounds one TCP dial.
const DefaultReachabilityTimeout = 5 * time.Second

// Reachability outcomes.
const (
	ReachabilityReached    = "reached"
	ReachabilityRefused    = "refused"
	ReachabilityTimeout    = "timeout"
	ReachabilityDNSFailure = "dns_failure"
	ReachabilityFailed     = "failed"
)

// Dialer opens a TCP connection. *net.Dialer satisfies it; tests substitute a
// function so no automated test opens a remote socket.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ReachabilityResult is one completed dial attempt.
type ReachabilityResult struct {
	Address string
	Outcome string
	Elapsed time.Duration
	Detail  string
	Notice  string
}

// Reachability dials a destination directly, ignoring ProxyJump on purpose.
type Reachability struct {
	Dialer  Dialer
	Timeout time.Duration
}

// Check dials hostname:port once and classifies the outcome.
func (r Reachability) Check(ctx context.Context, hostname, port string) ReachabilityResult {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultReachabilityTimeout
	}
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(hostname, port)
	result := ReachabilityResult{Address: address, Notice: ProxyJumpNotice}

	started := time.Now()
	connection, err := r.Dialer.DialContext(dialContext, "tcp", address)
	result.Elapsed = time.Since(started)
	if err == nil {
		connection.Close()
		result.Outcome = ReachabilityReached
		return result
	}

	result.Detail = err.Error()
	var dnsError *net.DNSError
	switch {
	case errors.As(err, &dnsError):
		result.Outcome = ReachabilityDNSFailure
	case errors.Is(err, syscall.ECONNREFUSED):
		result.Outcome = ReachabilityRefused
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		result.Outcome = ReachabilityTimeout
	default:
		result.Outcome = ReachabilityFailed
	}
	return result
}
