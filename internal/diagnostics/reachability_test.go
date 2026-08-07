package diagnostics_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"sshc/internal/diagnostics"
)

// dialerFunc turns a function into a Dialer so a test can decide the outcome
// without opening a socket.
type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (dial dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dial(ctx, network, address)
}

func TestCheckReportsALoopbackListenerAsReached(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)

	result := diagnostics.Reachability{Dialer: &net.Dialer{}}.Check(
		context.Background(), "127.0.0.1", strconv.Itoa(address.Port))

	if result.Outcome != diagnostics.ReachabilityReached {
		t.Fatalf("outcome = %q, detail = %q", result.Outcome, result.Detail)
	}
	if result.Address != "127.0.0.1:"+strconv.Itoa(address.Port) {
		t.Errorf("address = %q", result.Address)
	}
	if !strings.Contains(result.Notice, "ProxyJump") {
		t.Errorf("notice = %q, want an explicit statement that ProxyJump was ignored", result.Notice)
	}
}

func TestCheckClassifiesFailuresWithoutGuessing(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "missing.invalid", IsNotFound: true}, diagnostics.ReachabilityDNSFailure},
		{"refused", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, diagnostics.ReachabilityTimeout},
		{"other", errors.New("network is unreachable"), diagnostics.ReachabilityFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reachability := diagnostics.Reachability{
				Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, test.err }),
			}
			result := reachability.Check(context.Background(), "example.internal", "22")
			if result.Outcome != test.want {
				t.Fatalf("outcome = %q, want %q (detail %q)", result.Outcome, test.want, result.Detail)
			}
		})
	}

	refused := diagnostics.Reachability{Dialer: &net.Dialer{}}
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(closed.Addr().(*net.TCPAddr).Port)
	closed.Close()
	if result := refused.Check(context.Background(), "127.0.0.1", port); result.Outcome != diagnostics.ReachabilityRefused {
		t.Fatalf("outcome = %q, want %q", result.Outcome, diagnostics.ReachabilityRefused)
	}
}

func TestCheckAppliesItsOwnTimeout(t *testing.T) {
	reachability := diagnostics.Reachability{
		Timeout: 50 * time.Millisecond,
		Dialer: dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	}
	started := time.Now()
	result := reachability.Check(context.Background(), "slow.internal", "22")
	if result.Outcome != diagnostics.ReachabilityTimeout {
		t.Fatalf("outcome = %q", result.Outcome)
	}
	if time.Since(started) > time.Second {
		t.Error("the check did not apply its own timeout")
	}
}
