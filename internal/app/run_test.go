package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type browserFunc func(context.Context, string) error

func (function browserFunc) Open(ctx context.Context, target string) error {
	return function(ctx, target)
}

func TestRunUsesRandomIPv4LoopbackAndReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opened := make(chan string, 1)
	var gotNetwork, gotAddress string
	dependencies := Dependencies{
		Random: bytes.NewReader(bytes.Repeat([]byte{0x81}, 96)),
		Browser: browserFunc(func(_ context.Context, target string) error {
			opened <- target
			return nil
		}),
		Listen: func(network, address string) (net.Listener, error) {
			gotNetwork, gotAddress = network, address
			return net.Listen(network, address)
		},
		UI:     fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:   t.TempDir(),
	}

	done := make(chan error, 1)
	go func() { done <- Run(ctx, dependencies, "test") }()

	target := <-opened
	if gotNetwork != "tcp4" || gotAddress != "127.0.0.1:0" {
		t.Fatalf("listen = %s %s", gotNetwork, gotAddress)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Hostname() != "127.0.0.1" || parsed.RawQuery != "" || !strings.HasPrefix(parsed.Fragment, "bootstrap=") {
		t.Fatalf("target = %q", target)
	}
	if got := strings.TrimPrefix(parsed.Fragment, "bootstrap="); len(got) != 43 {
		t.Fatalf("bootstrap length = %d, want 43", len(got))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

var errAccept = errors.New("accept failed")

type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errAccept }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 43123}
}

func TestRunReturnsServerFailureWithoutWaitingForCancellation(t *testing.T) {
	dependencies := Dependencies{
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x91}, 96)),
		Browser: browserFunc(func(context.Context, string) error { return nil }),
		Listen:  func(string, string) (net.Listener, error) { return failingListener{}, nil },
		UI:      fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:    t.TempDir(),
	}

	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), dependencies, "test") }()

	select {
	case err := <-done:
		if !errors.Is(err, errAccept) {
			t.Fatalf("Run error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run waited for context after server failure")
	}
}

func TestRunShutsServerDownWhenBrowserFails(t *testing.T) {
	browserErr := errors.New("browser unavailable")
	listener := &trackingListener{Listener: mustListen(t)}
	dependencies := Dependencies{
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x72}, 96)),
		Browser: browserFunc(func(context.Context, string) error { return browserErr }),
		Listen:  func(string, string) (net.Listener, error) { return listener, nil },
		UI:      fstest.MapFS{"index.html": {Data: []byte("ok")}},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Home:    t.TempDir(),
	}

	err := Run(context.Background(), dependencies, "test")
	if !errors.Is(err, browserErr) {
		t.Fatalf("Run error = %v", err)
	}
	if !listener.closed {
		t.Fatal("listener was not closed after browser failure")
	}
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

type trackingListener struct {
	net.Listener
	closed bool
}

func (listener *trackingListener) Close() error {
	listener.closed = true
	return listener.Listener.Close()
}
