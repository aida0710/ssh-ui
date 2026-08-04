package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"ssh-ui/internal/session"
)

type fakeListener struct{ address net.Addr }

func (listener fakeListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (listener fakeListener) Close() error              { return nil }
func (listener fakeListener) Addr() net.Addr            { return listener.address }

func TestNewRejectsNonLoopbackListeners(t *testing.T) {
	tests := []struct {
		name    string
		address net.Addr
	}{
		{name: "unspecified IPv4", address: &net.TCPAddr{IP: net.IPv4zero}},
		{name: "unspecified IPv6", address: &net.TCPAddr{IP: net.IPv6unspecified}},
		{name: "non TCP address", address: fakeAddr("unix")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Options{Listener: fakeListener{address: test.address}})
			if !errors.Is(err, ErrNonLoopbackListener) {
				t.Fatalf("New error = %v, want %v", err, ErrNonLoopbackListener)
			}
		})
	}
}

func TestServerServesStaticFilesAndShutsDownAfterCancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager, _, err := session.NewManager(bytes.NewReader(bytes.Repeat([]byte{0x73}, 96)))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server, err := New(Options{
		Listener: listener,
		Sessions: manager,
		UI: fstest.MapFS{
			"asset.txt": &fstest.MapFile{Data: []byte("static asset")},
		},
		Version: "test-version",
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()

	response, err := http.Get(server.URL() + "/asset.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("static status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "static asset" {
		t.Fatalf("static body = %q", got)
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit after context cancellation")
	}
	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), 100*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("listener still accepts connections after Serve returns")
	}
}

type fakeAddr string

func (address fakeAddr) Network() string { return string(address) }
func (address fakeAddr) String() string  { return string(address) }
