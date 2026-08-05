package acceptance_test

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestBuiltBinaryServesTheEmbeddedUIAndStopsOnSIGTERM builds and runs the real
// artefact.
//
// This is the one place in the repository that executes a program this project
// produced. It uses the local Go toolchain, which is already required to run
// the test at all, and points HOME at a temporary directory, so the real ~/.ssh
// is never read. Nothing here contacts a network.
func TestBuiltBinaryServesTheEmbeddedUIAndStopsOnSIGTERM(t *testing.T) {
	repository := filepath.Join("..", "..")
	binary := filepath.Join(t.TempDir(), "ssh-ui")

	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/ssh-ui")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build = %v\n%s", err, output)
	}

	embedded, err := os.ReadFile(filepath.Join(repository, "internal", "ui", "dist", "index.html"))
	if err != nil {
		t.Fatalf("the committed UI distribution is missing: %v", err)
	}
	if len(embedded) == 0 {
		t.Fatal("the committed UI distribution is empty")
	}

	home := t.TempDir()
	process := exec.Command(binary, "-open=false")
	process.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	process.Stderr = &stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	// One goroutine reaps the process, and exactly one reader takes its result.
	// Cleanup must never wait on a channel the body already drained, so it
	// checks whether the body reaped the process and otherwise kills it with a
	// deadline of its own.
	exit := make(chan error, 1)
	go func() { exit <- process.Wait() }()
	reaped := false
	t.Cleanup(func() {
		if reaped {
			return
		}
		_ = process.Process.Signal(syscall.SIGKILL)
		select {
		case <-exit:
		case <-time.After(5 * time.Second):
			t.Error("the binary did not exit after SIGKILL")
		}
	})

	lines := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		line, _ := reader.ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()

	var announced string
	select {
	case announced = <-lines:
	case <-time.After(15 * time.Second):
		t.Fatalf("the binary printed no URL within 15s; stderr:\n%s", stderr.String())
	}
	if !strings.HasPrefix(announced, "http://127.0.0.1:") || !strings.Contains(announced, "/#bootstrap=") {
		t.Fatalf("announced URL = %q", announced)
	}
	base, fragment, _ := strings.Cut(announced, "/#bootstrap=")
	host := strings.TrimPrefix(base, "http://")
	if len(fragment) != 43 {
		t.Fatalf("bootstrap fragment length = %d, want 43", len(fragment))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = host
	request.Header.Set("Accept", "text/html")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET / = %v", err)
	}
	responseStatus := response.StatusCode
	served := readBody(t, response)
	if responseStatus != http.StatusOK {
		t.Fatalf("GET / = %d", responseStatus)
	}
	if served != string(embedded) {
		t.Fatal("the binary served something other than the UI it embedded")
	}

	// The listener is loopback only. A connection to the same port on a
	// routable address of this machine must not be accepted.
	assertBoundToLoopbackOnly(t, host)

	bootstrap, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/api/v1/session/bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap.Host = host
	bootstrap.Header.Set("Origin", base)
	bootstrap.Header.Set("Sec-Fetch-Site", "same-origin")
	bootstrap.Header.Set("X-SSH-UI-Bootstrap", fragment)
	exchanged, err := client.Do(bootstrap)
	if err != nil {
		t.Fatalf("bootstrap = %v", err)
	}
	exchangedStatus := exchanged.StatusCode
	readBody(t, exchanged)
	if exchangedStatus != http.StatusOK {
		t.Fatalf("bootstrap = %d", exchangedStatus)
	}

	if _, err := os.Stat(filepath.Join(home, ".ssh")); err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat of the temporary home failed: %v", err)
	}

	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exit:
		reaped = true
		if err != nil {
			t.Fatalf("the binary exited with %v after SIGTERM; stderr:\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the binary did not exit within 10s of SIGTERM; stderr:\n%s", stderr.String())
	}

	// The port must be free once the process is gone. A listener that outlived
	// its process would keep the port bound and leak an open API.
	assertPortIsFree(t, host)

	if combined := stderr.String(); strings.Contains(combined, fragment) {
		t.Fatal("the binary logged the bootstrap token on standard error")
	}
	if strings.Count(announced, fragment) != 1 {
		t.Fatal("the bootstrap token appeared more than once in the announced URL")
	}
}

// assertBoundToLoopbackOnly checks that nothing but 127.0.0.1 answers on the
// port the binary chose.
//
// A routable address of this machine is only probed when one exists; on a
// machine with no non-loopback IPv4 address there is nothing to prove and the
// check is skipped silently rather than reported as a pass.
func assertBoundToLoopbackOnly(t testing.TB, hostPort string) {
	t.Helper()
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok || network.IP.IsLoopback() || network.IP.To4() == nil {
			continue
		}
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort(network.IP.String(), port), 500*time.Millisecond)
		if err == nil {
			connection.Close()
			t.Fatalf("the binary accepted a connection on %s, which is not loopback", network.IP)
		}
	}
}

func assertPortIsFree(t testing.TB, hostPort string) {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", hostPort, 500*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatalf("%s still accepts connections after the process exited", hostPort)
	}
}

// TestNoTestOnlyPackageReachesTheShippedBinary keeps the hardening suite out of
// the artefact. internal/acceptance is test-only by construction, but a future
// helper moved into a non-test file would change that silently.
func TestNoTestOnlyPackageReachesTheShippedBinary(t *testing.T) {
	list := exec.Command("go", "list", "-deps", "./cmd/ssh-ui")
	list.Dir = filepath.Join("..", "..")
	output, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list = %v\n%s", err, output)
	}
	seen := 0
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			seen++
		}
		switch trimmed {
		case "ssh-ui/internal/acceptance":
			t.Error("the hardening suite is linked into the shipped binary")
		case "testing", "net/http/httptest":
			t.Errorf("%s is linked into the shipped binary", trimmed)
		}
	}
	if seen == 0 {
		t.Fatal("go list reported no dependency at all; this check is not looking at the binary")
	}
}
