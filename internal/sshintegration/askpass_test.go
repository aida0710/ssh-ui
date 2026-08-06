// Package sshintegration holds tests that need a real OpenSSH server.
//
// Everything here skips unless SSH_UI_TEST_SSH_ADDR names one. `make
// integration` starts one in a container and sets it; CI does the same.
//
// The point is the one thing no fake can establish: that OpenSSH accepts what
// the askpass helper hands it and authenticates. Everything else in the
// password feature is covered hermetically — the prompt rule, the token
// semantics, the refusals — and all of that is a description of what should
// happen. This is whether it does.
//
// Terminal.app is the only production component substituted, and it is
// substituted by exactly the command its AppleScript would have run. The
// helper, the endpoint, the vault and the token are the shipped code.
package sshintegration_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crypto/rand"

	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/secret"
	"ssh-ui/internal/session"
	"ssh-ui/internal/storage"
)

const (
	addressVariable  = "SSH_UI_TEST_SSH_ADDR"
	userVariable     = "SSH_UI_TEST_SSH_USER"
	passwordVariable = "SSH_UI_TEST_SSH_PASSWORD"

	alias      = "integration"
	passphrase = "correct horse battery staple"
)

type target struct{ host, port, user, password string }

func requireTarget(t *testing.T) target {
	t.Helper()
	address := os.Getenv(addressVariable)
	if address == "" {
		t.Skipf("%s is not set; start a server with `make integration` to run this", addressVariable)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("%s = %q: %v", addressVariable, address, err)
	}
	return target{host: host, port: port, user: os.Getenv(userVariable), password: os.Getenv(passwordVariable)}
}

func helperPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "bin", "ssh-ui"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the binary under test is missing; run `make build` first: %v", err)
	}
	return path
}

// buildHome writes a workspace whose only host is the container, with the host
// key already known.
//
// Scanning the key rather than disabling the check is deliberate: the feature
// refuses to answer the host key question, so a test that turned
// StrictHostKeyChecking off would be testing a configuration this application
// never produces.
func buildHome(t *testing.T, destination target) string {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "known_hosts"), hostKeyOf(t, destination), 0o600); err != nil {
		t.Fatal(err)
	}

	configuration := strings.Join([]string{
		"Host " + alias,
		"\tHostName " + destination.host,
		"\tPort " + destination.port,
		"\tUser " + destination.user,
		// Absolute, because OpenSSH expands ~ from the passwd database rather
		// than from HOME. Setting HOME is enough for a relative Include but
		// not for this, which is how the first CI run of this suite failed:
		// ssh never read the configuration at all and tried to resolve the
		// alias as a hostname.
		"\tUserKnownHostsFile " + filepath.Join(root, "known_hosts"),
		// The point is the password path, so the key paths are closed off.
		"\tPubkeyAuthentication no",
		"\tPreferredAuthentications password",
		"\tStrictHostKeyChecking yes",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "config"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

var (
	hostKeyMutex sync.Mutex
	hostKey      []byte
	hostKeyError error
	hostKeyKnown bool
)

// hostKeyOf scans the server's host key once for the whole package.
//
// It used to be scanned once per test. Four tests meant four scans on top of
// the connections the tests themselves make, and in CI the third and fourth
// came back empty while the first two had just passed: a container sshd limits
// how many unauthenticated connections it will start at once, and a keyscan is
// one of those. The key is the same key every time, so scanning it again was
// never doing anything but spending that budget.
//
// The retry is for the same reason rather than for flakiness in general: a
// refusal here is a "not now", and a second's wait is enough for it to stop
// being one. When every attempt is refused that is reported, not smoothed over.
func hostKeyOf(t *testing.T, destination target) []byte {
	t.Helper()
	hostKeyMutex.Lock()
	defer hostKeyMutex.Unlock()
	if hostKeyKnown {
		if hostKeyError != nil {
			t.Fatalf("ssh-keyscan produced nothing: %v", hostKeyError)
		}
		return hostKey
	}

	empty := t.TempDir()
	for attempt := range 5 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		scan := exec.Command("ssh-keyscan", "-p", destination.port, destination.host)
		scan.Env = []string{"HOME=" + empty, "PATH=" + os.Getenv("PATH")}
		scanned, err := scan.Output()
		switch {
		case err != nil:
			hostKeyError = err
		case len(scanned) == 0:
			hostKeyError = errors.New("the scan succeeded but returned no key")
		default:
			hostKey, hostKeyError = scanned, nil
		}
		if hostKeyError == nil {
			break
		}
	}
	hostKeyKnown = true
	if hostKeyError != nil {
		t.Fatalf("ssh-keyscan produced nothing after 5 attempts: %v", hostKeyError)
	}
	return hostKey
}

// countingListener counts the connections the server accepts.
//
// It is the only way a test can tell "ssh refused the password this vault
// holds" from "the helper never asked". Both end in Permission denied, and for
// one CI run every negative test here passed while the helper was starting a
// second copy of the application instead of answering: SSH_ASKPASS names a
// program that OpenSSH execs with the prompt as its only argument, and the
// binary was looking for a subcommand word that could never arrive.
type countingListener struct {
	net.Listener
	connections atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.connections.Add(1)
	}
	return connection, err
}

func requireTheHelperAsked(t *testing.T, listener *countingListener, before int64, output string) {
	t.Helper()
	if listener.connections.Load() <= before {
		t.Fatalf("the helper never reached this application, so nothing about the password was tested:\n%s", output)
	}
}

// startServer runs the real HTTP server with the real /askpass endpoint.
func startServer(t *testing.T, home string) (*secret.Service, string, *countingListener) {
	t.Helper()
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	vault := secret.NewService(workspace, storage.NewManager(workspace, time.Now, rand.Reader), time.Now)
	if err := vault.Initialise(passphrase); err != nil {
		t.Fatal(err)
	}

	bare, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countingListener{Listener: bare}
	sessions, _, err := session.NewManager(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := httpserver.New(httpserver.Options{
		Listener:   listener,
		Sessions:   sessions,
		UI:         os.DirFS(home),
		Version:    "integration",
		Passwords:  vault,
		Answerable: answerable,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveContext, stop := context.WithCancel(context.Background())
	go func() { _ = server.Serve(serveContext) }()
	t.Cleanup(stop)
	// server.URL() carries the one-time bootstrap fragment; the askpass
	// endpoint needs the origin only, and must never be handed a session token.
	origin := server.URL()
	if index := strings.Index(origin, "#"); index >= 0 {
		origin = origin[:index]
	}
	return vault, strings.TrimSuffix(origin, "/") + httpserver.AskpassPath, listener
}

// answerable is the production rule, restated here because cmd/ssh-ui is a
// main package and cannot be imported. A test that used a laxer rule would
// prove nothing about the shipped one, so this is the same predicate: the
// prompt ends in OpenSSH's password suffix and mentions nothing else.
func answerable(prompt string) bool {
	trimmed := strings.ToLower(strings.TrimRight(prompt, " \t\r\n"))
	for _, marker := range []string{"passphrase", "continue connecting", "fingerprint", "yes/no"} {
		if strings.Contains(trimmed, marker) {
			return false
		}
	}
	return strings.HasSuffix(trimmed, "'s password:")
}

func runSSH(t *testing.T, home, endpoint, token string, arguments ...string) (string, error) {
	t.Helper()
	// Exactly what TerminalPasswordScript tells the shell to run.
	// -F is explicit for the same reason UserKnownHostsFile is: the default
	// user configuration path comes from the passwd database, not from HOME,
	// so a test that only set HOME would silently run with no configuration.
	command := exec.Command("ssh", append([]string{
		"-F", filepath.Join(home, ".ssh", "config"),
		"-o", "NumberOfPasswordPrompts=1",
		"-o", "BatchMode=no",
		"--", alias,
	}, arguments...)...)
	command.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"SSH_ASKPASS=" + helperPath(t),
		"SSH_ASKPASS_REQUIRE=force",
		"SSH_UI_ASKPASS_URL=" + endpoint,
		"SSH_UI_ASKPASS_TOKEN=" + token,
		"SSH_UI_ASKPASS_ALIAS=" + alias,
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestTheHelperAuthenticatesAgainstARealServer(t *testing.T) {
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token, "echo", "authenticated-by-askpass")
	if err != nil {
		t.Fatalf("ssh = %v\n%s", err, output)
	}
	requireTheHelperAsked(t, listener, asked, output)
	if !strings.Contains(output, "authenticated-by-askpass") {
		t.Errorf("the remote command did not run:\n%s", output)
	}
}

func TestTheWrongStoredPasswordFailsOnceRatherThanRepeatedly(t *testing.T) {
	// NumberOfPasswordPrompts=1 is in the shipped command because a wrong
	// stored password offered three times counts towards a lockout on some
	// servers. This is where that stops being a claim.
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password+"-wrong"); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token)
	if err == nil {
		t.Fatalf("ssh authenticated with the wrong password:\n%s", output)
	}
	requireTheHelperAsked(t, listener, asked, output)
	requireAuthenticationWasAttempted(t, output)
	if attempts := strings.Count(output, "Permission denied"); attempts > 1 {
		t.Errorf("the password was offered %d times:\n%s", attempts, output)
	}
}

func TestASpentTokenDoesNotAuthenticate(t *testing.T) {
	// A token is spent by the connection it was made for. If it were not, a
	// token seen once in a process list would be usable for as long as its two
	// minutes lasted.
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runSSH(t, home, endpoint, token, "true"); err != nil {
		t.Fatalf("the first connection = %v\n%s", err, output)
	}

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token, "true")
	if err == nil {
		t.Fatalf("the spent token authenticated a second connection:\n%s", output)
	}
	// The helper asked a second time and was told no, rather than not asking.
	requireTheHelperAsked(t, listener, asked, output)
	requireAuthenticationWasAttempted(t, output)
}

func TestALockedVaultCannotAnswer(t *testing.T) {
	destination := requireTarget(t)
	home := buildHome(t, destination)
	vault, endpoint, listener := startServer(t, home)

	if err := vault.Set(alias, destination.password); err != nil {
		t.Fatal(err)
	}
	token, err := vault.IssueToken(alias)
	if err != nil {
		t.Fatal(err)
	}
	vault.Lock()

	asked := listener.connections.Load()
	output, err := runSSH(t, home, endpoint, token, "true")
	if err == nil {
		t.Fatalf("a locked vault still answered:\n%s", output)
	}
	requireTheHelperAsked(t, listener, asked, output)
	requireAuthenticationWasAttempted(t, output)
}

// requireAuthenticationWasAttempted stops a test passing for the wrong reason.
//
// Every negative case here asserts that ssh failed, and ssh fails for many
// reasons. The first CI run of this suite had two of them passing while ssh was
// not reaching the server at all — it could not resolve the alias, because it
// had never read the configuration. A test that cannot tell "the password was
// refused" from "there was no connection" is not testing the password.
func requireAuthenticationWasAttempted(t *testing.T, output string) {
	t.Helper()
	for _, symptom := range []string{
		"Could not resolve hostname",
		"Connection refused",
		"No route to host",
		"Host key verification failed",
	} {
		if strings.Contains(output, symptom) {
			t.Fatalf("ssh failed before authentication (%s):\n%s", symptom, output)
		}
	}
	if !strings.Contains(output, "Permission denied") {
		t.Fatalf("ssh did not report a refused authentication, so it may have failed earlier:\n%s", output)
	}
}
