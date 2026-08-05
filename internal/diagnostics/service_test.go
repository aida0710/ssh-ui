package diagnostics_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssh-ui/internal/diagnostics"
	"ssh-ui/internal/effective"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/storage"
)

const serviceConfig = "Host bastion\n" +
	"\tHostName 203.0.113.10\n" +
	"\tUser ops\n" +
	"\tPort 2222\n" +
	"\n" +
	"Host risky\n" +
	"\tProxyCommand /usr/bin/nc %h %p\n"

func newServiceWorkspace(t *testing.T, contents string) *storage.Workspace {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}

func newTestService(t *testing.T, runner platform.OutputRunner) *diagnostics.Service {
	t.Helper()
	service := diagnostics.NewService(
		newServiceWorkspace(t, serviceConfig),
		runner,
		fixedToolchain{ssh: "/usr/bin/ssh", keyscan: "/usr/bin/ssh-keyscan"},
		nil,
		nil,
	)
	service.Reachability = diagnostics.Reachability{
		Dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: errRefusedForTest}
		}),
	}
	return service
}

var errRefusedForTest = net.UnknownNetworkError("refused in test")

func TestServiceInspectEvaluatesSafeConfigurationsAutomatically(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{Stdout: []byte("hostname 203.0.113.10\nuser ops\nport 2222\n")}}
	service := newTestService(t, runner)

	inspection, err := service.Inspect(context.Background(), "bastion", false)
	if err != nil {
		t.Fatalf("Inspect = %v", err)
	}
	if !inspection.Evaluated || inspection.RequiresConfirmation {
		t.Fatalf("inspection = %#v", inspection)
	}
	if got := inspection.Values.First("hostname"); got != "203.0.113.10" {
		t.Errorf("hostname = %q", got)
	}
	if source, ok := inspection.Projection.Value("hostname"); !ok || source.Line != 2 {
		t.Errorf("projection = %#v", inspection.Projection)
	}
	if len(inspection.Report.Directives) != 1 || inspection.Report.Directives[0].Keyword != "ProxyCommand" {
		t.Errorf("report = %#v", inspection.Report)
	}
}

func TestServiceInspectReportsAnOpenSSHFailureAsData(t *testing.T) {
	runner := &scriptedRunner{output: platform.Output{ExitCode: 255, Stderr: []byte("Bad configuration option\n")}}
	inspection, err := newTestService(t, runner).Inspect(context.Background(), "bastion", false)
	if err != nil {
		t.Fatalf("Inspect = %v", err)
	}
	if inspection.Evaluated || inspection.Failure == nil || inspection.Failure.ExitCode != 255 {
		t.Fatalf("inspection = %#v", inspection)
	}
}

func TestServiceDestinationUsesTheEngineSoABlockedEvaluationStillWorks(t *testing.T) {
	runner := &scriptedRunner{}
	service := newTestService(t, runner)

	hostname, port, err := service.Destination("bastion")
	if err != nil {
		t.Fatalf("Destination = %v", err)
	}
	if hostname != "203.0.113.10" || port != "2222" {
		t.Fatalf("destination = %s:%s", hostname, port)
	}

	unknownHostname, unknownPort, err := service.Destination("unlisted")
	if err != nil {
		t.Fatalf("Destination = %v", err)
	}
	if unknownHostname != "unlisted" || unknownPort != "22" {
		t.Errorf("defaults = %s:%s, want unlisted:22", unknownHostname, unknownPort)
	}

	result, err := service.Reach(context.Background(), "bastion")
	if err != nil {
		t.Fatalf("Reach = %v", err)
	}
	if result.Address != "203.0.113.10:2222" || result.Notice == "" {
		t.Errorf("result = %#v", result)
	}
	if len(runner.commands) != 0 {
		t.Fatal("reachability must not start ssh")
	}
}

func TestServiceConfigCheckSummarisesTheIncludeGraph(t *testing.T) {
	report, err := newTestService(t, &scriptedRunner{}).ConfigCheck()
	if err != nil {
		t.Fatalf("ConfigCheck = %v", err)
	}
	if len(report.Files) != 1 || !report.Files[0].Editable || report.Files[0].Missing {
		t.Fatalf("files = %#v", report.Files)
	}
	for _, diagnostic := range report.Diagnostics {
		if diagnostic.Severity > 0 {
			t.Errorf("unexpected diagnostic: %#v", diagnostic)
		}
	}
}

// TestServiceAuthenticateSanitisesTheHomePathOutOfReportedOutput guards what
// leaves this process. Verbose ssh output names every file it read by absolute
// path, which would carry the account name into a response body.
func TestServiceAuthenticateSanitisesTheHomePathOutOfReportedOutput(t *testing.T) {
	service := newTestService(t, &scriptedRunner{})
	home := service.Workspace.Home()
	service.Authentication.Runner = &scriptedRunner{output: platform.Output{
		ExitCode: 255,
		Stderr: []byte("debug1: Reading configuration data " + home + "/.ssh/config\n" +
			"ops@203.0.113.10: Permission denied (publickey).\n"),
	}}

	result, err := service.Authenticate(context.Background(), "bastion", true)
	if err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if strings.Contains(result.Stderr, home) {
		t.Fatalf("reported stderr names the home directory: %q", result.Stderr)
	}
	if !strings.Contains(result.Stderr, "~/.ssh/config") {
		t.Errorf("stderr = %q, want the path rewritten to ~", result.Stderr)
	}
	if !strings.Contains(result.Stderr, "Permission denied") {
		t.Error("sanitising removed the reason for the failure")
	}
}

func TestServiceProjectedValueReadsTheEngineWithoutRunningSSH(t *testing.T) {
	runner := &scriptedRunner{}
	service := newTestService(t, runner)

	user, ok := service.ProjectedValue("bastion", "user")
	if !ok || user != "ops" {
		t.Fatalf("ProjectedValue = %q, %v", user, ok)
	}
	if _, ok := service.ProjectedValue("bastion", "identityfile"); ok {
		t.Error("a keyword the configuration does not set must report false")
	}
	if _, ok := service.ProjectedValue("bad alias", "user"); ok {
		t.Error("an unsafe alias must not be projected")
	}
	if len(runner.commands) != 0 {
		t.Fatal("projecting a value started a process")
	}
}

type recordingTerminal struct{ aliases []string }

func (terminal *recordingTerminal) Launch(_ context.Context, alias string) error {
	terminal.aliases = append(terminal.aliases, alias)
	return nil
}

func TestServiceLaunchesOnlySafeAliases(t *testing.T) {
	terminal := &recordingTerminal{}
	service := newTestService(t, &scriptedRunner{})
	service.Terminal = terminal

	if err := service.LaunchTerminal(context.Background(), "bastion"); err != nil {
		t.Fatalf("LaunchTerminal = %v", err)
	}
	if len(terminal.aliases) != 1 || terminal.aliases[0] != "bastion" {
		t.Fatalf("aliases = %#v", terminal.aliases)
	}

	// An alias carrying AppleScript quoting is refused before it reaches the
	// launcher, never escaped into the automation payload.
	for _, unsafe := range []string{"a b", `bastion" & (do shell script "id") & "`, "a;id"} {
		if err := service.LaunchTerminal(context.Background(), unsafe); err == nil {
			t.Errorf("LaunchTerminal(%q) was accepted", unsafe)
		}
	}
	if len(terminal.aliases) != 1 {
		t.Fatalf("an unsafe alias reached the launcher: %#v", terminal.aliases)
	}

	command, launchable, warning := service.TerminalCommand("a b")
	if launchable || warning == "" || command != "ssh -- a b" {
		t.Fatalf("TerminalCommand = %q, %v, %q", command, launchable, warning)
	}
	if command, launchable, warning := service.TerminalCommand("bastion"); !launchable || warning != "" || command != "ssh -- bastion" {
		t.Fatalf("TerminalCommand = %q, %v, %q", command, launchable, warning)
	}
}

func TestServiceReportsAMissingTerminalLauncher(t *testing.T) {
	service := newTestService(t, &scriptedRunner{})
	if err := service.LaunchTerminal(context.Background(), "bastion"); !errors.Is(err, diagnostics.ErrTerminalNotConfigured) {
		t.Fatalf("LaunchTerminal = %v, want ErrTerminalNotConfigured", err)
	}
}

func TestServiceSafetyReportsTheSameEvidenceAsAFreshScan(t *testing.T) {
	service := newTestService(t, &scriptedRunner{})
	report, err := service.Safety()
	if err != nil {
		t.Fatalf("Safety = %v", err)
	}
	if report.Evidence() == (effective.Report{}).Evidence() {
		t.Error("a configuration with a ProxyCommand must not produce empty evidence")
	}
}

// The account name must not be carried out of ssh's own output. It is replaced
// in the stderr of an authentication test and was not replaced in the values of
// an evaluation, though both are ssh output put into a response — and the
// values are the part that always contains a home path, because
// UserKnownHostsFile and the default IdentityFile list are absolute.
func TestInspectReplacesTheHomeDirectoryInEvaluatedValues(t *testing.T) {
	workspace := newServiceWorkspace(t, serviceConfig)
	home := workspace.Home()
	runner := &scriptedRunner{output: platform.Output{Stdout: []byte(
		"hostname 203.0.113.10\n" +
			"userknownhostsfile " + home + "/.ssh/known_hosts " + home + "/.ssh/known_hosts2\n" +
			"identityfile " + home + "/.ssh/id_ed25519\n")}}
	service := diagnostics.NewService(workspace, runner,
		fixedToolchain{ssh: "/usr/bin/ssh", keyscan: "/usr/bin/ssh-keyscan"}, nil, nil)

	inspection, err := service.Inspect(context.Background(), "bastion", false)
	if err != nil {
		t.Fatalf("Inspect error = %v", err)
	}
	if !inspection.Evaluated {
		t.Fatal("the fixture did not evaluate")
	}
	for _, keyword := range inspection.Values.Keywords {
		for _, value := range inspection.Values.Entries[keyword] {
			if strings.Contains(value, home) {
				t.Errorf("%s = %q still carries the home directory %q", keyword, value, home)
			}
		}
	}
	if got := inspection.Values.First("userknownhostsfile"); got != "~/.ssh/known_hosts ~/.ssh/known_hosts2" {
		t.Errorf("userknownhostsfile = %q, want both paths shortened", got)
	}
}
