package diagnostics_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
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
