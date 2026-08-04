package knownhosts_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"ssh-ui/internal/knownhosts"
	"ssh-ui/internal/platform"
)

type stubRunner struct {
	commands []platform.Command
	output   platform.Output
}

func (runner *stubRunner) RunOutput(_ context.Context, command platform.Command) (platform.Output, error) {
	runner.commands = append(runner.commands, command)
	return runner.output, nil
}

type stubToolchain struct{}

func (stubToolchain) SSH() (string, error)     { return "/usr/bin/ssh", nil }
func (stubToolchain) KeyScan() (string, error) { return "/usr/bin/ssh-keyscan", nil }
func (stubToolchain) KeyGen() (string, error)  { return "/usr/bin/ssh-keygen", nil }
func (stubToolchain) KeyAdd() (string, error)  { return "/usr/bin/ssh-add", nil }

func TestScanReturnsUnverifiedCandidates(t *testing.T) {
	runner := &stubRunner{output: platform.Output{Stdout: []byte(
		"# bastion.example.com:2222 SSH-2.0-OpenSSH_9.6\n" +
			"bastion.example.com " + fixtureKeyType + " " + fixtureKey + "\n")}}

	candidates, err := knownhosts.Scanner{Runner: runner, Toolchain: stubToolchain{}}.
		Scan(context.Background(), "bastion.example.com", 2222)
	if err != nil {
		t.Fatalf("Scan = %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	candidate := candidates[0]
	if candidate.Verified {
		t.Error("a scanned key is never verified")
	}
	if candidate.Fingerprint != fixtureFingerprint || candidate.Port != 2222 {
		t.Errorf("candidate = %#v", candidate)
	}

	command := runner.commands[0]
	if command.Path != "/usr/bin/ssh-keyscan" {
		t.Errorf("path = %q", command.Path)
	}
	if !slices.Equal(command.Arguments, []string{"-T", "5", "-p", "2222", "bastion.example.com"}) {
		t.Fatalf("arguments = %#v", command.Arguments)
	}
	if !strings.Contains(knownhosts.UnverifiedNotice, "does not prove") {
		t.Error("the notice must say what a scan does not prove")
	}
}

func TestScanRejectsUnsafeTargetsBeforeStartingAProcess(t *testing.T) {
	runner := &stubRunner{}
	scanner := knownhosts.Scanner{Runner: runner, Toolchain: stubToolchain{}}

	if _, err := scanner.Scan(context.Background(), "-p2222", 22); !errors.Is(err, platform.ErrUnsafeHostname) {
		t.Fatalf("unsafe host = %v, want ErrUnsafeHostname", err)
	}
	if _, err := scanner.Scan(context.Background(), "example.com", 0); !errors.Is(err, platform.ErrUnsafePort) {
		t.Fatalf("invalid port = %v, want ErrUnsafePort", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("an unsafe target started a process")
	}
}
