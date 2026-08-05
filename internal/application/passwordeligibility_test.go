package application

import (
	"os"
	"path/filepath"
	"testing"
)

// newEligibilityService writes a workspace whose entry file declares the four
// situations these rules are about, and a known_hosts that knows one of them.
func newEligibilityService(t *testing.T) *Service {
	t.Helper()
	service, workspace := newTestService(t)
	entry := "Host known\n" +
		"\tHostName 203.0.113.10\n" +
		"\n" +
		"Host keyed\n" +
		"\tHostName 198.51.100.7\n" +
		"\tIdentityFile ~/.ssh/keys/id_ed25519\n" +
		"\n" +
		"Host nopassword\n" +
		"\tHostName 198.51.100.8\n" +
		"\tPasswordAuthentication no\n" +
		"\n" +
		"Host oddport\n" +
		"\tHostName 203.0.113.20\n" +
		"\tPort 2222\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}
	known := "203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture\n" +
		"[203.0.113.20]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "known_hosts"), []byte(known), 0o600); err != nil {
		t.Fatal(err)
	}
	return service
}

func codesOf(notices []Notice) map[string]bool {
	codes := map[string]bool{}
	for _, notice := range notices {
		codes[notice.Code] = true
	}
	return codes
}

func TestAHostThatRefusesPasswordAuthenticationCannotStoreOne(t *testing.T) {
	// PasswordAuthentication is a client-side setting, so with it off the
	// client will never offer the password however good it is. Storing one
	// would put a secret on disk that has no use at all.
	report, err := newEligibilityService(t).PasswordEligibility("nopassword")
	if err != nil {
		t.Fatal(err)
	}
	if report.Storable {
		t.Error("a host that will never be offered a password accepted one")
	}
	if !codesOf(report.Blockers)[BlockerPasswordAuthenticationOff] {
		t.Errorf("blockers = %#v", report.Blockers)
	}
}

func TestAConfiguredKeyIsAWarningAndNotARefusal(t *testing.T) {
	// The key may not be authorised on the far side, which is an ordinary
	// situation, so this is said and the decision is left with the user.
	report, err := newEligibilityService(t).PasswordEligibility("keyed")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Storable {
		t.Error("a configured key refused a password outright")
	}
	if !codesOf(report.Warnings)[WarnIdentityFileConfigured] {
		t.Errorf("warnings = %#v", report.Warnings)
	}
}

func TestAnUnknownHostKeyIsReportedBecauseTheHelperWillNotAnswerThatQuestion(t *testing.T) {
	// Forcing askpass routes the host-key question to the helper too, and the
	// helper refuses it. So a first connection to an unverified host stops at
	// that prompt with the password unused, and saying so here is the
	// difference between a feature that seems broken and one that explains
	// itself.
	report, err := newEligibilityService(t).PasswordEligibility("keyed")
	if err != nil {
		t.Fatal(err)
	}
	if !codesOf(report.Warnings)[WarnHostKeyUnknown] {
		t.Errorf("an unverified host was not reported: %#v", report.Warnings)
	}

	known, err := newEligibilityService(t).PasswordEligibility("known")
	if err != nil {
		t.Fatal(err)
	}
	if codesOf(known.Warnings)[WarnHostKeyUnknown] {
		t.Errorf("a host already in known_hosts was reported as unknown: %#v", known.Warnings)
	}
}

func TestANonDefaultPortIsLookedUpInTheFormKnownHostsUses(t *testing.T) {
	// known_hosts writes a non-default port as [host]:port. Looking up the
	// bare host would report every such host as unverified, and a warning that
	// is always there is a warning nobody reads.
	report, err := newEligibilityService(t).PasswordEligibility("oddport")
	if err != nil {
		t.Fatal(err)
	}
	if report.Port != "2222" {
		t.Errorf("port = %q", report.Port)
	}
	if codesOf(report.Warnings)[WarnHostKeyUnknown] {
		t.Errorf("a host known at its own port was reported as unknown: %#v", report.Warnings)
	}
}

func TestAPatternIsNotAHostAndCannotHoldAPassword(t *testing.T) {
	report, err := newEligibilityService(t).PasswordEligibility("*")
	if err != nil {
		t.Fatal(err)
	}
	if report.Storable {
		t.Error("a pattern accepted a password")
	}
	if !codesOf(report.Blockers)[BlockerAliasNotSimple] {
		t.Errorf("blockers = %#v", report.Blockers)
	}
}

func TestAnOrdinaryVerifiedHostHasNothingToSay(t *testing.T) {
	// A warning on every host would be noise, and noise is how a real warning
	// gets ignored.
	report, err := newEligibilityService(t).PasswordEligibility("known")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Storable || len(report.Blockers) != 0 || len(report.Warnings) != 0 {
		t.Errorf("an ordinary host reported %#v / %#v", report.Blockers, report.Warnings)
	}
	if report.HostName != "203.0.113.10" {
		t.Errorf("hostName = %q", report.HostName)
	}
}
