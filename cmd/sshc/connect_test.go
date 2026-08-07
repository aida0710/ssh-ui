package main

import (
	"strings"
	"testing"
)

// The whole command is the alias. Everything else is a flag, the askpass
// subcommand, or the application itself.
func TestWhatCountsAsAConnectInvocation(t *testing.T) {
	for _, test := range []struct {
		argv  []string
		alias string
		ok    bool
	}{
		{[]string{"sshc", "tv-recoding"}, "tv-recoding", true},
		{[]string{"sshc", "mdx-aida-serv-1"}, "mdx-aida-serv-1", true},
		// The application, not a connection.
		{[]string{"sshc"}, "", false},
		{[]string{"sshc", "-open=false"}, "", false},
		{[]string{"sshc", "--open=false"}, "", false},
		// The one word that is a command rather than a host.
		{[]string{"sshc", "open"}, "", false},
		// The helper OpenSSH runs, which takes the prompt as its argument.
		{[]string{"sshc", "askpass"}, "", false},
		{[]string{"sshc", "askpass", "password:"}, "", false},
		// Two words is not an alias; it is a command this does not have.
		{[]string{"sshc", "connect", "bastion"}, "", false},
	} {
		alias, ok := connectInvocation(test.argv)
		if ok != test.ok || alias != test.alias {
			t.Errorf("connectInvocation(%v) = %q, %v; want %q, %v", test.argv, alias, ok, test.alias, test.ok)
		}
	}
}

// The variables this sets must be the ones OpenSSH reads.
//
// syscall.Exec passes the array as given, and getenv answers with the first
// match in it. Appending to the inherited environment therefore loses to an
// SSH_ASKPASS the user exported years ago in a shell profile — and loses while
// still handing that program the one-time token, which it can redeem for a
// stored password. The bar for that attack is one exported variable.
func TestConnectEnvironmentReplacesWhatItSetsRatherThanAppending(t *testing.T) {
	inherited := []string{
		"HOME=/Users/tester",
		"SSH_ASKPASS=/tmp/not-ours",
		"SSH_ASKPASS_REQUIRE=never",
		"SSHC_ASKPASS_TOKEN=stale",
		"PATH=/usr/bin",
	}
	built := connectEnvironment(inherited, "/Users/tester/.local/bin/sshc",
		"http://127.0.0.1:1/askpass", "the-one-time-token", "bastion")

	counted := map[string][]string{}
	for _, entry := range built {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		counted[name] = append(counted[name], value)
	}
	for name, want := range map[string]string{
		"SSH_ASKPASS":         "/Users/tester/.local/bin/sshc",
		"SSH_ASKPASS_REQUIRE": "force",
		URLVariable:           "http://127.0.0.1:1/askpass",
		TokenVariable:         "the-one-time-token",
		AliasVariable:         "bastion",
	} {
		if len(counted[name]) != 1 {
			t.Errorf("%s appears %d times: %v", name, len(counted[name]), counted[name])
			continue
		}
		if counted[name][0] != want {
			t.Errorf("%s = %q, want %q", name, counted[name][0], want)
		}
	}
	// Everything else the user had is still theirs: this is the environment
	// they would have had typing ssh themselves, with our five decided by us.
	if len(counted["HOME"]) != 1 || counted["HOME"][0] != "/Users/tester" {
		t.Errorf("HOME = %v", counted["HOME"])
	}
	if len(counted["PATH"]) != 1 {
		t.Errorf("PATH = %v", counted["PATH"])
	}
}

// Without a token nothing is armed, and a stale variable from the user's
// environment must not arm it either.
func TestConnectEnvironmentDropsStaleArmingWhenNothingIsStored(t *testing.T) {
	built := connectEnvironment([]string{"SSH_ASKPASS=/tmp/not-ours", "SSHC_ASKPASS_TOKEN=stale"}, "", "", "", "")
	for _, entry := range built {
		for _, name := range []string{"SSH_ASKPASS=", TokenVariable + "=", URLVariable + "=", AliasVariable + "="} {
			if strings.HasPrefix(entry, name) {
				t.Errorf("an unarmed connection still carries %q", entry)
			}
		}
	}
}
