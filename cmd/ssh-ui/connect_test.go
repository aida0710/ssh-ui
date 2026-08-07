package main

import (
	"crypto/ed25519"
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
		{[]string{"ssh-ui", "tv-recoding"}, "tv-recoding", true},
		{[]string{"ssh-ui", "mdx-aida-serv-1"}, "mdx-aida-serv-1", true},
		// The application, not a connection.
		{[]string{"ssh-ui"}, "", false},
		{[]string{"ssh-ui", "-open=false"}, "", false},
		{[]string{"ssh-ui", "--open=false"}, "", false},
		// The one word that is a command rather than a host.
		{[]string{"ssh-ui", "open"}, "", false},
		// The helper OpenSSH runs, which takes the prompt as its argument.
		{[]string{"ssh-ui", "askpass"}, "", false},
		{[]string{"ssh-ui", "askpass", "password:"}, "", false},
		// Two words is not an alias; it is a command this does not have.
		{[]string{"ssh-ui", "connect", "bastion"}, "", false},
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
		"SSH_UI_ASKPASS_TOKEN=stale",
		"PATH=/usr/bin",
	}
	built := connectEnvironment(inherited, "/Users/tester/.local/bin/ssh-ui",
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
		"SSH_ASKPASS":         "/Users/tester/.local/bin/ssh-ui",
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
	built := connectEnvironment([]string{"SSH_ASKPASS=/tmp/not-ours", "SSH_UI_ASKPASS_TOKEN=stale"}, "", "", "", "")
	for _, entry := range built {
		for _, name := range []string{"SSH_ASKPASS=", TokenVariable + "=", URLVariable + "=", AliasVariable + "="} {
			if strings.HasPrefix(entry, name) {
				t.Errorf("an unarmed connection still carries %q", entry)
			}
		}
	}
}

// A build made from a working tree does not replace itself.
//
// It trusts no signing key, so it could verify nothing anyway, and what it
// would be replacing is the output of a build the person in front of it just
// ran. Only a build made from a tag carries the keys and the button.
func TestOnlyAReleaseBuildCanUpdateItself(t *testing.T) {
	if updater(developmentVersion) != nil {
		t.Error("a development build carries an updater")
	}
	release := updater("v0.1.0")
	if release == nil {
		t.Fatal("a release build carries no updater")
	}
	if len(release.PublicKeys) == 0 {
		t.Error("a release build trusts no signing key, so it can accept nothing")
	}
}

// The keys compiled in have to decode, or the release that ships with them can
// verify nothing and every installation of it is stuck.
func TestTheCompiledInKeysDecode(t *testing.T) {
	keys := releaseKeys()
	if len(keys) != len(releaseSigningKeys) {
		t.Fatalf("%d of %d keys decoded", len(keys), len(releaseSigningKeys))
	}
	for index, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			t.Errorf("key %d is %d bytes", index, len(key))
		}
	}
}
