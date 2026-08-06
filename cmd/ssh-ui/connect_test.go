package main

import (
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
