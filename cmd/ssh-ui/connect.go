package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ssh-ui/internal/handoff"
	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/platform"
)

// connectResponse is what the running application answers.
type connectAnswer struct {
	Alias        string   `json:"alias"`
	AskpassToken string   `json:"askpassToken"`
	AskpassURL   string   `json:"askpassUrl"`
	Warnings     []string `json:"warnings"`
}

// connectInvocation reports whether this process was started to connect.
//
// A bare word that is not a flag and not the askpass subcommand is an alias.
// That is the whole command: `ssh-ui <alias>`. The five environment variables
// it replaces were the hand-written form of what the Terminal button already
// did for itself, and nothing about them was ever meant to be typed.
func connectInvocation(argv []string) (string, bool) {
	if len(argv) != 2 {
		return "", false
	}
	word := argv[1]
	if word == "" || word[0] == '-' || word == AskpassSubcommand || word == OpenSubcommand {
		return "", false
	}
	return word, true
}

// OpenSubcommand opens the running application in a browser.
//
// A bootstrap token is spent on first use, so a background agent — whose
// standard output goes nowhere on purpose, because that URL carries a live one
// — has no way to hand one out. This asks for a fresh one when the user wants
// to look at something. A host called "open" is a host this cannot connect to
// by name; there is one word and this is it.
const OpenSubcommand = "open"

// runOpen asks the running application for a way in and opens the browser.
func runOpen(ctx context.Context, stateDir string, client *http.Client, browser func(string) error, stderr io.Writer) int {
	found, err := handoff.Read(stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "ssh-ui: not running")
		return 1
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, found.URL+httpserver.OpenPath, bytes.NewReader([]byte("{}")))
	if err != nil {
		fmt.Fprintf(stderr, "ssh-ui: %v\n", err)
		return 1
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(handoff.HeaderName, found.Secret)
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintln(stderr, "ssh-ui: not answering")
		return 1
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "ssh-ui: refused")
		return 1
	}
	var answer struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&answer); err != nil || answer.URL == "" {
		fmt.Fprintln(stderr, "ssh-ui: the answer carried no way in")
		return 1
	}
	// The URL is handed to the browser and never printed. It carries a live
	// bootstrap token, and a terminal keeps what it is shown.
	if err := browser(answer.URL); err != nil {
		fmt.Fprintf(stderr, "ssh-ui: %v\n", err)
		return 1
	}
	return 0
}

// sshFinder resolves the ssh program. It is the same seam every other part of
// this application uses, so there is one answer to "which ssh".
type sshFinder interface{ SSH() (string, error) }

// connectEnvironment is the environment ssh will run with.
//
// The user's own environment is passed through, because this is the connection
// they would have made themselves. The five variables that arm the askpass
// helper are not passed through: they are removed and then set, so what OpenSSH
// reads is what this decided.
//
// It matters more than it looks. syscall.Exec hands the array over as given and
// getenv answers with the first match in it, so appending would lose to an
// SSH_ASKPASS the user exported years ago — while still handing that program
// the one-time token, which it can redeem for a stored password. An unarmed
// connection removes them too, so a stale variable cannot arm one.
func connectEnvironment(inherited []string, helper, url, token, alias string) []string {
	decided := map[string]string{}
	if helper != "" && token != "" {
		decided = map[string]string{
			"SSH_ASKPASS":         helper,
			"SSH_ASKPASS_REQUIRE": "force",
			URLVariable:           url,
			TokenVariable:         token,
			AliasVariable:         alias,
		}
	}
	ours := map[string]bool{
		"SSH_ASKPASS": true, "SSH_ASKPASS_REQUIRE": true,
		URLVariable: true, TokenVariable: true, AliasVariable: true,
	}

	environment := make([]string, 0, len(inherited)+len(decided))
	for _, entry := range inherited {
		name, _, found := strings.Cut(entry, "=")
		if found && ours[name] {
			continue
		}
		environment = append(environment, entry)
	}
	for _, name := range []string{"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", URLVariable, TokenVariable, AliasVariable} {
		if value, set := decided[name]; set {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

// runConnect asks the running application for what this connection needs and
// hands the terminal to ssh.
//
// No application running is not an error. The user asked to connect to a host,
// and `ssh <alias>` is what they would have typed: OpenSSH asks for the
// password itself, which is a working connection. Saying so on stderr means the
// difference is visible without being in the way.
func runConnect(ctx context.Context, alias string, stateDir string, client *http.Client, toolchain sshFinder, stderr io.Writer) int {
	if err := platform.ValidateAlias(alias); err != nil {
		fmt.Fprintf(stderr, "ssh-ui: %q is not an alias this will put on a command line\n", alias)
		return 2
	}

	armed := false
	helper, url, token := "", "", ""
	answer, err := askApplication(ctx, alias, stateDir, client)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "ssh-ui: connecting without a stored password (%v)\n", err)
	default:
		for _, warning := range answer.Warnings {
			fmt.Fprintf(stderr, "ssh-ui: %s\n", warning)
		}
		if answer.AskpassToken != "" {
			resolved, pathErr := os.Executable()
			if pathErr != nil {
				fmt.Fprintf(stderr, "ssh-ui: connecting without a stored password (%v)\n", pathErr)
			} else {
				armed, helper, url, token = true, resolved, answer.AskpassURL, answer.AskpassToken
			}
		}
	}
	environment := connectEnvironment(os.Environ(), helper, url, token, alias)

	// Resolved the way every other OpenSSH program this application starts is
	// resolved: from a fixed list of directories, to an absolute path. PATH is
	// not consulted, because the token above would otherwise be handed to
	// whatever is first on it.
	ssh, err := toolchain.SSH()
	if err != nil || !filepath.IsAbs(ssh) {
		fmt.Fprintf(stderr, "ssh-ui: ssh was not found where it is expected: %v\n", err)
		return 1
	}
	// The terminal belongs to ssh from here. Exec rather than a child process
	// so there is no second thing between the user and the connection —
	// nothing to forward signals through and no exit status to translate.
	arguments := []string{"ssh"}
	if armed {
		// A wrong stored password offered three times counts towards a lockout
		// on some servers, so an armed connection gets one attempt. Without a
		// stored password this is left alone: the user is typing, and typing it
		// wrong once is not a reason to give up.
		arguments = append(arguments, "-o", "NumberOfPasswordPrompts=1")
	}
	arguments = append(arguments, "--", alias)
	if err := syscall.Exec(ssh, arguments, environment); err != nil {
		fmt.Fprintf(stderr, "ssh-ui: %v\n", err)
		return 1
	}
	return 0
}

// askApplication reads the handoff and asks for one connection's worth.
func askApplication(ctx context.Context, alias, stateDir string, client *http.Client) (connectAnswer, error) {
	found, err := handoff.Read(stateDir)
	if err != nil {
		return connectAnswer{}, fmt.Errorf("ssh-ui is not running")
	}
	body, err := json.Marshal(map[string]string{"alias": alias})
	if err != nil {
		return connectAnswer{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		found.URL+httpserver.ConnectPath, bytes.NewReader(body))
	if err != nil {
		return connectAnswer{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(handoff.HeaderName, found.Secret)

	response, err := client.Do(request)
	if err != nil {
		return connectAnswer{}, fmt.Errorf("ssh-ui is not answering")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return connectAnswer{}, fmt.Errorf("ssh-ui refused the request")
	}
	var answer connectAnswer
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&answer); err != nil {
		return connectAnswer{}, err
	}
	return answer, nil
}

// connectTimeout bounds the one request this makes. It is asking a process on
// this machine for a token, not doing anything over a network.
const connectTimeout = 5 * time.Second
