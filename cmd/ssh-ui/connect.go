package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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
	if word == "" || word[0] == '-' || word == AskpassSubcommand {
		return "", false
	}
	return word, true
}

// runConnect asks the running application for what this connection needs and
// hands the terminal to ssh.
//
// No application running is not an error. The user asked to connect to a host,
// and `ssh <alias>` is what they would have typed: OpenSSH asks for the
// password itself, which is a working connection. Saying so on stderr means the
// difference is visible without being in the way.
func runConnect(ctx context.Context, alias string, stateDir string, client *http.Client, stderr io.Writer) int {
	if err := platform.ValidateAlias(alias); err != nil {
		fmt.Fprintf(stderr, "ssh-ui: %q is not an alias this will put on a command line\n", alias)
		return 2
	}

	environment := os.Environ()
	armed := false
	answer, err := askApplication(ctx, alias, stateDir, client)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "ssh-ui: connecting without a stored password (%v)\n", err)
	default:
		for _, warning := range answer.Warnings {
			fmt.Fprintf(stderr, "ssh-ui: %s\n", warning)
		}
		if answer.AskpassToken != "" {
			helper, pathErr := os.Executable()
			if pathErr != nil {
				fmt.Fprintf(stderr, "ssh-ui: connecting without a stored password (%v)\n", pathErr)
				break
			}
			armed = true
			environment = append(environment,
				"SSH_ASKPASS="+helper,
				"SSH_ASKPASS_REQUIRE=force",
				URLVariable+"="+answer.AskpassURL,
				TokenVariable+"="+answer.AskpassToken,
				AliasVariable+"="+alias,
			)
		}
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		fmt.Fprintf(stderr, "ssh-ui: ssh is not on the path: %v\n", err)
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
