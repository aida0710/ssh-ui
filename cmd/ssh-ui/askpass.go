package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The askpass helper.
//
// OpenSSH takes a secret from a program instead of a terminal when SSH_ASKPASS
// names one and SSH_ASKPASS_REQUIRE is `force`. That program is this binary,
// invoked as `ssh-ui askpass <prompt>`, and whatever it writes to standard
// output becomes the answer.
//
// It holds no secret and can decrypt nothing. The passwords live in an
// encrypted file whose key exists only inside a running, unlocked ssh-ui, so
// this helper asks that process over the loopback interface, presenting a
// one-time token the same process minted when the user asked to connect. Run
// by hand it obtains nothing: there is no token, and a token is spent by the
// connection it was made for.
//
// internal/platform withholds SSH_ASKPASS from every child this application
// starts, and that decision stands. Its reason is that a secret must not be
// moved onto a program this application did not choose. Here the program is
// this application, at an absolute path, armed for one alias, for one
// connection the user asked for.

const (
	// AliasVariable names the host the answer belongs to.
	//
	// The alias arrives in the environment and never by reading it out of the
	// prompt: OpenSSH's prompt carries the *resolved* user and hostname, which
	// is not what a password is filed under, and parsing it would tie this to
	// a format string in someone else's source.
	AliasVariable = "SSH_UI_ASKPASS_ALIAS"
	// URLVariable is the loopback endpoint of the ssh-ui that armed this.
	URLVariable = "SSH_UI_ASKPASS_URL"
	// TokenVariable is the one-time token for this connection.
	TokenVariable = "SSH_UI_ASKPASS_TOKEN"

	// AskpassTokenHeader carries the token. A custom header forces a CORS
	// preflight, which this server does not answer, so no web page can reach
	// the endpoint however much it knows about it.
	AskpassTokenHeader = "X-SSH-UI-Askpass"

	// passwordPromptSuffix is what OpenSSH appends when it wants the remote
	// account's password. Its format is "%.30s@%.128s's password: ".
	passwordPromptSuffix = "'s password:"
)

// refusalMarkers disqualify a prompt outright. The rule below is an allowlist,
// so these are belt and braces: a prompt that somehow both ends in the
// password suffix and mentions one of these is still refused.
var refusalMarkers = []string{
	"passphrase",
	"continue connecting",
	"fingerprint",
	"yes/no",
	"verification code",
	"one-time",
	"token",
}

// AnswerablePrompt reports whether this prompt asks for the remote account's
// password, and nothing else.
//
// The default is refusal, and that is the point of the function. Forcing
// askpass routes *every* interactive question through this program, including
// the host key confirmation — "Are you sure you want to continue connecting
// (yes/no/[fingerprint])?" — which is the only check a first connection
// performs. A helper that answers that question has removed it. A helper that
// answers a key passphrase prompt with an account password has handed the
// account password to a question that did not ask for it.
//
// The server applies this same rule before it returns anything, so the check
// cannot be skipped by invoking the helper differently. It is here as well so
// that an unanswerable prompt costs no round trip and spends no token.
func AnswerablePrompt(prompt string) bool {
	trimmed := strings.ToLower(strings.TrimRight(prompt, " \t\r\n"))
	if trimmed == "" {
		return false
	}
	for _, marker := range refusalMarkers {
		if strings.Contains(trimmed, marker) {
			return false
		}
	}
	return strings.HasSuffix(trimmed, passwordPromptSuffix)
}

// Exit statuses. OpenSSH treats any non-zero status as "no answer", so the
// distinction is for the person reading the Terminal window, not for ssh.
const (
	askpassOK      = 0
	askpassRefused = 1
	askpassNoEntry = 2
)

type askpassRequest struct {
	Alias  string `json:"alias"`
	Prompt string `json:"prompt"`
}

type askpassResponse struct {
	Password string `json:"password"`
}

// runAskpass is the whole of `ssh-ui askpass <prompt>`.
//
// On success it writes the password to out and nothing else. On any refusal it
// writes zero bytes to out, because a diagnostic on standard output would be
// handed to OpenSSH as the password.
func runAskpass(
	ctx context.Context,
	arguments []string,
	lookup func(string) string,
	client *http.Client,
	out io.Writer,
	errOut io.Writer,
) int {
	if len(arguments) == 0 {
		return refuse(errOut, "ssh-ui askpass expects the prompt as its argument")
	}
	prompt := arguments[0]

	alias := lookup(AliasVariable)
	endpoint := lookup(URLVariable)
	token := lookup(TokenVariable)
	if alias == "" || endpoint == "" || token == "" {
		// Without all three there is nothing to ask and no way to prove the
		// question was authorised. Answering the wrong host would disclose a
		// credential to it.
		return refuse(errOut, "ssh-ui askpass was started without "+
			AliasVariable+", "+URLVariable+" and "+TokenVariable)
	}
	if err := validateLoopbackEndpoint(endpoint); err != nil {
		return refuse(errOut, "ssh-ui askpass refuses to send a password to "+endpoint)
	}

	if !AnswerablePrompt(prompt) {
		return refuse(errOut,
			"ssh-ui askpass answers the remote password prompt only. This prompt was "+
				"something else, so nothing was supplied — answer it yourself, or add "+
				"the host key through the Known Hosts screen first.")
	}

	password, status := fetchPassword(ctx, client, endpoint, token, alias, prompt)
	if status != askpassOK {
		switch status {
		case askpassNoEntry:
			writeLine(errOut, "ssh-ui has no stored password for "+alias+", or its vault is locked")
		default:
			writeLine(errOut, "ssh-ui refused the request for "+alias+"'s password")
		}
		return status
	}

	// OpenSSH strips one trailing newline, so a password that legitimately
	// ends in whitespace survives.
	if _, err := io.WriteString(out, password+"\n"); err != nil {
		return askpassRefused
	}
	return askpassOK
}

func fetchPassword(
	ctx context.Context, client *http.Client, endpoint, token, alias, prompt string,
) (string, int) {
	body, err := json.Marshal(askpassRequest{Alias: alias, Prompt: prompt})
	if err != nil {
		return "", askpassRefused
	}
	callContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(callContext, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", askpassRefused
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(AskpassTokenHeader, token)

	response, err := client.Do(request)
	if err != nil {
		return "", askpassRefused
	}
	defer func() { _ = response.Body.Close() }()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusConflict:
		return "", askpassNoEntry
	default:
		return "", askpassRefused
	}

	var decoded askpassResponse
	// The body is bounded: a password is not megabytes, and this process is
	// about to write whatever it reads onto a pipe OpenSSH is holding.
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&decoded); err != nil {
		return "", askpassRefused
	}
	if decoded.Password == "" {
		return "", askpassNoEntry
	}
	return decoded.Password, askpassOK
}

// validateLoopbackEndpoint refuses to send a password anywhere but this
// machine. The endpoint arrives in an environment variable, so it is input,
// and an exported SSH_UI_ASKPASS_URL pointing at someone else's server would
// otherwise turn this helper into an exfiltration tool.
func validateLoopbackEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" {
		return errNotLoopback
	}
	host, _, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return err
	}
	address := net.ParseIP(host)
	if address == nil || !address.Equal(net.IPv4(127, 0, 0, 1)) {
		return errNotLoopback
	}
	return nil
}

var errNotLoopback = &endpointError{}

type endpointError struct{}

func (*endpointError) Error() string { return "the askpass endpoint is not 127.0.0.1" }

func refuse(errOut io.Writer, message string) int {
	writeLine(errOut, message)
	return askpassRefused
}

func writeLine(w io.Writer, message string) {
	if w == nil {
		return
	}
	_, _ = io.WriteString(w, message+"\n")
}
