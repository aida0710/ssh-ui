package effective

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"ssh-ui/internal/platform"
)

// DefaultEvaluationTimeout bounds one `ssh -G` run. Evaluation never touches
// the network, so a slow run means something is wrong locally.
const DefaultEvaluationTimeout = 10 * time.Second

var (
	// ErrEvaluationNotConfirmed reports that evaluating this configuration can
	// run a command and the caller did not present a confirmation.
	ErrEvaluationNotConfirmed = errors.New("evaluating this configuration can run a command and needs explicit confirmation")
	// ErrOutputTruncated reports that ssh printed more than the capture limit,
	// so the parsed values would be incomplete and are not returned.
	ErrOutputTruncated = errors.New("ssh -G produced more output than the capture limit")
)

// Values is the effective configuration OpenSSH reported for one alias.
// Keywords keeps the output order; Entries keeps every value of a keyword that
// may appear more than once, such as identityfile.
type Values struct {
	Keywords []string
	Entries  map[string][]string
}

// First returns the first value of keyword, or an empty string.
func (v Values) First(keyword string) string {
	values := v.Entries[strings.ToLower(keyword)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// All returns every value of keyword in output order.
func (v Values) All(keyword string) []string { return v.Entries[strings.ToLower(keyword)] }

// ParseValues parses `ssh -G` output. Each line is a lowercase keyword, a
// single space and the rest of the line, which may itself contain spaces.
func ParseValues(stdout []byte) Values {
	values := Values{Entries: make(map[string][]string)}
	for _, raw := range strings.Split(string(stdout), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		keyword, argument, _ := strings.Cut(line, " ")
		keyword = strings.ToLower(keyword)
		if _, seen := values.Entries[keyword]; !seen {
			values.Keywords = append(values.Keywords, keyword)
		}
		values.Entries[keyword] = append(values.Entries[keyword], argument)
	}
	return values
}

// OpenSSHError reports that the installed ssh rejected the request. Stderr is
// already bounded by the process seam and is meant for display, not for logs.
type OpenSSHError struct {
	ExitCode  int
	Stderr    string
	Truncated bool
}

func (e *OpenSSHError) Error() string {
	return fmt.Sprintf("ssh exited with status %d", e.ExitCode)
}

// Evaluator runs `ssh -G` for one alias against a specific configuration file.
type Evaluator struct {
	Runner     platform.OutputRunner
	Toolchain  platform.Toolchain
	ConfigPath string
	Timeout    time.Duration
}

// Evaluate asks the installed OpenSSH for the effective configuration of alias.
//
// confirmed must come from a consumed action token. When the configuration can
// execute a command during evaluation, Evaluate refuses without it and starts
// no process at all.
func (e Evaluator) Evaluate(ctx context.Context, report Report, alias string, confirmed bool) (Values, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Values{}, err
	}
	if report.EvaluationNeedsConfirmation() && !confirmed {
		return Values{}, ErrEvaluationNotConfirmed
	}
	program, err := e.Toolchain.SSH()
	if err != nil {
		return Values{}, err
	}

	timeout := e.Timeout
	if timeout <= 0 {
		timeout = DefaultEvaluationTimeout
	}
	output, err := e.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-G", "-F", e.ConfigPath, "--", alias},
		Timeout:   timeout,
	})
	if err != nil {
		return Values{}, err
	}
	if output.Truncated {
		return Values{}, ErrOutputTruncated
	}
	if output.ExitCode != 0 {
		return Values{}, &OpenSSHError{
			ExitCode:  output.ExitCode,
			Stderr:    string(output.Stderr),
			Truncated: output.Truncated,
		}
	}
	return ParseValues(output.Stdout), nil
}
