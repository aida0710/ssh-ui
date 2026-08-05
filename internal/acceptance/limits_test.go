package acceptance_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"ssh-ui/internal/httpserver"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/session"
)

// maxAcceptableResponseBytes bounds what any single response may be. Nothing in
// this application has a legitimate reason to return more.
const maxAcceptableResponseBytes = 4 << 20

// bodyOfSize builds a syntactically valid JSON object of roughly size bytes.
func bodyOfSize(size int) []byte {
	if size < 16 {
		size = 16
	}
	var builder bytes.Buffer
	builder.WriteString(`{"base":"`)
	builder.Write(bytes.Repeat([]byte("a"), size-len(`{"base":""}`)))
	builder.WriteString(`"}`)
	return builder.Bytes()
}

func TestNoAPIRouteReadsAnUnboundedBody(t *testing.T) {
	f := newFixture(t)
	oversized := bodyOfSize(httpserver.MaxRequestBodyCeiling + (1 << 20))

	for _, route := range f.apiRoutes() {
		if route.Method == http.MethodGet || route.Method == http.MethodHead {
			continue
		}
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			f.runner.reset()
			f.terminal.reset()
			before := f.read("config")

			response := f.do(route.Method, path, oversized)
			status := response.StatusCode
			body := readBody(t, response)

			if status < 400 || status >= 500 {
				t.Fatalf("status = %d, want a 4xx refusal", status)
			}
			if len(body) > maxAcceptableResponseBytes {
				t.Fatalf("refusal body = %d bytes", len(body))
			}
			if strings.Contains(body, strings.Repeat("a", 256)) {
				t.Fatal("the refusal echoed the oversized body back")
			}
			if commands := f.runner.recorded(); len(commands) != 0 {
				t.Fatalf("an oversized body still started %d command(s)", len(commands))
			}
			if launched := f.terminal.launched(); len(launched) != 0 {
				t.Fatalf("an oversized body still launched Terminal for %#v", launched)
			}
			if !bytes.Equal(before, f.read("config")) {
				t.Fatal("an oversized body changed a configuration file")
			}
		})
	}

	// Positive control: the server is still healthy, and an ordinary body is
	// still accepted, so the refusals above are the limit doing its job rather
	// than a server that stopped answering.
	health := f.do(http.MethodGet, "/api/v1/health", nil)
	healthStatus := health.StatusCode
	readBody(t, health)
	if healthStatus != http.StatusOK {
		t.Fatalf("health after the oversized sweep = %d", healthStatus)
	}
	ordinary := f.do(http.MethodPost, "/api/v1/config/preview", mustJSON(t, map[string]any{
		"kind":  "host_fields",
		"path":  "config",
		"alias": "bastion",
		"base":  string(f.read("config")),
		"fields": []map[string]any{
			{"action": "set", "keyword": "Port", "values": []string{"2244"}, "line": 8},
		},
	}))
	ordinaryStatus := ordinary.StatusCode
	ordinaryBody := readBody(t, ordinary)
	if ordinaryStatus != http.StatusOK {
		t.Fatalf("an ordinary preview = %d (%s), want 200; the ceiling is rejecting legitimate work",
			ordinaryStatus, ordinaryBody)
	}
}

// fabricatedHostname is placed only in the part of a synthetic `ssh -G`
// transcript that would be lost to truncation. A response that shows it has
// treated a truncated transcript as a complete answer.
const fabricatedHostname = "truncated-transcript-must-not-be-parsed.invalid"

func TestTruncatedCommandOutputIsRefusedRatherThanParsed(t *testing.T) {
	f := newFixture(t)

	transcript := []byte("hostname " + fabricatedHostname + "\nuser ops\nport 2222\n")
	transcript = append(transcript, bytes.Repeat([]byte("identityfile /padding\n"), 4096)...)
	f.runner.answer(func(platform.Command) (platform.Output, error) {
		return platform.Output{
			Stdout:    transcript[:platform.MaxCapturedOutput],
			Truncated: true,
		}, nil
	})

	f.runner.reset()
	token := f.actionToken(t, session.ActionEvaluate, "bastion")
	response := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}), withAction(token))
	status := response.StatusCode
	body := readBody(t, response)

	// Positive control. Without it this test would pass just as happily if the
	// confirmation had been refused before ssh was ever reached, which is the
	// failure mode that makes a security test worthless.
	if commands := f.runner.recorded(); len(commands) == 0 {
		t.Fatalf("ssh -G was never reached (status %d, body %s); the truncation rule was not exercised", status, body)
	}
	if strings.Contains(body, fabricatedHostname) {
		t.Fatal("a truncated ssh -G transcript was parsed and served as an effective value")
	}
	if len(body) > maxAcceptableResponseBytes {
		t.Fatalf("response = %d bytes", len(body))
	}
}

func TestReportedCommandOutputStaysWithinItsPublishedCeiling(t *testing.T) {
	f := newFixture(t)

	f.runner.answer(func(platform.Command) (platform.Output, error) {
		return platform.Output{
			Stderr:    bytes.Repeat([]byte("noisy stderr line\n"), 64<<10),
			ExitCode:  255,
			Truncated: true,
		}, nil
	})

	f.runner.reset()
	token := f.actionToken(t, session.ActionAuthentication, "bastion")
	response := f.do(http.MethodPost, "/api/v1/diagnostics/authentication", mustJSON(t, map[string]any{
		"alias":                 "bastion",
		"acknowledgeExecutable": true,
	}), withAction(token))
	status := response.StatusCode
	body := readBody(t, response)

	// Positive control, for the same reason as above: the ceiling can only be
	// under test if the authentication check actually ran.
	if commands := f.runner.recorded(); len(commands) == 0 {
		t.Fatalf("ssh was never reached (status %d, body %s); the ceiling was not exercised", status, body)
	}
	if count := strings.Count(body, "noisy stderr line"); count > 1024 {
		t.Fatalf("the response relayed %d stderr lines; the ceiling is not applied", count)
	}
	if len(body) > maxAcceptableResponseBytes {
		t.Fatalf("response = %d bytes", len(body))
	}
}
