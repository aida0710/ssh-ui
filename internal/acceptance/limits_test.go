package acceptance_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"sshc/internal/httpserver"
	"sshc/internal/platform"
	"sshc/internal/session"
)

// maxAcceptableResponseBytes は、単一のレスポンスが取りうる上限を定める。
// このアプリケーションには、それ以上を返す正当な理由が何もない。
const maxAcceptableResponseBytes = 4 << 20

// bodyOfSize は、おおよそ size バイトの構文的に正しい JSON object を組み立てる。
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

	// 正のコントロール: サーバーは依然として健全であり、普通の body は
	// 依然として受け入れられる。したがって上の拒否は、応答しなくなった
	// サーバーではなく、limit がその仕事をしている証拠である。
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

// fabricatedHostname は、合成した `ssh -G` transcript のうち
// truncation で失われるはずの部分にだけ置かれる。それを示すレスポンスは、
// 切り詰められた transcript を完全な答えとして扱ったことになる。
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

	// 正のコントロール。これがなければ、このテストは ssh に到達する前に
	// 確認が拒否されていても平然と通ってしまう。それは
	// セキュリティテストを無価値にする失敗モードである。
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

	// 正のコントロール。理由は上と同じである: 上限を検査できるのは、
	// authentication check が実際に走った場合に限られる。
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
