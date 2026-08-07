package acceptance_test

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"sshc/internal/httpserver"
	"sshc/internal/session"
)

// expectedContentSecurityPolicy は、意図的に完全一致で検証する。
// policy を緩めるにはサーバー側だけでなくここでも意図的な編集が
// 要るようにし、迷い込んだ 'unsafe-inline' が気づかれず紛れ込めないようにする。
const expectedContentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; " +
	"frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; require-trusted-types-for 'script'"

// transportProblemCodes は、検査対象の transport check が拒否した
// 証拠としてこの suite が受け入れる唯一の拒否である。
//
// 素の 403 を主張するだけでは不十分である: いくつかの route は
// confirmation token が欠けているために 403 を返すため、それでは
// 名指す header check が削除されていても敵対的なケースが通ってしまう。
var transportProblemCodes = []string{"invalid_host", "cross_site_request"}

func hasTransportProblemCode(body string) bool {
	for _, code := range transportProblemCodes {
		if strings.Contains(body, code) {
			return true
		}
	}
	return false
}

func TestEveryAPIRouteRefusesTheWrongHostOriginAndFetchSite(t *testing.T) {
	f := newFixture(t)
	for _, route := range f.apiRoutes() {
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			// 正のコントロール: 正しいリクエストは transport rule によって
			// 拒否されてはならない。さもなければ以下の敵対的なケースは何も証明しない。
			// 別の理由 — action token の欠落、未知の identifier — で
			// 拒否されるのは十分ありうるし、ここではそれで構わない。
			baseline := f.do(route.Method, path, emptyBodyFor(route.Method))
			baselineBody := readBody(t, baseline)
			if hasTransportProblemCode(baselineBody) {
				t.Fatalf("the correct request was already refused by a transport rule (%d %s); "+
					"the hostile cases below would prove nothing", baseline.StatusCode, baselineBody)
			}

			hostile := []struct {
				name   string
				adjust func(*http.Request)
			}{
				{"host is a name", func(r *http.Request) { r.Host = "localhost" + portOf(f.host) }},
				{"host has no port", func(r *http.Request) { r.Host = "127.0.0.1" }},
				{"host is another address", func(r *http.Request) { r.Host = "192.168.1.10" + portOf(f.host) }},
				{"fetch site is cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
				{"fetch site is same-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
				{"fetch site is absent", func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }},
			}
			if route.Method != http.MethodGet && route.Method != http.MethodHead {
				hostile = append(hostile,
					struct {
						name   string
						adjust func(*http.Request)
					}{"origin is another site", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
					struct {
						name   string
						adjust func(*http.Request)
					}{"origin is absent", func(r *http.Request) { r.Header.Del("Origin") }},
				)
			}

			for _, test := range hostile {
				t.Run(test.name, func(t *testing.T) {
					response := f.do(route.Method, path, emptyBodyFor(route.Method), test.adjust)
					status := response.StatusCode
					body := readBody(t, response)
					if status != http.StatusForbidden {
						t.Fatalf("status = %d, want %d", status, http.StatusForbidden)
					}
					if !hasTransportProblemCode(body) {
						t.Fatalf("body = %q, want a transport problem code", body)
					}
				})
			}
		})
	}
}

func TestEveryAPIRouteExceptBootstrapRequiresASession(t *testing.T) {
	f := newFixture(t)
	for _, route := range f.apiRoutes() {
		if route.Path == "/api/v1/session/bootstrap" {
			continue
		}
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			response := f.doAnonymous(route.Method, path, emptyBodyFor(route.Method))
			status := response.StatusCode
			body := readBody(t, response)
			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
			}
			if !strings.Contains(body, "session_required") && !strings.Contains(body, "invalid_session") {
				t.Fatalf("body = %q", body)
			}
		})
	}
}

func TestEveryAPIResponseIsNoStoreAndCarriesTheExactPolicy(t *testing.T) {
	f := newFixture(t)
	for _, route := range f.apiRoutes() {
		path := f.concretePath(route.Path)
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			for _, authenticated := range []bool{true, false} {
				response := f.do(route.Method, path, emptyBodyFor(route.Method))
				if !authenticated {
					response = f.doAnonymous(route.Method, path, emptyBodyFor(route.Method))
				}
				cache := response.Header.Get("Cache-Control")
				policy := response.Header.Get("Content-Security-Policy")
				readBody(t, response)
				if cache != "no-store" {
					t.Errorf("authenticated=%v Cache-Control = %q, want no-store", authenticated, cache)
				}
				if policy != expectedContentSecurityPolicy {
					t.Errorf("authenticated=%v CSP = %q, want %q", authenticated, policy, expectedContentSecurityPolicy)
				}
			}
		})
	}

	navigation := f.do(http.MethodGet, "/", nil)
	policy := navigation.Header.Get("Content-Security-Policy")
	readBody(t, navigation)
	if policy != expectedContentSecurityPolicy {
		t.Fatalf("navigation CSP = %q", policy)
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "*"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("CSP contains %q", forbidden)
		}
	}
	for _, required := range []string{"default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(policy, required) {
			t.Errorf("CSP is missing %q", required)
		}
	}
}

func TestBootstrapTokenIsSingleUse(t *testing.T) {
	f := newFixture(t)
	response := f.do(http.MethodPost, "/api/v1/session/bootstrap", nil, func(request *http.Request) {
		request.Header.Set("X-SSHC-Bootstrap", f.canaries.Bootstrap)
	})
	status := response.StatusCode
	cookies := response.Cookies()
	body := readBody(t, response)
	if status != http.StatusConflict {
		t.Fatalf("replay = %d, want %d", status, http.StatusConflict)
	}
	if len(cookies) != 0 {
		t.Fatalf("replay set %d cookies", len(cookies))
	}
	if !strings.Contains(body, "bootstrap_used") {
		t.Fatalf("body = %q", body)
	}
}

func TestServerRefusesEveryListenerThatIsNotUnmappedLoopbackIPv4(t *testing.T) {
	manager, _, err := session.NewManager(strings.NewReader(strings.Repeat("k", 512)))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		address net.Addr
		wantErr bool
	}{
		{"unmapped loopback", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 51234}, false},
		{"mapped loopback", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51234}, true},
		{"wildcard", &net.TCPAddr{IP: net.IPv4zero.To4(), Port: 51234}, true},
		{"ipv6 loopback", &net.TCPAddr{IP: net.IPv6loopback, Port: 51234}, true},
		{"private address", &net.TCPAddr{IP: net.ParseIP("192.168.1.10").To4(), Port: 51234}, true},
		{"public address", &net.TCPAddr{IP: net.ParseIP("203.0.113.10").To4(), Port: 51234}, true},
		{"unix socket", &net.UnixAddr{Name: "/tmp/sshc.sock", Net: "unix"}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := httpserver.New(httpserver.Options{
				Listener: stubListener{address: test.address},
				Sessions: manager,
				Version:  "listener-policy",
			})
			if test.wantErr && err == nil {
				t.Fatalf("New() accepted %v", test.address)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("New() = %v, want nil", err)
			}
		})
	}

	if _, err := httpserver.New(httpserver.Options{Sessions: manager}); err == nil {
		t.Fatal("New() accepted a nil listener")
	}
}

type stubListener struct{ address net.Addr }

func (stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (stubListener) Close() error              { return nil }
func (l stubListener) Addr() net.Addr          { return l.address }

func TestRouteTableMatchesTheOpenAPIContract(t *testing.T) {
	f := newFixture(t)

	contents, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}

	declared := map[string]bool{}
	for path, operations := range document.Paths {
		for method := range operations {
			switch strings.ToUpper(method) {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				declared[strings.ToUpper(method)+" "+echoPath(path)] = true
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("api/openapi.yaml declared no operation; the contract test is reading the wrong file")
	}

	registered := map[string]bool{}
	for _, route := range f.apiRoutes() {
		registered[route.Method+" "+route.Path] = true
	}

	for key := range declared {
		if !registered[key] {
			t.Errorf("api/openapi.yaml declares %q but the server registers no such route", key)
		}
	}
	for key := range registered {
		if !declared[key] {
			t.Errorf("the server registers %q but api/openapi.yaml declares no such operation", key)
		}
	}
}

// echoPath は OpenAPI の path template を Echo の parameter 綴りに変換する。
func echoPath(path string) string {
	replaced := strings.ReplaceAll(path, "{", ":")
	return strings.ReplaceAll(replaced, "}", "")
}

func emptyBodyFor(method string) []byte {
	if method == http.MethodGet || method == http.MethodHead {
		return nil
	}
	return []byte("{}")
}

func portOf(hostPort string) string {
	index := strings.LastIndex(hostPort, ":")
	if index < 0 {
		return ""
	}
	return hostPort[index:]
}
