package acceptance_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshc/internal/session"
)

// guardedRoute は、プロセスを起動する、通常の edit 経路の外で
// ファイルを変更する、あるいは key material を渡す操作の 1 つである。
//
// そのどれもが X-SSHC-Action ヘッダーで確認を受け取る:
// merge されたツリーは 1 つの配送方式に落ち着いたため、plan の
// tokenInBody という variant は、記述すべき route を持たない。
type guardedRoute struct {
	Method string
	// Path は Echo path であり、以下の router cross-check がそれと
	// 比較できるようにする。Target は concrete path と token target を
	// 併せて解決する。完全削除ではこの 2 つが同じ値であり、実在する
	// trash entry でなければならないからである。
	Path string
	Kind string
	// Target は、route の確認が紐づく値を返す。文字列ではなく
	// 関数になっているのは、行ごとに使うたびに新しい subject を発行できる
	// ようにするためである。permanent-delete の行にはそれが要る。
	// その positive control が、発行された entry を消費してしまうからである。
	Target func(t testing.TB) string
	// Concrete は、解決済みの target から request path を組み立てる。
	Concrete func(target string) string
	Body     func(f *fixture, target string) map[string]any
}

func constantTarget(value string) func(testing.TB) string {
	return func(testing.TB) string { return value }
}

func fixedPath(path string) func(string) string {
	return func(string) string { return path }
}

func guardedRoutes(f *fixture) []guardedRoute {
	keyID := f.keyID()
	knownHostsPath := f.knownHostsPath()
	alias := func(extra map[string]any) func(*fixture, string) map[string]any {
		return func(_ *fixture, _ string) map[string]any {
			body := map[string]any{"alias": "bastion"}
			for key, value := range extra {
				body[key] = value
			}
			return body
		}
	}
	return []guardedRoute{
		{http.MethodPost, "/api/v1/diagnostics/reachability", session.ActionReachability,
			constantTarget("bastion"), fixedPath("/api/v1/diagnostics/reachability"), alias(nil)},
		{http.MethodPost, "/api/v1/diagnostics/authentication", session.ActionAuthentication,
			constantTarget("bastion"), fixedPath("/api/v1/diagnostics/authentication"),
			alias(map[string]any{"acknowledgeExecutable": true})},
		{http.MethodPost, "/api/v1/terminal/launch", session.ActionTerminalLaunch,
			constantTarget("bastion"), fixedPath("/api/v1/terminal/launch"), alias(nil)},
		{http.MethodPost, "/api/v1/known-hosts/delete", session.ActionKnownHostsDelete,
			constantTarget(knownHostsPath), fixedPath("/api/v1/known-hosts/delete"),
			func(*fixture, string) map[string]any {
				return map[string]any{"entries": []map[string]any{{"line": 2, "digest": strings.Repeat("0", 64)}}}
			}},
		{http.MethodPost, "/api/v1/known-hosts/scan", session.ActionKnownHostsScan,
			constantTarget("203.0.113.10"), fixedPath("/api/v1/known-hosts/scan"),
			func(*fixture, string) map[string]any {
				return map[string]any{"host": "203.0.113.10", "port": 22}
			}},
		{http.MethodPost, "/api/v1/known-hosts/add", session.ActionKnownHostsAdd,
			constantTarget("203.0.113.10"), fixedPath("/api/v1/known-hosts/add"),
			func(*fixture, string) map[string]any {
				return map[string]any{
					"host": "203.0.113.10", "port": 22, "keyType": "ssh-ed25519",
					"key":                 "AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl",
					"expectedFingerprint": "", "acknowledged": true,
				}
			}},
		{http.MethodPost, "/api/v1/remote-keys/register", session.ActionRemoteKeyRegister,
			constantTarget("bastion"), fixedPath("/api/v1/remote-keys/register"),
			func(f *fixture, _ string) map[string]any {
				return map[string]any{
					"alias": "bastion", "keyPath": "id_ed25519.pub",
					"publicKey":             string(bytes.TrimSpace(f.read("id_ed25519.pub"))),
					"acknowledgeExecutable": true,
				}
			}},
		{http.MethodPost, "/api/v1/keys/:keyId/reveal", session.ActionRevealPrivateKey,
			constantTarget(keyID),
			func(target string) string { return "/api/v1/keys/" + target + "/reveal" }, nil},
		{http.MethodDelete, "/api/v1/trash/:entryId", session.ActionPurgeTrashEntry,
			func(t testing.TB) string { return f.newTrashEntry(t) },
			func(target string) string { return "/api/v1/trash/" + target }, nil},
	}
}

// sendGuarded は、route が期待するヘッダーに token を載せて
// 1 つの guarded request を発行する。presented が空ならヘッダー自体を付けない。
func (f *fixture) sendGuarded(t testing.TB, route guardedRoute, target, presented string) *http.Response {
	t.Helper()
	var body []byte
	if route.Body != nil {
		body = mustJSON(t, route.Body(f, target))
	}
	return f.do(route.Method, route.Concrete(target), body, withAction(presented))
}

func TestEveryGuardedRouteRefusesAMissingWrongOrExpiredToken(t *testing.T) {
	f := newFixture(t)
	routes := guardedRoutes(f)

	for _, route := range routes {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			// まず positive control: 正しい token は operation に届かねば
			// ならない。さもなければ以下の拒否は何も証明しない。
			f.runner.reset()
			controlTarget := route.Target(t)
			valid := f.actionToken(t, route.Kind, controlTarget)
			accepted := f.sendGuarded(t, route, controlTarget, valid)
			acceptedStatus := accepted.StatusCode
			acceptedBody := readBody(t, accepted)
			if acceptedStatus == http.StatusForbidden && strings.Contains(acceptedBody, "action_token") {
				t.Fatalf("a freshly issued token was refused: %d %s", acceptedStatus, acceptedBody)
			}

			refusals := []struct {
				name  string
				token func(target string) string
			}{
				{"no token", func(string) string { return "" }},
				{"token from another kind", func(target string) string {
					other := session.ActionReachability
					if route.Kind == other {
						other = session.ActionTerminalLaunch
					}
					return f.tryActionToken(other, target)
				}},
				{"token for another target", func(string) string {
					return f.tryActionToken(route.Kind, "some-other-target")
				}},
				{"token already spent", func(target string) string {
					spent := f.actionToken(t, route.Kind, target)
					readBody(t, f.sendGuarded(t, route, target, spent))
					return spent
				}},
				{"token past its lifetime", func(target string) string {
					aged := f.actionToken(t, route.Kind, target)
					f.clock.advance(session.ActionTokenTTL + time.Minute)
					return aged
				}},
				{"token invented by the caller", func(string) string { return strings.Repeat("A", 43) }},
			}

			for _, refusal := range refusals {
				t.Run(refusal.name, func(t *testing.T) {
					// 各拒否は自分専用の subject を得る。そのため、control が
					// 発行された分を消費してしまった行でも、拒否する対象として
					// 生きた subject が残っている。
					target := route.Target(t)
					presented := refusal.token(target)
					f.runner.reset()
					f.terminal.reset()
					before := f.read("known_hosts")

					response := f.sendGuarded(t, route, target, presented)
					status := response.StatusCode
					body := readBody(t, response)

					if status < 400 || status >= 500 {
						t.Fatalf("status = %d, want a 4xx refusal", status)
					}
					if commands := f.runner.recorded(); len(commands) != 0 {
						t.Fatalf("the refused request still started %d command(s): %#v", len(commands), commands)
					}
					if launched := f.terminal.launched(); len(launched) != 0 {
						t.Fatalf("the refused request still launched Terminal for %#v", launched)
					}
					if !bytes.Equal(before, f.read("known_hosts")) {
						t.Fatal("the refused request still changed known_hosts")
					}
					if strings.Contains(body, f.canaries.PrivateKeyLine) {
						t.Fatal("the refused request still returned key material")
					}
				})
			}
		})
	}

	// この表は router に追随していなければならない。Echo path が
	// token で守られた operation のいずれかを指す route は、すべて上に現れねばならない。
	tabled := map[string]bool{}
	for _, route := range routes {
		tabled[route.Method+" "+route.Path] = true
	}
	for _, route := range f.apiRoutes() {
		key := route.Method + " " + route.Path
		if !requiresConfirmation(route.Path) || tabled[key] {
			continue
		}
		t.Errorf("route %s is a confirmation-guarded operation with no row in guardedRoutes", key)
	}
	// 逆もまた然り: router が登録していない route を名指す行は、
	// 何もテストせずに黙って通ってしまう。
	registered := map[string]bool{}
	for _, route := range f.apiRoutes() {
		registered[route.Method+" "+route.Path] = true
	}
	for key := range tabled {
		if !registered[key] {
			t.Errorf("guardedRoutes names %s but the server registers no such route", key)
		}
	}
}

// requiresConfirmation は、design §8.2 が action token の背後に
// 置く route の系列を名指しする: 接続するもの、Terminal を起動する
// もの、known_hosts を編集するもの、リモートホストに key を登録する
// もの、private key を reveal するもの、あるいはそれを完全削除するもの。
//
// POST /api/v1/diagnostics/effective は意図的に含まれていない。
// design §8.3 はその確認を条件付きにしている — 評価が
// コマンドを実行するのは、設定が Match exec を持つときだけである —
// そのためここでは token がないことは拒否ではなく、単に評価されていない答えにすぎない。
// その条件付きゲートには、Match exec を持つ設定に対する専用テストが以下にある。
func requiresConfirmation(path string) bool {
	switch {
	case path == "/api/v1/diagnostics/config", path == "/api/v1/diagnostics/effective":
		return false
	case strings.HasPrefix(path, "/api/v1/diagnostics/"):
		return true
	case path == "/api/v1/terminal/launch":
		return true
	case strings.HasPrefix(path, "/api/v1/known-hosts/"):
		return true
	case path == "/api/v1/remote-keys/register":
		return true
	case strings.HasSuffix(path, "/reveal"):
		return true
	case strings.HasPrefix(path, "/api/v1/trash/") && !strings.HasSuffix(path, "/restore"):
		return true
	default:
		return false
	}
}

// TestEvaluationOfAnExecutableConfigurationNeedsAConfirmation は、
// 上の表が漏らしたゲートをカバーする。
//
// Match exec は、OpenSSH が設定ファイルを読むだけの際に実行する
// 唯一のディレクティブであり、そのため `ssh -G` をそうしたファイルに
// かけるのは、ユーザーが見せられた正確なコマンドを確認するまで始まってはならない。
func TestEvaluationOfAnExecutableConfigurationNeedsAConfirmation(t *testing.T) {
	f := newFixture(t)

	// diagnostics token が運ぶ evidence は、その時点の設定が持つ
	// 実行可能なディレクティブから導かれるため、token を発行する前に
	// ファイルは書き換えられている。
	mustWrite(t, filepath.Join(f.root, "config"), []byte(""+
		"Match exec \"true\"\n"+
		"\tUser matched\n"+
		"\n"+
		"Host bastion\n"+
		"\tHostName 203.0.113.10\n"), 0o600)

	f.runner.reset()
	unconfirmed := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}))
	unconfirmedBody := readBody(t, unconfirmed)
	if commands := f.runner.recorded(); len(commands) != 0 {
		t.Fatalf("evaluating an executable configuration ran %#v without a confirmation", commands)
	}
	if !strings.Contains(unconfirmedBody, `"requiresConfirmation":true`) {
		t.Fatalf("the unconfirmed answer does not report that a confirmation is required: %s", unconfirmedBody)
	}
	if strings.Contains(unconfirmedBody, `"evaluated":true`) {
		t.Fatal("an executable configuration was evaluated without a confirmation")
	}

	// 誤った token は、未確認の答えへ黙って格下げされるのではなく、
	// きっぱりと拒否される。
	f.runner.reset()
	refused := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}), withAction(strings.Repeat("B", 43)))
	refusedStatus := refused.StatusCode
	readBody(t, refused)
	if refusedStatus != http.StatusForbidden {
		t.Fatalf("an invented token = %d, want 403", refusedStatus)
	}
	if commands := f.runner.recorded(); len(commands) != 0 {
		t.Fatalf("an invented token still ran %#v", commands)
	}

	// 正のコントロール: 確認があれば評価は実際に走る。
	// つまり上の 2 つの拒否は、一度も動かない route ではなくゲートが機能している証拠である。
	f.runner.reset()
	token := f.actionToken(t, session.ActionEvaluate, "bastion")
	confirmed := f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}), withAction(token))
	confirmedBody := readBody(t, confirmed)
	if commands := f.runner.recorded(); len(commands) == 0 {
		t.Fatalf("a confirmed evaluation started no process: %s", confirmedBody)
	}
}

// contentBearingRoutes は、ユーザーがファイルの中身だと認識する
// ような material を含んでよい唯一のレスポンスである。各 entry は理由を述べる。
//
// この map は便宜ではなく assertion そのものである: ここに行が
// ないまま漏らす route も失敗し、漏らさなくなった route を持つ行も
// 失敗する。そのため allowlist は黙って包括的な免除へと広がることができない。
var contentBearingRoutes = map[string]string{
	"GET /api/v1/config/overview":  "the overview carries the parsed text of every managed file",
	"GET /api/v1/config/file":      "the raw editor is the feature; it returns the file the user asked to edit",
	"GET /api/v1/config/host":      "the block editor returns the raw text of the block the user opened",
	"POST /api/v1/config/preview":  "a save preview is a diff of configuration text",
	"POST /api/v1/config/save":     "a save result reports the diff it wrote",
	"POST /api/v1/history/restore": "a restore reports the diff it wrote",
}

// keyMaterialRoutes は、private key のバイト列を含んでよい唯一のレスポンスである。
// design §6.3 は、これを他のあらゆる API から意図的に切り離している。
var keyMaterialRoutes = map[string]string{
	"POST /api/v1/keys/:keyId/reveal": "the separated reveal API, behind a one-time action token",
}

func TestNoResponseCarriesASecretItIsNotEntitledTo(t *testing.T) {
	f := newFixture(t)

	type observation struct {
		key  string
		body string
	}
	var observed []observation

	record := func(method, path string, body []byte, adjust ...func(*http.Request)) {
		response := f.do(method, path, body, adjust...)
		text := readBody(t, response)
		if len(text) > maxAcceptableResponseBytes {
			t.Fatalf("%s %s returned %d bytes", method, path, len(text))
		}
		observed = append(observed, observation{key: method + " " + path, body: text})
	}

	// reveal を先に行う。以下の phase one は fixture key に対して
	// POST /api/v1/keys/:keyId/trash を駆動するが、trash 済みの key には
	// もう reveal の確認を発行できない。そのため key material を
	// 運んでよい唯一のレスポンスは、key がまだ存在するうちに収集しなければならない。
	keyID := f.keyID()
	revealToken := f.actionToken(t, session.ActionRevealPrivateKey, keyID)
	record(http.MethodPost, "/api/v1/keys/"+keyID+"/reveal", nil, withAction(revealToken))

	// Phase one: 登録済みの route をすべて触る。そうすれば、後から追加された route も、
	// 誰も意味のあるリクエストを書いていなくても掃かれる。ここでは 400 の応答でよい。
	// assertion は何が成功するかではなく、何が漏れるかについてのものだからである。
	for _, route := range f.apiRoutes() {
		if route.Path == "/api/v1/session/bootstrap" {
			continue
		}
		record(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method))
	}

	// Phase one は POST /api/v1/passwords/lock に触れ、アプリケーション
	// 全体を閉じてしまう: それ以降のすべての read は vault_locked を
	// 返す。もう一度開くことで、phase two は problem document ではなく
	// 中身の詰まった body を見られるようになる — これが、この sweep が
	// 何かを証明することと何も証明しないことの違いである。
	f.unlockAgain()

	// Phase two: read 経路を本物の 200 まで駆動し、sweep が
	// problem document ではなく中身の詰まった body を見るようにする。
	record(http.MethodGet, "/api/v1/config/overview", nil)
	record(http.MethodGet, "/api/v1/config/file?path=config", nil)
	record(http.MethodGet, "/api/v1/config/host?path=config&alias=bastion", nil)
	record(http.MethodGet, "/api/v1/metadata", nil)
	record(http.MethodGet, "/api/v1/history", nil)
	record(http.MethodGet, "/api/v1/keys", nil)
	record(http.MethodGet, "/api/v1/trash", nil)
	record(http.MethodGet, "/api/v1/known-hosts?query=203", nil)

	sawFileContents := map[string]bool{}
	sawKeyMaterial := map[string]bool{}
	for _, entry := range observed {
		normalised := normaliseObservationKey(entry.key, keyID)

		// 決して、どこであっても、いかなる状況でも。
		for name, secret := range map[string]string{
			"a file outside ~/.ssh": f.canaries.Outside,
			"the key passphrase":    f.canaries.Passphrase,
			"the bootstrap token":   f.canaries.Bootstrap,
			"the session id":        f.canaries.SessionID,
		} {
			if secret != "" && strings.Contains(entry.body, secret) {
				t.Errorf("%s leaked %s", entry.key, name)
			}
		}

		if strings.Contains(entry.body, f.canaries.PrivateKeyLine) {
			sawKeyMaterial[normalised] = true
			if _, allowed := keyMaterialRoutes[normalised]; !allowed {
				t.Errorf("%s returned private key material and is not the separated reveal API", entry.key)
			}
		}
		if strings.Contains(entry.body, "Managed by hand since 2019") {
			sawFileContents[normalised] = true
			if _, allowed := contentBearingRoutes[normalised]; !allowed {
				t.Errorf("%s returned configuration file contents without being a content-bearing route", entry.key)
			}
		}
	}

	for route := range keyMaterialRoutes {
		if !sawKeyMaterial[route] {
			t.Errorf("%s is allowlisted for key material but returned none; the sweep is not reaching it", route)
		}
	}
	if len(sawFileContents) == 0 {
		t.Error("no route returned configuration contents; the sweep is not reaching the read paths")
	}
}

// normaliseObservationKey は、concrete な request path を
// allowlist が使う Echo parameter の綴りへ戻す。
func normaliseObservationKey(key, keyID string) string {
	normalised := strings.Split(key, "?")[0]
	if keyID != "" {
		normalised = strings.ReplaceAll(normalised, "/"+keyID, "/:keyId")
	}
	return strings.ReplaceAll(normalised, "/acceptance-placeholder", "/:entryId")
}

func TestNoLogLineCarriesASecret(t *testing.T) {
	f := newFixture(t)

	// reveal を先に行うのは、response sweep と同じ理由による:
	// 以下の route walk は fixture key を trash してしまうからである。
	keyID := f.keyID()
	revealToken := f.actionToken(t, session.ActionRevealPrivateKey, keyID)
	readBody(t, f.do(http.MethodPost, "/api/v1/keys/"+keyID+"/reveal", nil, withAction(revealToken)))

	// すべての route を動かし、ログに何かが残るようにする。拒否も
	// 含めてであり、それは拒絶されたものを反響させる可能性が最も高い行だからである。
	for _, route := range f.apiRoutes() {
		readBody(t, f.do(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method)))
		readBody(t, f.do(route.Method, f.concretePath(route.Path), emptyBodyFor(route.Method), func(request *http.Request) {
			request.Header.Set("Sec-Fetch-Site", "cross-site")
		}))
	}

	logged := f.logText()
	if strings.TrimSpace(logged) == "" {
		t.Log("the server logged nothing at all, which satisfies this test trivially but is worth knowing")
	}
	for name, secret := range map[string]string{
		"the bootstrap token":      f.canaries.Bootstrap,
		"the session id":           f.canaries.SessionID,
		"the CSRF token":           f.canaries.CSRF,
		"an action token":          revealToken,
		"the key passphrase":       f.canaries.Passphrase,
		"private key material":     f.canaries.PrivateKeyLine,
		"a file outside ~/.ssh":    f.canaries.Outside,
		"configuration file bytes": "Managed by hand since 2019",
	} {
		if secret != "" && strings.Contains(logged, secret) {
			t.Errorf("the log contains %s", name)
		}
	}
	if strings.Contains(logged, f.home) {
		t.Error("the log contains the absolute home directory path")
	}
}

// TestTheLogScrapeWouldNoticeASecret は、leak sweep 自身の control である。
//
// TestNoLogLineCarriesASecret は、何もログしないサーバーに対しては
// 自明に通ってしまい、このアプリケーションはログがごく少ない。
// これは、scrape がサーバーの書き込み先と同じ stream を読んでいることを
// 証明するもので、将来 secret をログしてしまう handler は黙って見逃されず捕まる。
func TestTheLogScrapeWouldNoticeASecret(t *testing.T) {
	f := newFixture(t)
	if _, err := f.logs.Write([]byte("level=INFO msg=\"planted\" token=" + f.canaries.SessionID + "\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.logText(), f.canaries.SessionID) {
		t.Fatal("logText did not observe a line written to the server's own log stream")
	}
	if _, err := os.Stat(filepath.Join(f.home, ".ssh")); err != nil {
		t.Fatal(err)
	}
}

// backup directory の中身は、master password なしには何 1 つ読めない。
//
// generational backup は、このアプリケーションが置き換える
// すべてのファイルの、以前の中身を保持する。だからこそ、以前の
// 中身が private key でありうる書き込みは、かつては一切 backup を
// 残さず、そのため決して元に戻せなかった。これを安全にしているのは、
// ディレクトリ全体が ciphertext であり、復元は vault を経て戻ってくることである。
func TestNothingInTheBackupDirectoryIsReadable(t *testing.T) {
	f := newFixture(t)

	base := string(f.read("config"))
	saved := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "config", "base": base,
		"raw": base + "\n# a line that makes this a change\n",
	}))
	status := saved.StatusCode
	body := readBody(t, saved)
	if status != http.StatusOK {
		t.Fatalf("save = %d (%s); there would be no backup to inspect", status, body)
	}

	backups := filepath.Join(f.root, "sshc", "backups")
	found := 0
	err := filepath.WalkDir(backups, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		found++
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		// この backup が何のものかといえば以前の configuration であり、
		// その識別可能な断片が見つかれば、ファイルが平文で書かれたことを意味する。
		for _, secret := range []string{"Host bastion", "203.0.113.10", "IdentityFile"} {
			if bytes.Contains(contents, []byte(secret)) {
				t.Errorf("%s carries %q in the clear", path, secret)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no backup was written, so this test proved nothing")
	}

	// そしてそれは今なお復元できる。それこそが保持している意味そのものである。
	history := f.do(http.MethodGet, "/api/v1/history", nil)
	defer func() { _ = history.Body.Close() }()
	if history.StatusCode != http.StatusOK {
		t.Fatalf("history = %d", history.StatusCode)
	}
	var listed struct {
		Entries []struct {
			ID         string   `json:"id"`
			Restorable []string `json:"restorable"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(readBody(t, history)), &listed); err != nil {
		t.Fatal(err)
	}
	restored := false
	for _, entry := range listed.Entries {
		for _, path := range entry.Restorable {
			if path != "config" {
				continue
			}
			response := f.do(http.MethodPost, "/api/v1/history/restore",
				mustJSON(t, map[string]any{"transactionId": entry.ID, "path": path}))
			code := response.StatusCode
			restoreBody := readBody(t, response)
			if code != http.StatusOK {
				t.Fatalf("restore = %d (%s)", code, restoreBody)
			}
			restored = true
		}
	}
	if !restored {
		t.Fatal("nothing was offered as restorable")
	}
	if got := string(f.read("config")); got != base {
		t.Errorf("after restoring, config = %q, want the bytes from before the save", got)
	}
}
