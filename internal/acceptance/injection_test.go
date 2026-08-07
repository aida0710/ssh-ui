package acceptance_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshc/internal/config"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/platform/macos"
	"sshc/internal/remotekey"
	"sshc/internal/session"
	"sshc/internal/storage"
)

// hostileArguments は、OpenSSH 自身が Host 行の中で受け入れるであろう値、あるいは
// ユーザーが打ち込みうる値であり、そのまま渡されればコマンドライン、AppleScript の
// 文字列、リモートシェルの文字列の意味を変えてしまう値である。"\x00" と "\n" を
// 意図してエスケープで書いてあるのは、ソースファイル中の生の制御文字がレビューでは
// 見えないからである。
var hostileArguments = []string{
	"-oProxyCommand=/bin/sh",
	"-oPermitLocalCommand=yes",
	"--config=/etc/passwd",
	"-l",
	"-",
	"--",
	"bastion -oProxyCommand=id",
	"bastion;touch /tmp/sshc-pwned",
	"bastion|id",
	"bastion&&id",
	"bastion$(id)",
	"bastion`id`",
	"bastion\"; do script \"id",
	"bastion' & do shell script \"id\" & '",
	"bastion\nHost evil",
	"bastion\x00evil",
	"bastion\tevil",
	"bastion evil",
	"%h.example.com",
	"~/evil",
	"../../etc/ssh/ssh_config",
	".",
	"..",
	"",
	strings.Repeat("a", 65),
}

// aliasRoute は、alias を外部効果に変える route の 1 つである。
type aliasRoute struct {
	path string
	kind string
	body func(alias string) map[string]any
}

func aliasRoutes() []aliasRoute {
	plain := func(alias string) map[string]any { return map[string]any{"alias": alias} }
	return []aliasRoute{
		{"/api/v1/diagnostics/effective", session.ActionEvaluate, plain},
		{"/api/v1/diagnostics/reachability", session.ActionReachability, plain},
		{"/api/v1/diagnostics/authentication", session.ActionAuthentication, func(alias string) map[string]any {
			return map[string]any{"alias": alias, "acknowledgeExecutable": true}
		}},
		{"/api/v1/terminal/launch", session.ActionTerminalLaunch, plain},
		{"/api/v1/remote-keys/register", session.ActionRemoteKeyRegister, func(alias string) map[string]any {
			return map[string]any{
				"alias": alias, "keyPath": "id_ed25519.pub",
				"publicKey": "", "acknowledgeExecutable": true,
			}
		}},
	}
}

func TestNoRouteEverPutsAHostileValueOnACommandLine(t *testing.T) {
	f := newFixture(t)
	publicKey := string(bytes.TrimSpace(f.read("id_ed25519.pub")))

	// 正のコントロール: 安全な alias は process seam に届かねばならず、
	// "--" separator の後に 1 つの完全な argument として到達しなければならない。
	f.runner.reset()
	f.runner.answer(func(platform.Command) (platform.Output, error) {
		return platform.Output{Stdout: []byte("hostname 203.0.113.10\nport 2222\n")}, nil
	})
	token := f.actionToken(t, session.ActionEvaluate, "bastion")
	readBody(t, f.do(http.MethodPost, "/api/v1/diagnostics/effective", mustJSON(t, map[string]any{
		"alias": "bastion",
	}), withAction(token)))
	control := f.runner.recorded()
	if len(control) == 0 {
		t.Fatal("a safe alias never reached the process seam; every refusal below would prove nothing")
	}
	assertAliasArrivesInert(t, control[0].Arguments, "bastion")

	// 敵対的な側。あらゆる敵対的な値は platform.ValidateAlias に
	// 落ちるため、ここで主張する性質は決定的なもの: 外部効果が一切起きないことである。
	//
	// 代わりに敵対的な値が「argv のどこかに無害な形で届く」ことを
	// 主張するのは、ここでは使い物にならない: "-" や "." のような値は
	// 固定オプションや設定パスの部分文字列でもあるため、部分文字列規則では
	// このアプリケーションがハードコードする argument にまで反応してしまう。
	for _, route := range aliasRoutes() {
		for _, hostile := range hostileArguments {
			t.Run(route.path+" "+quoteForName(hostile), func(t *testing.T) {
				f.runner.reset()
				f.terminal.reset()
				// 敵対的な target に対しても、それが可能な場合は token を
				// 発行する。そうすることで、リクエストは token rule だけでなく
				// alias rule によって拒否される。
				issued := f.tryActionToken(route.kind, hostile)
				body := route.body(hostile)
				if key, ok := body["publicKey"]; ok && key == "" {
					body["publicKey"] = publicKey
				}
				readBody(t, f.do(http.MethodPost, route.path, mustJSON(t, body), withAction(issued)))

				if commands := f.runner.recorded(); len(commands) != 0 {
					t.Fatalf("a hostile alias reached the process seam: %#v", commands)
				}
				for _, launched := range f.terminal.launched() {
					t.Fatalf("Terminal was launched for the hostile alias %q", launched)
				}
			})
		}
	}
}

// assertAliasArrivesInert は、alias が argv の中に、"--" separator
// 直後の要素全体としてちょうど 1 回現れない限り失敗する。
func assertAliasArrivesInert(t testing.TB, arguments []string, alias string) {
	t.Helper()
	separator := -1
	for index, argument := range arguments {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		t.Fatalf("argv has no %q separator: %#v", "--", arguments)
	}
	if separator+1 >= len(arguments) {
		t.Fatalf("argv ends at the %q separator: %#v", "--", arguments)
	}
	if got := arguments[separator+1]; got != alias {
		t.Fatalf("argv[%d] = %q, want the alias %q whole", separator+1, got, alias)
	}
	for index, argument := range arguments[:separator] {
		if strings.Contains(argument, alias) {
			t.Fatalf("argv[%d] = %q carries the alias before the %q separator", index, argument, "--")
		}
	}
	for index, argument := range arguments {
		for _, forbidden := range []string{"\x00", "\n", "\r"} {
			if strings.Contains(argument, forbidden) {
				t.Fatalf("argv[%d] = %q contains a control character", index, argument)
			}
		}
	}
}

// TestTheProcessSeamRefusesAHostileAliasWithoutTheHTTPGuard は、
// 前段に handler を置かずに継ぎ目を直接駆動する。
//
// 上の HTTP テストでは、2 つの alias check のどちらがリクエストを
// 拒否したのか区別できない: handler も検証するし、コマンドを
// 組み立てるコードも検証する。片方だけ消してももう片方が残るため、
// そのテストは本物の防御を取り除いた mutation を生き延びてしまう。
// このテストは command builder を直接呼ぶので、各層が自分自身に対して責任を持つ。
func TestTheProcessSeamRefusesAHostileAliasWithoutTheHTTPGuard(t *testing.T) {
	runner := &recordingRunner{}
	evaluator := effective.Evaluator{
		Runner:     runner,
		Toolchain:  fixedToolchain{},
		ConfigPath: "/nonexistent/config",
	}
	service := remotekey.Service{
		Runner:     runner,
		Toolchain:  fixedToolchain{},
		ConfigPath: "/nonexistent/config",
	}
	key, _, err := remotekey.ParsePublicKey(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture")
	if err != nil {
		t.Fatal(err)
	}

	// 正のコントロール: 安全な alias は両方の継ぎ目を通ってランナーに届く。
	runner.reset()
	if _, err := evaluator.Evaluate(context.Background(), effective.Report{}, "bastion", true); err != nil {
		t.Fatalf("Evaluate(bastion) = %v", err)
	}
	if len(runner.recorded()) != 1 {
		t.Fatalf("a safe alias produced %d commands, want 1", len(runner.recorded()))
	}
	assertAliasArrivesInert(t, runner.recorded()[0].Arguments, "bastion")

	for _, hostile := range hostileArguments {
		t.Run(quoteForName(hostile), func(t *testing.T) {
			if err := platform.ValidateAlias(hostile); err == nil {
				t.Fatalf("ValidateAlias(%q) = nil", hostile)
			}

			runner.reset()
			if _, err := evaluator.Evaluate(context.Background(), effective.Report{}, hostile, true); err == nil {
				t.Fatalf("Evaluate(%q) was accepted", hostile)
			}
			if commands := runner.recorded(); len(commands) != 0 {
				t.Fatalf("Evaluate(%q) still ran %#v", hostile, commands)
			}

			runner.reset()
			if _, err := service.Register(context.Background(), effective.Report{}, hostile, key, true); err == nil {
				t.Fatalf("Register(%q) was accepted", hostile)
			}
			if commands := runner.recorded(); len(commands) != 0 {
				t.Fatalf("Register(%q) still ran %#v", hostile, commands)
			}
		})
	}
}

func TestTerminalLaunchNeverBuildsAppleScriptFromInput(t *testing.T) {
	// スクリプト自体には置換点が一切あってはならない。
	//
	// plan のリストは AppleScript の連結演算子も禁じていたが、
	// コミットされたスクリプトはそれを使って *定数* の prefix を
	// `quoted form of targetAlias` に連結しており、これは危険な方ではなく
	// 安全な構成である。存在してはならないのは、呼び出し元のテキストが
	// スクリプトへと書式化される点であり、これら 4 通りの綴りはまさにそれに当たる。
	for _, forbidden := range []string{"%s", "%v", "%q", "${"} {
		if strings.Contains(macos.TerminalScript, forbidden) {
			t.Fatalf("TerminalScript contains a substitution point %q", forbidden)
		}
	}
	if !strings.Contains(macos.TerminalScript, "quoted form of") {
		t.Fatal("TerminalScript does not quote its argument for the shell that runs it")
	}
	if !strings.Contains(macos.TerminalScript, "item 1 of argv") {
		t.Fatal("TerminalScript does not take the alias from argv")
	}

	runner := &recordingRunner{}
	terminal := macos.Terminal{Runner: runner, Program: "/usr/bin/osascript", Timeout: 5 * time.Second}

	// Positive control。
	if err := terminal.Launch(context.Background(), "bastion"); err != nil {
		t.Fatalf("Launch(bastion) = %v", err)
	}
	recorded := runner.recorded()
	if len(recorded) != 1 {
		t.Fatalf("a safe alias produced %d commands, want 1", len(recorded))
	}
	command := recorded[0]
	if command.Path != "/usr/bin/osascript" {
		t.Fatalf("path = %q", command.Path)
	}
	if len(command.Arguments) != 2 || command.Arguments[0] != "-" || command.Arguments[1] != "bastion" {
		t.Fatalf("arguments = %#v, want [- bastion]", command.Arguments)
	}
	if string(command.Stdin) != macos.TerminalScript {
		t.Fatal("the script sent on stdin is not the package constant")
	}
	if strings.Contains(string(command.Stdin), "bastion") {
		t.Fatal("the alias was concatenated into the script")
	}

	// Hostile half。
	for _, hostile := range hostileArguments {
		t.Run(quoteForName(hostile), func(t *testing.T) {
			runner.reset()
			err := terminal.Launch(context.Background(), hostile)
			if err == nil {
				t.Fatalf("Launch(%q) was accepted", hostile)
			}
			if commands := runner.recorded(); len(commands) != 0 {
				t.Fatalf("a refused launch still ran %#v", commands)
			}
		})
	}
}

func TestRemoteRegistrationNeverInterpolatesInputIntoTheRemoteShell(t *testing.T) {
	f := newFixture(t)

	publicKey := string(bytes.TrimSpace(f.read("id_ed25519.pub")))

	// 正のコントロール: 本物の登録は継ぎ目に 2 回届く — POSIX の
	// probe と固定の routine — そして key は stdin を伝わり、argv には決して乗らない。
	f.runner.reset()
	f.runner.answer(func(command platform.Command) (platform.Output, error) {
		if strings.Contains(strings.Join(command.Arguments, " "), remotekey.ProbeCommand) {
			return platform.Output{Stdout: []byte(remotekey.ProbeMarker + "\n")}, nil
		}
		return platform.Output{Stdout: []byte("sshc: added\n")}, nil
	})
	token := f.actionToken(t, session.ActionRemoteKeyRegister, "bastion")
	registered := f.do(http.MethodPost, "/api/v1/remote-keys/register", mustJSON(t, map[string]any{
		"alias": "bastion", "keyPath": "id_ed25519.pub",
		"publicKey": publicKey, "acknowledgeExecutable": true,
	}), withAction(token))
	registeredBody := readBody(t, registered)

	recorded := f.runner.recorded()
	if len(recorded) < 2 {
		t.Fatalf("registration ran %d commands (%d %s), want the probe and the routine",
			len(recorded), registered.StatusCode, registeredBody)
	}
	routine := recorded[len(recorded)-1]
	if routine.Arguments[len(routine.Arguments)-1] != remotekey.Routine {
		t.Fatal("the last argument is not the fixed remote routine constant")
	}
	if !strings.Contains(string(routine.Stdin), publicKey) {
		t.Fatal("the public key did not travel on standard input")
	}
	for _, argument := range routine.Arguments {
		if strings.Contains(argument, publicKey) {
			t.Fatal("the public key was placed in the argument vector")
		}
	}

	// この routine は定数である: どんな入力も 1 バイトたりとも変えられない。
	before := remotekey.Routine
	for _, hostile := range hostileArguments {
		t.Run(quoteForName(hostile), func(t *testing.T) {
			f.runner.reset()
			issued := f.tryActionToken(session.ActionRemoteKeyRegister, hostile)
			readBody(t, f.do(http.MethodPost, "/api/v1/remote-keys/register", mustJSON(t, map[string]any{
				"alias": hostile, "keyPath": "id_ed25519.pub",
				"publicKey": publicKey, "acknowledgeExecutable": true,
			}), withAction(issued)))
			if commands := f.runner.recorded(); len(commands) != 0 {
				t.Fatalf("a hostile alias reached the remote seam: %#v", commands)
			}
			if remotekey.Routine != before {
				t.Fatal("the remote routine constant changed")
			}
		})
	}

	// 2 つ以上の authorized_keys entry になりうる public key line、
	// あるいはそもそも key ではない行は、何かがリモートホストに
	// 届くより前に parser によって拒否される。
	for _, line := range []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl a\nssh-ed25519 AAAA b",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl a\x00b",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl a\rb",
		"ssh-ed25519 not-base64!! comment",
		"echo pwned",
		"",
	} {
		if _, _, err := remotekey.ParsePublicKey(line); err == nil {
			t.Errorf("ParsePublicKey accepted %q", line)
		}
	}

	// shell のメタ文字を含む comment は受け入れられる。これは見落と
	// しではなく正しい: OpenSSH はどんな comment も許すし、固定の
	// routine は key を常に double quote の中でしか展開しないため、
	// comment 中の ";" は無害である。plan はここで拒否を期待していたが、
	// 拒否すれば何も塞がないまま実在ユーザーの key を弾いてしまう。生き
	// 残ってはならないのは line separator であり、それはすぐ上のケースである。
	metacharacters := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl a; rm -rf ~"
	if _, _, err := remotekey.ParsePublicKey(metacharacters); err != nil {
		t.Errorf("ParsePublicKey rejected a legitimate comment: %v", err)
	}
	if !strings.Contains(remotekey.Routine, `printf '%s\n' "$key"`) {
		t.Error("the remote routine no longer expands the key inside double quotes, " +
			"which is what makes a comment with shell metacharacters inert")
	}

	if _, _, err := remotekey.ParsePublicKey(publicKey); err != nil {
		t.Fatalf("ParsePublicKey rejected the fixture public key: %v", err)
	}
}

func TestNoRouteWritesOutsideTheWorkspaceOrThroughASymbolicLink(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(f.home, "private-notes", "canary.txt")
	original, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}

	// 正のコントロール: ワークスペース内の普通のパスは受け入れられる。
	base := string(f.read("config"))
	accepted := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "config", "base": base, "raw": base + "\n# appended by the positive control\n",
	}))
	acceptedStatus := accepted.StatusCode
	acceptedBody := readBody(t, accepted)
	if acceptedStatus != http.StatusOK {
		t.Fatalf("an ordinary save = %d (%s); the refusals below would prove nothing", acceptedStatus, acceptedBody)
	}
	base = string(f.read("config"))

	hostilePaths := []string{
		"../private-notes/canary.txt",
		"../../etc/ssh/ssh_config",
		"conf.d/../../private-notes/canary.txt",
		"/etc/ssh/ssh_config",
		"/private-notes/canary.txt",
		"conf.d/./../..//private-notes/canary.txt",
		"~/private-notes/canary.txt",
		"config\x00.conf",
		"config\n../escape.conf",
		".",
		"",
		strings.Repeat("a/", 300) + "deep.conf",
	}
	for _, hostile := range hostilePaths {
		t.Run(quoteForName(hostile), func(t *testing.T) {
			response := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
				"kind": "file_raw", "path": hostile, "base": "", "raw": "Host injected\n",
			}))
			status := response.StatusCode
			readBody(t, response)
			if status < 400 || status >= 500 {
				t.Fatalf("status = %d, want a 4xx refusal", status)
			}
			current, err := os.ReadFile(outside)
			if err != nil {
				t.Fatalf("the canary file disappeared: %v", err)
			}
			if !bytes.Equal(original, current) {
				t.Fatal("a hostile path changed a file outside the workspace")
			}
		})
	}

	// ワークスペース内の symbolic link を通して書き込まれてはならない。
	linked := filepath.Join(f.root, "linked.conf")
	if err := os.Symlink(outside, linked); err != nil {
		t.Fatal(err)
	}
	response := f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "linked.conf", "base": "", "raw": "Host through-a-link\n",
	}))
	status := response.StatusCode
	readBody(t, response)
	if status < 400 || status >= 500 {
		t.Fatalf("writing through a symbolic link = %d, want a 4xx refusal", status)
	}
	current, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, current) {
		t.Fatal("a write followed a symbolic link out of the workspace")
	}

	// read と save の間でディレクトリ構成要素が symbolic link に
	// すり替えられた場合も拒否せねばならない。これは README が best
	// effort と述べる time-of-check/time-of-use のケースである。best effort
	// であっても、見えているすり替えを拒否することに変わりはない。
	swapped := filepath.Join(f.root, "swapped")
	if err := os.MkdirAll(swapped, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(swapped, "x.conf"), []byte("Host swapped\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readBody(t, f.do(http.MethodGet, "/api/v1/config/file?path=swapped/x.conf", nil))
	if err := os.RemoveAll(swapped); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.home, "private-notes"), swapped); err != nil {
		t.Fatal(err)
	}
	response = f.do(http.MethodPost, "/api/v1/config/save", mustJSON(t, map[string]any{
		"kind": "file_raw", "path": "swapped/canary.txt", "base": "", "raw": "Host swapped-in\n",
	}))
	status = response.StatusCode
	readBody(t, response)
	if status < 400 || status >= 500 {
		t.Fatalf("writing through a swapped directory component = %d, want a 4xx refusal", status)
	}
	current, err = os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, current) {
		t.Fatal("a swapped directory component let a write escape the workspace")
	}
	if after := string(f.read("config")); after != base {
		t.Fatal("a refused save still changed the entry configuration file")
	}
}

// TestTheWorkspaceGuardRefusesTraversalAndSymlinksWithoutTheHTTPLayer は、
// workspace guard 単体に責任を持たせる。
//
// symbolic link を通した書き込みは二重に阻まれる: ResolveForWrite が
// パスをたどって link の構成要素を拒否し、OSFileSystem.ReadFile は
// O_NOFOLLOW で開くため save 自身の precondition read が先に失敗する。
// 多層防御は歓迎すべきものだが、それは上の end-to-end テストがどちらか片方の guard
// だけを消しても通ってしまうことを意味する。このテストは guard を直接呼ぶ。
func TestTheWorkspaceGuardRefusesTraversalAndSymlinksWithoutTheHTTPLayer(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh", "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "private-notes"), 0o700); err != nil {
		t.Fatal(err)
	}

	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		t.Fatal(err)
	}
	// ワークスペースは自分自身の root を解決し、macOS では t.TempDir() が
	// /var の symlink を返すため、以下の候補はすべて、このテストに
	// たまたま渡されたパスではなく、解決済みの root から組み立てる。
	root := workspace.Root()
	outside := filepath.Join(filepath.Dir(root), "private-notes", "canary.txt")
	if err := os.WriteFile(outside, []byte(canaryOutsideContents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "linked-dir")); err != nil {
		t.Fatal(err)
	}

	// 正のコントロール: ワークスペース内の普通のパスは解決できる。
	if _, err := workspace.ResolveForWrite(filepath.Join(root, "conf.d", "20-new.conf")); err != nil {
		t.Fatalf("ResolveForWrite on an ordinary path = %v", err)
	}

	refused := []struct {
		name      string
		candidate string
		want      error
	}{
		{"a link as the final component", filepath.Join(root, "linked.conf"), storage.ErrSymlinkPath},
		{"a link as a directory component", filepath.Join(root, "linked-dir", "x.conf"), storage.ErrSymlinkPath},
		{"traversal out of the workspace", filepath.Join(root, "..", "private-notes", "canary.txt"), storage.ErrOutsideWorkspace},
		{"an absolute path elsewhere", "/etc/ssh/ssh_config", storage.ErrOutsideWorkspace},
		{"a missing parent directory", filepath.Join(root, "absent", "x.conf"), storage.ErrMissingDirectory},
	}
	for _, test := range refused {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := workspace.ResolveForWrite(test.candidate)
			if !errors.Is(err, test.want) {
				t.Fatalf("ResolveForWrite(%q) = %q, %v; want %v", test.candidate, resolved, err, test.want)
			}
			if resolved != "" {
				t.Fatalf("ResolveForWrite(%q) returned %q alongside its error", test.candidate, resolved)
			}
		})
	}

	current, err := os.ReadFile(outside)
	if err != nil || string(current) != canaryOutsideContents {
		t.Fatalf("the guard's own refusals disturbed the file outside the workspace: %v", err)
	}
}

func TestAnAliasOpenSSHWouldAcceptIsStillRefusedForEveryExternalEffect(t *testing.T) {
	f := newFixture(t)

	// 設定ファイルには、このアプリケーションが決して起動しない
	// Host line が正当に含まれうる。読み込みは無損失でなければならず、それを実行することは
	// 拒否せねばならない。この 2 つの規則は同時に成り立つ必要がある。
	source := []byte("Host -oProxyCommand=id\n\tHostName 203.0.113.10\n" +
		"Host \"bastion evil\"\n\tUser ops\n" +
		"Host with\x00nul\n\tUser ops\n")
	parsed := config.Parse(source)
	if rendered := parsed.Render(); !bytes.Equal(rendered, source) {
		t.Fatalf("a hostile Host line did not round trip: %q", rendered)
	}

	for _, alias := range []string{
		"-oProxyCommand=id",
		"bastion evil",
		"with\x00nul",
		"with\nnewline",
		"-leading-hyphen",
	} {
		t.Run(quoteForName(alias), func(t *testing.T) {
			if err := platform.ValidateAlias(alias); err == nil {
				t.Fatalf("ValidateAlias(%q) = nil", alias)
			}
			f.runner.reset()
			f.terminal.reset()
			for _, path := range []string{
				"/api/v1/diagnostics/effective",
				"/api/v1/diagnostics/reachability",
				"/api/v1/diagnostics/authentication",
				"/api/v1/terminal/launch",
			} {
				response := f.do(http.MethodPost, path, mustJSON(t, map[string]any{
					"alias": alias, "acknowledgeExecutable": true,
				}), withAction(f.tryActionToken(session.ActionTerminalLaunch, alias)))
				status := response.StatusCode
				readBody(t, response)
				if status >= 200 && status < 300 {
					t.Errorf("%s accepted the alias with %d", path, status)
				}
			}
			if commands := f.runner.recorded(); len(commands) != 0 {
				t.Fatalf("a refused alias still started %#v", commands)
			}
			if launched := f.terminal.launched(); len(launched) != 0 {
				t.Fatalf("a refused alias still launched Terminal: %#v", launched)
			}
		})
	}

	// POST /api/v1/terminal/command は、unsafe な alias に対しても
	// 意図的に応答を許されている: design §6.5 は、UI が起動の代わりにコピー可能なコマンドを
	// 提示すると定めている。そう述べねばならず、alias が起動可能だと主張してはならない。
	response := f.do(http.MethodPost, "/api/v1/terminal/command", mustJSON(t, map[string]any{
		"alias": "bastion evil",
	}))
	body := readBody(t, response)
	if strings.Contains(body, `"launchable":true`) {
		t.Fatal("an unsafe alias was reported as launchable")
	}
	if commands := f.runner.recorded(); len(commands) != 0 {
		t.Fatalf("describing a command started %#v", commands)
	}
}

// quoteForName は、敵対的な値を subtest 名として使えるようにする。
func quoteForName(value string) string {
	replaced := strings.NewReplacer("\x00", "<nul>", "\n", "<lf>", "\r", "<cr>", "\t", "<tab>", " ", "_", "/", "_")
	if value == "" {
		return "<empty>"
	}
	return replaced.Replace(value)
}
