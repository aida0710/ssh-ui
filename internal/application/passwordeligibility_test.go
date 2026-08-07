package application

import (
	"os"
	"path/filepath"
	"testing"
)

// newEligibilityService は、これらの規則が扱う 4 個の状況を宣言するエントリファイル
// と、そのうち 1 個を知っている known_hosts を持つワークスペースを書き出す。
func newEligibilityService(t *testing.T) *Service {
	t.Helper()
	service, workspace := newTestService(t)
	entry := "Host known\n" +
		"\tHostName 203.0.113.10\n" +
		"\n" +
		"Host keyed\n" +
		"\tHostName 198.51.100.7\n" +
		"\tIdentityFile ~/.ssh/keys/id_ed25519\n" +
		"\n" +
		"Host nopassword\n" +
		"\tHostName 198.51.100.8\n" +
		"\tPasswordAuthentication no\n" +
		"\n" +
		"Host oddport\n" +
		"\tHostName 203.0.113.20\n" +
		"\tPort 2222\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}
	known := "203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture\n" +
		"[203.0.113.20]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture\n"
	if err := os.WriteFile(filepath.Join(workspace.Root(), "known_hosts"), []byte(known), 0o600); err != nil {
		t.Fatal(err)
	}
	return service
}

func codesOf(notices []Notice) map[string]bool {
	codes := map[string]bool{}
	for _, notice := range notices {
		codes[notice.Code] = true
	}
	return codes
}

func TestAHostThatRefusesPasswordAuthenticationCannotStoreOne(t *testing.T) {
	// PasswordAuthentication はクライアント側の設定なので、これが off だと
	// クライアントはどれほど良いパスワードでも決して提示しない。保存する
	// ことは、まったく使い道のない秘密をディスクに置くことになる。
	report, err := newEligibilityService(t).PasswordEligibility("nopassword")
	if err != nil {
		t.Fatal(err)
	}
	if report.Storable {
		t.Error("a host that will never be offered a password accepted one")
	}
	if !codesOf(report.Blockers)[BlockerPasswordAuthenticationOff] {
		t.Errorf("blockers = %#v", report.Blockers)
	}
}

func TestAConfiguredKeyIsAWarningAndNotARefusal(t *testing.T) {
	// 鍵が向こう側で認可されていないかもしれないというのは普通の状況
	// なので、これは言明されるだけで判断はユーザーに委ねられる。
	report, err := newEligibilityService(t).PasswordEligibility("keyed")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Storable {
		t.Error("a configured key refused a password outright")
	}
	if !codesOf(report.Warnings)[WarnIdentityFileConfigured] {
		t.Errorf("warnings = %#v", report.Warnings)
	}
}

func TestAnUnknownHostKeyIsReportedBecauseTheHelperWillNotAnswerThatQuestion(t *testing.T) {
	// askpass を強制すると、ホスト鍵の問いも helper へ回されるが、
	// helper はそれを拒否する。そのため未検証のホストへの最初の接続は
	// そのプロンプトでパスワードが使われないまま止まる。それをここで
	// 言明することが、壊れているように見える機能と自ら説明する機能との
	// 違いになる。
	report, err := newEligibilityService(t).PasswordEligibility("keyed")
	if err != nil {
		t.Fatal(err)
	}
	if !codesOf(report.Warnings)[WarnHostKeyUnknown] {
		t.Errorf("an unverified host was not reported: %#v", report.Warnings)
	}

	known, err := newEligibilityService(t).PasswordEligibility("known")
	if err != nil {
		t.Fatal(err)
	}
	if codesOf(known.Warnings)[WarnHostKeyUnknown] {
		t.Errorf("a host already in known_hosts was reported as unknown: %#v", known.Warnings)
	}
}

func TestANonDefaultPortIsLookedUpInTheFormKnownHostsUses(t *testing.T) {
	// known_hosts はデフォルト以外のポートを[host]:port として書く。素の
	// ホストだけを調べると、そのようなホストすべてを未検証として報告して
	// しまい、常に出ている warning は誰も読まない warning になる。
	report, err := newEligibilityService(t).PasswordEligibility("oddport")
	if err != nil {
		t.Fatal(err)
	}
	if report.Port != "2222" {
		t.Errorf("port = %q", report.Port)
	}
	if codesOf(report.Warnings)[WarnHostKeyUnknown] {
		t.Errorf("a host known at its own port was reported as unknown: %#v", report.Warnings)
	}
}

func TestAPatternIsNotAHostAndCannotHoldAPassword(t *testing.T) {
	report, err := newEligibilityService(t).PasswordEligibility("*")
	if err != nil {
		t.Fatal(err)
	}
	if report.Storable {
		t.Error("a pattern accepted a password")
	}
	if !codesOf(report.Blockers)[BlockerAliasNotSimple] {
		t.Errorf("blockers = %#v", report.Blockers)
	}
}

func TestAnOrdinaryVerifiedHostHasNothingToSay(t *testing.T) {
	// すべてのホストに出る warning は雑音であり、
	// 雑音こそが本当の warning が無視される原因である。
	report, err := newEligibilityService(t).PasswordEligibility("known")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Storable || len(report.Blockers) != 0 || len(report.Warnings) != 0 {
		t.Errorf("an ordinary host reported %#v / %#v", report.Blockers, report.Warnings)
	}
	if report.HostName != "203.0.113.10" {
		t.Errorf("hostName = %q", report.HostName)
	}
}
