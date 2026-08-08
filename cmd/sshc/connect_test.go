package main

import (
	"strings"
	"testing"
)

// コマンドの全体が alias である。それ以外はフラグか、askpass サブコマンドか、
// アプリケーション自身のいずれかだ。
func TestWhatCountsAsAConnectInvocation(t *testing.T) {
	for _, test := range []struct {
		argv  []string
		alias string
		ok    bool
	}{
		{[]string{"sshc", "tv-recoding"}, "tv-recoding", true},
		{[]string{"sshc", "mdx-aida-serv-1"}, "mdx-aida-serv-1", true},
		// 接続ではなく、アプリケーション。
		{[]string{"sshc"}, "", false},
		{[]string{"sshc", "-open=false"}, "", false},
		{[]string{"sshc", "--open=false"}, "", false},
		// ホストではなくコマンドである語。
		{[]string{"sshc", "open"}, "", false},
		{[]string{"sshc", "list"}, "", false},
		{[]string{"sshc", "connect"}, "", false},
		// OpenSSH が実行するヘルパー。プロンプトを引数に取る。
		{[]string{"sshc", "askpass"}, "", false},
		{[]string{"sshc", "askpass", "password:"}, "", false},
		// 二語は alias ではない。このコマンドには存在しないものだ。
		{[]string{"sshc", "connect", "bastion"}, "", false},
	} {
		alias, ok := connectInvocation(test.argv)
		if ok != test.ok || alias != test.alias {
			t.Errorf("connectInvocation(%v) = %q, %v; want %q, %v", test.argv, alias, ok, test.alias, test.ok)
		}
	}
}

// ここで設定する変数は、OpenSSH が読むものと一致していなければならない。
//
// syscall.Exec は配列をそのまま渡し、getenv はその中で最初に一致したものを返す。
// したがって継承した環境に追記する方式では、ユーザーが何年も前にシェルのプロファイル
// でエクスポートした SSH_ASKPASS に負ける — しかも負けながら、保存済みパスワードと
// 引き換えられるワンタイムトークンをそのプログラムに渡してしまう。この攻撃の敷居は、
// エクスポートされた変数ひとつである。
func TestConnectEnvironmentReplacesWhatItSetsRatherThanAppending(t *testing.T) {
	inherited := []string{
		"HOME=/Users/tester",
		"SSH_ASKPASS=/tmp/not-ours",
		"SSH_ASKPASS_REQUIRE=never",
		"SSHC_ASKPASS_TOKEN=stale",
		"PATH=/usr/bin",
	}
	built := connectEnvironment(inherited, "/Users/tester/.local/bin/sshc",
		"http://127.0.0.1:1/askpass", "the-one-time-token", "bastion")

	counted := map[string][]string{}
	for _, entry := range built {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		counted[name] = append(counted[name], value)
	}
	for name, want := range map[string]string{
		"SSH_ASKPASS":         "/Users/tester/.local/bin/sshc",
		"SSH_ASKPASS_REQUIRE": "force",
		URLVariable:           "http://127.0.0.1:1/askpass",
		TokenVariable:         "the-one-time-token",
		AliasVariable:         "bastion",
	} {
		if len(counted[name]) != 1 {
			t.Errorf("%s appears %d times: %v", name, len(counted[name]), counted[name])
			continue
		}
		if counted[name][0] != want {
			t.Errorf("%s = %q, want %q", name, counted[name][0], want)
		}
	}
	// それ以外にユーザーが持っていたものはすべてそのまま本人のものだ。これは自分で ssh を
	// 打ったときに得たであろう環境に、こちらが決めた五つを加えたものである。
	if len(counted["HOME"]) != 1 || counted["HOME"][0] != "/Users/tester" {
		t.Errorf("HOME = %v", counted["HOME"])
	}
	if len(counted["PATH"]) != 1 {
		t.Errorf("PATH = %v", counted["PATH"])
	}
}

// トークンがなければ何も武装されない。ユーザーの環境に残った古い変数もまた、それを
// 武装させてはならない。
func TestConnectEnvironmentDropsStaleArmingWhenNothingIsStored(t *testing.T) {
	built := connectEnvironment([]string{"SSH_ASKPASS=/tmp/not-ours", "SSHC_ASKPASS_TOKEN=stale"}, "", "", "", "")
	for _, entry := range built {
		for _, name := range []string{"SSH_ASKPASS=", TokenVariable + "=", URLVariable + "=", AliasVariable + "="} {
			if strings.HasPrefix(entry, name) {
				t.Errorf("an unarmed connection still carries %q", entry)
			}
		}
	}
}

// `sshc help` は使い方を出す。
//
// これがないと "help" は裸の語として alias になり、`ssh -- help` として exec される。
// 使い方を求めた人が受け取るのは
// "Could not resolve hostname help" である。-h は flag パッケージが拾うが、
// 打つ言葉として自然なのはこちらであり、`open` と `list` を予約したのと同じ理由で
// 予約する。
func TestHelpIsASubcommandAndNotAnAlias(t *testing.T) {
	if alias, ok := connectInvocation([]string{"sshc", HelpSubcommand}); ok {
		t.Fatalf("help was read as the alias %q", alias)
	}
	for _, word := range []string{"help", "-h", "--help"} {
		if !helpInvocation([]string{"sshc", word}) {
			t.Errorf("helpInvocation(%q) = false, want true", word)
		}
	}
	// 引数を伴えば使い方ではない。`sshc help me` はホスト "help" への接続でもない。
	if helpInvocation([]string{"sshc", "help", "me"}) {
		t.Error("help with an argument was read as a request for usage")
	}
	if helpInvocation([]string{"sshc", "bastion"}) {
		t.Error("an ordinary alias was read as a request for usage")
	}
}
