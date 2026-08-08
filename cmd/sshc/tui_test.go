package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTUIFiltersAcrossAliasUserAndHostname(t *testing.T) {
	hosts := []tuiHost{
		{Alias: "bastion-prod", Hostname: "203.0.113.10", User: "ops", Tags: []string{"eu", "jump"}},
		{Alias: "database", Hostname: "db.internal", User: "postgres", Port: "5432"},
	}
	for query, want := range map[string]string{
		"bast":     "bastion-prod",
		"postgres": "database",
		"internal": "database",
		"ops 203":  "bastion-prod",
		"jump":     "bastion-prod",
		"5432":     "database",
	} {
		got := filterTUIHosts(hosts, query)
		if len(got) != 1 || got[0].Alias != want {
			t.Errorf("filter(%q) = %#v, want %q", query, got, want)
		}
	}
}

func TestTUIRenderKeepsSelectionVisible(t *testing.T) {
	hosts := make([]tuiHost, 10)
	for index := range hosts {
		hosts[index].Alias = fmt.Sprintf("host-%02d", index)
	}
	model := &tuiModel{hosts: hosts, selected: 9}
	var output bytes.Buffer
	renderTUI(&output, model, 80, 10)
	if !strings.Contains(output.String(), "\x1b[7m  host-09") {
		t.Fatalf("selected host was not visible:\n%s", output.String())
	}
	// 画面に収まらなかった分を黙って落とすと、見えている分がすべてに見える。
	if !strings.Contains(output.String(), "7 more") {
		t.Errorf("the hosts that did not fit were not counted:\n%s", output.String())
	}
}

// 折り返した行は選択の反転表示を次の行へこぼす。行は端末の幅で終わらなければ
// ならない。
func TestTUIRenderFitsTheTerminalWidth(t *testing.T) {
	model := &tuiModel{hosts: []tuiHost{{
		Alias:    "very-long-alias-name-that-exceeds-the-column-width",
		Hostname: "host.example.internal",
		User:     "administrator",
	}}}
	var output bytes.Buffer
	renderTUI(&output, model, 40, 24)
	for _, line := range strings.Split(output.String(), "\r\n") {
		plain := strings.NewReplacer("\x1b[H\x1b[2J", "", "\x1b[1m", "", "\x1b[7m", "",
			"\x1b[36m", "", "\x1b[2m", "", "\x1b[0m", "").Replace(line)
		if len([]rune(plain)) > 40 {
			t.Errorf("line is %d columns wide: %q", len([]rune(plain)), plain)
		}
	}
}

func TestTUIModelSearchesMovesAndChooses(t *testing.T) {
	model := &tuiModel{hosts: []tuiHost{{Alias: "alpha"}, {Alias: "bastion"}, {Alias: "beta"}}}
	model.feed([]byte("b"))
	if got := model.visible(); len(got) != 2 {
		t.Fatalf("visible = %#v", got)
	}
	model.feed([]byte("\x1b[B"))
	alias, done := model.feed([]byte("\r"))
	if !done || alias != "beta" {
		t.Fatalf("enter = %q, %v", alias, done)
	}
}

// 扱わないキーは、そのシーケンスの終端まで読み捨てなければならない。そうしないと
// Delete が "~" を、Ctrl-矢印が ";5A" を検索語へ書き込む。
func TestTUIDiscardsWholeEscapeSequences(t *testing.T) {
	for _, sequence := range []string{"\x1b[3~", "\x1b[1;5A", "\x1b[200~", "\x1bOP", "\x1bx"} {
		model := &tuiModel{hosts: []tuiHost{{Alias: "alpha"}}}
		if alias, done := model.feed([]byte(sequence)); done {
			t.Errorf("feed(%q) ended the picker with %q", sequence, alias)
		}
		if model.query != "" {
			t.Errorf("feed(%q) left %q in the search field", sequence, model.query)
		}
	}
	// 同じ読み取りに続く文字は、シーケンスの後ろから入力として届く。
	model := &tuiModel{hosts: []tuiHost{{Alias: "alpha"}}}
	model.feed([]byte("\x1b[3~al"))
	if model.query != "al" {
		t.Errorf("query = %q, want \"al\"", model.query)
	}
}

// Esc は、それ自体がキーであり、同時にすべての矢印キーの先頭でもある。読み取りの
// 最後のバイトであるときだけ、キーとして押されたと分かる。
func TestTUIEscapeAloneCancelsButArrowKeysDoNot(t *testing.T) {
	model := &tuiModel{hosts: []tuiHost{{Alias: "alpha"}, {Alias: "beta"}}}
	if alias, done := model.feed([]byte("\x1b")); !done || alias != "" {
		t.Errorf("Esc = %q, %v, want a cancelled picker", alias, done)
	}
	if _, done := model.feed([]byte("\x1b[A")); done {
		t.Error("an arrow key cancelled the picker")
	}
}

// 検索語の 1 文字は 1 バイトとは限らない。バイト単位で消すと、同じ端末が
// そのまま表示する文字を壊す。
func TestTUIBackspaceRemovesAWholeCharacter(t *testing.T) {
	model := &tuiModel{hosts: []tuiHost{{Alias: "alpha"}}}
	model.feed([]byte("東京"))
	model.feed([]byte{127})
	if model.query != "東" {
		t.Errorf("query = %q, want \"東\"", model.query)
	}
}

func TestTUILoadsConcreteHostsAndPutsFavouritesFirst(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(ssh, "sshc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte(
		"Host alpha\n  HostName alpha.example\nHost bastion\n  HostName 203.0.113.10\n  User ops\n  Port 2222\nHost *\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	metadata := `{"schemaVersion":2,"terminal":"terminal","hosts":[` +
		`{"identity":{"path":"config","alias":"bastion"},"favourite":true,"tags":["eu"]}]}`
	if err := os.WriteFile(filepath.Join(ssh, "sshc", "metadata.json"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := loadTUIHosts(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0].Alias != "bastion" || !hosts[0].Favourite {
		t.Fatalf("hosts = %#v", hosts)
	}
	if hosts[0].Hostname != "203.0.113.10" || hosts[0].User != "ops" || hosts[0].Port != "2222" {
		t.Errorf("bastion = %#v", hosts[0])
	}
	if len(hosts[0].Tags) != 1 || hosts[0].Tags[0] != "eu" {
		t.Errorf("tags = %#v", hosts[0].Tags)
	}
}

// 読めない設定は空の設定ではない。一覧と選択画面が、そこで違うことを言っては
// ならない。
func TestTUIReportsAConfigItCannotRead(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte("Host alpha\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTUIHosts(home); err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("loadTUIHosts = %v, want the unreadable config to be reported", err)
	}
}
