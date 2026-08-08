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
		{Alias: "bastion-prod", Hostname: "203.0.113.10", User: "ops"},
		{Alias: "database", Hostname: "db.internal", User: "postgres"},
	}
	for query, want := range map[string]string{
		"bast":     "bastion-prod",
		"postgres": "database",
		"internal": "database",
		"ops 203":  "bastion-prod",
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
	renderTUI(&output, model, 10)
	if !strings.Contains(output.String(), "\x1b[7m  host-09") {
		t.Fatalf("selected host was not visible:\n%s", output.String())
	}
}

func TestTUIModelSearchesMovesAndChooses(t *testing.T) {
	model := &tuiModel{hosts: []tuiHost{{Alias: "alpha"}, {Alias: "bastion"}, {Alias: "beta"}}}
	for _, value := range []byte("b") {
		model.input(value)
	}
	if got := model.visible(); len(got) != 2 {
		t.Fatalf("visible = %#v", got)
	}
	model.input(27)
	model.input('[')
	model.input('B')
	alias, done := model.input(13)
	if !done || alias != "beta" {
		t.Fatalf("enter = %q, %v", alias, done)
	}
}

func TestTUILoadsConcreteHostsAndPutsFavouritesFirst(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(ssh, "sshc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte(
		"Host alpha\n  HostName alpha.example\nHost bastion\n  HostName 203.0.113.10\n  User ops\nHost *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := `{"schemaVersion":2,"terminal":"terminal","hosts":[{"identity":{"path":"config","alias":"bastion"},"favourite":true}]}`
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
	if hosts[0].Hostname != "203.0.113.10" || hosts[0].User != "ops" {
		t.Errorf("bastion = %#v", hosts[0])
	}
}
