package application

import "testing"

const effectiveFiles = `Include conf.d/*.conf
Host bastion
	User ops
	IdentityFile ~/.ssh/id_a
	IdentityFile ~/.ssh/id_b
Match host bastion
	User match-user
Host *
	User fallback
	ServerAliveInterval 30
`

func TestComputeEffectiveTakesTheFirstValueAndKeepsItsSource(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":               effectiveFiles,
		"conf.d/10-first.conf": "Host bastion\n\tPort 2200\n",
	})

	effective := ComputeEffective(graph, testRoot, "bastion")
	if !effective.Approximate {
		t.Fatal("explained values must be marked approximate until ssh -G arrives")
	}
	want := []struct {
		keyword string
		value   string
		path    string
		line    int
	}{
		{"IdentityFile", "~/.ssh/id_a", "config", 4},
		{"IdentityFile", "~/.ssh/id_b", "config", 5},
		{"Port", "2200", "conf.d/10-first.conf", 2},
		{"ServerAliveInterval", "30", "config", 10},
		{"User", "ops", "config", 3},
	}
	if len(effective.Entries) != len(want) {
		t.Fatalf("entries = %#v", effective.Entries)
	}
	for index, expected := range want {
		entry := effective.Entries[index]
		if entry.Keyword != expected.keyword || entry.Values[0] != expected.value {
			t.Fatalf("entry[%d] = %#v, want %q %q", index, entry, expected.keyword, expected.value)
		}
		if entry.Source.Path != expected.path || entry.Source.Line != expected.line {
			t.Fatalf("entry[%d] source = %#v, want %q line %d", index, entry.Source, expected.path, expected.line)
		}
	}

	codes := map[string]bool{}
	for _, notice := range effective.Notices {
		codes[notice.Code] = true
	}
	if !codes[NoticeMatchBlock] || !codes[NoticeComplexExternalRule] || !codes[NoticeExplainedValuesOnly] {
		t.Fatalf("notices = %#v", effective.Notices)
	}
}

func TestComputeEffectiveIgnoresBlocksThatDoNotMatch(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "Host other\n\tUser other-user\nHost !bastion *\n\tUser negated\n",
	})
	effective := ComputeEffective(graph, testRoot, "bastion")
	if len(effective.Entries) != 0 {
		t.Fatalf("entries = %#v", effective.Entries)
	}
}

func TestDiffEffectiveReportsAddedChangedAndRemovedValues(t *testing.T) {
	before := Effective{Alias: "build01", Entries: []EffectiveEntry{
		{Keyword: "User", Values: []string{"ops"}, Source: Source{Path: "config", Line: 3}},
		{Keyword: "Port", Values: []string{"22"}, Source: Source{Path: "config", Line: 4}},
	}}
	after := Effective{Alias: "build01", Entries: []EffectiveEntry{
		{Keyword: "User", Values: []string{"ops"}, Source: Source{Path: "config", Line: 3}},
		{Keyword: "Port", Values: []string{"2222"}, Source: Source{Path: "groups.ssh-ui.conf", Line: 5}},
		{Keyword: "ServerAliveInterval", Values: []string{"30"}, Source: Source{Path: "groups.ssh-ui.conf", Line: 6}},
	}}

	diff := DiffEffective(before, after)
	if diff.Alias != "build01" || len(diff.Changes) != 2 {
		t.Fatalf("diff = %#v", diff)
	}
	if diff.Changes[0].Keyword != "Port" || diff.Changes[0].Before[0] != "22" || diff.Changes[0].After[0] != "2222" {
		t.Fatalf("port change = %#v", diff.Changes[0])
	}
	if diff.Changes[0].AfterSources[0].Path != "groups.ssh-ui.conf" {
		t.Fatalf("port source = %#v", diff.Changes[0].AfterSources)
	}
	if diff.Changes[1].Keyword != "ServerAliveInterval" || len(diff.Changes[1].Before) != 0 {
		t.Fatalf("added change = %#v", diff.Changes[1])
	}
}

// TestDiffEffectiveIgnoresALineShiftButNotARealMove pins what counts as a
// change of source. Inserting a line into a file pushes every value below it
// down, and an unchanged value that merely moved is not something the user
// edited; a value that moved to another file or another block is.
func TestDiffEffectiveIgnoresALineShiftButNotARealMove(t *testing.T) {
	before := Effective{Alias: "nas", Entries: []EffectiveEntry{
		{Keyword: "ServerAliveInterval", Values: []string{"30"}, Source: Source{Path: "config", Absolute: "/root/config", Line: 10, Condition: "Host *"}},
	}}

	shifted := Effective{Alias: "nas", Entries: []EffectiveEntry{
		{Keyword: "ServerAliveInterval", Values: []string{"30"}, Source: Source{Path: "config", Absolute: "/root/config", Line: 11, Condition: "Host *"}},
	}}
	if diff := DiffEffective(before, shifted); len(diff.Changes) != 0 {
		t.Fatalf("a pure line shift was reported as a change: %#v", diff.Changes)
	}

	movedFile := Effective{Alias: "nas", Entries: []EffectiveEntry{
		{Keyword: "ServerAliveInterval", Values: []string{"30"}, Source: Source{Path: "groups.ssh-ui.conf", Absolute: "/root/groups.ssh-ui.conf", Line: 7, Condition: "Host nas"}},
	}}
	if diff := DiffEffective(before, movedFile); len(diff.Changes) != 1 {
		t.Fatalf("a move to another file was not reported: %#v", diff.Changes)
	}

	movedBlock := Effective{Alias: "nas", Entries: []EffectiveEntry{
		{Keyword: "ServerAliveInterval", Values: []string{"30"}, Source: Source{Path: "config", Absolute: "/root/config", Line: 10, Condition: "Host nas"}},
	}}
	if diff := DiffEffective(before, movedBlock); len(diff.Changes) != 1 {
		t.Fatalf("a move to another block was not reported: %#v", diff.Changes)
	}
}

// The Effective tab of a host detail is where a user asks "what do I actually
// get?". Two files claiming the alias is the one situation where the answer is
// not what the block on screen says, so it is the situation the tab most needs
// to mention. The connections tree flags it; this said nothing.
func TestComputeEffectiveReportsAnAliasClaimedByTwoFiles(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":              "Include conf.d/*.conf\n\nHost nas\n\tUser aida\n",
		"conf.d/10-home.conf": "Host nas\n\tUser someone-else\n",
	})

	effective := ComputeEffective(graph, testRoot, "nas")
	found := false
	for _, notice := range effective.Notices {
		if notice.Code == NoticeDuplicateAlias {
			found = true
		}
	}
	if !found {
		t.Errorf("notices = %#v, want a duplicate_alias", effective.Notices)
	}
}

func TestComputeEffectiveDoesNotCallOneBlockADuplicate(t *testing.T) {
	graph := newTestGraph(t, map[string]string{"config": "Host nas\n\tUser aida\n"})

	for _, notice := range ComputeEffective(graph, testRoot, "nas").Notices {
		if notice.Code == NoticeDuplicateAlias {
			t.Errorf("a single block was reported as a duplicate: %#v", notice)
		}
	}
}
