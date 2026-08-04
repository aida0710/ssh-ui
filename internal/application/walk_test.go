package application

import (
	"testing"

	"ssh-ui/internal/config"
)

func TestWalkDirectivesFollowsIncludesAtTheirLinePosition(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "Host early\n\tUser first\n" +
			"Include conf.d/*.conf\n" +
			"Host late\n\tUser last\n",
		"conf.d/10-home.conf": "Host home\n\tUser home-user\n",
		"conf.d/20-work.conf": "Host work\n\tUser work-user\n",
	})

	var order []string
	WalkDirectives(graph, func(visit Visit) bool {
		order = append(order, visit.Line.Keyword+" "+joinValues(visit.Line.Values()))
		return true
	})

	want := []string{
		"Host early",
		"User first",
		"Include conf.d/*.conf",
		"Host home",
		"User home-user",
		"Host work",
		"User work-user",
		"Host late",
		"User last",
	}
	if len(order) != len(want) {
		t.Fatalf("order = %#v", order)
	}
	for index := range want {
		if order[index] != want[index] {
			t.Fatalf("order[%d] = %q, want %q", index, order[index], want[index])
		}
	}
}

func TestWalkDirectivesReportsTheOwningBlockAndStopsEarly(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "ServerAliveInterval 30\nHost bastion\n\tUser ops\nMatch host nas\n\tUser nas-user\n",
	})

	var kinds []config.BlockKind
	var conditions []string
	WalkDirectives(graph, func(visit Visit) bool {
		kinds = append(kinds, visit.Block.Kind)
		conditions = append(conditions, visit.Condition)
		return visit.Line.Keyword != "Match"
	})

	wantKinds := []config.BlockKind{config.BlockGlobal, config.BlockHost, config.BlockHost, config.BlockMatch}
	if len(kinds) != len(wantKinds) {
		t.Fatalf("kinds = %#v", kinds)
	}
	for index := range wantKinds {
		if kinds[index] != wantKinds[index] {
			t.Fatalf("kinds[%d] = %v, want %v", index, kinds[index], wantKinds[index])
		}
	}
	if conditions[0] != "" || conditions[1] != "Host bastion" || conditions[3] != "Match host nas" {
		t.Fatalf("conditions = %#v", conditions)
	}
}

func TestWalkDirectivesTerminatesOnAnIncludeCycle(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":    "Include loop.conf\nHost after\n",
		"loop.conf": "Include config\nHost inside\n",
	})

	visits := 0
	WalkDirectives(graph, func(Visit) bool {
		visits++
		return visits < 100
	})
	if visits == 0 || visits >= 100 {
		t.Fatalf("walk visited %d directives; a cycle guard is missing", visits)
	}
}

func joinValues(values []string) string {
	joined := ""
	for index, value := range values {
		if index > 0 {
			joined += " "
		}
		joined += value
	}
	return joined
}
