package application

import (
	"errors"
	"strings"
	"testing"

	"sshc/internal/config"
)

const projectionConfig = `# personal configuration
Include conf.d/*.conf

Host bastion jump.example.com
	HostName=203.0.113.10
	User ops
	Port 22
	ProxyJump edge
	UnknownFutureDirective yes
	# keep this comment
	SetEnv EDITOR=vi

Host !secret *.internal
	User internal-user

Host *
	ServerAliveInterval 30
`

func TestProjectHostsListsEveryBlockWithItsRealNature(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":              projectionConfig,
		"conf.d/10-home.conf": "Host nas\n\tUser aida\nHost nas\n\tUser duplicate\n",
	})

	hosts, notices := ProjectHosts(graph, testRoot)
	if len(hosts) != 5 {
		t.Fatalf("hosts = %#v", hosts)
	}

	first := hosts[0]
	if first.Identity.Alias != "nas" || first.Identity.Path != "conf.d/10-home.conf" {
		t.Fatalf("first host = %#v", first)
	}
	if !first.Editable || first.Wildcard || first.Negated || first.Duplicate {
		t.Fatalf("first host flags = %#v", first)
	}
	if hosts[1].Identity.Alias != "nas" || !hosts[1].Duplicate {
		t.Fatalf("duplicate host = %#v", hosts[1])
	}
	if hosts[2].Identity.Alias != "bastion" || hosts[2].Line != 4 {
		t.Fatalf("bastion host = %#v", hosts[2])
	}
	if len(hosts[2].Patterns) != 2 || hosts[2].Patterns[1] != "jump.example.com" {
		t.Fatalf("bastion patterns = %#v", hosts[2].Patterns)
	}
	if !hosts[3].Negated || !hosts[3].Wildcard || !hosts[3].Identity.IsZero() {
		t.Fatalf("negated host = %#v", hosts[3])
	}
	if !hosts[4].Wildcard || !hosts[4].Identity.IsZero() {
		t.Fatalf("wildcard host = %#v", hosts[4])
	}

	codes := map[string]bool{}
	for _, notice := range notices {
		codes[notice.Code] = true
	}
	for _, want := range []string{NoticeDuplicateAlias, NoticeNegatedPattern, NoticeUnnamedHostBlock, NoticeWildcardShadow} {
		if !codes[want] {
			t.Errorf("missing notice %q in %#v", want, notices)
		}
	}
}

func TestProjectHostFormKeepsEveryDirectiveIncludingUnknownOnes(t *testing.T) {
	graph := newTestGraph(t, map[string]string{"config": projectionConfig})

	form, err := ProjectHostForm(graph, testRoot, HostIdentity{Path: "config", Alias: "bastion"})
	if err != nil {
		t.Fatal(err)
	}
	if len(form.Fields) != 6 {
		t.Fatalf("fields = %#v", form.Fields)
	}
	wantFields := []struct {
		keyword  string
		category FieldCategory
		values   []string
		line     int
	}{
		{"HostName", CategoryBasic, []string{"203.0.113.10"}, 5},
		{"User", CategoryBasic, []string{"ops"}, 6},
		{"Port", CategoryBasic, []string{"22"}, 7},
		{"ProxyJump", CategoryJump, []string{"edge"}, 8},
		{"UnknownFutureDirective", CategoryAdvanced, []string{"yes"}, 9},
		{"SetEnv", CategoryAdvanced, []string{"EDITOR=vi"}, 11},
	}
	for index, want := range wantFields {
		field := form.Fields[index]
		if field.Keyword != want.keyword || field.Category != want.category || field.Line != want.line {
			t.Fatalf("field[%d] = %#v, want %q %q line %d", index, field, want.keyword, want.category, want.line)
		}
		if len(field.Values) != len(want.values) || field.Values[0] != want.values[0] {
			t.Fatalf("field[%d] values = %#v, want %#v", index, field.Values, want.values)
		}
		if !field.Editable {
			t.Fatalf("field[%d] must be editable", index)
		}
	}
	if form.Raw != "Host bastion jump.example.com\n\tHostName=203.0.113.10\n\tUser ops\n\tPort 22\n\tProxyJump edge\n\tUnknownFutureDirective yes\n\t# keep this comment\n\tSetEnv EDITOR=vi\n\n" {
		t.Fatalf("raw block = %q", form.Raw)
	}
}

// The Raw editor writes this text back, and a delete is that write with the
// block removed. Showing the generated region as part of a connection therefore
// hands the group declarations to whichever edit happens to that connection
// next: rewriting one loses them, deleting one takes them with it.
// OpenSSH keeps the first value it reads, across the whole Include graph and
// not merely within one file. Two files claiming one alias is the case that
// rule exists for, and the case a reader cannot see by looking at either file:
// the loser looks perfectly correct where it sits. Keying the check on the
// file, as it was, only ever caught two blocks a reader could already see side
// by side.
func TestProjectHostsFlagsAnAliasDeclaredInAnotherFile(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config":              "Include conf.d/*.conf\n\nHost nas\n\tUser aida\n",
		"conf.d/10-home.conf": "Host nas\n\tUser someone-else\n",
	})

	hosts, notices := ProjectHosts(graph, testRoot)
	claiming := []HostEntry{}
	for _, host := range hosts {
		if host.Identity.Alias == "nas" {
			claiming = append(claiming, host)
		}
	}
	if len(claiming) != 2 {
		t.Fatalf("hosts claiming nas = %d, want 2", len(claiming))
	}
	// The Include is read where the line sits, so the included file wins and
	// the entry file's own block is the one that loses.
	if claiming[0].Duplicate {
		t.Errorf("the first block read must not be flagged: %#v", claiming[0])
	}
	if !claiming[1].Duplicate {
		t.Errorf("the shadowed block is not flagged: %#v", claiming[1])
	}
	found := false
	for _, notice := range notices {
		if notice.Code == NoticeDuplicateAlias && notice.Detail == "nas" {
			found = true
			if notice.Path != claiming[1].File.Path {
				t.Errorf("the notice names %q, want the shadowed block's file %q",
					notice.Path, claiming[1].File.Path)
			}
		}
	}
	if !found {
		t.Errorf("notices = %#v, want a duplicate_alias for nas", notices)
	}
}

func TestProjectHostFormRawStopsAtTheGeneratedRegion(t *testing.T) {
	graph := newTestGraph(t, map[string]string{"config": "Host bastion\n\tUser ops\n\n" +
		RegionStartMarker + "\nInclude connections/work/*.conf\n" + RegionEndMarker + "\n\nHost *\n\tServerAliveInterval 30\n"})

	form, err := ProjectHostForm(graph, testRoot, HostIdentity{Path: "config", Alias: "bastion"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(form.Raw, RegionStartMarker) || strings.Contains(form.Raw, "Include connections/") {
		t.Errorf("raw block carried the generated region:\n%s", form.Raw)
	}
}

func TestProjectHostFormFlagsDangerousDirectivesAndUnstructuredLines(t *testing.T) {
	graph := newTestGraph(t, map[string]string{
		"config": "Host risky\n\tProxyCommand /usr/bin/nc %h %p\n\tLocalCommand echo hi\n\tSendEnv \"broken\n",
	})

	form, err := ProjectHostForm(graph, testRoot, HostIdentity{Path: "config", Alias: "risky"})
	if err != nil {
		t.Fatal(err)
	}
	if len(form.Fields) != 2 || !form.Fields[0].Dangerous || !form.Fields[1].Dangerous {
		t.Fatalf("fields = %#v", form.Fields)
	}
	if form.Fields[0].Category != CategoryJump || form.Fields[1].Category != CategoryAdvanced {
		t.Fatalf("categories = %#v", form.Fields)
	}
	codes := map[string]bool{}
	for _, notice := range form.Notices {
		codes[notice.Code] = true
	}
	if !codes[NoticeDangerousDirective] || !codes[NoticeUnstructuredLine] {
		t.Fatalf("notices = %#v", form.Notices)
	}
}

func TestProjectHostFormRejectsAnUnknownIdentity(t *testing.T) {
	graph := newTestGraph(t, map[string]string{"config": "Host bastion\n\tUser ops\n"})
	if _, err := ProjectHostForm(graph, testRoot, HostIdentity{Path: "config", Alias: "absent"}); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("error = %v, want ErrHostNotFound", err)
	}
}

func TestMatchHostLineFollowsOpenSSHPatternRules(t *testing.T) {
	tests := []struct {
		patterns  string
		candidate string
		want      bool
	}{
		{"bastion", "bastion", true},
		{"bastion", "Bastion", false},
		{"*.internal", "db.internal", true},
		{"*.internal", "internal", false},
		{"web?", "web1", true},
		{"web?", "web12", false},
		{"*", "anything", true},
		{"!secret *.internal", "secret", false},
		{"!secret *.internal", "db.internal", true},
		{"a* !ab", "ab", false},
		{"a* !ab", "ac", true},
	}
	for _, test := range tests {
		header := config.Parse([]byte("Host " + test.patterns + "\n"))
		block := header.Blocks()[1]
		if got := MatchHostLine(block.Patterns, test.candidate); got != test.want {
			t.Errorf("MatchHostLine(%q, %q) = %v, want %v", test.patterns, test.candidate, got, test.want)
		}
	}
}

func TestNewDiagnosticViewKeepsExternalPathsVisible(t *testing.T) {
	inside := NewDiagnosticView(testRoot, config.Diagnostic{
		Severity: config.SeverityWarning,
		Code:     config.DiagnosticIncludeNoMatch,
		Path:     testRoot + "/config",
		Line:     3,
		Detail:   testRoot + "/conf.d/*.conf",
	})
	if inside.Severity != "warning" || inside.Path != "config" || inside.External {
		t.Fatalf("inside view = %#v", inside)
	}
	outside := NewDiagnosticView(testRoot, config.Diagnostic{
		Severity: config.SeverityInfo,
		Code:     config.DiagnosticIncludeOutsideRoot,
		Path:     "/etc/ssh/ssh_config",
	})
	if !outside.External || outside.Path != "" || outside.Absolute != "/etc/ssh/ssh_config" {
		t.Fatalf("outside view = %#v", outside)
	}
}

func TestHostEntryGroupComesFromTheDirectoryNotFromMetadata(t *testing.T) {
	// The directory is the membership. A metadata entry that disagrees has
	// nothing to disagree with any more: version 2 dropped the field, and a
	// host projected from connections/work reports "work" whatever else says.
	graph := newTestGraph(t, map[string]string{
		"config":                    "Include connections/work/*.conf\nInclude connections/*.conf\n",
		"connections/work/web.conf": "Host web-1\n\tHostName 203.0.113.10\n",
		"connections/loose.conf":    "Host loose\n\tHostName 203.0.113.11\n",
	})
	hosts, _ := ProjectHosts(graph, testRoot)

	byAlias := map[string]HostEntry{}
	for _, host := range hosts {
		byAlias[host.Identity.Alias] = host
	}
	if got := byAlias["web-1"].Group; got != "work" {
		t.Errorf("web-1 group = %q, want work", got)
	}
	// A file directly under connections/ is in no group: nothing declares it
	// and nothing reads it, so claiming a group for it would be a fiction.
	if got := byAlias["loose"].Group; got != "" {
		t.Errorf("loose group = %q, want none", got)
	}
}
