package effective_test

import (
	"testing"

	"sshc/internal/effective"
)

func codesOf(complexities []effective.Complexity) map[string]effective.Complexity {
	byCode := make(map[string]effective.Complexity, len(complexities))
	for _, complexity := range complexities {
		byCode[complexity.Code] = complexity
	}
	return byCode
}

func TestProjectAttributesTheFirstValueOfEachKeyword(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Include conf.d/*.conf\n" +
			"Host bastion\n" +
			"\tHostName 203.0.113.10\n" +
			"\tPort 2222\n",
		"/Users/tester/.ssh/conf.d/10-defaults.conf": "Host bastion\n" +
			"\tPort 9999\n" +
			"\tUser ops\n",
	})

	projection := effective.Project(graph, "bastion")

	hostName, ok := projection.Value("hostname")
	if !ok || hostName.Value != "203.0.113.10" || hostName.Path != testConfig || hostName.Line != 3 {
		t.Fatalf("hostname source = %#v, ok = %v", hostName, ok)
	}
	if hostName.Condition != "Host bastion" || hostName.Kind != effective.SourceExact || !hostName.Winner {
		t.Errorf("hostname source = %#v", hostName)
	}

	// The Include is on line 1 and the Host block below it, so OpenSSH reads
	// the whole of conf.d/10-defaults.conf before it reaches Port 2222. First
	// value wins, so 9999 is the winner — file order is not load order, and
	// this assertion used to say the opposite.
	port, _ := projection.Value("port")
	if port.Value != "9999" || port.Path != "/Users/tester/.ssh/conf.d/10-defaults.conf" {
		t.Errorf("OpenSSH keeps the first value it read: %#v", port)
	}
	user, ok := projection.Value("user")
	if !ok || user.Value != "ops" || user.Path != "/Users/tester/.ssh/conf.d/10-defaults.conf" {
		t.Errorf("user source = %#v", user)
	}

	losers := 0
	for _, source := range projection.Sources {
		if !source.Winner {
			losers++
		}
	}
	if losers != 1 {
		t.Errorf("the overridden Port must still be listed once: %#v", projection.Sources)
	}
	if projection.Simple() {
		t.Error("two Host blocks claiming the same alias is not a simple projection")
	}
	if _, ok := codesOf(projection.Complexities)[effective.ComplexityDuplicateAlias]; !ok {
		t.Errorf("complexities = %#v", projection.Complexities)
	}
}

func TestProjectFlagsWildcardNegationAndMatchAsComplexExternalRules(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Host !legacy *.internal\n" +
			"\tUser ops\n" +
			"Match host db user ops\n" +
			"\tIdentityAgent none\n" +
			"Host *\n" +
			"\tServerAliveInterval 30\n",
	})

	projection := effective.Project(graph, "db.internal")
	codes := codesOf(projection.Complexities)
	for _, code := range []string{
		effective.ComplexityWildcardPattern,
		effective.ComplexityNegatedPattern,
		effective.ComplexityMatchBlock,
	} {
		if _, ok := codes[code]; !ok {
			t.Errorf("missing complexity %q in %#v", code, projection.Complexities)
		}
	}
	if user, ok := projection.Value("user"); !ok || user.Kind != effective.SourceWildcard {
		t.Errorf("user source = %#v, ok = %v", user, ok)
	}
	if _, ok := projection.Value("identityagent"); ok {
		t.Error("a Match block must not contribute a projected value")
	}
	if interval, ok := projection.Value("serveraliveinterval"); !ok || interval.Value != "30" {
		t.Errorf("Host * still contributes a value: %#v", interval)
	}

	excluded := effective.Project(graph, "legacy")
	if _, ok := excluded.Value("user"); ok {
		t.Error("a negated pattern must exclude the block")
	}
}

func TestProjectReportsUnresolvedIncludesInsteadOfInventingValues(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Include %h/from-hostname.conf\nHost bastion\n\tUser ops\n",
	})

	projection := effective.Project(graph, "bastion")
	if _, ok := codesOf(projection.Complexities)[effective.ComplexityUnresolvedInclude]; !ok {
		t.Fatalf("complexities = %#v", projection.Complexities)
	}
	if projection.Simple() {
		t.Error("an unresolved Include is not a simple projection")
	}
}

func TestMatchPatternFollowsOpenSSHSemantics(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"bastion", "bastion", true},
		{"BASTION", "bastion", true},
		{"*", "anything", true},
		{"*.internal", "db.internal", true},
		{"*.internal", "internal", false},
		{"web-?", "web-1", true},
		{"web-?", "web-12", false},
		{"a*c*e", "abcde", true},
		{"a*c*e", "abcd", false},
		{"host*", "host", true},
		{"[abc]", "a", false},
	}
	for _, test := range tests {
		if got := effective.MatchPattern(test.pattern, test.value); got != test.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", test.pattern, test.value, got, test.want)
		}
	}
}
