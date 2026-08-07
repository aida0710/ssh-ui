package effective_test

import (
	"errors"
	"strconv"
	"testing"

	"sshc/internal/effective"
)

func TestParseChainReadsEveryDestinationForm(t *testing.T) {
	chain, err := effective.ParseChain("ops@edge:2201, inner ,[2001:db8::1]:2202,[2001:db8::2]")
	if err != nil {
		t.Fatalf("ParseChain = %v", err)
	}
	if len(chain.Hops) != 4 {
		t.Fatalf("hops = %#v", chain.Hops)
	}
	first := chain.Hops[0]
	if first.User != "ops" || first.Host != "edge" || first.Port != "2201" || !first.UserExplicit || !first.PortExplicit {
		t.Errorf("hop 0 = %#v", first)
	}
	second := chain.Hops[1]
	if second.Host != "inner" || second.Port != effective.DefaultJumpPort || second.PortExplicit {
		t.Errorf("hop 1 = %#v", second)
	}
	if third := chain.Hops[2]; third.Host != "2001:db8::1" || third.Port != "2202" {
		t.Errorf("hop 2 = %#v", third)
	}
	if fourth := chain.Hops[3]; fourth.Host != "2001:db8::2" || fourth.Port != effective.DefaultJumpPort {
		t.Errorf("hop 3 = %#v", fourth)
	}

	disabled, err := effective.ParseChain("none")
	if err != nil || !disabled.Disabled || len(disabled.Hops) != 0 {
		t.Errorf("ParseChain(none) = %#v, %v", disabled, err)
	}

	for _, invalid := range []string{"edge,,inner", "@edge", "ops@", "[2001:db8::1", "edge:"} {
		if _, err := effective.ParseChain(invalid); !errors.Is(err, effective.ErrInvalidJump) {
			t.Errorf("ParseChain(%q) = %v, want ErrInvalidJump", invalid, err)
		}
	}
}

func TestExpandRouteFollowsCommaSeparatedAndNestedJumps(t *testing.T) {
	graph := graphFor(t, map[string]string{
		testConfig: "Host target\n" +
			"\tProxyJump ops@edge:2201,inner\n" +
			"Host edge\n" +
			"\tHostName 192.0.2.7\n" +
			"\tPort 22\n" +
			"Host inner\n" +
			"\tHostName 10.1.1.5\n" +
			"\tUser deploy\n" +
			"\tProxyJump edge\n",
	})

	stages, complexities := effective.ExpandRoute(graph, "target")
	if len(complexities) != 0 {
		t.Fatalf("complexities = %#v", complexities)
	}
	if len(stages) != 3 {
		t.Fatalf("stages = %#v", stages)
	}

	first := stages[0]
	if first.Order != 1 || first.Depth != 0 || first.Parent != "target" {
		t.Errorf("stage 0 position = %#v", first)
	}
	if first.Hostname != "192.0.2.7" || first.User != "ops" || first.Port != "2201" {
		t.Errorf("stage 0 destination = %#v", first)
	}

	second := stages[1]
	if second.Depth != 0 || second.Hostname != "10.1.1.5" || second.User != "deploy" || second.Port != "22" {
		t.Errorf("stage 1 = %#v", second)
	}

	nested := stages[2]
	if nested.Depth != 1 || nested.Parent != "inner" || nested.Hostname != "192.0.2.7" {
		t.Errorf("nested stage = %#v", nested)
	}
}

// TestExpandRouteBoundsAWideRoute は、MaxJumpDepth が制限しない唯一の形を守る。
// カンマ区切りリストの各ホップが自身のリストを持ちうるので、段数は和ではなく
// リスト長の積として増える。3 ホップ 8 段なら 9840 段であり、30 ホップ 8 段なら、
// どんなレスポンスにも収まりうる大きさを
// はるかに超える。
func TestExpandRouteBoundsAWideRoute(t *testing.T) {
	contents := ""
	for level := 1; level < 9; level++ {
		next := strconv.Itoa(level + 1)
		contents += "Host h" + strconv.Itoa(level) + "\n" +
			"\tProxyJump h" + next + ",h" + next + ",h" + next + "\n"
	}
	contents += "Host h9\n\tHostName 198.51.100.9\n"

	stages, complexities := effective.ExpandRoute(graphFor(t, map[string]string{testConfig: contents}), "h1")
	if len(stages) > effective.MaxRouteStages {
		t.Fatalf("route expanded to %d stages, want at most %d", len(stages), effective.MaxRouteStages)
	}
	if _, ok := codesOf(complexities)[effective.ComplexityJumpDepth]; !ok {
		t.Fatalf("a route the engine stopped following must say so: %#v", complexities)
	}
}

func TestExpandRouteStopsAtACycleAndReportsInvalidValues(t *testing.T) {
	cyclic := graphFor(t, map[string]string{
		testConfig: "Host alpha\n\tProxyJump bravo\nHost bravo\n\tProxyJump alpha\n",
	})
	stages, complexities := effective.ExpandRoute(cyclic, "alpha")
	if len(stages) == 0 {
		t.Fatal("a cycle must still show the hops it walked")
	}
	if _, ok := codesOf(complexities)[effective.ComplexityJumpCycle]; !ok {
		t.Fatalf("complexities = %#v", complexities)
	}

	broken := graphFor(t, map[string]string{
		testConfig: "Host alpha\n\tProxyJump ops@\n",
	})
	if _, complexities := effective.ExpandRoute(broken, "alpha"); len(complexities) != 1 ||
		complexities[0].Code != effective.ComplexityJumpInvalid {
		t.Fatalf("complexities = %#v", complexities)
	}

	none := graphFor(t, map[string]string{
		testConfig: "Host alpha\n\tProxyJump none\n",
	})
	if stages, complexities := effective.ExpandRoute(none, "alpha"); len(stages) != 0 || len(complexities) != 0 {
		t.Fatalf("ProxyJump none = %#v, %#v", stages, complexities)
	}
}
