package config

import "testing"

func TestBlocksSplitGlobalHostAndMatchRanges(t *testing.T) {
	source := []byte("Port 22\n\nHost alpha bravo\n\tUser ops\n\nHost !legacy *.internal\n\tPort 2222\n\nMatch host db user ops\n\tIdentityAgent none\n")
	file := Parse(source)
	blocks := file.Blocks()
	if len(blocks) != 4 {
		t.Fatalf("blocks = %d, want 4", len(blocks))
	}

	global := blocks[0]
	if global.Kind != BlockGlobal || global.Header != -1 || global.Start != 0 || global.End != 2 {
		t.Errorf("global = %#v", global)
	}

	alpha := blocks[1]
	if alpha.Kind != BlockHost || alpha.Header != 2 || alpha.Start != 3 || alpha.End != 5 {
		t.Errorf("alpha = %#v", alpha)
	}
	if len(alpha.Patterns) != 2 || alpha.Patterns[0].Value != "alpha" || alpha.Patterns[1].Value != "bravo" {
		t.Errorf("alpha patterns = %#v", alpha.Patterns)
	}

	negated := blocks[2].Patterns
	if len(negated) != 2 {
		t.Fatalf("negated patterns = %#v", negated)
	}
	if !negated[0].Negated || negated[0].Value != "legacy" || negated[0].Raw != "!legacy" {
		t.Errorf("negated[0] = %#v", negated[0])
	}
	if negated[1].Negated || !negated[1].Wildcard || negated[1].Value != "*.internal" {
		t.Errorf("negated[1] = %#v", negated[1])
	}

	match := blocks[3]
	if match.Kind != BlockMatch || len(match.Criteria) != 2 {
		t.Fatalf("match = %#v", match)
	}
	if match.Criteria[0].Keyword != "host" || match.Criteria[0].Argument != "db" {
		t.Errorf("criterion 0 = %#v", match.Criteria[0])
	}
	if match.Criteria[1].Keyword != "user" || match.Criteria[1].Argument != "ops" {
		t.Errorf("criterion 1 = %#v", match.Criteria[1])
	}
	if got := file.Condition(match); got != "Match host db user ops" {
		t.Errorf("condition = %q", got)
	}
	if got := file.Condition(global); got != "" {
		t.Errorf("global condition = %q", got)
	}
}

func TestMatchCriteriaCoverEqualsFormAndArgumentlessKeywords(t *testing.T) {
	file := Parse([]byte("Match final !host=db canonical\n"))
	criteria := file.Blocks()[1].Criteria
	if len(criteria) != 3 {
		t.Fatalf("criteria = %#v", criteria)
	}
	if criteria[0].Keyword != "final" || criteria[0].Argument != "" {
		t.Errorf("criterion 0 = %#v", criteria[0])
	}
	if criteria[1].Keyword != "host" || criteria[1].Argument != "db" || !criteria[1].Negated {
		t.Errorf("criterion 1 = %#v", criteria[1])
	}
	if criteria[2].Keyword != "canonical" {
		t.Errorf("criterion 2 = %#v", criteria[2])
	}
}

func TestBlockAtReturnsEnclosingBlockForEveryLine(t *testing.T) {
	file := Parse([]byte("Port 22\nHost alpha\n\tUser ops\n"))
	if file.BlockAt(0).Kind != BlockGlobal {
		t.Error("line 0 is not global")
	}
	if file.BlockAt(1).Kind != BlockHost || file.BlockAt(2).Kind != BlockHost {
		t.Error("host header and body are not in the host block")
	}
}

func TestEmptyFileStillHasGlobalBlock(t *testing.T) {
	blocks := Parse(nil).Blocks()
	if len(blocks) != 1 || blocks[0].Kind != BlockGlobal || blocks[0].End != 0 {
		t.Fatalf("blocks = %#v", blocks)
	}
}
