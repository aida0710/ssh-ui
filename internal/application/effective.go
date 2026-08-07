package application

import (
	"sort"
	"strconv"
	"strings"

	"sshc/internal/config"
)

// cumulativeKeywords は、最初の値だけを残すのではなく
// OpenSSH が累積するディレクティブである。他の keyword はすべて先勝ちに従う。
var cumulativeKeywords = map[string]bool{
	"identityfile": true, "certificatefile": true, "localforward": true,
	"remoteforward": true, "dynamicforward": true, "sendenv": true, "setenv": true,
}

// Source は値がどこから来たかを表す。
type Source struct {
	Path      string `json:"path,omitempty"`
	Absolute  string `json:"absolute,omitempty"`
	Line      int    `json:"line,omitempty"`
	Condition string `json:"condition,omitempty"`
}

// EffectiveEntry は説明付きの 1 つの値である。
type EffectiveEntry struct {
	Keyword string   `json:"keyword"`
	Values  []string `json:"values"`
	Source  Source   `json:"source"`
}

// Effective は、alias が受け取る値についてのこのエンジンの説明である。
//
// Approximate は常に true である。設計 §5.5 はインストール
// 済みの OpenSSH の `ssh -G` を権威としており、その評価は
// ユーザーのコマンドを実行しうるため後段のサブシステムに属する。このビューは
// 値がどこから来るかを示すために存在し、最終的な答えだと主張する代わりにそう言っている。
type Effective struct {
	Alias       string           `json:"alias"`
	Approximate bool             `json:"approximate"`
	Entries     []EffectiveEntry `json:"entries"`
	Notices     []Notice         `json:"notices,omitempty"`
}

// declaresExactly は、Host 行がパターンによる一致ではなく
// この alias を名指ししているかどうかを報告する。catch-all は全 alias に一致し
// 何も宣言しないので、「2 つのブロックがこの名前を主張する」ケースには決してなり得ない。
func declaresExactly(patterns []config.Pattern, alias string) bool {
	for _, pattern := range patterns {
		if pattern.Negated || pattern.Wildcard {
			continue
		}
		if pattern.Value == alias {
			return true
		}
	}
	return false
}

// ComputeEffective は読み込み順にグラフをたどり、各 keyword の
// 最初の値を記録し、OpenSSH が累積する keyword は累積する。
// Match ブロックは、`Match exec` がユーザーのシェルを
// 実行しうるため決して評価されない。その存在は代わりに複雑な外部ルールとして報告される。
func ComputeEffective(graph *config.Graph, root, alias string) Effective {
	effective := Effective{Alias: alias, Approximate: true, Entries: []EffectiveEntry{}}
	effective.Notices = appendNotice(effective.Notices, Notice{Code: NoticeExplainedValuesOnly})
	seen := map[string]bool{}
	// この alias を名指ししているブロックを、それがある場所を
	// キーにして保持する。走査はディレクティブごとに 1 回ブロックを
	// 訪れるからだ。たまたま一致した catch-all はこれに含まれない。
	// それは別の話であるワイルドカードシャドウとして報告される。
	// 2 つのブロックが 1 つの alias を宣言している場合、画面上の値とユーザーが実際に得る
	// 値が異なる。「実際には何を得るのか?」に答えるためのタブは、それを言わなければならない。
	declaring := map[string]bool{}

	WalkDirectives(graph, func(visit Visit) bool {
		if visit.Block.Header == visit.Index {
			return true
		}
		if config.EqualKeyword(visit.Line.Keyword, "Include") {
			return true
		}
		reference := NewFileRef(root, visit.Path)

		switch visit.Block.Kind {
		case config.BlockMatch:
			effective.Notices = appendNotice(effective.Notices, Notice{
				Code: NoticeMatchBlock, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
			})
			effective.Notices = appendNotice(effective.Notices, Notice{
				Code: NoticeComplexExternalRule, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
			})
			return true
		case config.BlockHost:
			if !MatchHostLine(visit.Block.Patterns, alias) {
				return true
			}
			if declaresExactly(visit.Block.Patterns, alias) {
				where := visit.Path + "\x00" + strconv.Itoa(visit.Block.Header)
				if !declaring[where] {
					declaring[where] = true
					if len(declaring) > 1 {
						effective.Notices = appendNotice(effective.Notices, Notice{
							Code: NoticeDuplicateAlias, Path: reference.Path,
							Line: visit.Block.Header + 1, Detail: alias,
						})
					}
				}
			}
			for _, pattern := range visit.Block.Patterns {
				if !pattern.Negated {
					continue
				}
				effective.Notices = appendNotice(effective.Notices, Notice{
					Code: NoticeNegatedPattern, Path: reference.Path, Line: visit.Block.Header + 1, Detail: visit.Condition,
				})
			}
		}

		lowered := strings.ToLower(visit.Line.Keyword)
		if seen[lowered] && !cumulativeKeywords[lowered] {
			return true
		}
		seen[lowered] = true
		effective.Entries = append(effective.Entries, EffectiveEntry{
			Keyword: visit.Line.Keyword,
			Values:  visit.Line.Values(),
			Source: Source{
				Path:      reference.Path,
				Absolute:  reference.Absolute,
				Line:      visit.Index + 1,
				Condition: visit.Condition,
			},
		})
		return true
	})

	sort.SliceStable(effective.Entries, func(first, second int) bool {
		return strings.ToLower(effective.Entries[first].Keyword) < strings.ToLower(effective.Entries[second].Keyword)
	})
	return effective
}

// EffectiveChange は、説明付きの値が変化する 1 つの keyword である。
type EffectiveChange struct {
	Keyword       string   `json:"keyword"`
	Before        []string `json:"before"`
	After         []string `json:"after"`
	BeforeSources []Source `json:"beforeSources,omitempty"`
	AfterSources  []Source `json:"afterSources,omitempty"`
}

// EffectiveDiff は、グループの変更を保存する前に設計 §5.4 が
// 要求する前後比較ビューである。
type EffectiveDiff struct {
	Alias   string            `json:"alias"`
	Changes []EffectiveChange `json:"changes"`
}

// DiffEffective は 2 つの説明を keyword ごとに比較する。
func DiffEffective(before, after Effective) EffectiveDiff {
	diff := EffectiveDiff{Alias: after.Alias, Changes: []EffectiveChange{}}
	if diff.Alias == "" {
		diff.Alias = before.Alias
	}
	beforeIndex := indexEffective(before)
	afterIndex := indexEffective(after)

	keywords := make([]string, 0, len(beforeIndex)+len(afterIndex))
	for keyword := range beforeIndex {
		keywords = append(keywords, keyword)
	}
	for keyword := range afterIndex {
		if _, ok := beforeIndex[keyword]; !ok {
			keywords = append(keywords, keyword)
		}
	}
	sort.Strings(keywords)

	for _, keyword := range keywords {
		beforeValues, beforeSources, display := renderEffective(beforeIndex[keyword])
		afterValues, afterSources, afterDisplay := renderEffective(afterIndex[keyword])
		if afterDisplay != "" {
			display = afterDisplay
		}
		if equalStrings(beforeValues, afterValues) && equalSources(beforeSources, afterSources) {
			continue
		}
		diff.Changes = append(diff.Changes, EffectiveChange{
			Keyword:       display,
			Before:        beforeValues,
			After:         afterValues,
			BeforeSources: beforeSources,
			AfterSources:  afterSources,
		})
	}
	return diff
}

func indexEffective(effective Effective) map[string][]EffectiveEntry {
	index := make(map[string][]EffectiveEntry, len(effective.Entries))
	for _, entry := range effective.Entries {
		lowered := strings.ToLower(entry.Keyword)
		index[lowered] = append(index[lowered], entry)
	}
	return index
}

func renderEffective(entries []EffectiveEntry) (values []string, sources []Source, display string) {
	values = []string{}
	sources = []Source{}
	for _, entry := range entries {
		if display == "" {
			display = entry.Keyword
		}
		values = append(values, strings.Join(entry.Values, " "))
		sources = append(sources, entry.Source)
	}
	return values, sources, display
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

// equalSources は、行番号を無視して 2 つの説明が値をどこから得たかを
// 比較する。ファイルとそれを支配するブロックが変わっていない値は、
// そのファイルの他の場所での編集が行を 1 つ下げただけでは変化した
// ことにならない。それを変化として報告すれば、グループのプレビューが
// ユーザーがしていない編集で埋まってしまう。別のファイルや別の Host / Match
// ブロックへ本当に移動した値は Path、Absolute、Condition が異なり、引き続き報告される。
func equalSources(first, second []Source) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if !equivalentSource(first[index], second[index]) {
			return false
		}
	}
	return true
}

func equivalentSource(first, second Source) bool {
	return first.Path == second.Path &&
		first.Absolute == second.Absolute &&
		first.Condition == second.Condition
}
