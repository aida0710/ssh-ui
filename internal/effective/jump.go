package effective

import (
	"errors"
	"strings"

	"sshc/internal/config"
)

const (
	// DefaultJumpPort は、ポート指定のないホップに OpenSSH が使うポート。
	DefaultJumpPort = "22"
	// MaxJumpDepth は、入れ子になった ProxyJump をどこまでたどるかを制限する。
	MaxJumpDepth = 8
	// MaxRouteStages は、展開された経路ひとつが含みうるホップ数を制限する。
	//
	// MaxJumpDepth だけでは走査は制限されない。カンマ区切りリストの
	// 各ホップが自身のリストを持ちうるので、段数は和ではなくリスト長の
	// 積として増える。この上限で止められた経路は
	// ComplexityJumpDepth を報告する。
	MaxRouteStages = 256
	// jumpDisabled は、ProxyJump を無効にするリテラル。
	jumpDisabled = "none"
)

// ErrInvalidJump は、このエンジンが解釈を拒む ProxyJump の値を報告する。
var ErrInvalidJump = errors.New("ProxyJump value is not a valid destination list")

// Hop は ProxyJump リストの行き先ひとつ。UserExplicit と PortExplicit は、その値が
// リスト自体から来たのかを記録する。リストに書かれた値は、そのホップ自身の設定に
// 勝つからである。
type Hop struct {
	Raw          string
	User         string
	Host         string
	Port         string
	UserExplicit bool
	PortExplicit bool
}

// Chain は解析済みの ProxyJump の値。
type Chain struct {
	Raw      string
	Disabled bool
	Hops     []Hop
}

// ParseChain は、単一またはカンマ区切りの ProxyJump 値を読む。
func ParseChain(raw string) (Chain, error) {
	chain := Chain{Raw: raw}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return chain, nil
	}
	if strings.EqualFold(trimmed, jumpDisabled) {
		chain.Disabled = true
		return chain, nil
	}

	for _, element := range strings.Split(trimmed, ",") {
		element = strings.TrimSpace(element)
		if element == "" {
			return Chain{}, ErrInvalidJump
		}
		hop := Hop{Raw: element, Port: DefaultJumpPort}
		destination := element
		if at := strings.LastIndex(destination, "@"); at >= 0 {
			hop.User = destination[:at]
			hop.UserExplicit = true
			destination = destination[at+1:]
			if hop.User == "" || destination == "" {
				return Chain{}, ErrInvalidJump
			}
		}
		switch {
		case strings.HasPrefix(destination, "["):
			closing := strings.Index(destination, "]")
			if closing < 0 {
				return Chain{}, ErrInvalidJump
			}
			hop.Host = destination[1:closing]
			if remainder := destination[closing+1:]; remainder != "" {
				if !strings.HasPrefix(remainder, ":") {
					return Chain{}, ErrInvalidJump
				}
				hop.Port = remainder[1:]
				hop.PortExplicit = true
			}
		default:
			if colon := strings.LastIndex(destination, ":"); colon >= 0 && !strings.Contains(destination[:colon], ":") {
				hop.Host = destination[:colon]
				hop.Port = destination[colon+1:]
				hop.PortExplicit = true
			} else {
				hop.Host = destination
			}
		}
		if hop.Host == "" || hop.Port == "" {
			return Chain{}, ErrInvalidJump
		}
		chain.Hops = append(chain.Hops, hop)
	}
	return chain, nil
}

// Stage は経路のホップひとつ。API と UI が再帰型を必要としないよう平坦化してある。
// Depth は、対象自身の ProxyJump リストについては 0。自身の ProxyJump を持つ踏み台
// ホストは、次の深さに段を寄与する。
type Stage struct {
	Order    int
	Depth    int
	Parent   string
	Hop      Hop
	Hostname string
	User     string
	Port     string
	Sources  []Source
	Complex  bool
}

// ExpandRoute は、alias とその中のすべての踏み台ホストの ProxyJump 連鎖を展開する。
// これにより、最初のホップだけでなく経路の全体を表示できる。
func ExpandRoute(graph *config.Graph, alias string) ([]Stage, []Complexity) {
	walk := routeWalk{graph: graph, ancestors: map[string]bool{strings.ToLower(alias): true}}
	return walk.expand(alias, 0)
}

// routeWalk は、ExpandRoute 一回分の状態を運ぶ。
//
// ancestors は、開始 alias から、いま展開しているホップまでの経路上にある alias を
// ちょうど保持し、走査が戻るときに巻き戻される。循環とは、自分自身の経路上に再び
// 現れるホップのことだ。永久に再帰しうるのはそれだけだからである。別の枝を通って
// 再び到達される踏み台ホストは普通の形であり、そこでも
// 展開される。
type routeWalk struct {
	graph     *config.Graph
	ancestors map[string]bool
	order     int
}

func (w *routeWalk) expand(alias string, depth int) ([]Stage, []Complexity) {
	projection := Project(w.graph, alias)
	source, ok := projection.Value("proxyjump")
	if !ok {
		return nil, nil
	}
	chain, err := ParseChain(source.Value)
	if err != nil {
		return nil, []Complexity{{
			Code:   ComplexityJumpInvalid,
			Path:   source.Path,
			Line:   source.Line,
			Detail: source.Value,
		}}
	}
	if chain.Disabled {
		return nil, nil
	}
	if depth >= MaxJumpDepth {
		return nil, []Complexity{{
			Code:   ComplexityJumpDepth,
			Path:   source.Path,
			Line:   source.Line,
			Detail: "the jump route is deeper than this engine follows",
		}}
	}

	var stages []Stage
	var complexities []Complexity
	for _, hop := range chain.Hops {
		if w.order >= MaxRouteStages {
			complexities = append(complexities, Complexity{
				Code:   ComplexityJumpDepth,
				Path:   source.Path,
				Line:   source.Line,
				Detail: "the jump route has more hops than this engine follows",
			})
			break
		}

		hopProjection := Project(w.graph, hop.Host)
		w.order++
		stage := Stage{
			Order:    w.order,
			Depth:    depth,
			Parent:   alias,
			Hop:      hop,
			Hostname: hop.Host,
			User:     hop.User,
			Port:     hop.Port,
			Complex:  !hopProjection.Simple(),
		}
		if hostName, found := hopProjection.Value("hostname"); found {
			stage.Hostname = hostName.Value
			stage.Sources = append(stage.Sources, hostName)
		}
		if !hop.UserExplicit {
			if user, found := hopProjection.Value("user"); found {
				stage.User = user.Value
				stage.Sources = append(stage.Sources, user)
			}
		}
		if !hop.PortExplicit {
			if port, found := hopProjection.Value("port"); found {
				stage.Port = port.Value
				stage.Sources = append(stage.Sources, port)
			}
		}
		stages = append(stages, stage)

		lowered := strings.ToLower(hop.Host)
		if w.ancestors[lowered] {
			complexities = append(complexities, Complexity{
				Code:   ComplexityJumpCycle,
				Path:   source.Path,
				Line:   source.Line,
				Detail: hop.Host + " already appears earlier in this route",
			})
			continue
		}
		w.ancestors[lowered] = true
		nestedStages, nestedComplexities := w.expand(hop.Host, depth+1)
		delete(w.ancestors, lowered)
		stages = append(stages, nestedStages...)
		complexities = append(complexities, nestedComplexities...)
	}
	return stages, complexities
}
