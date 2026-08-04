package effective

import (
	"errors"
	"strings"

	"ssh-ui/internal/config"
)

const (
	// DefaultJumpPort is the port OpenSSH uses for a hop without one.
	DefaultJumpPort = "22"
	// MaxJumpDepth bounds how far nested ProxyJump values are followed.
	MaxJumpDepth = 8
	// MaxRouteStages bounds how many hops one expanded route may contain.
	//
	// MaxJumpDepth alone does not bound the walk: every hop of a
	// comma-separated list may carry a list of its own, so the number of
	// stages grows as a product of the list lengths rather than a sum. A route
	// stopped by this ceiling reports ComplexityJumpDepth.
	MaxRouteStages = 256
	// jumpDisabled is the literal that switches ProxyJump off.
	jumpDisabled = "none"
)

// ErrInvalidJump reports a ProxyJump value this engine refuses to interpret.
var ErrInvalidJump = errors.New("ProxyJump value is not a valid destination list")

// Hop is one destination of a ProxyJump list. UserExplicit and PortExplicit
// record whether the value came from the list itself, because a value written
// in the list wins over the hop's own configuration.
type Hop struct {
	Raw          string
	User         string
	Host         string
	Port         string
	UserExplicit bool
	PortExplicit bool
}

// Chain is a parsed ProxyJump value.
type Chain struct {
	Raw      string
	Disabled bool
	Hops     []Hop
}

// ParseChain reads a single or comma-separated ProxyJump value.
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

// Stage is one hop of the route, flattened so the API and the UI do not need a
// recursive type. Depth is 0 for the target's own ProxyJump list; a jump host
// that carries its own ProxyJump contributes stages at the next depth.
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

// ExpandRoute expands the ProxyJump chain of alias and of every jump host in
// it, so the whole route can be shown rather than only its first hop.
func ExpandRoute(graph *config.Graph, alias string) ([]Stage, []Complexity) {
	walk := routeWalk{graph: graph, ancestors: map[string]bool{strings.ToLower(alias): true}}
	return walk.expand(alias, 0)
}

// routeWalk carries the state of one ExpandRoute call.
//
// ancestors holds exactly the aliases on the path from the starting alias down
// to the hop being expanded, and is unwound as the walk returns. A cycle is a
// hop that reappears on its own path, because only that can recurse forever; a
// jump host reached again through a different branch is an ordinary shape and
// is expanded there too.
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
