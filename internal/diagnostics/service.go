package diagnostics

import (
	"context"
	"errors"
	"net"
	"path/filepath"

	"ssh-ui/internal/config"
	"ssh-ui/internal/effective"
	"ssh-ui/internal/platform"
	"ssh-ui/internal/storage"
)

// ConfigFile is one file of the Include graph, summarised for display.
type ConfigFile struct {
	Path     string
	Editable bool
	Missing  bool
	Loads    int
	Includes int
}

// ConfigReport is the syntax and Include check. It starts no process.
type ConfigReport struct {
	Root        string
	Files       []ConfigFile
	Diagnostics []config.Diagnostic
}

// Inspection is everything the effective-configuration screen needs.
type Inspection struct {
	Alias                string
	Report               effective.Report
	RequiresConfirmation bool
	Evaluated            bool
	Values               effective.Values
	Projection           effective.Projection
	Route                []effective.Stage
	RouteComplexities    []effective.Complexity
	Failure              *effective.OpenSSHError
}

// Service composes the configuration engine with the checks in this package.
// It re-reads the configuration for every request, because the files are the
// source of truth and may change between two requests.
type Service struct {
	Workspace      *storage.Workspace
	Resolver       config.Resolver
	Evaluator      effective.Evaluator
	Reachability   Reachability
	Authentication Authentication
	Terminal       platform.TerminalLauncher
}

// NewService wires the production dependencies together.
//
// lookup reads the parent environment and may be nil in a test, in which case
// the children inherit this process's environment. In production it is the
// entry point's os.LookupEnv, so every OpenSSH program this service starts
// receives platform.MinimalEnvironment instead: SSH_ASKPASS is withheld, and a
// passphrase prompt can only go to the standard input this application
// supplies rather than to a program the user happens to have exported.
func NewService(workspace *storage.Workspace, runner platform.OutputRunner, toolchain platform.Toolchain, terminal platform.TerminalLauncher, lookup func(string) (string, bool)) *Service {
	configPath := filepath.Join(workspace.Root(), "config")
	var environment []string
	if lookup != nil {
		environment = platform.MinimalEnvironment(lookup)
	}
	return &Service{
		Workspace:    workspace,
		Resolver:     storage.NewResolver(workspace),
		Evaluator:    effective.Evaluator{Runner: runner, Toolchain: toolchain, ConfigPath: configPath, Environment: environment},
		Reachability: Reachability{Dialer: &net.Dialer{}},
		Authentication: Authentication{
			Runner: runner, Toolchain: toolchain, ConfigPath: configPath, Environment: environment,
		},
		Terminal: terminal,
	}
}

// ConfigPath is the user configuration this service evaluates.
func (s *Service) ConfigPath() string { return filepath.Join(s.Workspace.Root(), "config") }

// Home is the user's home directory, used to sanitise captured output before
// it leaves this process.
func (s *Service) Home() string { return s.Workspace.Home() }

func (s *Service) graph() (*config.Graph, error) { return s.Resolver.Resolve(s.ConfigPath()) }

// Safety scans the current configuration for executable directives.
func (s *Service) Safety() (effective.Report, error) {
	graph, err := s.graph()
	if err != nil {
		return effective.Report{}, err
	}
	return effective.Scan(graph), nil
}

// ConfigCheck reports the Include graph and its diagnostics.
func (s *Service) ConfigCheck() (ConfigReport, error) {
	graph, err := s.graph()
	if err != nil {
		return ConfigReport{}, err
	}
	report := ConfigReport{Root: graph.Root, Diagnostics: graph.Diagnostics}
	for _, path := range graph.Order {
		node := graph.Nodes[path]
		if node == nil {
			continue
		}
		report.Files = append(report.Files, ConfigFile{
			Path:     node.Path,
			Editable: node.Editable,
			Missing:  node.Missing,
			Loads:    node.Loads,
			Includes: len(node.Includes),
		})
	}
	return report, nil
}

// Inspect explains one alias and, when that is allowed, evaluates it.
//
// A refused evaluation and a failing ssh are both returned as data: the screen
// still shows the engine's own projection and the exact commands that must be
// confirmed first.
func (s *Service) Inspect(ctx context.Context, alias string, confirmed bool) (Inspection, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Inspection{}, err
	}
	graph, err := s.graph()
	if err != nil {
		return Inspection{}, err
	}

	inspection := Inspection{Alias: alias, Report: effective.Scan(graph)}
	inspection.Projection = effective.Project(graph, alias)
	inspection.Route, inspection.RouteComplexities = effective.ExpandRoute(graph, alias)
	inspection.RequiresConfirmation = inspection.Report.EvaluationNeedsConfirmation()

	values, err := s.Evaluator.Evaluate(ctx, inspection.Report, alias, confirmed)
	var opensshError *effective.OpenSSHError
	switch {
	case err == nil:
		inspection.Values = values
		inspection.Evaluated = true
	case errors.Is(err, effective.ErrEvaluationNotConfirmed):
		// Expected: the caller has not confirmed yet.
	case errors.As(err, &opensshError):
		inspection.Failure = opensshError
	default:
		return Inspection{}, err
	}
	return inspection, nil
}

// Destination returns the hostname and port the engine projects for alias.
//
// It never runs ssh, so a reachability check still works while evaluation is
// blocked by an executable directive.
func (s *Service) Destination(alias string) (string, string, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return "", "", err
	}
	graph, err := s.graph()
	if err != nil {
		return "", "", err
	}
	projection := effective.Project(graph, alias)
	hostname := alias
	if source, ok := projection.Value("hostname"); ok {
		hostname = source.Value
	}
	port := "22"
	if source, ok := projection.Value("port"); ok {
		port = source.Value
	}
	return hostname, port, nil
}

// ProjectedValue returns the engine's own reading of one keyword for alias.
//
// Like Destination it starts no process, so a caller can describe a
// destination while evaluation is blocked by an executable directive. The
// value is the engine's projection, not OpenSSH's answer, and callers that
// display it must say so.
func (s *Service) ProjectedValue(alias, keyword string) (string, bool) {
	if err := platform.ValidateAlias(alias); err != nil {
		return "", false
	}
	graph, err := s.graph()
	if err != nil {
		return "", false
	}
	source, ok := effective.Project(graph, alias).Value(keyword)
	if !ok {
		return "", false
	}
	return source.Value, true
}

// Reach dials the destination directly, ignoring ProxyJump.
func (s *Service) Reach(ctx context.Context, alias string) (ReachabilityResult, error) {
	hostname, port, err := s.Destination(alias)
	if err != nil {
		return ReachabilityResult{}, err
	}
	if err := platform.ValidateHostname(hostname); err != nil {
		return ReachabilityResult{}, err
	}
	return s.Reachability.Check(ctx, hostname, port), nil
}

// ErrTerminalNotConfigured reports that no terminal launcher was wired in.
var ErrTerminalNotConfigured = errors.New("terminal launcher is not configured")

// UnsafeAliasWarning explains why an alias is copy-only.
const UnsafeAliasWarning = "This alias contains characters that could change the meaning of a command line. Copy the command and check it before running it yourself."

// LaunchTerminal opens an interactive session for alias.
func (s *Service) LaunchTerminal(ctx context.Context, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	if s.Terminal == nil {
		return ErrTerminalNotConfigured
	}
	return s.Terminal.Launch(ctx, alias)
}

// TerminalCommand returns the command a user would run by hand.
//
// An alias outside the safe character set is never launched; the command is
// still returned as text so the user can inspect and quote it themselves.
func (s *Service) TerminalCommand(alias string) (string, bool, string) {
	command := "ssh -- " + alias
	if err := platform.ValidateAlias(alias); err != nil {
		return command, false, UnsafeAliasWarning
	}
	return command, true, ""
}

// Authenticate runs the authentication test for alias.
//
// The captured stderr is shown to the user, so the home directory is rewritten
// to "~" first: verbose OpenSSH output names every file it read by absolute
// path, which would otherwise carry the account name into a response body.
func (s *Service) Authenticate(ctx context.Context, alias string, acknowledged bool) (AuthenticationResult, error) {
	report, err := s.Safety()
	if err != nil {
		return AuthenticationResult{}, err
	}
	result, err := s.Authentication.Test(ctx, report, alias, acknowledged)
	if err != nil {
		return AuthenticationResult{}, err
	}
	result.Stderr = platform.SanitiseHomePaths(result.Stderr, s.Workspace.Home())
	return result, nil
}
