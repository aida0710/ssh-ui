package config

import (
	"errors"
	"path"
	"strings"
)

// DefaultMaxDepth mirrors OpenSSH's MAX_READCONF_DEPTH.
const DefaultMaxDepth = 16

// ErrUnsupportedExpansion is returned for an Include argument whose meaning
// depends on information the engine does not have. The graph reports the
// pattern verbatim instead of guessing which files it would match.
var ErrUnsupportedExpansion = errors.New("include pattern uses an unsupported expansion")

// Loader gives the resolver read-only access to configuration files. The
// storage layer supplies the implementation used in production; tests supply a
// map-backed fake. Paths and patterns are absolute and already cleaned.
type Loader interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// Resolver walks an Include graph starting from a user configuration file.
//
// Home is the absolute home directory used for '~' and '%d'. Root is the
// directory that relative Include arguments resolve against, which OpenSSH
// defines as ~/.ssh for user configuration files, and is also the only
// directory this application may write to. Tokens holds the percent tokens
// that are known before a destination host is chosen; any other token is
// reported as an unsupported expansion.
type Resolver struct {
	Loader   Loader
	Home     string
	Root     string
	Tokens   map[byte]string
	MaxDepth int
}

func (r Resolver) maxDepth() int {
	if r.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return r.MaxDepth
}

// expandPattern converts one Include argument into an absolute glob pattern.
func (r Resolver) expandPattern(argument string) (string, error) {
	if argument == "" {
		return "", ErrUnsupportedExpansion
	}
	expanded, err := r.expandTokens(argument)
	if err != nil {
		return "", err
	}
	switch {
	case expanded == "~":
		expanded = r.Home
	case strings.HasPrefix(expanded, "~/"):
		expanded = r.Home + expanded[1:]
	case strings.HasPrefix(expanded, "~"):
		// '~user/...' needs a password database lookup the engine does not do.
		return "", ErrUnsupportedExpansion
	case !strings.HasPrefix(expanded, "/"):
		expanded = r.Root + "/" + expanded
	}
	return path.Clean(expanded), nil
}

func (r Resolver) expandTokens(argument string) (string, error) {
	if !strings.ContainsRune(argument, '%') {
		return argument, nil
	}
	var builder strings.Builder
	for index := 0; index < len(argument); index++ {
		if argument[index] != '%' {
			builder.WriteByte(argument[index])
			continue
		}
		if index+1 >= len(argument) {
			return "", ErrUnsupportedExpansion
		}
		index++
		if argument[index] == '%' {
			builder.WriteByte('%')
			continue
		}
		value, ok := r.Tokens[argument[index]]
		if !ok {
			return "", ErrUnsupportedExpansion
		}
		builder.WriteString(value)
	}
	return builder.String(), nil
}
