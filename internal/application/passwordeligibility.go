package application

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"ssh-ui/internal/effective"
	"ssh-ui/internal/knownhosts"
)

// Codes for what stands between a host and a stored password.
const (
	// BlockerPasswordAuthenticationOff reports PasswordAuthentication no for
	// this host. It is client-side, so the client will never offer a password
	// however good one is: storing it would be storing a secret that cannot be
	// used, which is the worst of both.
	BlockerPasswordAuthenticationOff = "password_authentication_off"
	// BlockerAliasNotSimple reports a pattern rather than a host. A password
	// belongs to one account on one machine; there is no such thing for `*`.
	BlockerAliasNotSimple = "alias_not_simple"
	// WarnIdentityFileConfigured reports that a key is already configured for
	// this host. It may still ask for a password — the key may not be
	// authorised there — so this does not block, but a password stored for a
	// host that never asks is exposure bought for nothing.
	WarnIdentityFileConfigured = "identity_file_configured"
	// WarnHostKeyUnknown reports that known_hosts has nothing for this host.
	// The first connection therefore asks whether to trust the key, and this
	// application refuses to answer that question on the user's behalf, so the
	// connection will stop there with the password unused.
	WarnHostKeyUnknown = "host_key_unknown"
	// WarnHostNameUnresolved reports that the engine could not attribute a
	// HostName. The password is filed under the alias either way, so this is
	// said rather than guessed at.
	WarnHostNameUnresolved = "hostname_unresolved"
)

// PasswordEligibility is what this application knows about storing a password
// for one alias, before anything is stored.
//
// Blockers and warnings are kept apart on purpose. A blocker is a fact that
// makes the stored password unusable, and refusing is then a kindness rather
// than a restriction. A warning is a fact the user may know better about — a
// key that is configured but not authorised on the far side is an ordinary
// situation — so it is said and the decision is left where it belongs.
type PasswordEligibility struct {
	Alias    string   `json:"alias"`
	Storable bool     `json:"storable"`
	Blockers []Notice `json:"blockers"`
	Warnings []Notice `json:"warnings"`
	HostName string   `json:"hostName,omitempty"`
	Port     string   `json:"port,omitempty"`
}

// PasswordEligibility reads the configuration and known_hosts and reports what
// stands between this alias and a stored password.
//
// It reads. It never writes, never connects, and never runs ssh: everything
// here is answerable from the files this application already parses, and a
// check that opened a connection to decide whether to store a password would
// be a connection the user did not ask for.
func (s *Service) PasswordEligibility(alias string) (PasswordEligibility, error) {
	report := PasswordEligibility{
		Alias:    alias,
		Blockers: []Notice{},
		Warnings: []Notice{},
	}
	if err := ValidateAlias(alias); err != nil {
		report.Blockers = append(report.Blockers, Notice{Code: BlockerAliasNotSimple, Detail: alias})
		return report, nil
	}

	graph, err := s.resolve()
	if err != nil {
		return PasswordEligibility{}, err
	}
	projection := effective.Project(graph, alias)

	if source, ok := projection.Value("PasswordAuthentication"); ok {
		if strings.EqualFold(strings.TrimSpace(source.Value), "no") {
			report.Blockers = append(report.Blockers, Notice{
				Code: BlockerPasswordAuthenticationOff,
				Path: s.displayPath(source.Path), Line: source.Line,
			})
		}
	}
	if source, ok := projection.Value("IdentityFile"); ok {
		report.Warnings = append(report.Warnings, Notice{
			Code: WarnIdentityFileConfigured,
			Path: s.displayPath(source.Path), Line: source.Line, Detail: source.Value,
		})
	}

	host := alias
	if source, ok := projection.Value("HostName"); ok && strings.TrimSpace(source.Value) != "" {
		host = strings.TrimSpace(source.Value)
	} else {
		report.Warnings = append(report.Warnings, Notice{Code: WarnHostNameUnresolved, Detail: alias})
	}
	report.HostName = host
	if source, ok := projection.Value("Port"); ok {
		if _, err := strconv.Atoi(strings.TrimSpace(source.Value)); err == nil {
			report.Port = strings.TrimSpace(source.Value)
		}
	}

	known, err := s.hostKeyIsKnown(host, report.Port)
	if err != nil {
		return PasswordEligibility{}, err
	}
	if !known {
		report.Warnings = append(report.Warnings, Notice{Code: WarnHostKeyUnknown, Detail: host})
	}

	report.Storable = len(report.Blockers) == 0
	return report, nil
}

// hostKeyIsKnown reports whether known_hosts already holds a key for this host.
//
// A non-default port is written `[host]:port` in known_hosts, so both forms are
// tried. A missing file is not an error: it is the normal state of a machine
// that has not connected anywhere yet, and the answer is simply no.
func (s *Service) hostKeyIsKnown(host, port string) (bool, error) {
	body, err := s.workspace.FileSystem().ReadFile(filepath.Join(s.workspace.Root(), "known_hosts"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	candidates := []string{host}
	if port != "" && port != "22" {
		candidates = append(candidates, "["+host+"]:"+port)
	}
	for _, line := range knownhosts.ParseFile(body).Entries() {
		if line.Entry == nil {
			continue
		}
		for _, candidate := range candidates {
			if line.Entry.MatchesHost(candidate) {
				return true, nil
			}
		}
	}
	return false, nil
}
