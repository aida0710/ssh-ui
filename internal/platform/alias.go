package platform

import (
	"errors"
	"regexp"
)

const (
	// MaxAliasLength bounds a Host alias this application is willing to place
	// on a command line.
	MaxAliasLength = 64
	// MaxHostnameLength is the DNS limit; ssh-keyscan targets may not exceed it.
	MaxHostnameLength = 255
)

var (
	ErrUnsafeAlias    = errors.New("alias contains characters this application refuses to pass to an external program")
	ErrUnsafeHostname = errors.New("hostname contains characters this application refuses to pass to an external program")
	ErrUnsafePort     = errors.New("port is outside the TCP range")
)

// safeAliasPattern is deliberately narrower than what OpenSSH accepts.
//
// OpenSSH will happily read a Host alias containing spaces, quotes, '%'
// tokens or a leading '-'. Such an alias could become an option ("-oProxy
// Command=..."), could change the meaning of a copied command line, or could
// escape a string in a terminal automation payload. An alias outside this set
// is never launched or evaluated; the UI offers the command as copyable text
// instead.
var safeAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// safeHostnamePattern allows DNS names, IPv4 literals and bare IPv6 literals.
// Brackets are excluded because this application adds them itself when it
// formats a known_hosts entry for a non-default port.
var safeHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$`)

// ValidateAlias reports whether alias may be handed to an external program.
func ValidateAlias(alias string) error {
	if len(alias) == 0 || len(alias) > MaxAliasLength || !safeAliasPattern.MatchString(alias) {
		return ErrUnsafeAlias
	}
	return nil
}

// ValidateHostname reports whether host may be handed to an external program.
func ValidateHostname(host string) error {
	if len(host) == 0 || len(host) > MaxHostnameLength || !safeHostnamePattern.MatchString(host) {
		return ErrUnsafeHostname
	}
	return nil
}

// ValidatePort reports whether port is a usable TCP port.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return ErrUnsafePort
	}
	return nil
}
