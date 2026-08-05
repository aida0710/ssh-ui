package application

import (
	"errors"
	"sort"
	"strings"
)

const (
	// ConnectionsDirectory holds one directory per group, each containing the
	// configuration files of the connections in it. A file's directory is what
	// makes it a member; nothing else records the membership.
	ConnectionsDirectory = "connections"
	// KeysDirectory mirrors ConnectionsDirectory for key files. It is created
	// on demand and never speculatively.
	KeysDirectory = "keys"

	// MaxGroupSegments bounds how deep a group may nest.
	//
	// The limit comes from the key scanner, not from anything here: it walks at
	// most eight directories down from ~/.ssh, and "keys" itself consumes one,
	// so a key inside a seventh group segment would be reported as
	// depth_exceeded and would vanish from the inventory instead of being
	// listed. Refusing the name is better than accepting it and dropping the
	// file that lands there.
	MaxGroupSegments = 6

	// maxGroupSegmentBytes matches the key vault's file-name policy, so a group
	// directory cannot be a name the rest of the workspace would refuse.
	maxGroupSegmentBytes = 64
)

// ErrInvalidGroupName reports a group name that is not a safe relative
// directory path under the connections directory.
var ErrInvalidGroupName = errors.New("group name is not a safe relative directory path")

// reservedGroupNames are the names OpenSSH and this application already give a
// meaning inside ~/.ssh. The comparison is case-insensitive because a default
// macOS volume treats "Config" and "config" as one directory entry.
var reservedGroupNames = map[string]bool{
	"ssh-ui":           true,
	"config":           true,
	"known_hosts":      true,
	"known_hosts2":     true,
	"authorized_keys":  true,
	"authorized_keys2": true,
	"environment":      true,
	"rc":               true,
	"connections":      true,
	"keys":             true,
}

// ValidateGroupName accepts a slash-separated relative directory path whose
// every segment is a safe single path component.
//
// The check is done segment by segment on the raw string rather than on a
// cleaned one: cleaning turns "work/../home" into "home", so validating the
// cleaned form would silently accept a name that traverses.
func ValidateGroupName(name string) error {
	if name == "" || strings.ContainsRune(name, '\x00') {
		return ErrInvalidGroupName
	}
	segments := strings.Split(name, "/")
	if len(segments) > MaxGroupSegments {
		return ErrInvalidGroupName
	}
	for _, segment := range segments {
		if err := validateGroupSegment(segment); err != nil {
			return err
		}
	}
	return nil
}

func validateGroupSegment(segment string) error {
	if segment == "" || len(segment) > maxGroupSegmentBytes {
		return ErrInvalidGroupName
	}
	if segment == "." || segment == ".." || strings.HasPrefix(segment, ".") {
		return ErrInvalidGroupName
	}
	if reservedGroupNames[strings.ToLower(segment)] {
		return ErrInvalidGroupName
	}
	for index := 0; index < len(segment); index++ {
		character := segment[index]
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.' || character == '-' || character == '_':
		default:
			return ErrInvalidGroupName
		}
	}
	return nil
}

// GroupDirectory is the workspace-relative directory holding a group's
// connection files.
func GroupDirectory(name string) string { return ConnectionsDirectory + "/" + name }

// GroupKeyDirectory is the workspace-relative directory holding a group's keys.
func GroupKeyDirectory(name string) string { return KeysDirectory + "/" + name }

// GroupIncludePattern is the Include argument that reads one group's files.
//
// It is one line per group rather than a single wildcard because '*' does not
// cross a path separator, in filepath.Glob or in glob(3), so a single pattern
// could never reach a nested group — and because the order of the lines is what
// decides precedence, which a glob would leave to lexical accident.
func GroupIncludePattern(name string) string { return GroupDirectory(name) + "/*.conf" }

// GroupOfPath reports the group a configuration file belongs to, by where it
// sits. A file directly under the connections directory belongs to no group.
func GroupOfPath(relative string) (name string, inGroup bool) {
	return groupOfPath(relative, ConnectionsDirectory)
}

// GroupOfKeyPath reports the group a key file belongs to.
func GroupOfKeyPath(relative string) (name string, inGroup bool) {
	return groupOfPath(relative, KeysDirectory)
}

func groupOfPath(relative, root string) (string, bool) {
	cleaned := strings.TrimPrefix(strings.ReplaceAll(relative, "\\", "/"), "./")
	segments := strings.Split(cleaned, "/")
	if len(segments) < 3 || segments[0] != root {
		return "", false
	}
	name := strings.Join(segments[1:len(segments)-1], "/")
	if ValidateGroupName(name) != nil {
		return "", false
	}
	return name, true
}

// ParentGroupName is the group one level up, or the empty string at the top.
// The name carries the hierarchy, so there is no parent field to disagree with.
func ParentGroupName(name string) string {
	index := strings.LastIndex(name, "/")
	if index < 0 {
		return ""
	}
	return name[:index]
}

// GroupSegments splits a group name into its directory components.
func GroupSegments(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, "/")
}

// GroupDepth counts the directories in a group name.
func GroupDepth(name string) int { return len(GroupSegments(name)) }

// GroupNameOrder sorts group names deepest first, then by display order, then
// by name — the same comparator the generated settings file uses, so a reader
// does not have to hold two precedence rules in their head.
func GroupNameOrder(names []string, order map[string]int) []string {
	ordered := append([]string(nil), names...)
	sort.SliceStable(ordered, func(first, second int) bool {
		firstDepth, secondDepth := GroupDepth(ordered[first]), GroupDepth(ordered[second])
		if firstDepth != secondDepth {
			return firstDepth > secondDepth
		}
		if order[ordered[first]] != order[ordered[second]] {
			return order[ordered[first]] < order[ordered[second]]
		}
		return ordered[first] < ordered[second]
	})
	return ordered
}
