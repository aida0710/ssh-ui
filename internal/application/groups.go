package application

import (
	"strings"

	"ssh-ui/internal/config"
)

// Group notice codes.
const (
	// NoticeGroupNotDeclared marks a directory under connections/ that no
	// Include line names. It is not a group: nothing reads it.
	NoticeGroupNotDeclared = "group_not_declared"
	// NoticeGroupDirectoryMissing marks a declared group whose directory does
	// not exist yet.
	NoticeGroupDirectoryMissing = "group_directory_missing"
	// NoticeGroupEmpty marks a declared group with no connections in it.
	NoticeGroupEmpty = "group_empty"
	// NoticeGroupFileUnreached marks a .conf file sitting directly under
	// connections/, which belongs to no group and which nothing includes.
	NoticeGroupFileUnreached = "group_file_unreached"
)

// GroupView is one group as the UI sees it: where it lives, whether it is
// declared, and the presentation metadata attached to its name.
type GroupView struct {
	Name             string    `json:"name"`
	Parent           string    `json:"parent,omitempty"`
	Directory        string    `json:"directory"`
	KeyDirectory     string    `json:"keyDirectory"`
	Colour           string    `json:"colour,omitempty"`
	Note             string    `json:"note,omitempty"`
	Order            int       `json:"order,omitempty"`
	Settings         []Setting `json:"settings,omitempty"`
	MemberCount      int       `json:"memberCount"`
	DirectoryPresent bool      `json:"directoryPresent"`
}

// DeclaredGroups returns the group names the entry file's generated region
// names, in the order the Include lines appear.
//
// The filesystem is not consulted. A directory is a group because a line in
// ~/.ssh/config says to read it, not because it exists: inferring membership
// from a directory that happens to be there would silently adopt a layout
// somebody else built for another purpose.
func DeclaredGroups(file *config.File) []string {
	start, end, found, err := FindRegion(file)
	if err != nil || !found {
		return nil
	}
	prefix := ConnectionsDirectory + "/"
	const suffix = "/*.conf"
	names := make([]string, 0)
	seen := make(map[string]bool)
	for index := start; index < end && index < len(file.Lines); index++ {
		line := file.Lines[index]
		if line.Kind != config.LineDirective || !config.EqualKeyword(line.Keyword, "Include") {
			continue
		}
		for _, value := range line.Values() {
			if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
			if ValidateGroupName(name) != nil || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// BuildGroupsView assembles what the Groups screen shows: the declared groups
// with their presentation metadata and member counts, plus a notice for every
// way the declaration and the disk disagree.
//
// present is the set of directories that exist under connections/, workspace
// relative and slash separated, as the caller found them.
func BuildGroupsView(entry *config.File, hosts []HostEntry, metadata Metadata, present []string) ([]GroupView, []Notice) {
	declared := DeclaredGroups(entry)
	declaredSet := make(map[string]bool, len(declared))
	for _, name := range declared {
		declaredSet[name] = true
	}
	presentSet := make(map[string]bool, len(present))
	for _, name := range present {
		presentSet[name] = true
	}

	byName := make(map[string]GroupMetadata, len(metadata.Groups))
	order := make(map[string]int, len(metadata.Groups))
	for _, group := range metadata.Groups {
		byName[group.Name] = group
		order[group.Name] = group.Order
	}
	members := make(map[string]int, len(declared))
	var notices []Notice
	for _, host := range hosts {
		if host.Group == "" {
			continue
		}
		members[host.Group]++
	}

	views := make([]GroupView, 0, len(declared))
	for _, name := range GroupNameOrder(declared, order) {
		stored := byName[name]
		view := GroupView{
			Name:             name,
			Parent:           ParentGroupName(name),
			Directory:        GroupDirectory(name),
			KeyDirectory:     GroupKeyDirectory(name),
			Colour:           stored.Colour,
			Note:             stored.Note,
			Order:            stored.Order,
			Settings:         stored.Settings,
			MemberCount:      members[name],
			DirectoryPresent: presentSet[name],
		}
		if !view.DirectoryPresent {
			notices = appendNotice(notices, Notice{Code: NoticeGroupDirectoryMissing, Detail: name, Path: view.Directory})
		} else if view.MemberCount == 0 {
			// The include_no_match diagnostic this produces is still reported.
			// Suppressing a real diagnostic because this application generated
			// the line that caused it would be the wrong kind of tidy.
			notices = appendNotice(notices, Notice{Code: NoticeGroupEmpty, Detail: name, Path: view.Directory})
		}
		views = append(views, view)
	}
	for _, name := range present {
		if declaredSet[name] {
			continue
		}
		notices = appendNotice(notices, Notice{
			Code: NoticeGroupNotDeclared, Detail: name, Path: ConnectionsDirectory + "/" + name,
		})
	}
	return views, notices
}

// CompileGroups renders the group settings as ordinary Host blocks.
//
// A parent block lists its own members and every member of its descendants, so
// a child inherits by being named in both blocks while its own block is read
// first. declared is the group set in the order the region declares it; the
// hierarchy comes from the names, because a name that contains its parent
// cannot disagree with a parent field.
func CompileGroups(declared []string, metadata Metadata, hosts []HostEntry, ending string) ([]byte, []Notice) {
	if ending == "" {
		ending = "\n"
	}
	byName := make(map[string]GroupMetadata, len(metadata.Groups))
	order := make(map[string]int, len(metadata.Groups))
	for _, group := range metadata.Groups {
		byName[group.Name] = group
		order[group.Name] = group.Order
	}

	aliasOrder := make([]string, 0, len(hosts))
	direct := make(map[string][]string, len(declared))
	seen := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if host.Identity.IsZero() || seen[host.Identity.Alias] {
			continue
		}
		seen[host.Identity.Alias] = true
		aliasOrder = append(aliasOrder, host.Identity.Alias)
		if host.Group != "" {
			direct[host.Group] = append(direct[host.Group], host.Identity.Alias)
		}
	}

	var notices []Notice
	var builder strings.Builder
	for _, comment := range []string{
		"# Generated by ssh-ui from ~/.ssh/ssh-ui/metadata.json.",
		"# Child groups come first because OpenSSH keeps the first value it reads.",
		"# Edit groups in the UI; hand edits to this file are replaced on the next save.",
	} {
		builder.WriteString(comment)
		builder.WriteString(ending)
	}

	for _, name := range GroupNameOrder(declared, order) {
		group := byName[name]
		members := groupMembers(direct, aliasOrder, name)
		if len(members) == 0 || len(group.Settings) == 0 {
			continue
		}
		header, err := buildLine("", "Host", members, ending)
		if err != nil {
			notices = appendNotice(notices, Notice{Code: NoticeGroupMemberMissing, Detail: name})
			continue
		}
		var block strings.Builder
		valid := true
		for _, setting := range group.Settings {
			line, settingErr := buildDirectiveLine("\t", setting.Keyword, setting.Values, ending)
			if settingErr != nil {
				notices = appendNotice(notices, Notice{
					Code: NoticeComplexExternalRule, Detail: name + ": " + setting.Keyword,
				})
				valid = false
				break
			}
			block.WriteString(line.Render())
		}
		if !valid {
			continue
		}

		builder.WriteString(ending)
		builder.WriteString("# group " + name)
		if parent := ParentGroupName(name); parent != "" {
			builder.WriteString(" (parent " + parent + ")")
		}
		builder.WriteString(ending)
		builder.WriteString(header.Render())
		builder.WriteString(block.String())
	}
	return []byte(builder.String()), notices
}

// groupMembers collects a group's own members and those of every group nested
// inside it, in the order the hosts were projected.
func groupMembers(direct map[string][]string, aliasOrder []string, name string) []string {
	collected := make(map[string]bool)
	for candidate, aliases := range direct {
		if candidate != name && !strings.HasPrefix(candidate, name+"/") {
			continue
		}
		for _, alias := range aliases {
			collected[alias] = true
		}
	}
	members := make([]string, 0, len(collected))
	for _, alias := range aliasOrder {
		if collected[alias] {
			members = append(members, alias)
		}
	}
	return members
}

// InsertIncludeLine writes an Include directive at the given index.
func InsertIncludeLine(file *config.File, relative string, index int) error {
	line, err := buildLine("", "Include", []string{relative}, dominantEnding(file))
	if err != nil {
		return err
	}
	if index < 0 || index > len(file.Lines) {
		return ErrEditLineOutsideBlock
	}
	insertLine(file, index, line)
	return nil
}

// declaredGroupSet is the group set a save declares.
//
// A group reaches the region because it is already declared there, or because
// the user made one by giving it presentation or settings in metadata. The
// filesystem is deliberately not a source: a directory somebody else created
// under connections/ is reported, never adopted.
func declaredGroupSet(entry *config.File, metadata Metadata) []string {
	seen := make(map[string]bool)
	names := make([]string, 0)
	add := func(name string) {
		if name == "" || seen[name] || ValidateGroupName(name) != nil {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, name := range DeclaredGroups(entry) {
		add(name)
	}
	for _, group := range metadata.Groups {
		add(group.Name)
	}
	order := make(map[string]int, len(metadata.Groups))
	for _, group := range metadata.Groups {
		order[group.Name] = group.Order
	}
	return GroupNameOrder(names, order)
}

// NoticeGroupDirectoryCreated marks a group directory this save creates.
//
// Directory creation happens outside the journal — Commit resolves a write path
// against real directories, so the directory has to be there first — which is
// why it is worth saying out loud rather than leaving as an invisible effect.
const NoticeGroupDirectoryCreated = "group_directory_created"
