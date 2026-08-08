package application

import (
	"strings"

	"sshc/internal/config"
)

// グループの notice コード。
const (
	// NoticeGroupNotDeclared は、どの Include 行も名指ししない connections/
	// 配下のディレクトリに印を付ける。それはグループではない: 何にも読まれないからだ。
	NoticeGroupNotDeclared = "group_not_declared"
	// NoticeGroupDirectoryMissing は、ディレクトリがまだ存在しない
	// 宣言済みグループに印を付ける。
	NoticeGroupDirectoryMissing = "group_directory_missing"
	// NoticeGroupEmpty は、connections が 1 つもない宣言済みグループに印を付ける。
	NoticeGroupEmpty = "group_empty"
	// NoticeGroupFileUnreached は、connections/ の直下にあり、
	// どのグループにも属さず、何にも include されない .conf ファイルに印を付ける。
	NoticeGroupFileUnreached = "group_file_unreached"
)

// GroupView は、UI から見た 1 つのグループである: どこにあるか、
// 宣言されているか、その名前に付いたプレゼンテーション metadata である。
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

// DeclaredGroups は、エントリファイルの生成領域が名指しする
// グループ名を、Include 行が現れる順序で返す。
//
// ファイルシステムは参照されない。ディレクトリがグループなのは
// ~/.ssh/config の中の行がそれを読めと言っているからであり、
// 存在するからではない。たまたまそこにあるディレクトリから
// メンバーシップを推測すれば、誰かが別の目的で作った layout を黙って採用してしまう。
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

// BuildGroupsView は、Groups 画面が表示するものを組み立てる:
// プレゼンテーション metadata とメンバー数を伴う宣言済み
// グループに加え、宣言とディスクが食い違うあらゆる形についての notice である。
//
// present は、呼び出し元が見つけたとおりの、connections/ 配下に
// 実在するディレクトリの集合であり、ワークスペース相対でスラッシュ区切りである。
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
			// これが生む include_no_match 診断は、それでも報告される。
			// このアプリケーションが原因となった行を生成したからといって
			// 本物の診断を抑制するのは、間違った種類の「整頓」だろう。
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

// CompileGroups は、グループ設定を普通の Host ブロックとしてレンダリングする。
//
// 親ブロックは自身のメンバーと子孫のすべてのメンバーを列挙する
// ので、子は両方のブロックに名指しされることで継承しつつ、
// 自身のブロックが先に読まれる。declared は region が宣言する
// 順序のグループ集合である。階層は名前から来る。親を含む名前は、
// parent フィールドと食い違いようがないからだ。
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
		"# Generated by sshc from ~/.ssh/sshc/metadata.json.",
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

// groupMembers は、グループ自身のメンバーとその内部にネストした
// すべてのグループのメンバーを、host が射影された順序で集める。
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

// declaredGroupSet は、保存が宣言するグループ集合である。
//
// グループが region に届くのは、既にそこで宣言されているか、
// ユーザーが metadata でプレゼンテーションや settings を与えて
// 1 つ作ったからである。ファイルシステムは意図的にソースではない:
// 誰かが connections/ 配下に作ったディレクトリは報告されるだけで、決して採用されない。
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

// NoticeGroupDirectoryCreated は、この保存が作るグループディレクトリに印を付ける。
//
// ディレクトリの作成はジャーナルの外で起こる — Commit は実在のディレクトリに
// 対して書き込みパスを解決するので、ディレクトリが先に存在していなければ
// ならない — だからこそ見えない効果として残すのではなく、はっきり言う価値がある。
const NoticeGroupDirectoryCreated = "group_directory_created"
