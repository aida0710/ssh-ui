package application

import (
	"errors"
	"sort"
	"strings"
)

const (
	// ConnectionsDirectory はグループごとに 1 つのディレクトリを
	// 保持し、それぞれがそのグループの connections の設定ファイルを
	// 収める。ファイルの置かれたディレクトリがメンバーシップを決め、他に記録するものはない。
	ConnectionsDirectory = "connections"
	// KeysDirectory は鍵ファイルについて ConnectionsDirectory を
	// 反映する。オンデマンドで作られ、先回りして作られることはない。
	KeysDirectory = "keys"

	// MaxGroupSegments は、グループがネストできる深さを制限する。
	//
	// この制限はここではなく鍵スキャナー由来である。~/.ssh から
	// 最大 8 階層のディレクトリを歩き、"keys" 自体がそのうち 1 つを
	// 消費するので、7 段目のグループセグメントの中にある鍵は
	// depth_exceeded として報告され、一覧に載る代わりにインベントリから消える。
	// その名前を拒否する方が、受け入れた上でそこに置かれた
	// ファイルを取りこぼすより良い。
	MaxGroupSegments = 6

	// maxGroupSegmentBytes は鍵 vault のファイル名ポリシーに合わせてあり、グループ
	// ディレクトリがワークスペースの他の部分が拒否するような名前にはならないようにする。
	maxGroupSegmentBytes = 64
)

// ErrInvalidGroupName は、connections ディレクトリ配下の
// 安全な相対ディレクトリパスになっていないグループ名を報告する。
var ErrInvalidGroupName = errors.New("group name is not a safe relative directory path")

// reservedGroupNames は、OpenSSH とこのアプリケーションが ~/.ssh の中で
// 既に意味を与えている名前である。比較は大小文字を区別しない。既定の
// macOS ボリュームは "Config" と "config" を同じディレクトリエントリとして扱うからだ。
var reservedGroupNames = map[string]bool{
	"sshc":             true,
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

// ValidateGroupName は、すべてのセグメントが安全な単一の
// パス構成要素であるスラッシュ区切りの相対ディレクトリパスを受け入れる。
//
// このチェックは、クリーンな文字列ではなく生の文字列に対して
// セグメントごとに行う。クリーンにすると "work/../home" は "home"
// になってしまい、クリーンな形を検証すると traverse する名前を黙って受け入れてしまう。
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

// GroupDirectory は、グループの connection ファイルを保持する
// ワークスペース相対のディレクトリである。
func GroupDirectory(name string) string { return ConnectionsDirectory + "/" + name }

// GroupKeyDirectory は、グループの鍵を保持するワークスペース相対のディレクトリである。
func GroupKeyDirectory(name string) string { return KeysDirectory + "/" + name }

// GroupIncludePattern は、1 つのグループのファイルを読む Include 引数である。
//
// 単一のワイルドカードではなくグループごとに 1 行なのは、
// filepath.Glob でも glob(3) でも '*' がパス区切りを越えないため、
// 単一のパターンではネストしたグループに決して届かないからだ。また
// 行の順序が優先順位を決めるが、glob ではそれが辞書順の偶然任せになってしまうからでもある。
func GroupIncludePattern(name string) string { return GroupDirectory(name) + "/*.conf" }

// groupFileSuffix は GroupIncludePattern が一致させる拡張子である。
// グループディレクトリ内にあってもこれで終わらない名前のファイルは
// そのグループの一部ではない。Include 行がそれを名指ししないので、何にも読まれない。
const groupFileSuffix = ".conf"

// GroupFileName は、まだ付いていなければ拡張子を追加することで、
// ソースファイルのベース名をグループの Include が読む名前に変える。
//
// グループへの移動はソースファイルの名前を保つので、シェル上で
// 見ればそれは新しい場所にある同じファイルである。ただしそれが
// 成り立つのは、その名前が移動を生き延びる場合だけだ。エントリ
// ファイルは "config" という名前で、宣言されていないすべての connection の
// 起点であるため、最もありふれた移動が "connections/<group>/config" を生む — グループ
// 自身の Include パターンには一致せず、正常に書かれた上で誰にも読まれないファイルである。
func GroupFileName(base string) string {
	if strings.HasSuffix(base, groupFileSuffix) && base != groupFileSuffix {
		return base
	}
	return base + groupFileSuffix
}

// GroupOfPath は、設定ファイルが置かれている場所によって属するグループ
// を報告する。connections ディレクトリの直下にあるファイルはどのグループにも属さない。
func GroupOfPath(relative string) (name string, inGroup bool) {
	return groupOfPath(relative, ConnectionsDirectory)
}

// GroupOfKeyPath は、鍵ファイルが属するグループを報告する。
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

// ParentGroupName は 1 階層上のグループ、最上位では空文字列で
// ある。名前自体が階層を運ぶので、食い違いうる parent フィールドは存在しない。
func ParentGroupName(name string) string {
	index := strings.LastIndex(name, "/")
	if index < 0 {
		return ""
	}
	return name[:index]
}

// GroupSegments は、グループ名をディレクトリ構成要素へ分割する。
func GroupSegments(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, "/")
}

// GroupDepth は、グループ名中のディレクトリ数を数える。
func GroupDepth(name string) int { return len(GroupSegments(name)) }

// GroupNameOrder は、グループ名を深い順、次に表示順、次に
// 名前順でソートする — 生成される settings ファイルが使うのと
// 同じ比較器であり、読み手が 2 つの優先順位規則を頭の中に持たずに済む。
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
