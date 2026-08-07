package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"sshc/internal/config"
	"sshc/internal/storage"
)

// Kind は、~/.ssh 配下のファイルを、名前ではなく中身によって分類する。
type Kind string

const (
	KindPrivateKey  Kind = "private_key"
	KindPublicKey   Kind = "public_key"
	KindCertificate Kind = "certificate"
	KindKnownHosts  Kind = "known_hosts"
	KindConfig      Kind = "config"
	KindOther       Kind = "other"
)

// Note のコードは、UI が自前の文言へ対応付ける安定した識別子。
const (
	NoteSymbolicLink           = "symbolic_link"
	NoteFingerprintUnavailable = "fingerprint_unavailable"
	NoteEmptyFile              = "empty_file"
	NoteNotRegularFile         = "not_regular_file"
	NoteCommentNotPreserved    = "comment_not_preserved"
)

// 読めない理由のコード。
const (
	ReasonFileTooLarge  = "file_too_large"
	ReasonReadFailed    = "read_failed"
	ReasonDepthExceeded = "depth_exceeded"
	ReasonTooManyFiles  = "too_many_files"
)

const (
	// StateDirectoryName は、ワークスペース内にあるエンジン自身のディレクトリ。
	// その下にあるもの — バックアップ、ごみ箱、ジャーナル、履歴 — はすべてエンジンの
	// 状態なので、インベントリに現れることはなく、エージェントに登録されることもなく、
	// IdentityFile として提案されることもない。
	StateDirectoryName = "sshc"

	maxScanDepth   = 8
	maxScanEntries = 4096
)

// CertificateInfo は、OpenSSH の証明書がまだ有用かどうかをユーザーが判断するのに
// 必要な部分を運ぶ。
type CertificateInfo struct {
	KeyID                string
	Principals           []string
	ValidBefore          uint64
	SignedKeyType        string
	SignedKeyFingerprint string
}

// Item は、ワークスペース内で分類済みのファイルひとつ。
type Item struct {
	ID             string
	RelativePath   string
	Kind           Kind
	Container      string
	Algorithm      Algorithm
	KeyType        string
	Bits           int
	Encrypted      bool
	Fingerprint    string
	Comment        string
	Permission     string
	PermissionRisk bool
	SizeBytes      int64
	Certificate    *CertificateInfo
	References     []Reference
	Notes          []string
}

// UnreadableFile は、スキャナが意図的に解釈を拒んだファイル。
type UnreadableFile struct {
	RelativePath string
	Reason       string
}

// Inventory は、分類済みのワークスペースの内容。
type Inventory struct {
	Items                []Item
	Unreadable           []UnreadableFile
	AgentDelegations     []Reference
	UnresolvedReferences []UnresolvedReference
}

// Find は、与えられた識別子を持つ item を返す。
func (inventory *Inventory) Find(id string) (*Item, bool) {
	for index := range inventory.Items {
		if inventory.Items[index].ID == id {
			return &inventory.Items[index], true
		}
	}
	return nil, false
}

// Group は、その item と、同じ鍵ペアに属する公開鍵ファイルおよび証明書ファイルを
// まとめて返す。
//
// 所属はフィンガープリントだけで決まる。名前の基底部分が同じというだけのファイルが
// グループ化されることは決してないので、そっくりなだけのファイルが、属していない鍵と
// 一緒にごみ箱へ送られることはない。暗号化された秘密鍵のフィンガープリントが得られ
// ない場合、グループはその item 単体になる。
func (inventory *Inventory) Group(item *Item) []Item {
	group := []Item{*item}
	if item.Kind != KindPrivateKey || item.Fingerprint == "" {
		return group
	}
	for _, candidate := range inventory.Items {
		if candidate.ID == item.ID {
			continue
		}
		switch candidate.Kind {
		case KindPublicKey:
			if candidate.Fingerprint == item.Fingerprint {
				group = append(group, candidate)
			}
		case KindCertificate:
			if candidate.Certificate != nil && candidate.Certificate.SignedKeyFingerprint == item.Fingerprint {
				group = append(group, candidate)
			}
		}
	}
	return group
}

// ItemID は、HTTP API がファイルひとつに使う、安定した、パスを含まない識別子。
// ワークスペース相対のパスから導出されるので、再起動しても生き残る。URL にパスを
// 持ち込むこともなく、現在のインベントリに含まれないファイルを指すこともでき
// ない。
func ItemID(relativePath string) string {
	sum := sha256.Sum256([]byte(relativePath))
	return hex.EncodeToString(sum[:16])
}

// Scanner は、ストレージのファイルシステムの継ぎ目を通してワークスペースを走査する。
type Scanner struct {
	workspace *storage.Workspace
}

func NewScanner(workspace *storage.Workspace) *Scanner {
	return &Scanner{workspace: workspace}
}

// Scan は、エンジン自身の状態ディレクトリを除き、ワークスペースのルート配下の
// すべての通常ファイルを分類する。
func (scanner *Scanner) Scan() (*Inventory, error) {
	inventory := &Inventory{}
	visited := 0
	if err := scanner.walk(inventory, scanner.workspace.Root(), 0, &visited); err != nil {
		return nil, err
	}
	sort.Slice(inventory.Items, func(first, second int) bool {
		return inventory.Items[first].RelativePath < inventory.Items[second].RelativePath
	})
	sort.Slice(inventory.Unreadable, func(first, second int) bool {
		return inventory.Unreadable[first].RelativePath < inventory.Unreadable[second].RelativePath
	})
	return inventory, nil
}

func (scanner *Scanner) walk(inventory *Inventory, directory string, depth int, visited *int) error {
	fileSystem := scanner.workspace.FileSystem()
	entries, err := fileSystem.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		absolute := filepath.Join(directory, entry.Name())
		if absolute == scanner.workspace.StateDir() {
			continue
		}
		relative := scanner.relativePath(absolute)
		if *visited >= maxScanEntries {
			inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonTooManyFiles})
			return nil
		}
		*visited++

		info, statErr := fileSystem.Lstat(absolute)
		if statErr != nil {
			inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonReadFailed})
			continue
		}
		mode := info.Mode()
		switch {
		case mode&fs.ModeSymlink != 0:
			inventory.Items = append(inventory.Items, Item{
				ID:           ItemID(relative),
				RelativePath: relative,
				Kind:         KindOther,
				Permission:   fmt.Sprintf("%04o", mode.Perm()),
				Notes:        []string{NoteSymbolicLink},
			})
		case mode.IsDir():
			if depth+1 > maxScanDepth {
				inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: ReasonDepthExceeded})
				continue
			}
			if err := scanner.walk(inventory, absolute, depth+1, visited); err != nil {
				return err
			}
		case mode.IsRegular():
			inventory.Items = append(inventory.Items, scanner.classifyFile(inventory, absolute, relative, info))
		default:
			inventory.Items = append(inventory.Items, Item{
				ID:           ItemID(relative),
				RelativePath: relative,
				Kind:         KindOther,
				Permission:   fmt.Sprintf("%04o", mode.Perm()),
				Notes:        []string{NoteNotRegularFile},
			})
		}
	}
	return nil
}

func (scanner *Scanner) relativePath(absolute string) string {
	relative, err := filepath.Rel(scanner.workspace.Root(), absolute)
	if err != nil {
		return absolute
	}
	return relative
}

func (scanner *Scanner) classifyFile(inventory *Inventory, absolute, relative string, info fs.FileInfo) Item {
	item := Item{
		ID:           ItemID(relative),
		RelativePath: relative,
		Kind:         KindOther,
		Permission:   fmt.Sprintf("%04o", info.Mode().Perm()),
		SizeBytes:    info.Size(),
	}
	contents, err := scanner.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		reason := ReasonReadFailed
		if errors.Is(err, storage.ErrFileTooLarge) {
			reason = ReasonFileTooLarge
		}
		inventory.Unreadable = append(inventory.Unreadable, UnreadableFile{RelativePath: relative, Reason: reason})
		return item
	}
	classify(&item, contents)
	if item.Kind == KindPrivateKey && info.Mode().Perm()&0o077 != 0 {
		item.PermissionRisk = true
	}
	return item
}

// classify は、ファイルが何であるかをそのバイト列から決める。順序が重要である。
// まず秘密鍵を認識し、次に authorized-keys の行、次に known_hosts の行、そして
// 設定の構文。そうしないと known_hosts の行が、オプション付きの公開鍵と取り
// 違えられてしまう。
func classify(item *Item, contents []byte) {
	if len(contents) == 0 {
		item.Notes = append(item.Notes, NoteEmptyFile)
		return
	}
	if material, err := InspectPrivateKey(contents); err == nil {
		item.Kind = KindPrivateKey
		item.Container = material.Container
		item.Encrypted = material.Encrypted
		item.Algorithm = material.Algorithm
		item.KeyType = material.KeyType
		item.Bits = material.Bits
		item.Fingerprint = material.Fingerprint
		if item.Fingerprint == "" {
			item.Notes = append(item.Notes, NoteFingerprintUnavailable)
		}
		return
	}

	line := firstMeaningfulLine(contents)
	if len(line) == 0 {
		return
	}
	fields := strings.Fields(string(line))
	if len(fields) >= 2 && looksLikeKeyType(fields[0]) {
		if info, err := InspectPublicKey(line); err == nil {
			item.Kind = KindPublicKey
			item.Algorithm = info.Algorithm
			item.KeyType = info.KeyType
			item.Bits = info.Bits
			item.Fingerprint = info.Fingerprint
			item.Comment = info.Comment
			if info.IsCertificate {
				item.Kind = KindCertificate
				item.Certificate = &CertificateInfo{
					KeyID:                info.CertificateKeyID,
					Principals:           info.CertificatePrincipals,
					ValidBefore:          info.CertificateValidBefore,
					SignedKeyType:        info.SignedKeyType,
					SignedKeyFingerprint: info.SignedKeyFingerprint,
				}
			}
			return
		}
	}
	if _, _, _, _, _, err := ssh.ParseKnownHosts(line); err == nil {
		item.Kind = KindKnownHosts
		return
	}
	if looksLikeConfiguration(contents) {
		item.Kind = KindConfig
	}
}

func firstMeaningfulLine(contents []byte) []byte {
	for _, raw := range strings.Split(string(contents), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return []byte(trimmed + "\n")
	}
	return nil
}

func looksLikeKeyType(field string) bool {
	prefixes := []string{"ssh-", "ecdsa-sha2-", "rsa-sha2-", "sk-ssh-", "sk-ecdsa-"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return false
}

var configurationKeywords = []string{
	"Host", "Match", "Include", "HostName", "IdentityFile", "ProxyJump", "User", "Port",
}

func looksLikeConfiguration(contents []byte) bool {
	for _, line := range config.Parse(contents).Lines {
		if line.Kind != config.LineDirective {
			continue
		}
		for _, keyword := range configurationKeywords {
			if config.EqualKeyword(line.Keyword, keyword) {
				return true
			}
		}
	}
	return false
}
