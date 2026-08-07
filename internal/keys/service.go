package keys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sshc/internal/config"
	"sshc/internal/platform"
	"sshc/internal/storage"
)

var (
	ErrUnknownKey = errors.New("no key with that identifier is in the inventory")
	// ErrNoPublicKey は、隣に公開鍵の片割れがない秘密鍵を報告する。エージェントから
	// の取り消しは公開鍵で行うので、それがなければ ssh-add に渡すものが
	// 何もない。
	ErrNoPublicKey                 = errors.New("this key has no public half, which is what removing it from the agent needs")
	ErrInvalidFileName             = errors.New("file name is not a safe single path segment")
	ErrInvalidComment              = errors.New("comment contains characters this application will not put in a command line")
	ErrConflictingPassphraseChoice = errors.New("a passphrase was supplied together with the unencrypted flag")
	ErrUnknownGroup                = errors.New("no declared group of that name")
)

// KeysDirectoryName は、グループごとにサブディレクトリをひとつ持つディレクトリ。
// 設定エンジンが所有する connections ディレクトリを映したものである。import すると
// 依存の向きが逆になるので、import ではなく名前を重複させてある。
const KeysDirectoryName = "keys"

// fileNamePattern は、安全なパスセグメントをひとつだけ受け付ける。先頭のドット、
// スラッシュ、'..' セグメントはこのパターンでは不可能なので、
// Workspace.ResolveForWrite が見る前から、~/.ssh の外のファイルは名指しできない。
var fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// hardwareCommentPattern は、シェルの引用を必要としない文字だけを受け付ける。
// ハードウェア鍵のコメントは、コピー可能な ssh-keygen のコマンドラインの中に表示
// され、ユーザーはその行を自分で実行するからである。
var hardwareCommentPattern = regexp.MustCompile(`^[A-Za-z0-9@._+=:,/-]{0,127}$`)

// commentPattern は、このアプリケーション自身が埋め込むコメントのルール。
//
// ソフトウェア鍵はプロセス内で生成され、そのコメントは ssh.MarshalPrivateKey へ
// 渡るので、シェルには届かず引用も要らない。それでもハードウェア用のルールが
// 適用されており、空白が拒否されていた — 普通のコメントに最も入りやすい文字であり、
// `ssh-keygen -C "work laptop"` がそこに入れる文字である。ここで拒否するのは、
// ファイルや、それが書かれる行を壊すもの、すなわち改行、復帰、ヌルで
// ある。
var commentPattern = regexp.MustCompile(`^[^\x00\r\n]{0,127}$`)

// safeArgumentPattern は、このアプリケーションが表示するコマンドラインの各要素に
// 最後に適用される検査。
var safeArgumentPattern = regexp.MustCompile(`^[A-Za-z0-9@%_+=:,./-]+$`)

// ValidateFileName は、安全な単一パスセグメントでないものをすべて拒否する。
func ValidateFileName(name string) error {
	if !fileNamePattern.MatchString(name) {
		return ErrInvalidFileName
	}
	if strings.HasSuffix(name, ".pub") || name == StateDirectoryName {
		return ErrInvalidFileName
	}
	if reservedFileNames[strings.ToLower(name)] {
		return ErrInvalidFileName
	}
	return nil
}

// reservedFileNames は、OpenSSH とこのアプリケーションが ~/.ssh の中ですでに
// 意味を与えている名前。
//
// そこへ鍵を書くのは、単に紛らわしいというだけでは済まない。空のワークスペースに
// "config" という名前の鍵を生成すれば、エントリ設定ファイルが作られ、その中身が
// 秘密鍵になる。既存のファイルはトランザクションの事前条件で守られるので、危険に
// さらされるのは新しいワークスペースだけだが、名前のポリシーは、すでに何かが
// 占めていることに頼るのではなく、アプリケーション自身が依存する名前を拒否すべき
// である。比較は大文字小文字を区別しない。macOS のファイルシステムは既定で大文字
// 小文字を区別せず、"Config" と "config" は同じファイルだから
// である。
var reservedFileNames = map[string]bool{
	"config":           true,
	"known_hosts":      true,
	"known_hosts2":     true,
	"authorized_keys":  true,
	"authorized_keys2": true,
	"environment":      true,
	"rc":               true,
	"sshc":             true,
}

// ValidateComment は、鍵ファイルや、それが書かれる行を壊すコメントを拒否する。
// これは、このアプリケーションが自ら生成する鍵のためのルールである。
func ValidateComment(comment string) error {
	if !commentPattern.MatchString(comment) {
		return ErrInvalidComment
	}
	return nil
}

// ValidateHardwareComment は、ハードウェア鍵のために表示する ssh-keygen の
// コマンドライン内で、引用しなければならなくなるコメントを拒否する。
func ValidateHardwareComment(comment string) error {
	if !hardwareCommentPattern.MatchString(comment) {
		return ErrInvalidComment
	}
	return nil
}

// Service は鍵 vault のユースケース層。HTTP も UI の関心事も持たず、読み取りは
// ストレージのファイルシステムの継ぎ目を通してのみ、書き込みはジャーナル付きの
// トランザクションマネージャを通してのみ行う。
type Service struct {
	workspace    *storage.Workspace
	transactions *storage.Manager
	resolver     config.Resolver
	catalogue    CatalogueReader
	agent        platform.KeyAgent
	now          func() time.Time
	random       io.Reader
	// validateGroup を注入するのは、グループとは何かが設定エンジンの領分だからである
	// — Include 行が宣言したときにグループは存在する — そしてこのパッケージは、それを
	// 尋ねるためにそのエンジンを import してはならない。
	validateGroup func(string) error
	// storedPassphrase は、ある鍵のために保持されているパスフレーズがあり、vault が
	// 開いていれば、それを答える。注入する理由は validateGroup と同じである。秘密が
	// どこにあるかは secret パッケージの領分であり、このパッケージはそれを尋ねるために
	// import してはならない。nil なら何も保存されていないことを意味し、それは何も保存
	// されていなかった頃の振る舞いである。
	storedPassphrase func(relativePath string) (string, bool)
}

type ServiceOptions struct {
	Workspace        *storage.Workspace
	Transactions     *storage.Manager
	Resolver         config.Resolver
	StoredPassphrase func(relativePath string) (string, bool)
	Catalogue        CatalogueReader
	Agent            platform.KeyAgent
	Now              func() time.Time
	Random           io.Reader
	ValidateGroup    func(string) error
}

func NewService(options ServiceOptions) *Service {
	return &Service{
		workspace:        options.Workspace,
		transactions:     options.Transactions,
		resolver:         options.Resolver,
		catalogue:        options.Catalogue,
		agent:            options.Agent,
		now:              options.Now,
		random:           options.Random,
		validateGroup:    options.ValidateGroup,
		storedPassphrase: options.StoredPassphrase,
	}
}

// SetStoredPassphrase は、構築後にこの参照関数を取り付ける。尋ねる相手の vault より
// 先にこのサービスを組み立てる配線のためである。
func (service *Service) SetStoredPassphrase(lookup func(relativePath string) (string, bool)) {
	service.storedPassphrase = lookup
}

// entryPath は、Include グラフの起点となるユーザー設定ファイル。
func (service *Service) entryPath() string {
	return filepath.Join(service.workspace.Root(), "config")
}

func (service *Service) absolutePath(relativePath string) string {
	return filepath.Join(service.workspace.Root(), relativePath)
}

// Inventory はワークスペースを分類し、各ファイルを名指しする Host を付与する。
func (service *Service) Inventory() (*Inventory, error) {
	inventory, err := NewScanner(service.workspace).Scan()
	if err != nil {
		return nil, err
	}
	graph, err := service.resolver.Resolve(service.entryPath())
	if err != nil {
		return inventory, nil
	}
	inventory.AttachReferences(BuildReferenceIndex(graph, service.workspace))
	return inventory, nil
}

// Algorithms は、インストールされている OpenSSH が対応する variant を報告する。
func (service *Service) Algorithms(ctx context.Context) Catalogue {
	return service.catalogue.Read(ctx)
}

// HardwareCommand は、ハードウェアの方式に対する ssh-keygen の引数リストを返す。
//
// このコマンドはグループ配下のフルパスを名指しするので、ユーザーが手で実行しても、
// このアプリケーションが置いたであろう場所にちょうど鍵が置かれる。
func (service *Service) HardwareCommand(algorithm Algorithm, fileName, group, comment string) ([]string, error) {
	directory, err := service.groupDirectory(group)
	if err != nil {
		return nil, err
	}
	return HardwareCommand(algorithm, fileName, comment, service.absolutePath(directory))
}

// groupDirectory はグループを検証し、その鍵が置かれるワークスペース相対の
// ディレクトリを返す。グループが空の場合は ~/.ssh のルートで、グループなしの鍵は
// そこに属する。
func (service *Service) groupDirectory(group string) (string, error) {
	if group == "" {
		return ".", nil
	}
	if service.validateGroup == nil {
		return "", ErrUnknownGroup
	}
	if err := service.validateGroup(group); err != nil {
		return "", err
	}
	return path.Join(KeysDirectoryName, group), nil
}

// GenerateRequest は、プロセス内での鍵生成ひとつ分。
//
// パスフレーズを空にするには Unencrypted を明示的に設定しなければならない。うっかり
// 空欄になったフィールドから、保護されない鍵が黙って生まれることは決してない。
type GenerateRequest struct {
	Algorithm Algorithm
	Bits      int
	FileName  string
	// Group は、そのグループの鍵ディレクトリにペアを置く。FileName の一部ではなく、
	// 別個に検証される独立したフィールドである。呼び出し側から渡されたグループを名前へ
	// 連結すると、鍵が "config" に書かれるのを止めている単一セグメントのルールを
	// 破ってしまうからだ。
	Group       string
	Comment     string
	Passphrase  []byte
	Unencrypted bool
}

type GenerateResult struct {
	ID                 string
	RelativePath       string
	PublicRelativePath string
	Fingerprint        string
	KeyType            string
	Bits               int
	Encrypted          bool
	TransactionID      string
}

// Generate は、このプロセス内でソフトウェアの鍵ペアを作り、両方のファイルを
// ひとつのジャーナル付きトランザクションでコミットする。パスフレーズが argv、環境、
// 別プロセスに届くことは決してなく、Generate が返る前に上書きされる。
func (service *Service) Generate(request GenerateRequest) (GenerateResult, error) {
	defer Wipe(request.Passphrase)

	if err := ValidateFileName(request.FileName); err != nil {
		return GenerateResult{}, err
	}
	if err := ValidateComment(request.Comment); err != nil {
		return GenerateResult{}, err
	}
	directory, err := service.groupDirectory(request.Group)
	if err != nil {
		return GenerateResult{}, err
	}
	if len(request.Passphrase) == 0 && !request.Unencrypted {
		return GenerateResult{}, ErrPassphraseRequired
	}
	if len(request.Passphrase) > 0 && request.Unencrypted {
		return GenerateResult{}, ErrConflictingPassphraseChoice
	}

	privateKey, err := GeneratePrivateKey(request.Algorithm, request.Bits, service.random)
	if err != nil {
		return GenerateResult{}, err
	}
	privateContents, err := EncodePrivateKey(privateKey, request.Comment, request.Passphrase)
	if err != nil {
		return GenerateResult{}, err
	}
	defer Wipe(privateContents)
	publicContents, err := EncodePublicKey(privateKey, request.Comment)
	if err != nil {
		return GenerateResult{}, err
	}
	info, err := InspectPublicKey(publicContents)
	if err != nil {
		return GenerateResult{}, err
	}

	if err := service.workspace.EnsureDirectory(service.absolutePath(directory)); err != nil {
		return GenerateResult{}, err
	}
	privateName := path.Join(directory, request.FileName)
	publicName := privateName + ".pub"
	result, err := service.transactions.Commit(storage.Request{
		Operation: "key.generate",
		Changes: []storage.Change{
			{Path: service.absolutePath(privateName), Contents: privateContents},
			{Path: service.absolutePath(publicName), Contents: publicContents},
		},
	})
	if err != nil {
		return GenerateResult{}, err
	}
	return GenerateResult{
		ID:                 ItemID(privateName),
		RelativePath:       privateName,
		PublicRelativePath: publicName,
		Fingerprint:        info.Fingerprint,
		KeyType:            info.KeyType,
		Bits:               info.Bits,
		Encrypted:          len(request.Passphrase) > 0,
		TransactionID:      result.ID,
	}, nil
}

// PassphraseChange は、秘密鍵ひとつを再暗号化する。
type PassphraseChange struct {
	KeyID       string
	Current     []byte
	New         []byte
	Unencrypted bool
}

type PassphraseResult struct {
	ID            string
	RelativePath  string
	Encrypted     bool
	Notes         []string
	TransactionID string
}

// ChangePassphrase は、現在のパスフレーズで鍵を復号し、新しいパスフレーズで暗号化
// して書き戻す。読み取ったファイルのダイジェストで守られた、ひとつのジャーナル付き
// トランザクションで行う。
//
// このトランザクションは世代バックアップを取らない。置き換える内容がユーザーの
// 秘密鍵であり、この設計は鍵素材の二つ目のコピーを ~/.ssh/sshc/backups/ に残すこと
// を拒むからだ。新しい鍵を設置する rename は原子的なので、中断されても古い鍵か
// 新しい鍵のどちらかが残る。中断された変更は完了させられるが、巻き戻すことは
// できない。
//
// x/crypto のパーサは OpenSSH の秘密鍵の中に保存されたコメントを公開しないので、
// コメントは、フィンガープリントが一致する公開鍵ファイルから取る。そうしたファイル
// が存在しなければ、新しい鍵はコメントを持たず、結果は NoteCommentNotPreserved で
// その旨を伝える。エンジンがコメントをでっちあげることは決してない。
func (service *Service) ChangePassphrase(change PassphraseChange) (PassphraseResult, error) {
	defer Wipe(change.Current)
	defer Wipe(change.New)

	if len(change.New) == 0 && !change.Unencrypted {
		return PassphraseResult{}, ErrPassphraseRequired
	}
	if len(change.New) > 0 && change.Unencrypted {
		return PassphraseResult{}, ErrConflictingPassphraseChoice
	}

	inventory, err := service.Inventory()
	if err != nil {
		return PassphraseResult{}, err
	}
	item, ok := inventory.Find(change.KeyID)
	if !ok || item.Kind != KindPrivateKey {
		return PassphraseResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	contents, err := service.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		return PassphraseResult{}, err
	}
	defer Wipe(contents)
	precondition := storage.Precondition{Exists: true, Digest: storage.Digest(contents)}

	privateKey, err := DecodePrivateKey(contents, change.Current)
	if err != nil {
		return PassphraseResult{}, err
	}
	comment, notes := commentForKey(inventory, item)
	encoded, err := EncodePrivateKey(privateKey, comment, change.New)
	if err != nil {
		return PassphraseResult{}, err
	}
	defer Wipe(encoded)

	result, err := service.transactions.Commit(storage.Request{
		Operation: "key.passphrase",
		Changes: []storage.Change{{
			Path:         absolute,
			Contents:     encoded,
			Precondition: precondition,
		}},
	})
	if err != nil {
		return PassphraseResult{}, err
	}
	return PassphraseResult{
		ID:            item.ID,
		RelativePath:  item.RelativePath,
		Encrypted:     len(change.New) > 0,
		Notes:         notes,
		TransactionID: result.ID,
	}, nil
}

// RevealResult は、確認済みの秘密鍵表示に対する答え。
type RevealResult struct {
	ID            string
	RelativePath  string
	Contents      []byte
	Encrypted     bool
	Fingerprint   string
	TransactionID string
}

// Reveal は、秘密鍵ひとつのバイト列を返す。
//
// 監査記録はバイト列が返される前に書かれるので、記録できなかった表示は起こらない。
// 記録はファイルと時刻を名指しし、鍵素材を含むことは決してない。Reveal に他の
// 呼び出し側が存在しないのは意図的である。通常の詳細 API が秘密鍵のバイト列を
// 返すことはない。
func (service *Service) Reveal(keyID string) (RevealResult, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return RevealResult{}, err
	}
	item, ok := inventory.Find(keyID)
	if !ok || item.Kind != KindPrivateKey {
		return RevealResult{}, ErrUnknownKey
	}

	absolute := service.absolutePath(item.RelativePath)
	contents, err := service.workspace.FileSystem().ReadFile(absolute)
	if err != nil {
		return RevealResult{}, err
	}
	result, err := service.transactions.Note("key.reveal", []string{absolute})
	if err != nil {
		Wipe(contents)
		return RevealResult{}, err
	}
	return RevealResult{
		ID:            item.ID,
		RelativePath:  item.RelativePath,
		Contents:      contents,
		Encrypted:     item.Encrypted,
		Fingerprint:   item.Fingerprint,
		TransactionID: result.ID,
	}, nil
}

// PublicKeyResult は、公開鍵ファイルまたは証明書ファイルひとつのテキスト。
type PublicKeyResult struct {
	ID           string
	RelativePath string
	Contents     string
	Fingerprint  string
	Comment      string
}

// PublicKey は、公開鍵または証明書ひとつのテキストを返す。
//
// これは意図的に Reveal ではない。公開鍵は秘密ではないので、確認も、監査の記録も、
// Cache-Control の小細工もない。それらは秘密鍵の素材が開示されるからこそ存在する
// のであって、ここでは何ひとつ開示されない。そしてそれを真に保っているのが kind の
// 検査である。スキャナが公開鍵または証明書と分類したものだけを受け付けるので、
// 秘密鍵の識別子がこの関数に届いても、それは読まれるのではなく拒否される。分類は
// .pub という接尾辞ではなく内容と権限によって行われるので、id_rsa.pub と誤って
// 名付けられた秘密鍵についても、同じく拒否
// される。
func (service *Service) PublicKey(keyID string) (PublicKeyResult, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return PublicKeyResult{}, err
	}
	item, ok := inventory.Find(keyID)
	if !ok || (item.Kind != KindPublicKey && item.Kind != KindCertificate) {
		return PublicKeyResult{}, ErrUnknownKey
	}
	contents, err := service.workspace.FileSystem().ReadFile(service.absolutePath(item.RelativePath))
	if err != nil {
		return PublicKeyResult{}, err
	}
	return PublicKeyResult{
		ID:           item.ID,
		RelativePath: item.RelativePath,
		Contents:     string(contents),
		Fingerprint:  item.Fingerprint,
		Comment:      item.Comment,
	}, nil
}

// ConfirmationSubject は、ワンタイムの確認が対象とする操作の種類を表す。これは
// このパッケージ自身の語彙であり、HTTP 層が session パッケージのアクション種別を
// これに対応付ける。そのためユースケース層は、セッションがどう認証されるかに依存
// しなくてよい。
type ConfirmationSubject string

const (
	ConfirmRevealKey  ConfirmationSubject = "reveal_key"
	ConfirmPurgeEntry ConfirmationSubject = "purge_entry"
)

// ErrUnknownConfirmation は、このアプリケーションがトークンを発行しない確認対象を
// 報告する。
var ErrUnknownConfirmation = errors.New("unknown confirmation subject")

// ConfirmationEvidence は、ある操作について確認ダイアログが表示するであろう内容を
// そのままダイジェストにする。トークンをそれに結び付けられるようにするためである。
//
// ダイジェストはトークンが使われるときに再計算される。その間に鍵やごみ箱のエントリ
// が変わっていればダイジェストは食い違い、確認は拒否される。ユーザーが同意したのは
// 見せられたものであって、それを置き換えた何かではないからだ。生成されるのは
// ダイジェストだけである。鍵素材も、パスも、この関数から出ていくことは
// 決してない。
func (service *Service) ConfirmationEvidence(subject ConfirmationSubject, target string) (string, error) {
	switch subject {
	case ConfirmRevealKey:
		return service.revealEvidence(target)
	case ConfirmPurgeEntry:
		return service.purgeEvidence(target)
	default:
		return "", ErrUnknownConfirmation
	}
}

func (service *Service) revealEvidence(keyID string) (string, error) {
	inventory, err := service.Inventory()
	if err != nil {
		return "", err
	}
	item, ok := inventory.Find(keyID)
	if !ok || item.Kind != KindPrivateKey {
		return "", ErrUnknownKey
	}
	contents, err := service.workspace.FileSystem().ReadFile(service.absolutePath(item.RelativePath))
	if err != nil {
		return "", err
	}
	// ファイルのダイジェストを取り、バッファは直ちに消去する。evidence が
	// バイト列そのものを保持することは決してない。
	contentsDigest := storage.Digest(contents)
	Wipe(contents)

	return digestFields(string(ConfirmRevealKey), item.RelativePath, item.Fingerprint, item.Permission, contentsDigest), nil
}

func (service *Service) purgeEvidence(entryID string) (string, error) {
	manifest, err := service.readManifest(entryID)
	if err != nil {
		return "", err
	}
	fields := []string{string(ConfirmPurgeEntry), manifest.EntryID, manifest.DeletedAt}
	for _, file := range manifest.Files {
		fields = append(fields, file.OriginalPath, file.TrashPath, file.Kind, file.Fingerprint, file.Permission)
		// その後に消えたファイルは、ダイアログが列挙する内容を変える。したがって
		// その存在も、ユーザーが確認している内容の一部である。
		if _, statErr := service.workspace.FileSystem().Lstat(filepath.Join(service.workspace.Root(), file.TrashPath)); statErr == nil {
			fields = append(fields, "present")
			continue
		}
		fields = append(fields, "missing")
	}
	return digestFields(fields...), nil
}

// digestFields は、曖昧さのない区切りでフィールドの並びをハッシュする。異なる
// 二つのフィールド並びが、連結によって同じダイジェストになることはありえない。
func digestFields(fields ...string) string {
	hash := sha256.New()
	for _, field := range fields {
		hash.Write([]byte(field))
		hash.Write([]byte("\x00"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// RegisterRequest は、鍵をひとつ読み込むようユーザーの ssh-agent に求める。
type RegisterRequest struct {
	KeyID           string
	Passphrase      []byte
	LifetimeSeconds int
	StoreInKeychain bool
}

type RegisterResult struct {
	ID               string
	RelativePath     string
	Fingerprint      string
	LifetimeSeconds  int
	StoredInKeychain bool
	Identities       []platform.AgentIdentity
}

// Register は秘密鍵をユーザーの ssh-agent へ読み込ませ、任意でそのパスフレーズを
// ログインキーチェーンへ保存する。
//
// 登録できるのは、いまインベントリに含まれる鍵だけである。したがって、ごみ箱に
// ある鍵と ~/.ssh/sshc 配下のものは、構造上到達できない。パスフレーズは Register
// が返る前に上書きされ、登録はそれを含まずに履歴へ記録される。監査の記録が書かれる
// のはエージェントが鍵を受け付けたあとだけなので、拒否された登録が、それが起きたと
// 主張する記録を残すことは
// ない。
func (service *Service) Register(ctx context.Context, request RegisterRequest) (RegisterResult, error) {
	defer Wipe(request.Passphrase)

	if service.agent == nil {
		return RegisterResult{}, platform.ErrAgentUnavailable
	}
	inventory, err := service.Inventory()
	if err != nil {
		return RegisterResult{}, err
	}
	item, ok := inventory.Find(request.KeyID)
	if !ok || item.Kind != KindPrivateKey {
		return RegisterResult{}, ErrUnknownKey
	}

	// 呼び出し側が何も渡さなかったときには、保存されているパスフレーズを使う。それが、
	// エージェントへの鍵の追加を二段階ではなく一度の操作にしている。ただし、打ち込まれた
	// ものより優先されることは決してない。キーボードの前にいる人の方が、ファイルよりも
	// 新しいからである。
	passphrase := request.Passphrase
	if len(passphrase) == 0 && service.storedPassphrase != nil {
		if stored, ok := service.storedPassphrase(item.RelativePath); ok {
			passphrase = []byte(stored)
			defer Wipe(passphrase)
		}
	}

	absolute := service.absolutePath(item.RelativePath)
	if err := service.agent.Add(ctx, platform.AgentAddRequest{
		PrivateKeyPath:  absolute,
		Passphrase:      passphrase,
		LifetimeSeconds: request.LifetimeSeconds,
		StoreInKeychain: request.StoreInKeychain,
	}); err != nil {
		return RegisterResult{}, err
	}
	if _, err := service.transactions.Note("key.agent_add", []string{absolute}); err != nil {
		return RegisterResult{}, err
	}

	identities, listErr := service.agent.List(ctx)
	if listErr != nil {
		identities = nil
	}
	return RegisterResult{
		ID:               item.ID,
		RelativePath:     item.RelativePath,
		Fingerprint:      item.Fingerprint,
		LifetimeSeconds:  request.LifetimeSeconds,
		StoredInKeychain: request.StoreInKeychain,
		Identities:       identities,
	}, nil
}

// Deregister は、鍵ひとつをエージェントから取り戻す。
//
// 鍵をエージェントに渡したまま取り戻せないことがありえた。そのため鍵を完全削除
// しても、ユーザーがたったいま破棄した素材をエージェントが持ち続け、エージェントの
// 保持内容を並べる画面は、それを並べることしかできなかった。
//
// `ssh-add -d` は *公開* 鍵を読むので、これには公開鍵の片割れが存在する必要がある。
// 公開鍵が失われた identity の削除は、エージェントのプロトコルだけが直接できること
// であり、このアプリケーションは意図的に ssh-add 経由でエージェントと話す。公開鍵が
// 見つからないときは、行われていない削除を主張するのではなく、エージェントには手を
// 触れずに呼び出し側へその旨を
// 伝える。
func (service *Service) Deregister(ctx context.Context, keyID string) error {
	if service.agent == nil {
		return platform.ErrAgentUnavailable
	}
	inventory, err := service.Inventory()
	if err != nil {
		return err
	}
	item, ok := inventory.Find(keyID)
	if !ok || item.Kind != KindPrivateKey {
		return ErrUnknownKey
	}
	public, ok := publicKeyFor(inventory, item)
	if !ok {
		return ErrNoPublicKey
	}
	if err := service.agent.Remove(ctx, service.absolutePath(public.RelativePath)); err != nil {
		return err
	}
	_, err = service.transactions.Note("key.agent_remove", []string{service.absolutePath(item.RelativePath)})
	return err
}

// publicKeyFor は、秘密鍵の公開鍵の片割れをフィンガープリントで探し、見つから
// なければ、隣にある慣例的な ".pub" という名前へフォールバックする。
func publicKeyFor(inventory *Inventory, item *Item) (*Item, bool) {
	for index := range inventory.Items {
		candidate := &inventory.Items[index]
		if candidate.Kind != KindPublicKey {
			continue
		}
		if item.Fingerprint != "" && candidate.Fingerprint == item.Fingerprint {
			return candidate, true
		}
		if candidate.RelativePath == item.RelativePath+".pub" {
			return candidate, true
		}
	}
	return nil, false
}

// AgentIdentities は、エージェントがいま保持しているものを報告する。二つ目の
// 戻り値は、到達できるエージェントがないときに false になる。UI が、動いている
// エージェントに見える空リストではなく、その旨を言えるようにするためだ。
func (service *Service) AgentIdentities(ctx context.Context) ([]platform.AgentIdentity, bool) {
	if service.agent == nil || !service.agent.Available(ctx) {
		return nil, false
	}
	identities, err := service.agent.List(ctx)
	if err != nil {
		return nil, false
	}
	return identities, true
}

// commentForKey は、同じフィンガープリントを持つ公開鍵ファイルから秘密鍵の
// コメントを復元する。
func commentForKey(inventory *Inventory, item *Item) (string, []string) {
	if item.Fingerprint != "" {
		for _, candidate := range inventory.Items {
			if candidate.Kind == KindPublicKey && candidate.Fingerprint == item.Fingerprint && candidate.Comment != "" {
				return candidate.Comment, nil
			}
		}
	}
	return "", []string{NoteCommentNotPreserved}
}
