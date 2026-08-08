package remotesync

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"sshc/internal/envelope"
	"sshc/internal/objectstore"
	"sshc/internal/storage"
)

// StatePath は、このマシンが最後に何を同期したかを記録する場所。ワークスペース
// ルートからの相対である。他のすべてのファイルと同じくトランザクションマネージャを
// 通して書かれるので、同期の記録が書きかけで残ることはない。
const StatePath = "sshc/sync-state.json"

// archiveSuffix は、そのバイト列が何であるかを示す。暗号化された envelope の中の
// tar.gz である。ライブのオブジェクトも、日付付きのコピーも、これを持つ。
const archiveSuffix = "tar.gz.enc"

// ObjectName は、設定が指すパスの下に置かれるライブのスナップショット。
//
// 名前がそれ自体を語る。envelope の内側でアーカイブは tar.gz であり、オブジェクト
// 自体は暗号文である。以前の名前 — workspace.snapshot — はそのどちらも語らなかった
// し、誰も知らない拡張子は、それをダウンロードした誰かに「このファイルは壊れて
// いる」と結論させかねない。
const ObjectName = "workspace." + archiveSuffix

// SnapshotPrefix は、ライブのオブジェクトの隣に、push ごとの日付付きコピーを保持する。
//
// ライブのオブジェクトが固定のキーを保つのは、条件付き書き込みには条件をかける
// 対象のオブジェクトがひとつ必要であり、その条件こそが、あるマシンが別のマシンの
// 作業を黙って踏み潰すのを止めている唯一のものだからだ。これらのコピーは手で読む
// ためのものである。このアプリケーションのどれもそれを読まないし、際限なく溜まる
// のを防ぐのはバケットのライフサイクルルールである。
const SnapshotPrefix = "snapshots/"

// datedLayout は、スナップショットが作られた瞬間にちなんでコピーを名付ける。
// ソート可能で、秒まで一意である。1 分間に 2 回の push が衝突してはならない。
const datedLayout = "2006-01-02-150405"

// joinKey は、設定されたパスの下にパスセグメントをひとつ置く。パスは既定で空で
// あり、それはバケットのルートを意味する。
func joinKey(path, name string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return name
	}
	return trimmed + "/" + name
}

// ObjectKeyFor は、この設定においてライブのスナップショットが置かれる場所。
func ObjectKeyFor(config Config) string {
	return joinKey(config.Path, ObjectName)
}

// SnapshotKeyFor は、createdAt に作られたスナップショットの日付付きコピーの場所。
func SnapshotKeyFor(config Config, createdAt string) (string, error) {
	moment, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return "", err
	}
	return joinKey(config.Path, SnapshotPrefix+moment.UTC().Format(datedLayout)+"."+archiveSuffix), nil
}

var (
	// ErrNotConfigured は、バケットが設定されていないことを報告する。
	ErrNotConfigured = errors.New("remote sync is not configured")
	// ErrRemoteMoved は、このマシンが最後に見て以降スナップショットが変わったことを
	// 報告する。compare-and-swap の失敗であり、それこそが自動 push を安全にしている
	// 性質である。何も上書きされない。
	ErrRemoteMoved = errors.New("another machine has pushed since this one last synced")
	// ErrNoSnapshot は、空のバケットを報告する。
	ErrNoSnapshot = errors.New("the bucket holds no snapshot yet")
	// ErrConflicts は、判断なしには pull を適用できないことを報告する。
	ErrConflicts = errors.New("this pull needs a decision on at least one file")
	// ErrPushRefused は、受信専用に設定されたマシンでの push を報告する。
	ErrPushRefused = errors.New("this machine is set to receive only")
	// ErrApplyRefused は、送信専用に設定されたマシンでの apply を報告する。
	ErrApplyRefused = errors.New("this machine is set to send only")
)

// Direction は、このマシンがどちら向きにデータを動かしてよいかを表す。
//
// 支配するのは二つの書き込みだけであり、それ以外は何も支配しない。プレビューは
// バケットを読むだけで何も書かないので、どちらの一方向設定でも利用できる。
// スナップショットを適用してはいけないノートパソコンでも、どれだけ遅れているかは
// 知ることができる。それが、安全設定と目隠しの違いである。
type Direction string

const (
	// DirectionBoth は既定。このマシンは push もでき、apply もできる。
	DirectionBoth Direction = "both"
	// DirectionPush は、そのマシンが源であるとき — 設定が保存する価値のあるものである
	// ワークステーション — のためのもの。スナップショットを適用しないので、別のマシン
	// が push したものがこのディスク上のものを上書きすることはない。
	DirectionPush Direction = "push"
	// DirectionPull は、そのマシンが写しであるとき — 共有のマシンや一時的なマシン —
	// のためのもの。バケットへ書き込まないので、ここで行ったことが他のマシンへ届く
	// ことはない。
	DirectionPull Direction = "pull"
)

// ParseDirection は三つの名前を受け付け、空文字列は both として扱う。direction を
// 一度も聞いたことのない呼び出し側は、従来どおりに振る舞う。
func ParseDirection(name string) (Direction, bool) {
	switch Direction(name) {
	case "", DirectionBoth:
		return DirectionBoth, true
	case DirectionPush:
		return DirectionPush, true
	case DirectionPull:
		return DirectionPull, true
	default:
		return DirectionBoth, false
	}
}

// Config は、ユーザーが一度だけ与えるもの。
type Config struct {
	Endpoint string
	Bucket   string
	Region   string
	// Path は、すべてのオブジェクトが置かれる接頭辞。空ならバケットのルート。
	// バケットはたいていすでにこのアプリケーションにちなんで名付けられているので、
	// その中で同じ名前を繰り返すフォルダは、何もない階層をひとつ増やすだけである。
	Path      string
	Direction Direction
}

// state は、最後に成功した同期についての、このマシンの記録。
type state struct {
	// ETag は、このマシンが最後に push または pull したスナップショットを識別する。
	// 次の条件付き書き込みが比較される世代である。
	ETag string `json:"etag"`
	// Key は、その ETag が属するオブジェクト。世代はひとつのオブジェクトについての
	// 事実なので、設定を別のオブジェクトへ向けること — 新しいパスや、オブジェクトに
	// 正直な名前を与えた改名 — は、保存された世代を無意味にする。これがないと、次の
	// push は存在しないオブジェクトの世代を要求し、「別のマシンが push した」として
	// 拒否され、そこで勧められた pull は、pull すべきものを何ひとつ見つけられな
	// かった。
	Key string `json:"key,omitempty"`
	// Base は、そのスナップショットのマニフェスト。あとの pull に「別のマシンで削除
	// された」と「前回の同期以降ここで作られた」の違いを教えるのが、これで
	// ある。
	Base *Manifest `json:"base,omitempty"`
	// Origin は、このインストールの不透明な ID。一度だけ生成され、マシンに関する何から
	// も導出されない。
	Origin string `json:"origin"`
}

// FileSource は、スナップショットに含めるべきワークスペース相対のパスを列挙する。
//
// これを注入するのは、「どのファイルが設定の一部なのか」が Include グラフの答える
// 問いであり、このパッケージからはそれが見えないからだ。答えを渡す形にすることで
// 依存の向きが正しく保たれる。ここにあるものは、設定サービスを何ひとつ import
// しない。
type FileSource func() ([]string, error)

// remoteBinding は、ひとつの設定保存で切り替わるリモート接続一式。
//
// client は Endpoint、Bucket、Region、資格情報を自分の中にも保持する。したがって、
// client と config を別々に読むと、再設定と同期が重なったときに、古いバケットへ
// 新しいパスで書くような、どの保存設定にも存在しなかった組合せを作れてしまう。
type remoteBinding struct {
	config Config
	creds  objectstore.Credentials
	client *objectstore.Client
}

// Service は、一度にひとつの push か pull を行う。
type Service struct {
	workspace    *storage.Workspace
	transactions *storage.Manager
	files        FileSource
	now          func() string
	newOrigin    func() (string, error)

	mu      sync.Mutex
	binding remoteBinding
}

// NewService は、未設定のサービスを返す。
func NewService(workspace *storage.Workspace, transactions *storage.Manager, files FileSource,
	now func() string, newOrigin func() (string, error)) *Service {
	return &Service{
		workspace: workspace, transactions: transactions, files: files,
		now: now, newOrigin: newOrigin,
	}
}

// Configure は、この実行のバケットと資格情報を設定する。
//
// 資格情報はメモリ上に保持され、ワークスペースへ書かれることは決してない。自分の
// バケットへの鍵を運ぶスナップショットは、ブートストラップの便宜と引き換えに
// 爆発半径をはるかに大きくする。
func (s *Service) Configure(config Config, credentials objectstore.Credentials, client *objectstore.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 末尾のスラッシュがリクエストへ届いたことはない — クライアントはパス全体を
	// 置き換える — が、スナップショットの行き先を表示するすべての画面には
	// "https://host//bucket" として届いていた。設定を保存する場所だけでなくここで
	// 切り詰めることで、これができる前に保存されたものもきれいになる。
	config.Endpoint = strings.TrimRight(config.Endpoint, "/")
	config.Path = strings.Trim(config.Path, "/")
	s.binding = remoteBinding{config: config, creds: credentials, client: client}
}

// configuredBinding は、同期処理の開始時点の接続一式をひとつの値として返す。
// Configure はこのロックの前か後のどちらかにしか現れず、一回の操作の途中で
// config と client の世代が混ざることはない。
func (s *Service) configuredBinding() (remoteBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding := s.binding
	if binding.client == nil || binding.config.Bucket == "" || binding.creds.AccessKeyID == "" {
		return remoteBinding{}, ErrNotConfigured
	}
	return binding, nil
}

// Configured は、バケットと資格情報が設定されているかを報告する。
func (s *Service) Configured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binding.client != nil && s.binding.config.Bucket != "" && s.binding.creds.AccessKeyID != ""
}

// Direction は、このマシンがどちら向きにデータを動かしてよいかを報告する。
func (s *Service) Direction() Direction {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding.config.Direction == "" {
		return DirectionBoth
	}
	return s.binding.config.Direction
}

// neverTravels は、どんな名前を与えられようとスナップショットが運んではならない
// ファイル。
//
// この除外は以前は暗黙だった。Collect は自分が取るものを列挙するので、列挙されて
// いないものは外れる。それは Collect が自分で加えるものについては真だが、与えられる
// ものについては真ではない — ファイルソースは Include グラフであり、これらのいずれか
// を名指しする Include 行があれば、それは入ってしまう。そうなればバケットへの鍵が
// バケットの中に入る。この設計が避けるために存在するまさにその配置なので、ないもの
// と決めてかからず、ここで拒否する。
var neverTravels = []string{
	// オブジェクトストアの資格情報。封じられてはいるが、自分のバケットへの鍵を運ぶ
	// スナップショットは、スナップショットをひとつ入手した者が以後のすべてを取得
	// できることを意味する。
	SettingsPathRelative,
	// ハンドオフ。あるマシンのある実行のための URL と秘密であり、他のどこでも
	// 何の意味も持たない。
	"sshc/cli",
	// このマシン自身の帳簿。別のマシンのジャーナルやバックアップは、ここでは
	// 一度も起きていない書き込みを記述している。
	"sshc/journal",
	"sshc/backups",
	"sshc/history",
	"sshc/trash",
	StatePath,
}

// SettingsPathRelative は、封をされたオブジェクトストアの設定。secret パッケージ
// から import せずここで名指ししてある。あちらはこちらを何ひとつ import しないし、
// これからも import しないままでなければならない。
const SettingsPathRelative = "sshc/sync-settings"

func excluded(relative string) bool {
	for _, name := range neverTravels {
		if relative == name || strings.HasPrefix(relative, name+"/") {
			return true
		}
	}
	return false
}

// Collect は、スナップショットに含めるべきすべてのファイルを読む。
//
// すなわち、FileSource が名指しするもの — エントリファイルと、Include グラフが
// ワークスペース内で到達するすべて — に加えて、metadata.json、パスワードの vault、
// そしてすべての鍵である。ソースが名指しするのに存在しないファイルは、失敗させず
// にスキップする。Include はまだ存在しないファイルを指しうるし、それは診断であって
// 同期を拒む理由ではない。
func (s *Service) Collect() (Manifest, map[string][]byte, error) {
	relatives, err := s.files()
	if err != nil {
		return Manifest{}, nil, err
	}
	keys, err := s.walkKeys()
	if err != nil {
		return Manifest{}, nil, err
	}
	relatives = append(relatives, keys...)
	relatives = append(relatives, "sshc/metadata.json", "sshc/secrets")

	seen := map[string]bool{}
	contents := map[string][]byte{}
	var entries []Entry
	for _, relative := range relatives {
		relative = filepath.ToSlash(relative)
		if seen[relative] || checkPath(relative) != nil || excluded(relative) {
			continue
		}
		seen[relative] = true

		absolute := filepath.Join(s.workspace.Root(), filepath.FromSlash(relative))
		body, err := s.workspace.FileSystem().ReadFile(absolute)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return Manifest{}, nil, err
		}
		mode := "0600"
		if info, err := os.Stat(absolute); err == nil && info.Mode().Perm() == 0o700 {
			mode = "0700"
		}
		contents[relative] = body
		entries = append(entries, Entry{
			Path:   relative,
			SHA256: Digest(body),
			Mode:   mode,
			// 秘密鍵とは、keys/ 配下で .pub の接尾辞を持たないものすべてである。この印が、
			// pull にそれを SkipBackup 付きで適用させる。
			Secret: strings.HasPrefix(relative, "keys/") && !strings.HasSuffix(relative, ".pub"),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	current, err := s.readState()
	if err != nil {
		return Manifest{}, nil, err
	}
	return Manifest{
		SchemaVersion: SchemaVersion,
		CreatedAt:     s.now(),
		Origin:        current.Origin,
		Files:         entries,
	}, contents, nil
}

func (s *Service) walkKeys() ([]string, error) {
	root := filepath.Join(s.workspace.Root(), "keys")
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(s.workspace.Root(), path)
		if err != nil {
			return err
		}
		found = append(found, filepath.ToSlash(relative))
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return found, nil
}

// Check は、この設定が機能するかを知るために、バケットに問いをひとつ投げる。
//
// これは、打ち間違いと「正しく見えるのに何時間もあとの最初の push で、タイプミスを
// した画面から遠く離れたところで失敗する設定」とのあいだに立つものである。まだ
// スナップショットを持たないバケットは「見つからない」と答えるが、それは機能して
// いるバケットである。問いは、このエンドポイント・このバケット名・この資格情報が、
// 答えを返すストアに届くかどうかであって、そこへ何かが push されたかどうかでは
// ない。
func (s *Service) Check(ctx context.Context) error {
	binding, err := s.configuredBinding()
	if err != nil {
		return err
	}
	return Check(ctx, binding.client, ObjectKeyFor(binding.config))
}

// Check は、このサービスが保持していないクライアントに対して同じ問いを投げる。
// 設定を保存する前に試せるようにするためだ。試されていない設定を登録することが、
// 打ち間違いを「正しく見える設定」に変えてしまう。
func Check(ctx context.Context, client *objectstore.Client, key string) error {
	if _, err := client.Head(ctx, key); err != nil && !errors.Is(err, objectstore.ErrNotFound) {
		return err
	}
	return nil
}

// Push は、このワークスペースを封じて書き込む。リモートが動いていれば拒否する。
//
// 条件こそが要点のすべてである。最初の書き込みには If-None-Match: *、それ以降の
// すべての書き込みには If-Match: <最後に見た ETag>。これにより、どの push も別の
// マシンの作業を黙って踏み潰せない — それが、これについて「自動」という語を安全に
// 使えるようにしている。
func (s *Service) Push(ctx context.Context, passphrase string) error {
	binding, err := s.configuredBinding()
	if err != nil {
		return err
	}
	if binding.config.Direction == DirectionPull {
		return ErrPushRefused
	}
	client := binding.client
	current, err := s.readState()
	if err != nil {
		return err
	}
	if current.Origin == "" {
		if current.Origin, err = s.newOrigin(); err != nil {
			return err
		}
	}

	manifest, contents, err := s.Collect()
	if err != nil {
		return err
	}
	manifest.Origin = current.Origin
	archive, err := Build(manifest, contents)
	if err != nil {
		return err
	}
	key, err := envelope.Derive(passphrase)
	if err != nil {
		return err
	}
	sealed, err := key.Seal(archive)
	if err != nil {
		return err
	}

	objectKey := ObjectKeyFor(binding.config)
	if current.Key != objectKey {
		// 別のオブジェクトの世代は、このオブジェクトについて何も語らない。
		// If-None-Match へフォールバックすることは、push がオブジェクトを作り、
		// すでに誰かが置いたものの上には書かないことを意味する。
		current.ETag = ""
	}
	ifMatch, ifNoneMatch := current.ETag, ""
	if ifMatch == "" {
		ifNoneMatch = "*"
	}
	// 日付付きのコピーが先。それが失敗すれば push は何も中途半端に残さず失敗する。
	// ライブの書き込みがそのあと競争に負けても、残るのはこのマシンがその時刻に確かに
	// 作ったスナップショットであり、それはそのフォルダが保持していると述べている
	// ものそのものである。
	dated, err := SnapshotKeyFor(binding.config, manifest.CreatedAt)
	if err != nil {
		return err
	}
	if _, err := client.Put(ctx, dated, sealed, "", ""); err != nil {
		return err
	}

	etag, err := client.Put(ctx, objectKey, sealed, ifMatch, ifNoneMatch)
	if err != nil {
		if errors.Is(err, objectstore.ErrPreconditionFailed) {
			return ErrRemoteMoved
		}
		return err
	}
	return s.writeState(state{ETag: etag, Key: objectKey, Base: &manifest, Origin: current.Origin})
}

// PullResult は、適用する前の、pull が行うであろう内容。
type PullResult struct {
	Request   storage.Request
	Conflicts []Conflict
	Manifest  Manifest
	ETag      string
	Origin    string
	objectKey string
}

// Pull はスナップショットを取得し、それを適用すると何が変わるかを算出する。
//
// 何も書かない。Apply を別の呼び出しにしてあるのは、書き込みの前に必ず見せる
// プレビューを、このアプリケーションの他の部分と同じくユーザーに見せるためである。
func (s *Service) Pull(ctx context.Context, passphrase string) (PullResult, error) {
	binding, err := s.configuredBinding()
	if err != nil {
		return PullResult{}, err
	}
	objectKey := ObjectKeyFor(binding.config)
	object, err := binding.client.Get(ctx, objectKey)
	if err != nil {
		if errors.Is(err, objectstore.ErrNotFound) {
			return PullResult{}, ErrNoSnapshot
		}
		return PullResult{}, err
	}
	// この envelope の中のパラメータを選んだのは、それを書いた誰かであって、必ずしも
	// このインストールではない。他人のスナップショットが、パスフレーズの誤りが判明
	// する前にこのマシンへ 1 ギガバイトと 16 スレッドを費やさせられるようであっては
	// ならない。
	archive, _, err := envelope.OpenWithin(object.Body, passphrase, envelope.AcceptedFromRemote)
	if err != nil {
		return PullResult{}, err
	}
	manifest, contents, err := Read(archive)
	if err != nil {
		return PullResult{}, err
	}

	current, err := s.readState()
	if err != nil {
		return PullResult{}, err
	}
	local, err := s.localDigests(manifest, current.Base)
	if err != nil {
		return PullResult{}, err
	}

	request, conflicts, err := Plan(s.workspace.Root(), current.Base, local, manifest, contents)
	if err != nil && !errors.Is(err, ErrNothingToApply) {
		return PullResult{}, err
	}
	return PullResult{
		Request: request, Conflicts: conflicts, Manifest: manifest,
		ETag: object.ETag, Origin: manifest.Origin, objectKey: objectKey,
	}, err
}

// Apply は pull をコミットする。どれかのファイルが衝突しているあいだは拒否する。
// 半分だけ適用すれば、どちらの側とも一致しないワークスペースになるからだ。
func (s *Service) Apply(result PullResult) error {
	// direction は Pull ではなくここで検査する。プレビューは何も書かないので、
	// 送信専用のマシンでも、どれだけ遅れているかは知ることができる。
	// これが、別のマシンのバイト列をこのディスクへ置く呼び出しである。
	if s.Direction() == DirectionPush {
		return ErrApplyRefused
	}
	if len(result.Conflicts) > 0 {
		return ErrConflicts
	}
	if len(result.Request.Changes)+len(result.Request.Removals) > 0 {
		// 別のマシンからのスナップショットは、このマシンにはないかもしれない
		// ディレクトリ — connections/work/、keys/work/ — を名指しする。そして
		// トランザクションマネージャが所有するのはファイルであってディレクトリでは
		// ない。ResolveForWrite は、親のない書き込みを拒否する。そこで、その
		// ディレクトリを同じリクエストに載せる。以前はジャーナルの外で作っており、
		// mkdir とコミットのあいだで落ちれば空のディレクトリが残った。
		result.Request.Directories = append(result.Request.Directories,
			changeDirectories(s.workspace.Root(), result.Request.Changes)...)
		if _, err := s.transactions.Commit(result.Request); err != nil {
			return err
		}
	}
	current, err := s.readState()
	if err != nil {
		return err
	}
	origin := current.Origin
	if origin == "" {
		if origin, err = s.newOrigin(); err != nil {
			return err
		}
	}
	manifest := result.Manifest
	return s.writeState(state{ETag: result.ETag, Key: result.objectKey, Base: &manifest, Origin: origin})
}

// changeDirectories は、変更が着地する先のディレクトリを重複なく返す。
//
// 直接の親だけでよい。DirectoryCreate はルートより下で欠けている親も作るので、
// 設定エンジンの書き手が渡しているのと同じものである。
func changeDirectories(root string, changes []storage.Change) []storage.DirectoryCreate {
	seen := map[string]bool{}
	var directories []storage.DirectoryCreate
	for _, change := range changes {
		parent := filepath.Dir(change.Path)
		if parent == root || seen[parent] {
			continue
		}
		seen[parent] = true
		directories = append(directories, storage.DirectoryCreate{Path: parent})
	}
	return directories
}

// localDigests は、どちらかの側が知っているすべてのパスをハッシュする。これにより、
// このディスク上にあってどちらのマニフェストにもないファイルは、参照も変更もされない。
func (s *Service) localDigests(remote Manifest, base *Manifest) (map[string]string, error) {
	paths := map[string]bool{}
	for _, item := range remote.Files {
		paths[item.Path] = true
	}
	if base != nil {
		for _, item := range base.Files {
			paths[item.Path] = true
		}
	}

	digests := map[string]string{}
	for path := range paths {
		body, err := s.workspace.FileSystem().ReadFile(filepath.Join(s.workspace.Root(), filepath.FromSlash(path)))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		digests[path] = Digest(body)
	}
	return digests, nil
}

func (s *Service) statePath() string {
	return filepath.Join(s.workspace.Root(), filepath.FromSlash(StatePath))
}

func (s *Service) readState() (state, error) {
	body, err := s.workspace.FileSystem().ReadFile(s.statePath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return state{}, nil
		}
		return state{}, err
	}
	var parsed state
	if err := json.Unmarshal(body, &parsed); err != nil {
		// 壊れた state ファイルは回復可能である。次の pull はこのマシンを、一度も
		// 同期していないマシンとして扱う。それは保守的な扱いだ — 何も削除せず、
		// 推測する代わりに衝突として報告する。
		return state{}, nil
	}
	return parsed, nil
}

func (s *Service) writeState(next state) error {
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := s.workspace.EnsureDirectory(s.workspace.StateDir()); err != nil {
		return err
	}
	precondition := storage.Precondition{}
	if current, err := s.workspace.FileSystem().ReadFile(s.statePath()); err == nil {
		precondition = storage.Precondition{Exists: true, Digest: storage.Digest(current)}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, err = s.transactions.Commit(storage.Request{
		Operation: "sync.state",
		Changes: []storage.Change{{
			Path:         s.statePath(),
			Contents:     body,
			Precondition: precondition,
			// state は秘密を何も名指ししないが、このアプリケーション自身のファイルで
			// あり、同期のたびにその世代が増えるのは、バックアップディレクトリの中の
			// 雑音でしかない。
			SkipBackup: true,
		}},
	})
	return err
}

// Target は、この実行が指しているエンドポイントとバケットを、表示のために返す。
// アクセスキーと秘密が何かによって返されることは決してない。
func (s *Service) Target() (endpoint, bucket, path, region string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binding.config.Endpoint, s.binding.config.Bucket, s.binding.config.Path, s.binding.config.Region
}

// LastSync は、state ファイルから、このマシンが最後に同期した内容を報告する。
func (s *Service) LastSync() (synced bool, at, origin string, files int) {
	current, err := s.readState()
	if err != nil || current.ETag == "" || current.Base == nil {
		return false, "", "", 0
	}
	return true, current.Base.CreatedAt, current.Base.Origin, len(current.Base.Files)
}

// DisplayPath は、ワークスペースの絶対パスを、このアプリケーションの他の部分が
// 表示する相対パスへ戻す。
func (s *Service) DisplayPath(absolute string) string {
	relative, err := filepath.Rel(s.workspace.Root(), absolute)
	if err != nil {
		return filepath.Base(absolute)
	}
	return filepath.ToSlash(relative)
}
