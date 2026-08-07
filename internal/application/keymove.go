package application

import (
	"errors"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"sshc/internal/config"
	"sshc/internal/keys"
	"sshc/internal/storage"
)

var (
	// ErrKeyRelocateNotSupported は、鍵ではないエントリと、鍵ペアの
	// 片方だけを拒否する。
	ErrKeyRelocateNotSupported = errors.New("only a private key, or a public key with no private key beside it, can be relocated")
	// ErrKeyRelocateUnchanged は、何も移動しないリクエストを拒否する。
	ErrKeyRelocateUnchanged = errors.New("the key already has that name in that group")
	// ErrKeyRelocateBlocked は、このアプリケーションが書き換え
	// られない参照を残してしまう relocation を拒否する。
	ErrKeyRelocateBlocked = errors.New("relocating this key would leave a reference behind")
	// ErrKeyReferenceMoved は、relocation の準備中に変更された
	// 設定ファイルを報告する。
	ErrKeyReferenceMoved = errors.New("a configuration file changed while the relocation was being prepared")
)

// Blocker コードは、安定した識別子、':'、それが名指しする詳細である。
const (
	BlockerKeyTargetOccupied    = "key_destination_occupied"
	BlockerKeyUnresolved        = "key_reference_unresolved"
	BlockerKeyReferenceExternal = "key_reference_outside_workspace"
	BlockerKeyGroupNotDeclared  = "key_group_not_declared"
	BlockerKeyDestinationRead   = "key_destination_is_config"
	BlockerKeyStateDirectory    = "key_in_state_directory"
)

// NoteKeychainEntryStale は、ユーザーが Keychain エントリを
// 作っていた場合、それが以前のパスの下で鍵を名指ししたままであることを報告する。
const NoteKeychainEntryStale = "keychain_entry_stale"

// KeyRelocateRequest は、鍵の名前、グループ、あるいはその両方を変更する。
//
// nil フィールドは「これはそのままにする」を意味し、これに
// よって 1 つの操作が名前変更、グループ間の移動、両方同時のいずれ
// にも対応できる。Group が string ではなく pointer なのは、
// "" が実在の destination — ungrouped な鍵が住む ~/.ssh のルート — だからだ。
type KeyRelocateRequest struct {
	KeyID   string
	NewName *string
	Group   *string
}

// RelocatedKeyFile は relocation が移動した 1 つのファイルをワークスペース相対パスで表す。
type RelocatedKeyFile struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// RewrittenKeyReference は、relocation が更新した 1 つの設定ディレクティブである。
type RewrittenKeyReference struct {
	Directive  string `json:"directive"`
	ConfigPath string `json:"configPath"`
	Line       int    `json:"line"`
	From       string `json:"from"`
	To         string `json:"to"`
}

// KeyRelocateResult は、relocation が行ったこと、あるいはそれを止めたものである。
type KeyRelocateResult struct {
	ID            string                  `json:"id"`
	RelativePath  string                  `json:"relativePath"`
	Group         string                  `json:"group"`
	Files         []RelocatedKeyFile      `json:"files"`
	References    []RewrittenKeyReference `json:"references"`
	Skipped       []string                `json:"skipped"`
	Notes         []string                `json:"notes"`
	Blockers      []string                `json:"blockers"`
	TransactionID string                  `json:"transactionId"`
	Preview       SavePreview             `json:"preview"`
}

// ValidateDeclaredGroup は、あるグループが名前として解析でき、
// かつエントリファイルの生成領域によって宣言されているかを報告する。
//
// これは、別のパッケージがこのパッケージのユースケース層全体を
// import せずに、また自分で決めることもなく、グループとは
// 何かを尋ねられるように存在する: 鍵 vault は、~/.ssh/config の行が
// そのディレクトリはグループだと言っている場合にのみ、グループディレクトリの中に生成する。
func (s *Service) ValidateDeclaredGroup(name string) error {
	if err := ValidateGroupName(name); err != nil {
		return err
	}
	graph, err := s.resolve()
	if err != nil {
		return err
	}
	for _, declared := range s.declaredGroups(graph) {
		if declared == name {
			return nil
		}
	}
	return ErrGroupNotDeclared
}

// keyRelocation は、1 つのファイルについて計画された 1 件の移動である。
type keyRelocation struct {
	from string
	to   string
}

// RelocateKey は鍵を移動し、それを名指しするすべての設定
// ディレクティブを、設定マネージャを通してコミットされる
// 1 つのジャーナル済みトランザクションで書き換える。
//
// このマネージャが重要だ。鍵 vault は独自のものを持ち、意図的に設定
// バリデータを持たない。秘密鍵と JSON マニフェストを書き込むが、それらは
// 構文エラーとして拒否されてしまうからだ。relocation は逆のケースである:
// その危険な半分は設定の書き換えであり、1 バイトが着地する前に再パース・
// 再解決されなければならない。鍵ファイルは storage.Move として運ばれ、
// バリデータはそれを一切パースしないので、両方の半分が必要な扱いを受ける。
//
// 推測するのではなく拒否する。パスを解決できないディレクティブは
// この鍵かもしれない。~/.ssh の外の設定ファイルはそもそも
// 書き換えられない。Include glob が読むことになる destination は
// 秘密鍵を設定に変えてしまう。これらはそれぞれトランザクション全体を止め、報告される。
func (s *Service) RelocateKey(inventory *keys.Inventory, request KeyRelocateRequest) (KeyRelocateResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()

	prepared, result, err := s.planKeyRelocation(inventory, request)
	if err != nil {
		return result, err
	}
	for _, directory := range prepared.directories {
		if err := s.workspace.EnsureDirectory(directory); err != nil {
			return KeyRelocateResult{}, err
		}
	}

	s.pendingBase = prepared.base
	s.pendingBaseline = prepared.baseline
	defer func() { s.pendingBase, s.pendingBaseline = nil, nil }()

	committed, err := s.manager.Commit(storage.Request{
		Operation: prepared.operation,
		Changes:   prepared.changes,
		Moves:     prepared.moves,
	})
	var conflict *storage.ConflictError
	if errors.As(err, &conflict) {
		cleaned := filepath.Clean(conflict.Path)
		var edited []byte
		for _, change := range prepared.changes {
			if filepath.Clean(change.Path) == cleaned {
				edited = change.Contents
			}
		}
		return KeyRelocateResult{}, &ConflictError{Report: BuildConflictReport(
			s.displayPath(cleaned), prepared.base[cleaned], conflict.Current, edited,
		)}
	}
	if err != nil {
		return KeyRelocateResult{}, err
	}
	result.TransactionID = committed.ID
	return result, nil
}

// PreviewKeyRelocation は同じトランザクションを準備し、何も
// 書き込まずにそれが行うはずのことを返す。
func (s *Service) PreviewKeyRelocation(inventory *keys.Inventory, request KeyRelocateRequest) (KeyRelocateResult, error) {
	s.saveMutex.Lock()
	defer s.saveMutex.Unlock()
	_, result, err := s.planKeyRelocation(inventory, request)
	return result, err
}

func (s *Service) planKeyRelocation(inventory *keys.Inventory, request KeyRelocateRequest) (planned, KeyRelocateResult, error) {
	graph, err := s.resolve()
	if err != nil {
		return planned{}, KeyRelocateResult{}, err
	}
	item, ok := inventory.Find(request.KeyID)
	if !ok {
		return planned{}, KeyRelocateResult{}, keys.ErrUnknownKey
	}
	members, skipped, err := keyRelocationMembers(inventory, item)
	if err != nil {
		return planned{}, KeyRelocateResult{}, err
	}

	stem := keyStem(item)
	newStem := stem
	if request.NewName != nil {
		newStem = *request.NewName
		if err := keys.ValidateFileName(newStem); err != nil {
			return planned{}, KeyRelocateResult{}, err
		}
	}
	group, _ := GroupOfKeyPath(item.RelativePath)
	newGroup := group
	if request.Group != nil {
		newGroup = *request.Group
		if newGroup != "" {
			if err := ValidateGroupName(newGroup); err != nil {
				return planned{}, KeyRelocateResult{}, err
			}
		}
	}
	if newStem == stem && newGroup == group {
		return planned{}, KeyRelocateResult{}, ErrKeyRelocateUnchanged
	}

	directory := path.Dir(filepath.ToSlash(item.RelativePath))
	if request.Group != nil {
		directory = "."
		if newGroup != "" {
			directory = GroupKeyDirectory(newGroup)
		}
	}
	relocations := make([]keyRelocation, 0, len(members))
	for _, member := range members {
		suffix := strings.TrimPrefix(path.Base(filepath.ToSlash(member.RelativePath)), stem)
		relocations = append(relocations, keyRelocation{
			from: member.RelativePath,
			to:   path.Join(directory, newStem+suffix),
		})
	}

	result := KeyRelocateResult{
		ID:           keys.ItemID(relocations[0].to),
		RelativePath: relocations[0].to,
		Group:        newGroup,
		Files:        make([]RelocatedKeyFile, 0, len(relocations)),
		References:   []RewrittenKeyReference{},
		Skipped:      skipped,
		Notes:        []string{},
		Blockers:     []string{},
	}
	if item.Kind == keys.KindPrivateKey {
		// ログイン Keychain に保存されたパスフレーズは、鍵の絶対パスの
		// 下に登録される。macOS がそのエントリを所有しているので、
		// ここでは何もそれを移動できず、このアプリケーションは
		// Keychain を読まないので、存在するかどうかさえ判別できない。
		result.Notes = append(result.Notes, NoteKeychainEntryStale)
	}

	blockers := s.keyRelocationBlockers(graph, inventory, members, relocations, newGroup, request.Group != nil)
	if len(blockers) > 0 {
		result.Blockers = blockers
		return planned{}, result, ErrKeyRelocateBlocked
	}

	prepared := planned{
		operation: "key.relocate",
		base:      map[string][]byte{},
		baseline:  diagnosticBaseline(graph),
		preview:   SavePreview{Operation: "key.relocate"},
	}
	root := s.workspace.Root()
	for _, relocation := range relocations {
		absoluteFrom := filepath.Join(root, filepath.FromSlash(relocation.from))
		contents, readErr := s.workspace.FileSystem().ReadFile(absoluteFrom)
		if readErr != nil {
			return planned{}, KeyRelocateResult{}, readErr
		}
		digest := storage.Digest(contents)
		keys.Wipe(contents)
		prepared.moves = append(prepared.moves, storage.Move{
			From:         absoluteFrom,
			To:           filepath.Join(root, filepath.FromSlash(relocation.to)),
			Precondition: storage.Precondition{Exists: true, Digest: digest},
		})
		result.Files = append(result.Files, RelocatedKeyFile{From: relocation.from, To: relocation.to})
	}
	if directory != "." {
		absolute, dirErr := AbsolutePath(root, directory)
		if dirErr != nil {
			return planned{}, KeyRelocateResult{}, dirErr
		}
		prepared.directories = append(prepared.directories, absolute)
	}

	changes, rewritten, err := s.rewriteKeyReferences(members, relocations)
	if err != nil {
		return planned{}, KeyRelocateResult{}, err
	}
	prepared.changes = changes
	result.References = rewritten
	for _, change := range changes {
		previous, _, readErr := s.readFile(change.Path)
		if readErr != nil {
			return planned{}, KeyRelocateResult{}, readErr
		}
		prepared.base[filepath.Clean(change.Path)] = previous
		prepared.preview.Diffs = append(prepared.preview.Diffs,
			BuildFileDiff(s.displayPath(change.Path), previous, change.Contents))
	}
	result.Preview = prepared.preview
	return prepared, result, nil
}

// keyRelocationMembers は 1 件の relocation が移動するファイルを対象アイテムから順に返す。
//
// 秘密鍵は、その fingerprint を持ち、同じ名前の下でそばに
// 置かれている公開鍵と証明書ファイルを一緒に連れていく。
// fingerprint を共有する他のものはそのまま残され、名指しされる。ユーザー
// が無関係な名前を付けたファイルは、ユーザーが意図的にそう名付けたファイルだからだ。
//
// 公開鍵や証明書は単独でしか relocate できず、インベントリ
// 中にそれを所有する秘密鍵がない場合に限られる: OpenSSH は
// それでも 2 つのファイルを名前で対にするので、片方だけ移動するとペアを黙って壊してしまう。
func keyRelocationMembers(inventory *keys.Inventory, item *keys.Item) (members []keys.Item, skipped []string, err error) {
	switch item.Kind {
	case keys.KindPrivateKey:
		stem := path.Base(filepath.ToSlash(item.RelativePath))
		directory := path.Dir(filepath.ToSlash(item.RelativePath))
		members = append(members, *item)
		for _, candidate := range inventory.Group(item) {
			if candidate.ID == item.ID {
				continue
			}
			base := path.Base(filepath.ToSlash(candidate.RelativePath))
			if path.Dir(filepath.ToSlash(candidate.RelativePath)) != directory || !strings.HasPrefix(base, stem) {
				skipped = append(skipped, candidate.RelativePath)
				continue
			}
			members = append(members, candidate)
		}
		sort.Strings(skipped)
		return members, skipped, nil
	case keys.KindPublicKey, keys.KindCertificate:
		if privateKeyFor(inventory, item) {
			return nil, nil, ErrKeyRelocateNotSupported
		}
		return []keys.Item{*item}, nil, nil
	default:
		return nil, nil, ErrKeyRelocateNotSupported
	}
}

// privateKeyFor は、インベントリ中の秘密鍵がこの公開鍵や
// 証明書を所有しているかどうかを報告する。
func privateKeyFor(inventory *keys.Inventory, item *keys.Item) bool {
	fingerprint := item.Fingerprint
	if item.Kind == keys.KindCertificate && item.Certificate != nil {
		fingerprint = item.Certificate.SignedKeyFingerprint
	}
	if fingerprint == "" {
		return false
	}
	for index := range inventory.Items {
		candidate := &inventory.Items[index]
		if candidate.Kind == keys.KindPrivateKey && candidate.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// keyStem は、移動するすべてのファイルが共有するベース名の部分である。
//
// 秘密鍵にとってそれは名前全体である: OpenSSH は '.pub' を
// 付加して公開鍵の名前を導出し、ValidateFileName は既にその
// 綴りの秘密鍵の作成を拒否する。単独で relocate される公開鍵や
// 証明書にとっては、拡張子がそのファイルが何であるかを示すので
// それは保たれ、stem だけが変わる: 'old.pub' を 'new' に名前変更すると 'new.pub' になる。
func keyStem(item *keys.Item) string {
	base := path.Base(filepath.ToSlash(item.RelativePath))
	if item.Kind == keys.KindPrivateKey {
		return base
	}
	for _, suffix := range []string{"-cert.pub", ".pub"} {
		if trimmed := strings.TrimSuffix(base, suffix); trimmed != base && trimmed != "" {
			return trimmed
		}
	}
	return base
}

// keyRelocationBlockers は、この relocation が推測を要する
// すべての理由を報告する。各 blocker はトランザクション全体を拒否し、何も書き込まれない。
func (s *Service) keyRelocationBlockers(
	graph *config.Graph,
	inventory *keys.Inventory,
	members []keys.Item,
	relocations []keyRelocation,
	group string,
	groupRequested bool,
) []string {
	blockers := make([]string, 0)
	root := s.workspace.Root()

	if groupRequested && group != "" {
		declared := false
		for _, name := range s.declaredGroups(graph) {
			if name == group {
				declared = true
				break
			}
		}
		if !declared {
			// 鍵グループは connection グループを反映する。誰も宣言していない
			// グループのために keys/marketing を作るのは、この設計が避ける推測である。
			blockers = append(blockers, BlockerKeyGroupNotDeclared+":"+group)
		}
	}

	for _, relocation := range relocations {
		absolute := filepath.Join(root, filepath.FromSlash(relocation.to))
		if _, err := s.workspace.FileSystem().Lstat(absolute); err == nil {
			blockers = append(blockers, BlockerKeyTargetOccupied+":"+relocation.to)
		}
		if strings.HasPrefix(relocation.to+"/", keys.StateDirectoryName+"/") ||
			strings.HasPrefix(relocation.from+"/", keys.StateDirectoryName+"/") {
			// ごみ箱、バックアップ、ジャーナルはエンジンの状態である。
			// インベントリは既にそれらを除外しており、これは同じ扉の 2 番目の鍵である。
			blockers = append(blockers, BlockerKeyStateDirectory+":"+relocation.to)
		}
		if reachedByInclude(graph, absolute) {
			// 秘密鍵が ssh_config として読まれるのはあり得る中で最悪の結果
			// であり、Include glob が届く destination は端から拒否される。
			blockers = append(blockers, BlockerKeyDestinationRead+":"+relocation.to)
		}
	}

	for _, member := range members {
		for _, reference := range member.References {
			if !s.workspace.Contains(reference.ConfigPath) {
				// 設計 §5.3 は ~/.ssh の外への書き込みを禁じる。それでも鍵を
				// 移動すれば、そのファイルが消えたパスを名指ししたままになる。
				blockers = append(blockers, BlockerKeyReferenceExternal+":"+s.displayPath(reference.ConfigPath))
			}
		}
	}
	for _, unresolved := range inventory.UnresolvedReferences {
		if risk := unresolvedKeyRisk(unresolved, members); risk != "" {
			blockers = append(blockers, BlockerKeyUnresolved+":"+risk)
		}
	}
	if len(blockers) == 0 {
		return nil
	}
	sort.Strings(blockers)
	return blockers
}

// reachedByInclude は、グラフ中の Include glob がこのパスを
// 読むことになるかどうかを報告する。グラフが既に届いている
// destination は、鍵ファイルが設定としてパースされてしまう destination である。
func reachedByInclude(graph *config.Graph, absolute string) bool {
	cleaned := filepath.Clean(absolute)
	for _, node := range graph.Nodes {
		for _, edge := range node.Includes {
			if edge.Expanded == "" {
				continue
			}
			matched, err := filepath.Match(edge.Expanded, cleaned)
			if err == nil && matched {
				return true
			}
		}
	}
	return false
}

// unresolvedKeyRisk は、エンジンが解決できなかったディレクティブがこの
// relocation が移動するファイルのいずれかを名指ししている可能性があるかどうかを報告する。
//
// ワークスペースの外に解決された確定的な場所は、これらの
// ファイルのどれでもないので影響を受け得ない。相対パスは
// ディレクトリが不明だがベース名は分かっているので、その
// ベース名が移動対象の 1 つである場合にのみ問題になる。この
// エンジンが実装していない展開を含むパスは何にでもなり得るので、常に問題になる。
func unresolvedKeyRisk(unresolved keys.UnresolvedReference, members []keys.Item) string {
	if unresolved.Directive == "IdentityAgent" {
		return ""
	}
	switch unresolved.Reason {
	case keys.ReasonOutsideWorkspace:
		return ""
	case keys.ReasonRelativePath:
		base := path.Base(filepath.ToSlash(unresolved.Value))
		for _, member := range members {
			if path.Base(filepath.ToSlash(member.RelativePath)) == base {
				return unresolved.Value
			}
		}
		return ""
	default:
		return unresolved.Value
	}
}

// rewriteKeyReferences は、移動したファイルを名指しする
// すべてのディレクティブを書き換え、設定ファイルごとに 1 つの変更を生む。
//
// ユーザーが書いた形 — '~/.ssh/…'、'%d/…'、あるいは絶対パス —
// は OpenSSH が解決し、ユーザーが認識するものなので、prefix は
// 生き残り、ワークスペースのルートより下の部分だけが置き換え
// られる。この関数が分解できない形で綴られた値は、代わりに
// 常に解決できる絶対パスとして書き換えられる。
func (s *Service) rewriteKeyReferences(members []keys.Item, relocations []keyRelocation) ([]storage.Change, []RewrittenKeyReference, error) {
	root := s.workspace.Root()
	destinations := make(map[string]string, len(relocations))
	for _, relocation := range relocations {
		destinations[relocation.from] = relocation.to
	}
	byConfigPath := make(map[string][]keys.Reference)
	order := make([]string, 0)
	for _, member := range members {
		for _, reference := range member.References {
			if _, seen := byConfigPath[reference.ConfigPath]; !seen {
				order = append(order, reference.ConfigPath)
			}
			byConfigPath[reference.ConfigPath] = append(byConfigPath[reference.ConfigPath], reference)
		}
	}
	sort.Strings(order)

	changes := make([]storage.Change, 0, len(order))
	rewritten := make([]RewrittenKeyReference, 0)
	for _, configPath := range order {
		contents, err := s.workspace.FileSystem().ReadFile(configPath)
		if err != nil {
			return nil, nil, err
		}
		parsed := config.Parse(contents)
		touched := false

		for _, reference := range byConfigPath[configPath] {
			index := reference.Line - 1
			if index < 0 || index >= len(parsed.Lines) || parsed.Lines[index].Kind != config.LineDirective {
				return nil, nil, ErrKeyReferenceMoved
			}
			line := &parsed.Lines[index]
			for argumentIndex := range line.Arguments {
				argument := &line.Arguments[argumentIndex]
				// OpenSSH の引数リストは、引用されていない '#' で終わるので、
				// それに続くものはコメントであり、書かれたとおりに残される。
				if strings.HasPrefix(argument.Raw, "#") {
					break
				}
				from, moved := relocationFor(destinations, root, s.workspace, argument.Value)
				if !moved {
					continue
				}
				replacement := rewriteKeyValue(argument.Value, from, destinations[from], root)
				rendered, renderErr := config.RenderArgument(argument.Lead, replacement)
				if renderErr != nil {
					return nil, nil, renderErr
				}
				rewritten = append(rewritten, RewrittenKeyReference{
					Directive:  line.Keyword,
					ConfigPath: s.displayPath(configPath),
					Line:       reference.Line,
					From:       argument.Value,
					To:         replacement,
				})
				*argument = rendered
				touched = true
			}
		}
		if !touched {
			continue
		}
		changes = append(changes, storage.Change{
			Path:         configPath,
			Contents:     parsed.Render(),
			Precondition: storage.Precondition{Exists: true, Digest: storage.Digest(contents)},
		})
	}
	return changes, rewritten, nil
}

// relocationFor は、ディレクティブの引数がどの移動先ファイルを名指ししているかを報告する。
func relocationFor(destinations map[string]string, root string, workspace *storage.Workspace, value string) (string, bool) {
	for from := range destinations {
		if keys.ExpandsTo(workspace, value, filepath.Join(root, filepath.FromSlash(from))) {
			return from, true
		}
	}
	return "", false
}

// rewriteKeyValue は、ディレクティブの引数をファイルの新しいパスに合わせて
// 再表現し、ユーザーがワークスペースを名指しするのに使った prefix をそのまま保つ。
func rewriteKeyValue(value, from, to, root string) string {
	if prefix, ok := strings.CutSuffix(filepath.ToSlash(value), from); ok {
		return prefix + to
	}
	return filepath.ToSlash(filepath.Join(root, filepath.FromSlash(to)))
}
