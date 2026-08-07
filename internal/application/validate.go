package application

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"sshc/internal/config"
	"sshc/internal/storage"
)

// SyntaxError は、新しい内容を表現できない save を拒否する。これは
// location を運ぶが、ファイルの内容を運ぶことは決してない。
type SyntaxError struct {
	Path   string
	Line   int
	Column int
	Detail string
}

func (e *SyntaxError) Error() string {
	return "configuration syntax error at line " + strconv.Itoa(e.Line)
}

// GraphError は、新しい Include graph のエラーを持ち込む save を拒否する。
type GraphError struct {
	Diagnostics []DiagnosticView
}

func (e *GraphError) Error() string { return "include graph error" }

// ConflictError は、ディスク上のファイルが編集時のものと違うことを報告する。
type ConflictError struct {
	Report ConflictReport
}

func (e *ConflictError) Error() string { return "external change detected" }

// overlayLoader は、resolver に、transaction が作成しようとしている
// ファイルを含め、これから書き込もうとしている内容を見せ、
// そしてこれから取り去ろうとしているファイルを見えなくする。
//
// gone は最適化ではない。ファイルを移動する transaction は、
// destination にそれを書き込み source からそれを取り除くので、
// pending だけを運ぶ overlay は、そのファイルが両方の場所に同時に
// 存在する世界に対して graph を解決してしまうことになる。Include glob は 2
// 回 match し、存在しなくなるはずの重複 alias が報告され、move が実際には直している
// diagnostic が依然として存在するように見えてしまう。removal についても同じことが言える。
type overlayLoader struct {
	base    config.Loader
	pending map[string][]byte
	gone    map[string]bool
}

func (loader overlayLoader) ReadFile(name string) ([]byte, error) {
	cleaned := filepath.Clean(name)
	if contents, ok := loader.pending[cleaned]; ok {
		return contents, nil
	}
	// pending は gone に勝つので、ファイルを、自らも削除する path へ
	// 移動する transaction は、何も報告しないのではなく新しい内容を読む。
	if loader.gone[cleaned] {
		return nil, fs.ErrNotExist
	}
	return loader.base.ReadFile(name)
}

func (loader overlayLoader) Glob(pattern string) ([]string, error) {
	found, err := loader.base.Glob(pattern)
	if err != nil {
		return nil, err
	}
	matches := make([]string, 0, len(found))
	seen := make(map[string]bool, len(found))
	for _, match := range found {
		cleaned := filepath.Clean(match)
		if loader.gone[cleaned] && loader.pending[cleaned] == nil {
			continue
		}
		matches = append(matches, match)
		seen[cleaned] = true
	}
	for name := range loader.pending {
		if seen[name] {
			continue
		}
		matched, matchErr := filepath.Match(pattern, name)
		if matchErr != nil {
			return nil, matchErr
		}
		if matched {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

// overlayFor は、リクエストが生み出そうとしている filesystem を記述
// する。それが書き込む内容と、もはやそこに無くなる path である。
// move はその両方に寄与する。その destination が到着し、その source が去るからである。
func overlayFor(request storage.Request) (map[string][]byte, map[string]bool) {
	pending := make(map[string][]byte, len(request.Changes)+len(request.Moves))
	gone := make(map[string]bool, len(request.Moves)+len(request.Removals))
	for _, change := range request.Changes {
		pending[filepath.Clean(change.Path)] = change.Contents
	}
	for _, move := range request.Moves {
		gone[filepath.Clean(move.From)] = true
	}
	for _, removal := range request.Removals {
		gone[filepath.Clean(removal.Path)] = true
	}
	return pending, gone
}

// diagnosticKey は diagnostic を識別し、save が、設定が既に抱えていた
// 問題によってではなく、それ自身が持ち込む問題によってのみ block されるようにする。
func diagnosticKey(diagnostic config.Diagnostic) string {
	return diagnostic.Code + "\x00" + diagnostic.Path + "\x00" + strconv.Itoa(diagnostic.Line)
}

func diagnosticBaseline(graph *config.Graph) map[string]bool {
	baseline := make(map[string]bool, len(graph.Diagnostics))
	for _, diagnostic := range graph.Diagnostics {
		baseline[diagnosticKey(diagnostic)] = true
	}
	return baseline
}

// newUnstructuredLine は、編集が parse 不能にしてしまった行を見つける。
// 既に parse 不能だった行は許され続ける。エンジンはそれらを逐語的に
// 保存し、ユーザーは徐々にしか直せないかもしれないからである。
func newUnstructuredLine(before, after *config.File) (line, column int, found bool) {
	known := map[string]int{}
	if before != nil {
		for _, existing := range before.Lines {
			if existing.Kind == config.LineUnstructured {
				known[existing.Text]++
			}
		}
	}
	for index, candidate := range after.Lines {
		if candidate.Kind != config.LineUnstructured {
			continue
		}
		if known[candidate.Text] > 0 {
			known[candidate.Text]--
			continue
		}
		return index + 1, unstructuredColumn(candidate.Text), true
	}
	return 0, 0, false
}

func unstructuredColumn(text string) int {
	if index := strings.IndexByte(text, '"'); index >= 0 {
		return index + 1
	}
	return 1
}

// validate は storage.Manager.Validate として設置されるので、
// 事前条件がチェックされた後、何かが journal 化・stage・rename される
// 前に実行される。これはすべての新しい設定ファイルを parse し、
// その parse が同じバイト列へ描き戻せることを証明し、新たに parse
// 不能になった行を拒否し、pending の内容を重ねた状態で Include graph 全体を再解決する。
//
// これは設定だけを validate し、他の何も validate しない。ワークスペース
// の状態ディレクトリの中にあるファイル——metadata.json、journal、
// backup、password vault——はこのアプリケーション自身のものであり、
// ssh_config ではない。それらを ssh_config であるかのように parse する
// ことは、単に無意味であるだけではない。password vault は ciphertext であり、ランダム
// なバイト列がたまたま奇数個の引用符を含んでしまった blob は"unbalanced quoting"
// として拒否されていた。それは save のたびのコイン投げであり、これが見つかった経緯
// である——パスワードを保存した end-to-end テストは、local では通り CI では失敗した。
func (s *Service) validate(request storage.Request) error {
	pending, gone := overlayFor(request)

	metadataPath := filepath.Clean(s.metadata.Path())
	stateDir := filepath.Clean(s.workspace.StateDir())
	for _, change := range request.Changes {
		cleaned := filepath.Clean(change.Path)
		if cleaned == metadataPath {
			if _, err := DecodeMetadata(change.Contents); err != nil {
				return err
			}
			continue
		}
		// sshc/配下のそれ以外のものはすべてアプリケーションの状態であり、
		// OpenSSH に読まれることも、Include graph の一部になることも決してない。
		if isInside(stateDir, cleaned) {
			continue
		}
		parsed := config.Parse(change.Contents)
		if !bytes.Equal(parsed.Render(), change.Contents) {
			return &SyntaxError{Path: s.displayPath(cleaned), Line: 1, Column: 1, Detail: "parsed file does not render back to the same bytes"}
		}
		var base *config.File
		if contents, ok := s.pendingBase[cleaned]; ok {
			base = config.Parse(contents)
		}
		if line, column, found := newUnstructuredLine(base, parsed); found {
			return &SyntaxError{Path: s.displayPath(cleaned), Line: line, Column: column, Detail: "unbalanced quoting"}
		}
	}

	// OpenSSH が読む何にも触れないリクエストは、Include graph を変えている
	// はずがないので、解決可能な graph を生み出すことを求められない。
	// vault は sshc/配下にあり、アプリケーション全体がその向こう側にある。
	// これが無ければ、config ファイルが無いか壊れているワークスペースは、
	// master password を設定できないワークスペースになってしまい、壊れた
	// 設定を直すためのツールが、設定が壊れているという理由で起動を拒否することになる。
	if !s.touchesConfiguration(request) {
		return nil
	}

	resolver := s.resolver
	resolver.Loader = overlayLoader{base: s.resolver.Loader, pending: pending, gone: gone}
	graph, err := resolver.Resolve(s.entryPath)
	if err != nil {
		return err
	}
	var introduced []DiagnosticView
	for _, diagnostic := range graph.Diagnostics {
		if diagnostic.Severity != config.SeverityError || s.pendingBaseline[diagnosticKey(diagnostic)] {
			continue
		}
		introduced = append(introduced, NewDiagnosticView(s.workspace.Root(), diagnostic))
	}
	if len(introduced) > 0 {
		return &GraphError{Diagnostics: introduced}
	}
	return nil
}

// touchesConfiguration は、リクエストの中のどれかの path が、OpenSSH が
// 読み得る場所であるかどうかを報告する。metadata 文書はこの
// アプリケーション自身のものだが、状態ディレクトリの内側ではなく隣に置かれているので、
// ここでも名指される——それを変えても graph を変えることはできないからである。
func (s *Service) touchesConfiguration(request storage.Request) bool {
	stateDir := filepath.Clean(s.workspace.StateDir())
	metadataPath := filepath.Clean(s.metadata.Path())
	outside := func(path string) bool {
		cleaned := filepath.Clean(path)
		return cleaned != metadataPath && !isInside(stateDir, cleaned)
	}
	for _, change := range request.Changes {
		if outside(change.Path) {
			return true
		}
	}
	for _, move := range request.Moves {
		if outside(move.From) || outside(move.To) {
			return true
		}
	}
	for _, removal := range request.Removals {
		if outside(removal.Path) {
			return true
		}
	}
	// このアプリケーションが作成または削除するディレクトリは、常に
	// グループのディレクトリか自分自身のもののどちらかでしかなく、
	// グループのディレクトリは Include が届く範囲を変える。
	return len(request.Directories) > 0 || len(request.RemoveDirectories) > 0
}

// isInside は、path が directory それ自体かその下にあるかを報告する。
// これは文字列の前方一致ではなく、クリーニング済みの path を構成要素ごとに比較するので、
// sshc-backup という名前の兄弟が sshc の子であると誤認されることはない。
func isInside(directory, path string) bool {
	if path == directory {
		return true
	}
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
