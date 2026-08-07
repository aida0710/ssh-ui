package diagnostics

import (
	"context"
	"errors"
	"net"
	"path/filepath"

	"sshc/internal/config"
	"sshc/internal/effective"
	"sshc/internal/platform"
	"sshc/internal/storage"
)

// ConfigFile は Include グラフのファイルひとつを、表示用に要約したもの。
type ConfigFile struct {
	Path     string
	Editable bool
	Missing  bool
	Loads    int
	Includes int
}

// ConfigReport は構文と Include のチェック。プロセスは何も起動しない。
type ConfigReport struct {
	Root        string
	Files       []ConfigFile
	Diagnostics []config.Diagnostic
}

// Inspection は、実効設定の画面が必要とするすべて。
type Inspection struct {
	Alias                string
	Report               effective.Report
	RequiresConfirmation bool
	Evaluated            bool
	Values               effective.Values
	Projection           effective.Projection
	Route                []effective.Stage
	RouteComplexities    []effective.Complexity
	Failure              *effective.OpenSSHError
}

// Service は、設定エンジンとこのパッケージのチェックを組み合わせる。リクエストの
// たびに設定を読み直す。ファイルこそが真実の源であり、二つのリクエストのあいだに
// 変わりうるからである。
type Service struct {
	Workspace      *storage.Workspace
	Resolver       config.Resolver
	Evaluator      effective.Evaluator
	Reachability   Reachability
	Authentication Authentication
	Terminal       platform.TerminalLauncher
	// Self はこのバイナリの絶対パス。ユーザーに見せるコマンドを、実際に実行できる
	// ものにするためである。アプリケーションの内側には、それがどこにインストール
	// されたかを知るものがない。エントリポイントが一度だけ解決して渡す。空の場合は
	// 素の ssh にフォールバックし、それでも接続はできる。
	Self string
}

// NewService は本番用の依存を配線する。
//
// lookup は親の環境を読む。テストでは nil でもよく、その場合、子はこのプロセスの
// 環境を継承する。本番ではエントリポイントの os.LookupEnv であり、このサービスが
// 起動するすべての OpenSSH プログラムは代わりに platform.MinimalEnvironment を
// 受け取る。SSH_ASKPASS は与えられないので、パスフレーズのプロンプトは、ユーザーが
// たまたまエクスポートしていたプログラムではなく、このアプリケーションが用意する
// 標準入力にしか向かえない。
func NewService(workspace *storage.Workspace, runner platform.OutputRunner, toolchain platform.Toolchain, terminal platform.TerminalLauncher, lookup func(string) (string, bool)) *Service {
	configPath := filepath.Join(workspace.Root(), "config")
	var environment []string
	if lookup != nil {
		environment = platform.MinimalEnvironment(lookup)
	}
	return &Service{
		Workspace:    workspace,
		Resolver:     storage.NewResolver(workspace),
		Evaluator:    effective.Evaluator{Runner: runner, Toolchain: toolchain, ConfigPath: configPath, Environment: environment},
		Reachability: Reachability{Dialer: &net.Dialer{}},
		Authentication: Authentication{
			Runner: runner, Toolchain: toolchain, ConfigPath: configPath, Environment: environment,
		},
		Terminal: terminal,
	}
}

// ConfigPath は、このサービスが評価するユーザー設定。
func (s *Service) ConfigPath() string { return filepath.Join(s.Workspace.Root(), "config") }

// Home はユーザーのホームディレクトリ。取り込んだ出力がこのプロセスから出ていく
// 前に、それを浄化するために使う。
func (s *Service) Home() string { return s.Workspace.Home() }

func (s *Service) graph() (*config.Graph, error) { return s.Resolver.Resolve(s.ConfigPath()) }

// Safety は、現在の設定に実行を伴うディレクティブがないか走査する。
func (s *Service) Safety() (effective.Report, error) {
	graph, err := s.graph()
	if err != nil {
		return effective.Report{}, err
	}
	return effective.Scan(graph), nil
}

// ConfigCheck は、Include グラフとその診断を報告する。
func (s *Service) ConfigCheck() (ConfigReport, error) {
	graph, err := s.graph()
	if err != nil {
		return ConfigReport{}, err
	}
	report := ConfigReport{Root: graph.Root, Diagnostics: graph.Diagnostics}
	for _, path := range graph.Order {
		node := graph.Nodes[path]
		if node == nil {
			continue
		}
		report.Files = append(report.Files, ConfigFile{
			Path:     node.Path,
			Editable: node.Editable,
			Missing:  node.Missing,
			Loads:    node.Loads,
			Includes: len(node.Includes),
		})
	}
	return report, nil
}

// Inspect は alias ひとつを説明し、許されている場合はそれを評価する。
//
// 拒否された評価も、失敗した ssh も、どちらもデータとして返る。画面には、エンジン
// 自身の射影と、先に確認しなければならないコマンドそのものが引き続き表示
// される。
func (s *Service) Inspect(ctx context.Context, alias string, confirmed bool) (Inspection, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Inspection{}, err
	}
	graph, err := s.graph()
	if err != nil {
		return Inspection{}, err
	}

	inspection := Inspection{Alias: alias, Report: effective.Scan(graph)}
	inspection.Projection = effective.Project(graph, alias)
	inspection.Route, inspection.RouteComplexities = effective.ExpandRoute(graph, alias)
	inspection.RequiresConfirmation = inspection.Report.EvaluationNeedsConfirmation()

	values, err := s.Evaluator.Evaluate(ctx, inspection.Report, alias, confirmed)
	var opensshError *effective.OpenSSHError
	switch {
	case err == nil:
		// ssh は絶対パスを報告する — UserKnownHostsFile と既定の IdentityFile 一覧は
		// 常に、ControlPath などは設定されているときに — そして、そのどれもがユーザーの
		// ホームディレクトリで始まる。認証テストの stderr は、書かれたあとに短縮する
		// 処理が入った。一方でこれらの値は、同じ ssh の出力が同じ種類のレスポンスへ
		// 入るものであるにもかかわらず、その処理が入っていなかった。だからここで
		// 行う。
		inspection.Values = sanitiseValues(values, s.Workspace.Home())
		inspection.Evaluated = true
	case errors.Is(err, effective.ErrEvaluationNotConfirmed):
		// 想定内。呼び出し側はまだ確認していない。
	case errors.As(err, &opensshError):
		inspection.Failure = opensshError
	default:
		return Inspection{}, err
	}
	return inspection, nil
}

// Destination は、エンジンが alias に対して射影するホスト名とポートを返す。
//
// ssh を実行しないので、実行を伴うディレクティブによって評価が阻まれている
// あいだも到達性のチェックは機能する。
func (s *Service) Destination(alias string) (string, string, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return "", "", err
	}
	graph, err := s.graph()
	if err != nil {
		return "", "", err
	}
	projection := effective.Project(graph, alias)
	hostname := alias
	if source, ok := projection.Value("hostname"); ok {
		hostname = source.Value
	}
	port := "22"
	if source, ok := projection.Value("port"); ok {
		port = source.Value
	}
	return hostname, port, nil
}

// ProjectedValue は、alias に対するキーワードひとつについてエンジン自身の読みを返す。
//
// Destination と同様にプロセスを起動しないので、実行を伴うディレクティブで評価が
// 阻まれているあいだも、呼び出し側は接続先を記述できる。この値は OpenSSH の答え
// ではなくエンジンの射影であり、それを表示する呼び出し側は、その旨を述べなければ
// ならない。
func (s *Service) ProjectedValue(alias, keyword string) (string, bool) {
	if err := platform.ValidateAlias(alias); err != nil {
		return "", false
	}
	graph, err := s.graph()
	if err != nil {
		return "", false
	}
	source, ok := effective.Project(graph, alias).Value(keyword)
	if !ok {
		return "", false
	}
	return source.Value, true
}

// Reach は接続先へ直接ダイヤルし、ProxyJump を無視する。
func (s *Service) Reach(ctx context.Context, alias string) (ReachabilityResult, error) {
	hostname, port, err := s.Destination(alias)
	if err != nil {
		return ReachabilityResult{}, err
	}
	if err := platform.ValidateHostname(hostname); err != nil {
		return ReachabilityResult{}, err
	}
	return s.Reachability.Check(ctx, hostname, port), nil
}

// ErrTerminalNotConfigured は、端末ランチャーが配線されていないことを報告する。
var ErrTerminalNotConfigured = errors.New("terminal launcher is not configured")

// UnsafeAliasWarning は、なぜその alias がコピー専用なのかを説明する。
const UnsafeAliasWarning = "This alias contains characters that could change the meaning of a command line. Copy the command and check it before running it yourself."

// LaunchTerminal は、alias のための対話セッションを開く。
func (s *Service) LaunchTerminal(ctx context.Context, alias string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	if s.Terminal == nil {
		return ErrTerminalNotConfigured
	}
	return s.Terminal.Launch(ctx, alias)
}

// TerminalCommand は、ユーザーが手で実行するであろうコマンドを返す。
//
// これはこのバイナリと alias である。それがコマンドの全体だからだ。動作中の
// アプリケーションに保存済みパスワードを求め、なければ素の ssh にフォールバック
// する。これが置き換えたのは五つの環境変数とフラグで、それは Terminal のボタンが
// 自前で組み立てているものを手書きにした形にすぎず、そもそも人が打ち込むための
// ものではなかった。
//
// 安全な文字集合の外にある alias が起動されることは決してない。コマンド自体は
// テキストとして返るので、ユーザーは自分で内容を確かめ、引用符で囲める。
func (s *Service) TerminalCommand(alias string) (string, bool, string) {
	command := "ssh -- " + alias
	if s.Self != "" {
		command = s.Self + " " + alias
	}
	if err := platform.ValidateAlias(alias); err != nil {
		return command, false, UnsafeAliasWarning
	}
	return command, true, ""
}

// Authenticate は、alias に対する認証テストを実行する。
//
// 取り込んだ stderr はユーザーに表示されるので、先にホームディレクトリを "~" に
// 書き換える。冗長な OpenSSH の出力は、読んだファイルをすべて絶対パスで名指しする
// ため、そうしないとアカウント名がレスポンスの本文へ運ばれてしまう。
func (s *Service) Authenticate(ctx context.Context, alias string, acknowledged bool) (AuthenticationResult, error) {
	report, err := s.Safety()
	if err != nil {
		return AuthenticationResult{}, err
	}
	result, err := s.Authentication.Test(ctx, report, alias, acknowledged)
	if err != nil {
		return AuthenticationResult{}, err
	}
	result.Stderr = platform.SanitiseHomePaths(result.Stderr, s.Workspace.Home())
	return result, nil
}

// ErrPasswordLaunchUnsupported は、設定された端末では askpass ヘルパーを武装
// できないことを報告する。
var ErrPasswordLaunchUnsupported = errors.New("this terminal cannot open a session with a stored password")

// LaunchTerminalWithPassword は、ヘルパーを武装させた状態でセッションを開く。
//
// ヘルパーのパスとエンドポイントは呼び出し側が決める。このバイナリがどこにあり、
// どのアドレスで待ち受けているかを知るのはそこだけだからだ。ここではパスワードを
// 一切読まない。ヘルパーが提示するのはトークンであり、パスワードがこのプロセスの
// リクエスト経路に入ることはそもそもない。
func (s *Service) LaunchTerminalWithPassword(ctx context.Context, alias, helperPath, endpoint, token string) error {
	if err := platform.ValidateAlias(alias); err != nil {
		return err
	}
	if s.Terminal == nil {
		return ErrTerminalNotConfigured
	}
	launcher, ok := s.Terminal.(platform.PasswordTerminalLauncher)
	if !ok {
		return ErrPasswordLaunchUnsupported
	}
	return launcher.LaunchWithPassword(ctx, alias, helperPath, endpoint, token)
}

// sanitiseValues は、ssh が報告したすべての値の中で、ホームディレクトリを "~" に
// 書き換える。キーワードの一覧には手を触れない。キーワードは OpenSSH の固定名で
// あり、パスを含みようがないからだ。
func sanitiseValues(values effective.Values, home string) effective.Values {
	if home == "" {
		return values
	}
	sanitised := effective.Values{
		Keywords: values.Keywords,
		Entries:  make(map[string][]string, len(values.Entries)),
	}
	for keyword, entries := range values.Entries {
		shortened := make([]string, 0, len(entries))
		for _, entry := range entries {
			shortened = append(shortened, platform.SanitiseHomePaths(entry, home))
		}
		sanitised.Entries[keyword] = shortened
	}
	return sanitised
}
