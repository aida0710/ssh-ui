package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"sshc/internal/application"
	"sshc/internal/diagnostics"
	"sshc/internal/knownhosts"
	"sshc/internal/remotekey"
	"sshc/internal/remotesync"
	"sshc/internal/secret"
	"sshc/internal/selfupdate"
	"sshc/internal/session"
)

type Options struct {
	// CLISecret は `sshc <alias>` が提示すべきものである。実行のたびに
	// 発行して state directory に書き込むため、kill されたプロセスが
	// 残した handoff は、誰にも受け付けられない secret を運ぶことになる。
	CLISecret string
	// ConnectWarnings は OpenSSH がそのホストに対して実行するディレクティブを
	// 名指しする。これにより command line は接続中ではなく接続前にそれらを言える。
	ConnectWarnings func(alias string) []string
	// LoginItem は「ログイン時に起動」の on/off を切り替える。nil の場合、
	// launchd のないプラットフォームがそうであるように、非対応と報告する。
	LoginItem LoginItemController
	// Updates はプロジェクトのリリースを調べる。nil の場合、バージョンを
	// 報告するのみで何も提示しない。比較すべきリリースを持たないビルドが
	// すべきことはこれである。
	Updates     *selfupdate.Checker
	Listener    net.Listener
	Sessions    *session.Manager
	UI          fs.FS
	Version     string
	Logger      *slog.Logger
	Config      *application.Service
	Keys        KeyService
	Diagnostics *diagnostics.Service
	KnownHosts  *knownhosts.Service
	RemoteKeys  *remotekey.Service
	// Passwords は保存されたパスワードの vault である。nil の service は
	// すべてのパスワード用ルートと askpass エンドポイントを未登録のままに
	// する。これは、それを配線しないテストが当てにしていることである。
	Passwords *secret.Service
	// AskpassHelper はこのバイナリの絶対パスであり、OpenSSH がパスワードを
	// 得るために実行する program である。これを知り得るのは cmd/sshc だけだ。
	AskpassHelper string
	// Answerable はプロンプトの規則であり、server とヘルパーが 2 つの
	// 異なる規則へずれないよう注入されている。
	Answerable func(alias, prompt string) bool
	// Sync はワークスペースを object store へ運ぶ。nil の service は
	// すべての sync ルートを未登録のままにする。
	Sync *remotesync.Service
}

var ErrNonLoopbackListener = errors.New("listener must use 127.0.0.1")

type Server struct {
	listener net.Listener
	http     *http.Server
	url      string
	engine   *echo.Echo
	// cliSecret は `sshc <alias>` が提示すべきものである。これを保持する
	// のは、handoff の置き場所を知る呼び出し元が、別途持ち歩くのではなく
	// 読み戻せるようにするためだ。
	cliSecret string
}

// Route はこの server が登録したルートの 1 つである。
type Route struct {
	Method string
	Path   string
}

// Routes は登録済みの全ルートを登録順に報告する。
//
// hardening suite は自前のリストを持つ代わりにこれを列挙する。これにより
// 後の変更で追加されたルートも、誰も追加を覚えていなくてもトランスポート、
// cache、session、漏洩に関するアサーションを自動的に引き継ぐ。
func (s *Server) Routes() []Route {
	registered := s.engine.Router().Routes()
	routes := make([]Route, 0, len(registered))
	for _, info := range registered {
		routes = append(routes, Route{Method: info.Method, Path: info.Path})
	}
	return routes
}

func New(options Options) (*Server, error) {
	if options.Listener == nil {
		return nil, ErrNonLoopbackListener
	}
	tcpAddress, ok := options.Listener.Addr().(*net.TCPAddr)
	if !ok || len(tcpAddress.IP) != net.IPv4len || tcpAddress.IP[0] != 127 || tcpAddress.IP[1] != 0 || tcpAddress.IP[2] != 0 || tcpAddress.IP[3] != 1 {
		return nil, ErrNonLoopbackListener
	}

	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpAddress.Port))
	e := echo.New()
	if options.Logger != nil {
		e.Logger = options.Logger
	}
	e.Use((Security{
		ExpectedHost:   host,
		ExpectedOrigin: "http://" + host,
		Sessions:       options.Sessions,
		// application はマスターパスワードの向こう側にあるのであって、各画面
		// が個別にそうなのではない。vault なしで組み立てられた server は
		// したがって施錠されたままであり、これは配線し忘れにとって安全な方向である。
		Unlocked: func() bool { return options.Passwords != nil && options.Passwords.Unlocked() },
	}).Middleware)

	handlers := Handlers{Sessions: options.Sessions, Version: options.Version}
	e.POST("/api/v1/session/bootstrap", handlers.Bootstrap)
	e.POST("/api/v1/session/renew", handlers.Renew)
	e.GET("/api/v1/health", handlers.Health)
	if options.Config != nil {
		registerConfigRoutes(e, ConfigHandlers{Service: options.Config, Keys: options.Keys})
	}

	// 操作を確認するすべてのサブシステムは、自分の evidence resolver を
	// 1 つの registry に提供する。これにより、単一の POST /api/v1/actions
	// エンドポイントが、各 service に踏み込まずにそのどれにでもトークンを発行できる。
	registry := actionRegistry{}
	if options.Keys != nil {
		addKeyActions(registry, options.Keys)
	}
	if options.Diagnostics != nil {
		addDiagnosticsActions(registry, options.Diagnostics)
	}
	if options.KnownHosts != nil {
		addKnownHostsActions(registry, options.KnownHosts)
	}
	actions := ActionHandlers{Sessions: options.Sessions, Kinds: registry}

	if options.Keys != nil {
		registerKeyRoutes(e, KeyHandlers{
			Keys: options.Keys, Config: options.Config, Sessions: options.Sessions, Actions: actions,
		})
	}
	if options.Diagnostics != nil {
		registerDiagnosticsRoutes(e, DiagnosticsHandlers{
			Service:       options.Diagnostics,
			Actions:       actions,
			Passwords:     options.Passwords,
			AskpassHelper: options.AskpassHelper,
			AskpassURL:    "http://" + host + AskpassPath,
		})
	}
	if options.KnownHosts != nil {
		registerKnownHostsRoutes(e, KnownHostsHandlers{Service: options.KnownHosts, Actions: actions})
	}
	if options.RemoteKeys != nil && options.Diagnostics != nil {
		registerRemoteKeyRoutes(e, RemoteKeyHandlers{
			Service: options.RemoteKeys, Diagnostics: options.Diagnostics, Actions: actions,
		})
	}
	if options.Passwords != nil {
		// eligibility チェックは設定グラフと known_hosts を読むため、
		// vault からではなく configuration service から来る。vault は
		// そのどちらについても何も知らない。configuration service がなければ
		// 何もチェックされず、これはこの仕組みができる前に vault がしていた
		// ことであり、vault だけを配線するテストが当てにしていることでもある。
		var eligibility func(string) (application.PasswordEligibility, error)
		if options.Config != nil {
			eligibility = options.Config.PasswordEligibility
		}
		// bucket の最新スナップショットもマスターパスワードで封印されている
		// ため、変更すると再び push する。bucket のないマシンには更新すべき
		// ものがなく、応答はそう伝える。
		var reseal func(context.Context, string) error
		if options.Sync != nil {
			reseal = options.Sync.Push
		}
		registerPasswordRoutes(e, PasswordHandlers{
			Service:        options.Passwords,
			Answerable:     options.Answerable,
			Eligibility:    eligibility,
			ResealSnapshot: reseal,
		})
	}
	// `sshc <alias>` は、1 つの接続に必要なものをここに求める。secret は
	// 呼び出し元が state directory から読み出しているはずのものであり、
	// それがなければこのルートはすべてを拒否する。
	registerUpdateRoutes(e, &UpdateHandlers{Current: options.Version, Checker: options.Updates})
	registerLoginItemRoutes(e, LoginItemHandlers{
		Controller: options.LoginItem,
		Program:    options.AskpassHelper,
	})
	registerConnectRoutes(e, ConnectHandlers{
		Secret:     options.CLISecret,
		Passwords:  options.Passwords,
		AskpassURL: "http://" + host + AskpassPath,
		Warnings:   options.ConnectWarnings,
		Sessions:   options.Sessions,
		BaseURL:    "http://" + host,
	})
	if options.Sync != nil {
		registerSyncRoutes(e, SyncHandlers{Service: options.Sync, Secrets: options.Passwords})
	}
	if len(registry) > 0 {
		registerActionRoutes(e, actions)
	}
	static := echo.WrapHandler(spaHandler(options.UI))
	e.GET("/*", static)
	e.HEAD("/*", static)

	return &Server{
		listener: options.Listener,
		http: &http.Server{
			Handler:           e,
			ReadHeaderTimeout: 5 * time.Second,
		},
		url:       "http://" + host,
		cliSecret: options.CLISecret,
		engine:    e,
	}, nil
}

func spaHandler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean(request.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) {
			http.NotFound(response, request)
			return
		}
		if name == "api" || strings.HasPrefix(name, "api/") || request.URL.Path == "/api" || strings.HasPrefix(request.URL.Path, "/api/") {
			http.NotFound(response, request)
			return
		}

		contents, err := fs.ReadFile(assets, name)
		if err != nil {
			if !acceptsHTML(request.Header.Get("Accept")) {
				http.NotFound(response, request)
				return
			}
			name = "index.html"
			contents, err = fs.ReadFile(assets, name)
			if err != nil {
				http.NotFound(response, request)
				return
			}
		}

		if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
			response.Header().Set("Content-Type", contentType)
		}
		http.ServeContent(response, request, name, time.Time{}, bytes.NewReader(contents))
	})
}

func acceptsHTML(header string) bool {
	for _, value := range strings.Split(header, ",") {
		mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(value))
		if err != nil || mediaType != "text/html" {
			continue
		}

		quality := 1.0
		if raw, ok := parameters["q"]; ok {
			quality, err = strconv.ParseFloat(raw, 64)
			if err != nil {
				continue
			}
		}
		if quality > 0 && quality <= 1 {
			return true
		}
	}
	return false
}

// CLISecret は `sshc <alias>` が提示すべきものであり、handoff の
// 書き込み先を知る呼び出し元が、別途保持せずに読み戻せるようにする。
func (s *Server) CLISecret() string { return s.cliSecret }

func (s *Server) URL() string {
	return s.url
}

func (s *Server) Serve(ctx context.Context) error {
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- s.http.Serve(s.listener)
	}()

	select {
	case err := <-serveDone:
		return serveResult(err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return serveResult(<-serveDone)
	}
}

func serveResult(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
