package platform

import (
	"context"
	"errors"
	"time"
)

// MaxCapturedOutput は、外部コマンド一回について、片方のストリームをメモリに
// どれだけ保持するかの上限。
const MaxCapturedOutput = 64 << 10

var (
	// ErrTimedOut は、コマンドがタイムアウト内に終わらず kill されたことを報告
	// する。
	ErrTimedOut = errors.New("command did not finish before its timeout")
	// ErrProgramPathNotAbsolute は、そうしなければ PATH 経由で探されることになる
	// プログラムを拒否する。
	ErrProgramPathNotAbsolute = errors.New("program path must be absolute")
)

// Command は外部プロセスひとつ。
//
// Path は絶対的なプログラムパスで、Arguments はその argv の残り。コマンドライン
// のためのフィールドはない。このアプリケーションはコマンドラインを組み立てない
// からだ。ここにあるものがシェルに解釈されることは決してない。
type Command struct {
	Path      string
	Arguments []string
	// Stdin は標準入力の全体。常に与えられるので、子プロセスが端末を継承することも、
	// プロンプトで止まることもない。
	Stdin []byte
	// Timeout は、それを超えたときプロセスを kill する。0 は、呼び出し側の context
	// だけが上限であることを意味する。
	Timeout time.Duration
	// StopAfter は、このバイト列が stdout か stderr に現れた時点でプロセスを止める。
	// これにより、長時間動くコマンドが、自身のタイムアウトを待たずに決定的な結果を
	// 報告できる。
	StopAfter []byte
	// Env は子プロセスの完全な環境。nil の Env はこのプロセスの環境を継承し、nil で
	// ない Env は、たとえ空でもそれを完全に置き換える。OpenSSH のプログラムを実行する
	// 呼び出し側は MinimalEnvironment を渡すこと。そうすれば、ユーザーがたまたま
	// エクスポートしていた変数によって子プロセスの向きを変えられることが
	// なくなる。
	Env []string
}

// askpassVariables は、すべての子プロセスから意図的に取り除かれる。
//
// SSH_ASKPASS と SSH_ASKPASS_REQUIRE が設定されていると、ssh-add と ssh は、この
// アプリケーションが供給する標準入力を読む代わりに、外部プログラムへパスフレーズ
// を尋ねる。それは秘密を、このプロセスの管理下から、自分で選んだのではない
// プログラムの上へ移すことになる。DISPLAY を取り除くのも同じ理由から
// である。
var minimalEnvironmentVariables = []string{"HOME", "PATH", "LANG", "SSH_AUTH_SOCK"}

// MinimalEnvironment は、OpenSSH のクライアントプログラムが必要とする最小の環境
// を返す。各値は lookup から取り、設定されていないものは省く。SSH_AUTH_SOCK を
// 残すのは、動作中のエージェントへ到達することがサポートされた操作だからである。
// SSH_ASKPASS、SSH_ASKPASS_REQUIRE、DISPLAY は、そもそもまったく含め
// ない。
func MinimalEnvironment(lookup func(name string) (string, bool)) []string {
	environment := make([]string, 0, len(minimalEnvironmentVariables))
	for _, name := range minimalEnvironmentVariables {
		if value, ok := lookup(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

// Output は、外部コマンド一回の上限付きの結果。非ゼロの終了ステータスはエラー
// ではなくデータである。err == nil のまま ExitCode に報告される。
type Output struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
	Stopped   bool
	Elapsed   time.Duration
}

// OutputRunner は外部プログラムを一回実行し、上限付きの出力を返す。
type OutputRunner interface {
	RunOutput(ctx context.Context, command Command) (Output, error)
}

// Toolchain は、このマシンにインストールされた OpenSSH のプログラムを見つける。
//
// このアプリケーションが実行してよいプログラムはすべてここに名前があるので、
// 呼び出し側が自前でプログラムパスを組み立てることは決してできない。必要なものを
// 要求し、絶対パスかエラーを受け取る。
type Toolchain interface {
	SSH() (string, error)
	KeyScan() (string, error)
	KeyGen() (string, error)
	KeyAdd() (string, error)
}
