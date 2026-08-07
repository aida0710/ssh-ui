package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sshc/internal/effective"
	"sshc/internal/platform"
)

const (
	// AuthenticatedMarker は、セッションが認証されたときに OpenSSH が表示する語句。
	// これを監視することで、自前のタイムアウトを待たずに、問いの答えが出た時点で
	// テストを終えられる。
	AuthenticatedMarker = "Authenticated to "
	// MaxReportedOutput は、表示用に返す stderr の取り込み量に上限を設ける。
	MaxReportedOutput = 8 << 10
	// DefaultAuthenticationTimeout は、認証テスト一回に上限を設ける。
	DefaultAuthenticationTimeout = 20 * time.Second
	// DefaultConnectTimeout は OpenSSH に渡す。これにより、停止した TCP 接続は
	// このアプリケーション自身のタイムアウトが発火する前に失敗する。
	DefaultConnectTimeout = 8 * time.Second
)

// 認証テストの結果。
const (
	OutcomeAuthenticated  = "authenticated"
	OutcomeDenied         = "authentication_denied"
	OutcomeHostKeyUnknown = "host_key_unknown"
	OutcomeHostKeyChanged = "host_key_changed"
	OutcomeDNSFailure     = "dns_failure"
	OutcomeRefused        = "connection_refused"
	OutcomeTimeout        = "timeout"
	OutcomeFailed         = "failed"
)

// ExecutableDirectiveError は、接続するとコマンドラインオプションでは無効化できない
// コマンドが実行されること、そしてユーザーがそれを確認していないことを報告する。
type ExecutableDirectiveError struct {
	Directives []effective.Executable
}

func (e *ExecutableDirectiveError) Error() string {
	return fmt.Sprintf("connecting would run %d configured command(s) that cannot be disabled", len(e.Directives))
}

// AuthenticationResult は、完了した認証テストひとつ分。
type AuthenticationResult struct {
	Outcome       string
	Authenticated bool
	ExitCode      int
	Stderr        string
	Truncated     bool
	Elapsed       time.Duration
}

// Authentication は、本物の SSH 認証の試行を一回実行する。
type Authentication struct {
	Runner         platform.OutputRunner
	Toolchain      platform.Toolchain
	ConfigPath     string
	Timeout        time.Duration
	ConnectTimeout time.Duration
	// Environment は子プロセスの完全な環境。通常は platform.MinimalEnvironment で
	// ある。これは SSH_ASKPASS を与えない。与えてしまうと、エクスポートされた askpass
	// プログラムが、上限付きで非対話的なこのテストを、パスフレーズのダイアログ待ちに
	// 変えてしまいかねない。
	Environment []string
}

// HardeningOptions は、このテストに不要なものすべてを無力化するコマンドライン
// オプションを返す。コマンドラインオプションはあらゆる設定ファイルに優先するので、
// テストはそれに頼れる。SessionType=none はシェルもリモートコマンドも要求せず、
// ClearAllForwardings はローカル・リモート・動的の各転送を落とし、
// PermitLocalCommand=no は LocalCommand を封じ、StrictHostKeyChecking=yes は
// 未知のホスト鍵を黙って信頼することを拒む。
func HardeningOptions(connectTimeout time.Duration) []string {
	seconds := int(connectTimeout.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	settings := []string{
		"BatchMode=yes",
		"PermitLocalCommand=no",
		"ClearAllForwardings=yes",
		"ForwardAgent=no",
		"ForwardX11=no",
		"ForwardX11Trusted=no",
		"ControlMaster=no",
		"ControlPath=none",
		"RemoteCommand=none",
		"RequestTTY=no",
		"SessionType=none",
		"StrictHostKeyChecking=yes",
		"NumberOfPasswordPrompts=0",
		"ConnectTimeout=" + strconv.Itoa(seconds),
	}
	options := make([]string, 0, len(settings)*2)
	for _, setting := range settings {
		options = append(options, "-o", setting)
	}
	return options
}

// Test は alias に対して認証し、答えが判明した時点で止まる。
//
// acknowledged は、report.Unavoidable() のコマンドをそのまま表示したうえで消費
// されたアクショントークンから来なければならない。これがなければ、そうした
// コマンドを実行することになる設定は起動しない。
func (a Authentication) Test(ctx context.Context, report effective.Report, alias string, acknowledged bool) (AuthenticationResult, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return AuthenticationResult{}, err
	}
	if blocking := report.Unavoidable(); len(blocking) > 0 && !acknowledged {
		return AuthenticationResult{}, &ExecutableDirectiveError{Directives: blocking}
	}
	program, err := a.Toolchain.SSH()
	if err != nil {
		return AuthenticationResult{}, err
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = DefaultAuthenticationTimeout
	}
	connectTimeout := a.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = DefaultConnectTimeout
	}

	arguments := []string{"-v", "-F", a.ConfigPath}
	arguments = append(arguments, HardeningOptions(connectTimeout)...)
	arguments = append(arguments, "--", alias)

	output, runErr := a.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: arguments,
		Timeout:   timeout,
		StopAfter: []byte(AuthenticatedMarker),
		Env:       a.Environment,
	})
	if runErr != nil && !errors.Is(runErr, platform.ErrTimedOut) {
		return AuthenticationResult{}, runErr
	}

	result := AuthenticationResult{
		ExitCode:  output.ExitCode,
		Stderr:    trimOutput(string(output.Stderr)),
		Truncated: output.Truncated,
		Elapsed:   output.Elapsed,
	}
	result.Truncated = result.Truncated || len(output.Stderr) > MaxReportedOutput
	result.Outcome, result.Authenticated = classify(output, runErr)
	return result, nil
}

func classify(output platform.Output, runErr error) (string, bool) {
	stderr := string(output.Stderr)
	if strings.Contains(stderr, AuthenticatedMarker) || strings.Contains(string(output.Stdout), AuthenticatedMarker) {
		return OutcomeAuthenticated, true
	}
	if errors.Is(runErr, platform.ErrTimedOut) {
		return OutcomeTimeout, false
	}
	switch {
	case strings.Contains(stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return OutcomeHostKeyChanged, false
	case strings.Contains(stderr, "Host key verification failed"):
		return OutcomeHostKeyUnknown, false
	case strings.Contains(stderr, "Permission denied"):
		return OutcomeDenied, false
	case strings.Contains(stderr, "Could not resolve hostname"):
		return OutcomeDNSFailure, false
	case strings.Contains(stderr, "Connection refused"):
		return OutcomeRefused, false
	case strings.Contains(stderr, "Connection timed out"), strings.Contains(stderr, "Operation timed out"):
		return OutcomeTimeout, false
	default:
		return OutcomeFailed, false
	}
}

func trimOutput(text string) string {
	if len(text) <= MaxReportedOutput {
		return text
	}
	return text[:MaxReportedOutput]
}
