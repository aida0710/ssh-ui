package effective

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"sshc/internal/platform"
)

// DefaultEvaluationTimeout は `ssh -G` の実行一回に上限を設ける。評価はネット
// ワークに触れないので、実行が遅いならローカルで何かがおかしい。
const DefaultEvaluationTimeout = 10 * time.Second

var (
	// ErrEvaluationNotConfirmed は、この設定の評価がコマンドを実行しうるのに、
	// 呼び出し側が確認を提示しなかったことを報告する。
	ErrEvaluationNotConfirmed = errors.New("evaluating this configuration can run a command and needs explicit confirmation")
	// ErrOutputTruncated は、ssh が取り込み上限を超えて出力したため、解析した値が
	// 不完全になるので返さない、ということを報告する。
	ErrOutputTruncated = errors.New("ssh -G produced more output than the capture limit")
)

// Values は、OpenSSH がひとつの alias について報告した実効設定。
// Keywords は出力順を保ち、Entries は、identityfile のように複数回現れうる
// キーワードのすべての値を保つ。
type Values struct {
	Keywords []string
	Entries  map[string][]string
}

// First は keyword の最初の値を返す。なければ空文字列。
func (v Values) First(keyword string) string {
	values := v.Entries[strings.ToLower(keyword)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// All は keyword のすべての値を出力順で返す。
func (v Values) All(keyword string) []string { return v.Entries[strings.ToLower(keyword)] }

// ParseValues は `ssh -G` の出力を解析する。各行は小文字のキーワード、空白ひとつ、
// そして行の残りで、残りの部分自体が空白を含みうる。
func ParseValues(stdout []byte) Values {
	values := Values{Entries: make(map[string][]string)}
	for _, raw := range strings.Split(string(stdout), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		keyword, argument, _ := strings.Cut(line, " ")
		keyword = strings.ToLower(keyword)
		if _, seen := values.Entries[keyword]; !seen {
			values.Keywords = append(values.Keywords, keyword)
		}
		values.Entries[keyword] = append(values.Entries[keyword], argument)
	}
	return values
}

// OpenSSHError は、インストールされている ssh がリクエストを拒否したことを報告
// する。Stderr はプロセスの継ぎ目ですでに上限が課されており、ログ用ではなく表示用。
type OpenSSHError struct {
	ExitCode  int
	Stderr    string
	Truncated bool
}

func (e *OpenSSHError) Error() string {
	return fmt.Sprintf("ssh exited with status %d", e.ExitCode)
}

// Evaluator は、特定の設定ファイルに対して alias ひとつ分の `ssh -G` を実行する。
type Evaluator struct {
	Runner     platform.OutputRunner
	Toolchain  platform.Toolchain
	ConfigPath string
	Timeout    time.Duration
	// Environment は子プロセスの完全な環境。通常は platform.MinimalEnvironment。
	// nil ならこのプロセスの環境を継承するが、それが正しい既定なのはテストの中だけで
	// ある。
	Environment []string
}

// Evaluate は、インストールされている OpenSSH に alias の実効設定を尋ねる。
//
// confirmed は、消費されたアクショントークンから来なければならない。設定が評価中に
// コマンドを実行しうる場合、Evaluate はそれなしでは拒否し、プロセスをまったく
// 起動しない。
func (e Evaluator) Evaluate(ctx context.Context, report Report, alias string, confirmed bool) (Values, error) {
	if err := platform.ValidateAlias(alias); err != nil {
		return Values{}, err
	}
	if report.EvaluationNeedsConfirmation() && !confirmed {
		return Values{}, ErrEvaluationNotConfirmed
	}
	program, err := e.Toolchain.SSH()
	if err != nil {
		return Values{}, err
	}

	timeout := e.Timeout
	if timeout <= 0 {
		timeout = DefaultEvaluationTimeout
	}
	output, err := e.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-G", "-F", e.ConfigPath, "--", alias},
		Timeout:   timeout,
		Env:       e.Environment,
	})
	if err != nil {
		return Values{}, err
	}
	if output.Truncated {
		return Values{}, ErrOutputTruncated
	}
	if output.ExitCode != 0 {
		return Values{}, &OpenSSHError{
			ExitCode:  output.ExitCode,
			Stderr:    string(output.Stderr),
			Truncated: output.Truncated,
		}
	}
	return ParseValues(output.Stdout), nil
}
