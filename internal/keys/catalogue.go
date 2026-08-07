package keys

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"sshc/internal/platform"
)

// DiagnosticAlgorithmQueryFailed は、インストールされている OpenSSH に、どの
// アルゴリズムに対応しているかを尋ねられなかったときに報告される。
const DiagnosticAlgorithmQueryFailed = "algorithm_query_failed"

// このプロセス内でその variant を生成しない理由を説明する理由コード。
const ReasonHardwareToken = "hardware_token_required"

// Variant は、ユーザーが要求しうる鍵の種類ひとつ。
type Variant struct {
	Algorithm Algorithm
	Bits      int
	Label     string
	InProcess bool
	Reason    string
}

// Catalogue は、インストールされている OpenSSH が理解する variant の集合。
type Catalogue struct {
	Variants   []Variant
	Source     string
	Diagnostic string
}

// CatalogueReader は、対応する鍵アルゴリズムをインストール済みの OpenSSH に尋ねる。
//
// `ssh -F /dev/null -Q key` を実行する。これは静的な一覧を表示して終了する。この
// 呼び出しは設定ファイルを読まず、Match ブロックを評価せず、ユーザー由来の
// ディレクティブも実行しない。したがって、ロードマップのサブシステム 5 が所有し、
// このサブシステムが行ってはならない `ssh -G` の評価ではない。
//
// プログラムのパスは PATH ではなく Toolchain から来る。platform.Command は、絶対
// パスで名指しされていないプログラムを拒否するからである。
type CatalogueReader struct {
	Runner    platform.OutputRunner
	Toolchain platform.Toolchain
	Timeout   time.Duration
}

func (reader CatalogueReader) Read(ctx context.Context) Catalogue {
	timeout := reader.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if reader.Runner == nil || reader.Toolchain == nil {
		return fallbackCatalogue()
	}
	program, err := reader.Toolchain.SSH()
	if err != nil {
		return fallbackCatalogue()
	}

	output, err := reader.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-F", "/dev/null", "-Q", "key"},
		Timeout:   timeout,
	})
	if err != nil || output.ExitCode != 0 {
		return fallbackCatalogue()
	}

	supported := make(map[string]bool)
	for _, line := range strings.Split(string(output.Stdout), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			supported[trimmed] = true
		}
	}

	catalogue := Catalogue{Source: "ssh -Q key"}
	if supported["ssh-ed25519"] {
		catalogue.Variants = append(catalogue.Variants, Variant{Algorithm: AlgorithmEd25519, Bits: 256, Label: "Ed25519", InProcess: true})
	}
	if supported["ssh-rsa"] || supported["rsa-sha2-256"] || supported["rsa-sha2-512"] {
		for _, bits := range []int{2048, 3072, 4096} {
			catalogue.Variants = append(catalogue.Variants, Variant{Algorithm: AlgorithmRSA, Bits: bits, Label: "RSA", InProcess: true})
		}
	}
	for _, curve := range []struct {
		name string
		bits int
	}{{"ecdsa-sha2-nistp256", 256}, {"ecdsa-sha2-nistp384", 384}, {"ecdsa-sha2-nistp521", 521}} {
		if supported[curve.name] {
			catalogue.Variants = append(catalogue.Variants, Variant{Algorithm: AlgorithmECDSA, Bits: curve.bits, Label: "ECDSA", InProcess: true})
		}
	}
	if supported["sk-ssh-ed25519@openssh.com"] {
		catalogue.Variants = append(catalogue.Variants, Variant{
			Algorithm: AlgorithmEd25519SK, Label: "Ed25519 security key", InProcess: false, Reason: ReasonHardwareToken,
		})
	}
	if supported["sk-ecdsa-sha2-nistp256@openssh.com"] {
		catalogue.Variants = append(catalogue.Variants, Variant{
			Algorithm: AlgorithmECDSASK, Bits: 256, Label: "ECDSA security key", InProcess: false, Reason: ReasonHardwareToken,
		})
	}
	return catalogue
}

// fallbackCatalogue は、インストール済みの OpenSSH に何に対応しているかを尋ね
// られなかったときに提示される。項目が Ed25519 だけなのは、サポート対象のすべての
// OpenSSH リリースが受け付ける唯一のアルゴリズムであり、増やせば当て推量になるからだ。
func fallbackCatalogue() Catalogue {
	return Catalogue{
		Variants:   []Variant{{Algorithm: AlgorithmEd25519, Bits: 256, Label: "Ed25519", InProcess: true}},
		Source:     "fallback",
		Diagnostic: DiagnosticAlgorithmQueryFailed,
	}
}

// HardwareCommand は、ハードウェアに裏打ちされた鍵のためにユーザーが Terminal で
// 実行しなければならない引数リストを、そのまま返す。
//
// このサブシステムが Terminal を起動することは決してない。その段階はロードマップの
// サブシステム 5 が所有する。各要素はシェルの引用を必要としない文字集合に対して
// 検査されるので、表示される行は曖昧さがなく、どの要素もオプションとして読み直され
// えず、ここにあるものがあとで AppleScript やシェルの構文になることもない。
func HardwareCommand(algorithm Algorithm, fileName, comment, sshDirectory string) ([]string, error) {
	var keyType string
	switch algorithm {
	case AlgorithmEd25519SK:
		keyType = "ed25519-sk"
	case AlgorithmECDSASK:
		keyType = "ecdsa-sk"
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	if err := ValidateFileName(fileName); err != nil {
		return nil, err
	}
	// より厳しいルールを使う。このコマンドラインはユーザーが実行するために表示され
	// るので、ここの各引数はシェルへコピーされても壊れないものでなければならない。
	if err := ValidateHardwareComment(comment); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(sshDirectory) {
		return nil, ErrInvalidFileName
	}

	command := []string{"ssh-keygen", "-t", keyType}
	if comment != "" {
		command = append(command, "-C", comment)
	}
	command = append(command, "-f", filepath.Join(sshDirectory, fileName))
	for _, argument := range command {
		if !safeArgumentPattern.MatchString(argument) {
			return nil, ErrInvalidFileName
		}
	}
	return command, nil
}
