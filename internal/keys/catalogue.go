package keys

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"ssh-ui/internal/platform"
)

// DiagnosticAlgorithmQueryFailed is reported when the installed OpenSSH could
// not be asked which algorithms it supports.
const DiagnosticAlgorithmQueryFailed = "algorithm_query_failed"

// Reason codes explaining why a variant is not generated inside this process.
const ReasonHardwareToken = "hardware_token_required"

// Variant is one key type the user may ask for.
type Variant struct {
	Algorithm Algorithm
	Bits      int
	Label     string
	InProcess bool
	Reason    string
}

// Catalogue is the set of variants the installed OpenSSH understands.
type Catalogue struct {
	Variants   []Variant
	Source     string
	Diagnostic string
}

// CatalogueReader asks the installed OpenSSH which key algorithms it supports.
//
// It runs `ssh -F /dev/null -Q key`, which prints a static list and exits. That
// invocation reads no configuration file, evaluates no Match block and runs no
// user-supplied directive, so it is not the `ssh -G` evaluation that roadmap
// subsystem 5 owns and that this subsystem must not perform.
//
// The program path comes from the Toolchain rather than from PATH, because
// platform.Command refuses a program that is not named by an absolute path.
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

// fallbackCatalogue is offered when the installed OpenSSH could not be asked
// what it supports. Ed25519 is the only entry because it is the one algorithm
// every supported OpenSSH release accepts, and offering more would be a guess.
func fallbackCatalogue() Catalogue {
	return Catalogue{
		Variants:   []Variant{{Algorithm: AlgorithmEd25519, Bits: 256, Label: "Ed25519", InProcess: true}},
		Source:     "fallback",
		Diagnostic: DiagnosticAlgorithmQueryFailed,
	}
}

// HardwareCommand returns the exact argument list a user must run in Terminal
// for a hardware-backed key.
//
// This subsystem never launches Terminal; roadmap subsystem 5 owns that step.
// Every element is checked against a character set that needs no shell quoting,
// so the displayed line is unambiguous, no element can be re-read as an option,
// and nothing here can become AppleScript or shell syntax later.
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
	// The stricter rule, because this command line is shown for the user to
	// run: every argument here has to survive being copied into a shell.
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
