package knownhosts

import (
	"context"
	"strconv"
	"strings"
	"time"

	"sshc/internal/platform"
)

// UnverifiedNotice は、すべてのスキャン結果に付随する。
const UnverifiedNotice = "ssh-keyscan proves only that something answered at this address. It does not prove the host's identity. Compare the fingerprint with one you obtained another way before trusting it."

// DefaultScanTimeout は、ssh-keyscan の実行一回に上限を設ける。
const DefaultScanTimeout = 15 * time.Second

// Candidate は ssh-keyscan が報告した鍵ひとつ。ここでは Verified は常に false で
// ある。鍵が本物だと判断できるのはユーザーだけだ。
type Candidate struct {
	Host        string
	Port        int
	KeyType     string
	Key         string
	Fingerprint string
	Verified    bool
}

// Scanner はホスト鍵の候補を取得する。
type Scanner struct {
	Runner    platform.OutputRunner
	Toolchain platform.Toolchain
	Timeout   time.Duration
	// Environment は子プロセスの完全な環境。通常は platform.MinimalEnvironment で
	// あり、nil ならこのプロセスの環境を継承する。
	Environment []string
}

// Scan は、あるホストの鍵を ssh-keyscan に尋ねる。
//
// 結果に Verified が付くことはない。アドレスに到達できたことが証明するのは、そこで
// 何かが応答したという事実だけであり、鍵を信頼する判断はユーザーのもとに残る。
func (s Scanner) Scan(ctx context.Context, host string, port int) ([]Candidate, error) {
	if err := platform.ValidateHostname(host); err != nil {
		return nil, err
	}
	if err := platform.ValidatePort(port); err != nil {
		return nil, err
	}
	program, err := s.Toolchain.KeyScan()
	if err != nil {
		return nil, err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultScanTimeout
	}
	output, err := s.Runner.RunOutput(ctx, platform.Command{
		Path:      program,
		Arguments: []string{"-T", "5", "-p", strconv.Itoa(port), host},
		Timeout:   timeout,
		Env:       s.Environment,
	})
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	for _, line := range strings.Split(string(output.Stdout), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		fingerprint, fingerprintErr := Fingerprint(fields[2])
		if fingerprintErr != nil {
			continue
		}
		candidates = append(candidates, Candidate{
			Host:        host,
			Port:        port,
			KeyType:     fields[1],
			Key:         fields[2],
			Fingerprint: fingerprint,
		})
	}
	return candidates, nil
}
