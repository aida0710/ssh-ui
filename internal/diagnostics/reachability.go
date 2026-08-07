// Package diagnostics は、設計上、個別に起動される各種チェックを実行する。
// 設定のチェック、直接 TCP による到達性のチェック、そして SSH 認証テストである。
// いずれもユーザーが意図して開始する独立した操作であり、画面を開いた副作用として
// 走るものはここに何もない。
package diagnostics

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// ProxyJumpNotice は、すべての到達性の結果に付随する。このチェックは接続先へ
// 自分でダイヤルするので、踏み台ホスト経由でしか到達できないホストはここで失敗
// するのが当然である。UI は、そのホストが落ちていると受け取られないよう、その旨を
// 述べなければならない。
const ProxyJumpNotice = "This check dialled the destination directly. ProxyJump, ProxyCommand and any jump-host firewall were not used."

// DefaultReachabilityTimeout は、TCP ダイヤル一回に上限を設ける。
const DefaultReachabilityTimeout = 5 * time.Second

// 到達性の結果。
const (
	ReachabilityReached    = "reached"
	ReachabilityRefused    = "refused"
	ReachabilityTimeout    = "timeout"
	ReachabilityDNSFailure = "dns_failure"
	ReachabilityFailed     = "failed"
)

// Dialer は TCP 接続を開く。*net.Dialer がこれを満たす。テストは関数で差し替え、
// 自動テストがリモートのソケットを開くことがないようにする。
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ReachabilityResult は、完了したダイヤル試行ひとつ分。
type ReachabilityResult struct {
	Address string
	Outcome string
	Elapsed time.Duration
	Detail  string
	Notice  string
}

// Reachability は接続先へ直接ダイヤルし、意図的に ProxyJump を無視する。
type Reachability struct {
	Dialer  Dialer
	Timeout time.Duration
}

// Check は hostname:port へ一度ダイヤルし、その結果を分類する。
func (r Reachability) Check(ctx context.Context, hostname, port string) ReachabilityResult {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultReachabilityTimeout
	}
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(hostname, port)
	result := ReachabilityResult{Address: address, Notice: ProxyJumpNotice}

	started := time.Now()
	connection, err := r.Dialer.DialContext(dialContext, "tcp", address)
	result.Elapsed = time.Since(started)
	if err == nil {
		connection.Close()
		result.Outcome = ReachabilityReached
		return result
	}

	result.Detail = err.Error()
	var dnsError *net.DNSError
	switch {
	case errors.As(err, &dnsError):
		result.Outcome = ReachabilityDNSFailure
	case errors.Is(err, syscall.ECONNREFUSED):
		result.Outcome = ReachabilityRefused
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		result.Outcome = ReachabilityTimeout
	default:
		result.Outcome = ReachabilityFailed
	}
	return result
}
