package platform

import (
	"context"
	"errors"
)

var (
	ErrAgentUnavailable = errors.New("no ssh-agent is reachable from this process")
	ErrAgentRejected    = errors.New("ssh-add rejected the request")
)

// AgentIdentity は、ユーザーの ssh-agent に現在読み込まれている鍵ひとつ。
type AgentIdentity struct {
	Bits        int
	Fingerprint string
	Comment     string
	Algorithm   string
}

// AgentAddRequest は、秘密鍵をひとつ読み込むようエージェントに求める。
//
// Passphrase は子プロセスの標準入力を通る。引数になることも環境変数になることも
// 決してない。どちらも、同じユーザーで動くどのプロセスからも読めるもの
// だからである。
type AgentAddRequest struct {
	PrivateKeyPath  string
	Passphrase      []byte
	LifetimeSeconds int
	StoreInKeychain bool
}

// KeyAgent は、ユーザーの ssh-agent に、そして macOS ではログインキーチェーンにも
// 秘密鍵を登録する。自動テストは常に偽物で差し替える。このリポジトリのどのテストも
// 本物のエージェントや本物のキーチェーンとは話さない。
type KeyAgent interface {
	Available(ctx context.Context) bool
	List(ctx context.Context) ([]AgentIdentity, error)
	Add(ctx context.Context, request AgentAddRequest) error
	Remove(ctx context.Context, publicKeyPath string) error
}
