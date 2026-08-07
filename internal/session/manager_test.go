package session

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestBootstrapCreatesAuthenticatedSessionOnce(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 96))
	manager, bootstrap, err := NewManager(random)
	if err != nil {
		t.Fatal(err)
	}
	if len(bootstrap) != 43 {
		t.Fatalf("bootstrap length = %d", len(bootstrap))
	}

	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if ok := manager.Authenticate(credentials.SessionID); !ok {
		t.Fatal("new session was not authenticated")
	}
	if !manager.VerifyCSRF(credentials.SessionID, credentials.CSRFToken) {
		t.Fatal("csrf token was rejected")
	}
	if _, err := manager.Bootstrap(bootstrap); !errors.Is(err, ErrBootstrapUsed) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestBootstrapRejectsWrongTokenWithoutConsumingRealToken(t *testing.T) {
	manager, bootstrap, err := NewManager(bytes.NewReader(bytes.Repeat([]byte{0x21}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bootstrap("wrong"); !errors.Is(err, ErrInvalidBootstrap) {
		t.Fatalf("wrong-token error = %v", err)
	}
	if _, err := manager.Bootstrap(bootstrap); err != nil {
		t.Fatalf("valid bootstrap after rejection: %v", err)
	}
}

var errRandom = errors.New("random source failed")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errRandom }

func TestNewManagerPropagatesRandomFailure(t *testing.T) {
	if _, _, err := NewManager(errReader{}); !errors.Is(err, errRandom) {
		t.Fatalf("NewManager error = %v", err)
	}
}

func TestBootstrapPropagatesSessionRandomFailure(t *testing.T) {
	initial := bytes.NewReader(bytes.Repeat([]byte{0x31}, 32))
	manager, bootstrap, err := NewManager(io.MultiReader(initial, errReader{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bootstrap(bootstrap); !errors.Is(err, errRandom) {
		t.Fatalf("Bootstrap error = %v", err)
	}
	if ok := manager.Authenticate(""); ok {
		t.Fatal("failed bootstrap created a session")
	}
}

// リロードすると CSRF トークンは失われる。ページの中にあったからだ。Cookie は残る
// のでセッションは残る。だがそのためのトークンを得る手段がないと、バイナリを起動
// し直すまでアプリケーションは死んだままだった。リロードがそこまでの代償を払う
// べきではない。
//
// トークンは返すのではなく発行し直す。マネージャが保持するのはハッシュであって
// トークンではない。それが、メモリの漏洩を全セッションのトークンの漏洩にしない
// 性質であり、発行し直す方式はそれを保つ。
// countingReader はバイト列のパターンを繰り返さないので、そこから引いた二つの
// トークンは、本番でトークンが異なるのと同じ理由で異なる。
type countingReader struct{ next byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for index := range p {
		r.next++
		p[index] = r.next
	}
	return len(p), nil
}

func TestRenewCSRFIssuesAWorkingTokenAndRetiresTheOld(t *testing.T) {
	// 変動する乱数源。定数の乱数源ではすべてのトークンが同一になり、古いトークンを
	// そのまま返す実装でもこのテストが通ってしまう。
	manager, bootstrap, err := NewManager(&countingReader{})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Bootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}

	renewed, ok := manager.RenewCSRF(credentials.SessionID)
	if !ok || renewed == "" {
		t.Fatalf("RenewCSRF = %q, %v", renewed, ok)
	}
	if renewed == credentials.CSRFToken {
		t.Error("the renewed token is the old one")
	}
	if !manager.VerifyCSRF(credentials.SessionID, renewed) {
		t.Error("the renewed token does not verify")
	}
	if manager.VerifyCSRF(credentials.SessionID, credentials.CSRFToken) {
		t.Error("the retired token still verifies")
	}
}

func TestRenewCSRFRefusesASessionThatIsNotThere(t *testing.T) {
	manager, _, err := NewManager(bytes.NewReader(bytes.Repeat([]byte{0x32}, 4096)))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := manager.RenewCSRF("not a session"); ok {
		t.Error("RenewCSRF answered for a session that does not exist")
	}
}

// ブートストラップは初回の使用で消費される。再発行があることで、最初の一つを
// 表示したプロセスが、標準出力がどこにも届かないバックグラウンドエージェントで
// あっても、ブラウザが入れるようになる。
func TestReissueMintsAWayInWithoutDisturbingTheSessions(t *testing.T) {
	manager, first, err := NewManager(&countingReader{})
	if err != nil {
		t.Fatal(err)
	}
	established, err := manager.Bootstrap(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bootstrap(first); !errors.Is(err, ErrBootstrapUsed) {
		t.Fatalf("the first bootstrap is still spendable: %v", err)
	}

	second, err := manager.Reissue()
	if err != nil {
		t.Fatalf("Reissue = %v", err)
	}
	if second == first {
		t.Error("the reissued bootstrap is the one that was spent")
	}
	if _, err := manager.Bootstrap(first); err == nil {
		t.Error("the old bootstrap still works after a reissue")
	}
	if _, err := manager.Bootstrap(second); err != nil {
		t.Fatalf("the reissued bootstrap does not work: %v", err)
	}
	// すでに存在するセッションには手を触れない。これは、セッションを持たないブラウザ
	// のための入口であって、持っているものを終わらせる手段ではない。
	if ok := manager.Authenticate(established.SessionID); !ok {
		t.Error("an established session was lost")
	}
}
