package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrInvalidBootstrap = errors.New("invalid bootstrap token")
	ErrBootstrapUsed    = errors.New("bootstrap token already used")
)

type Credentials struct {
	SessionID string
	CSRFToken string
}

type Session struct {
	csrfHash [sha256.Size]byte
	// actions は、このセッションの未使用の確認を保持する。キーは配られたトークンの
	// ダイジェストで、セッション自身のキーの付け方とまったく同じである。このマップは
	// Session 値のすべてのコピーで共有されており、それによってアクション用のヘルパー
	// は、もう一度検索することなくここへ到達できる。
	actions map[[sha256.Size]byte]actionRecord
}

type Manager struct {
	mu            sync.RWMutex
	random        io.Reader
	bootstrapHash [sha256.Size]byte
	bootstrapUsed bool
	sessions      map[[sha256.Size]byte]Session

	// Now は、アクショントークンの失効に使う時計。本番では nil で time.Now が使われる。
	// テストは、マネージャが共有される前に一度だけこれを設定する。
	Now func() time.Time
}

func token(random io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func NewManager(random io.Reader) (*Manager, string, error) {
	bootstrap, err := token(random)
	if err != nil {
		return nil, "", err
	}

	return &Manager{
		random:        random,
		bootstrapHash: sha256.Sum256([]byte(bootstrap)),
		sessions:      make(map[[sha256.Size]byte]Session),
	}, bootstrap, nil
}

// Reissue は新しいブートストラップトークンを発行し、マネージャが持つものを置き換える。
//
// ブートストラップは初回の使用で消費される。これができるまでは、新しいプロセスだけ
// が次の一つを表示していた — ユーザーがアプリケーションを起動して URL が表示される
// なら問題ないが、標準出力がどこにも届かないバックグラウンドエージェントとして動く
// 場合は役に立たない。再発行を求めるのはコマンドラインであり、そもそも求めるには、
// このユーザーしか読めないファイルを読む必要がある。
//
// すでに確立しているセッションは確立したままである。これが置き換えるのは、まだ
// セッションを持たないブラウザのための入口だけだ。
func (m *Manager) Reissue() (string, error) {
	fresh, err := token(m.random)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bootstrapHash = sha256.Sum256([]byte(fresh))
	m.bootstrapUsed = false
	return fresh, nil
}

func (m *Manager) Bootstrap(presented string) (Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.bootstrapUsed {
		return Credentials{}, ErrBootstrapUsed
	}

	presentedHash := sha256.Sum256([]byte(presented))
	if subtle.ConstantTimeCompare(presentedHash[:], m.bootstrapHash[:]) != 1 {
		return Credentials{}, ErrInvalidBootstrap
	}

	sessionID, err := token(m.random)
	if err != nil {
		return Credentials{}, err
	}
	csrf, err := token(m.random)
	if err != nil {
		return Credentials{}, err
	}

	m.bootstrapUsed = true
	m.sessions[sha256.Sum256([]byte(sessionID))] = Session{
		csrfHash: sha256.Sum256([]byte(csrf)),
		actions:  make(map[[sha256.Size]byte]actionRecord),
	}
	return Credentials{SessionID: sessionID, CSRFToken: csrf}, nil
}

// RenewCSRF は、すでに存在するセッションのために新しい CSRF トークンを発行する。
//
// リロードするとトークンは失われる。ページの中にあったからだ。Cookie は残るので
// セッションは残る。これがないと、ブートストラップのフラグメントは初回の使用で
// 消費され、次の一つを表示するのは新しいプロセスだけなので、バイナリを起動し直す
// までアプリケーションは死んだままだった。
//
// トークンは返すのではなく発行し直す。このマネージャが保持するのはハッシュだけで
// あってトークンではない。それが、メモリの漏洩を全セッションのトークンの漏洩に
// しない性質であり、発行し直す方式はその性質を保つ。古いトークンは検証を通らなく
// なるが、それが正しい。セッションにつきページはひとつであり、新しいトークンが
// 発行されたあとも古いものが通るなら、それは誰も意図せず持っている二本目の鍵に
// なってしまう。
func (m *Manager) RenewCSRF(sessionID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := sha256.Sum256([]byte(sessionID))
	existing, ok := m.sessions[key]
	if !ok {
		return "", false
	}
	csrf, err := token(m.random)
	if err != nil {
		return "", false
	}
	existing.csrfHash = sha256.Sum256([]byte(csrf))
	m.sessions[key] = existing
	return csrf, true
}

// Authenticate は、セッションが存在するかどうかだけを報告する。
//
// 以前は Session そのものを返していた。その actions マップは、このマネージャが
// 守っている実体そのものである。たまたま呼び出し側がすべて破棄していたので競合は
// 起きなかったが、保持する呼び出し側がいれば、別の goroutine の書き込みの下で
// マップを読むことになり、それを知る術もなかった。
func (m *Manager) Authenticate(sessionID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	return ok
}

func (m *Manager) VerifyCSRF(sessionID, csrf string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessionValue, ok := m.sessions[sha256.Sum256([]byte(sessionID))]
	if !ok {
		return false
	}
	presentedHash := sha256.Sum256([]byte(csrf))
	return subtle.ConstantTimeCompare(presentedHash[:], sessionValue.csrfHash[:]) == 1
}
