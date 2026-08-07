package envelope_test

import (
	"errors"
	"sync"
	"testing"

	"sshc/internal/envelope"
)

// Seal は鍵だけで動き、開く操作はその鏡像である。すでに鍵を保持している
// 呼び出し側 — 鍵を保持し、パスフレーズは意図的に保持しない vault — は、自分の
// ファイルの隣にもうひとつ封をし、ユーザーに再度尋ねることなく読み戻すことが
// できる。
func TestAKeyOpensWhatItSealed(t *testing.T) {
	key, err := envelope.Derive("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte("the object store settings"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := key.Open(sealed)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	if string(plaintext) != "the object store settings" {
		t.Errorf("plaintext = %q", plaintext)
	}
}

func TestAnotherKeyCannotOpenIt(t *testing.T) {
	mine, err := envelope.Derive("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := envelope.Derive("a different master password")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := mine.Seal([]byte("the object store settings"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := theirs.Open(sealed); !errors.Is(err, envelope.ErrWrongPassphrase) {
		t.Errorf("Open with another key = %v, want ErrWrongPassphrase", err)
	}
}

func TestAKeyRefusesTamperedBytes(t *testing.T) {
	key, err := envelope.Derive("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte("the object store settings"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff

	if _, err := key.Open(sealed); err == nil {
		t.Error("a flipped bit was accepted")
	}
}

// 鍵の導出は意図的に高価なので、同時に何個走れるかは呼び出し側ではなくこちらが
// 決める数字である。
//
// アンロックも push も pull も導出を行い、三つとも普通のリクエストである。放って
// おけば、タブがいくつか開いたページやスクリプトが、64 MiB ずつのものを何十個も
// 要求しうる。これが加える待ち時間は無に等しく — 一人が操作するローカルの
// インターフェースだ — 確保せずに済むメモリはギガバイト単位である。
func TestDerivationsDoNotAllRunAtOnce(t *testing.T) {
	const attempts = 8
	var running, peak int64
	var mutex sync.Mutex
	var group sync.WaitGroup

	envelope.OnDerive = func(step func()) {
		mutex.Lock()
		running++
		if running > peak {
			peak = running
		}
		mutex.Unlock()
		step()
		mutex.Lock()
		running--
		mutex.Unlock()
	}
	t.Cleanup(func() { envelope.OnDerive = nil })

	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := envelope.Derive("a passphrase long enough"); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if peak > envelope.MaxConcurrentDerivations {
		t.Errorf("%d derivations ran at once, want at most %d", peak, envelope.MaxConcurrentDerivations)
	}
}

// ネットワーク越しに届いた envelope には、このインストールが書いたものより厳しい
// 上限を課す。その中のパラメータを選んだのはそれを書いた誰かであり、コストを
// 払うのは開くときだからである。
func TestARemoteEnvelopeMayNotAskForWhatALocalOneMay(t *testing.T) {
	// このインストールがローカルで受け入れるパラメータで封をしたもの。
	key, err := envelope.Derive("a passphrase long enough")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.Seal([]byte("a snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := envelope.OpenWithin(sealed, "a passphrase long enough", envelope.AcceptedFromRemote); err != nil {
		t.Fatalf("what Derive writes must open under the remote ceiling: %v", err)
	}

	// Derive が書く値を下回る上限は、コストを払わずに拒否する。
	tiny := envelope.Limits{Time: 1, MemoryKiB: 1024, Threads: 1}
	if _, _, err := envelope.OpenWithin(sealed, "a passphrase long enough", tiny); !errors.Is(err, envelope.ErrCostRefused) {
		t.Errorf("OpenWithin under a tiny ceiling = %v, want ErrCostRefused", err)
	}
}
