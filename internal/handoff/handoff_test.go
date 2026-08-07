package handoff_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/handoff"
)

func TestWritingTheHandoffAndTakingItAway(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sshc")
	secret, err := handoff.Mint(strings.NewReader(strings.Repeat("k", 64)))
	if err != nil {
		t.Fatalf("Mint = %v", err)
	}
	written, err := handoff.Write(directory, "http://127.0.0.1:52865", secret)
	if err != nil {
		t.Fatalf("Write = %v", err)
	}
	if len(written.Secret) < 32 {
		t.Errorf("the secret is %d characters, which is not one worth minting", len(written.Secret))
	}

	path := filepath.Join(directory, handoff.FileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the handoff was not written: %v", err)
	}
	// ~/.ssh の他のすべてと同じく、このユーザーだけが読める。
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}

	read, err := handoff.Read(directory)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if read.URL != written.URL || read.Secret != written.Secret {
		t.Errorf("read %+v, wrote %+v", read, written)
	}

	if err := handoff.Remove(directory); err != nil {
		t.Fatalf("Remove = %v", err)
	}
	if _, err := handoff.Read(directory); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Read after Remove = %v, want a missing file", err)
	}
	// ないものを削除することは、呼び出し側が求めた状態である。
	if err := handoff.Remove(directory); err != nil {
		t.Errorf("Remove twice = %v", err)
	}
}

// 二度目の実行は、一度目のファイルを信用せずに置き換える。秘密は実行ごとのもの
// なので、強制終了されたプロセスが残したハンドオフは、何も待ち受けていないポート
// を、誰も受け付けない秘密とともに指しているだけである。
func TestASecondRunReplacesTheHandoff(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sshc")
	firstSecret, err := handoff.Mint(strings.NewReader(strings.Repeat("a", 64)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := handoff.Write(directory, "http://127.0.0.1:1", firstSecret)
	if err != nil {
		t.Fatal(err)
	}
	secondSecret, err := handoff.Mint(strings.NewReader(strings.Repeat("b", 64)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := handoff.Write(directory, "http://127.0.0.1:2", secondSecret)
	if err != nil {
		t.Fatal(err)
	}
	if first.Secret == second.Secret {
		t.Error("two runs minted the same secret")
	}
	read, err := handoff.Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	if read.Secret != second.Secret || read.URL != "http://127.0.0.1:2" {
		t.Errorf("the file still describes the first run: %+v", read)
	}
}
