package macos

import (
	"context"
	"errors"
	"net/url"

	"sshc/internal/platform"
)

var ErrUnsafeBrowserURL = errors.New("browser URL must use loopback HTTP")

// openProgram は、macOS が URL を既定のブラウザへ渡すためのプログラム。
//
// 絶対パスである。以前はここだけ裸の "open" を二つ目のプロセス継ぎ目へ渡しており、
// PATH 経由で解決されていた。この URL は生きた bootstrap トークンを運ぶので、それを
// 渡す相手が PATH の先頭にあるものであってはならない。他のすべての子プロセスと
// 同じ規律である。
const openProgram = "/usr/bin/open"

// Browser は、既定のブラウザで URL を開く。
type Browser struct {
	runner platform.OutputRunner
}

func NewBrowser(runner platform.OutputRunner) Browser {
	return Browser{runner: runner}
}

// Open は、ループバックの http URL を既定のブラウザへ渡す。
//
// それ以外は拒否する。この URL はワンタイムの bootstrap トークンを運ぶので、
// 行き先はこのマシン上のこのプロセスだけでなければならない。シェルは介在せず、
// URL は 1 つの完全な引数として渡るので、その中の "$(...)" はただの文字である。
func (browser Browser) Open(ctx context.Context, target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		return ErrUnsafeBrowserURL
	}
	_, err = browser.runner.RunOutput(ctx, platform.Command{
		Path:      openProgram,
		Arguments: []string{target},
	})
	return err
}
