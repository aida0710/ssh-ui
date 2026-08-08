package storage

import (
	"os/user"

	"sshc/internal/config"
)

// ConfigLoader は、Include グラフにディスクへの読み取り専用アクセスを与える。
//
// 意図的にワークスペースのルート外のファイルも読む。よそを指す Include を表示する
// ことが設計上求められるからだ。ただしシンボリックリンクをたどることはなく、書き
// 込むこともない。何を変更してよいかを決めるのは Workspace.ResolveForWrite だけで
// ある。
type ConfigLoader struct {
	fileSystem FileSystem
}

func NewConfigLoader(workspace *Workspace) ConfigLoader {
	return ConfigLoader{fileSystem: workspace.FileSystem()}
}

func (l ConfigLoader) ReadFile(path string) ([]byte, error) {
	return l.fileSystem.ReadFile(path)
}

func (l ConfigLoader) Glob(pattern string) ([]string, error) {
	return l.fileSystem.Glob(pattern)
}

// NewResolver は、ワークスペースのための Include リゾルバを組み立てる。
//
// 供給するパーセントトークンは、接続先ホストが決まる前に確定しているものだけである。
// '%d'、'%u'、'%i' がそれにあたる。'%h' や '%C' は決まっていないので供給せず、それを
// 使う Include は推測されるのではなく非対応として報告される。
func NewResolver(workspace *Workspace) config.Resolver {
	tokens := map[byte]string{'d': workspace.Home()}
	// ユーザー名と uid はプロセスの性質であってワークスペースの性質ではないので、
	// Home のように注入するのではなくここで読む。ファイルには触れないため、これで
	// テストが本物のホームディレクトリに届くことはない。読めない環境では、その
	// トークンを供給しないことで、以前と同じく非対応として報告される。
	if current, err := user.Current(); err == nil {
		tokens['u'] = current.Username
		tokens['i'] = current.Uid
	}
	return config.Resolver{
		Loader: NewConfigLoader(workspace),
		Home:   workspace.Home(),
		Root:   workspace.Root(),
		// '~' と '%d' は、与えられたままのホームへ展開され、その結果に対する判断は
		// すべて解決済みのルートに対して行われる。両者を同じファイルに保つのが
		// Normalise である。
		Normalise: workspace.Normalise,
		Tokens:    tokens,
	}
}
