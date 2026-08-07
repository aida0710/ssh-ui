package storage

import "sshc/internal/config"

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
// パーセントトークンとして供給するのは '%d' だけである。'%u' と '%i' はローカルの
// ユーザー名と uid を必要とし、それはプラットフォーム層が後のサブシステムで提供
// する。それまでは、それらのパターンは推測されるのではなく非対応として報告される。
func NewResolver(workspace *Workspace) config.Resolver {
	return config.Resolver{
		Loader: NewConfigLoader(workspace),
		Home:   workspace.Home(),
		Root:   workspace.Root(),
		// '~' と '%d' は、与えられたままのホームへ展開され、その結果に対する判断は
		// すべて解決済みのルートに対して行われる。両者を同じファイルに保つのが
		// Normalise である。
		Normalise: workspace.Normalise,
		Tokens:    map[byte]string{'d': workspace.Home()},
	}
}
