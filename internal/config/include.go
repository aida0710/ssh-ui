package config

import (
	"errors"
	"path"
	"path/filepath"
	"strings"
)

// DefaultMaxDepth は OpenSSH の MAX_READCONF_DEPTH に対応する。
const DefaultMaxDepth = 16

// ErrUnsupportedExpansion は、その意味がエンジンの持たない情報に依存する Include
// の引数に対して返る。グラフは、どのファイルに一致するかを推測せず、パターンを
// そのまま報告する。
var ErrUnsupportedExpansion = errors.New("include pattern uses an unsupported expansion")

// Loader は、リゾルバに設定ファイルへの読み取り専用アクセスを与える。本番で使う
// 実装はストレージ層が供給し、テストはマップに裏打ちされた偽物を供給する。パスと
// パターンは絶対で、すでに正規化されている。
type Loader interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// Resolver は、ユーザー設定ファイルを起点に Include グラフを走査する。
//
// Home は '~' と '%d' に使う絶対的なホームディレクトリ。Root は相対的な Include
// 引数の解決基準となるディレクトリで、OpenSSH はユーザー設定ファイルについて
// これを ~/.ssh と定義しており、このアプリケーションが書き込んでよい唯一の
// ディレクトリでもある。Tokens は、接続先ホストが決まる前に判明しているパーセント
// トークンを保持する。それ以外のトークンは、非対応の展開として報告
// される。
type Resolver struct {
	Loader Loader
	Home   string
	Root   string
	// Normalise は、Home から組み立てたパスを Root の綴りと突き合わせる。両者が
	// 異なりうると知っている呼び出し側のためのものだ。ワークスペースはルートを
	// EvalSymlinks で解決し、ホームは与えられたまま保持するので、~/.ssh がリンク
	// 経由で到達される場合は常に "~/.ssh/x" と "<root>/x" が二つの名前を持つ同じ
	// ファイルになる — そしてこれがないと、そうした Include はすべてルートの外に
	// あると報告され、編集が拒否されていた。
	//
	// 省略可能。これを持たずに作られたリゾルバは、従来どおりに振る舞う。
	Normalise func(string) string
	Tokens    map[byte]string
	MaxDepth  int
}

func (r Resolver) maxDepth() int {
	if r.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return r.MaxDepth
}

// expandPattern は、Include の引数ひとつを絶対的なグロブパターンに変換する。
func (r Resolver) expandPattern(argument string) (string, error) {
	if argument == "" {
		return "", ErrUnsupportedExpansion
	}
	expanded, err := r.expandTokens(argument)
	if err != nil {
		return "", err
	}
	switch {
	case expanded == "~":
		expanded = r.Home
	case strings.HasPrefix(expanded, "~/"):
		expanded = r.Home + expanded[1:]
	case strings.HasPrefix(expanded, "~"):
		// '~user/...' は、エンジンが行わない passwd データベースの参照を必要とする。
		return "", ErrUnsupportedExpansion
	case !strings.HasPrefix(expanded, "/"):
		expanded = r.Root + "/" + expanded
	}
	cleaned := path.Clean(expanded)
	if r.Normalise != nil {
		cleaned = filepath.ToSlash(r.Normalise(filepath.FromSlash(cleaned)))
	}
	return cleaned, nil
}

func (r Resolver) expandTokens(argument string) (string, error) {
	if !strings.ContainsRune(argument, '%') {
		return argument, nil
	}
	var builder strings.Builder
	for index := 0; index < len(argument); index++ {
		if argument[index] != '%' {
			builder.WriteByte(argument[index])
			continue
		}
		if index+1 >= len(argument) {
			return "", ErrUnsupportedExpansion
		}
		index++
		if argument[index] == '%' {
			builder.WriteByte('%')
			continue
		}
		value, ok := r.Tokens[argument[index]]
		if !ok {
			return "", ErrUnsupportedExpansion
		}
		builder.WriteString(value)
	}
	return builder.String(), nil
}
