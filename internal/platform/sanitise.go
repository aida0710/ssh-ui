package platform

import "strings"

// SanitiseHomePaths は、テキスト中のユーザーのホームディレクトリを "~" に書き換える。
//
// 冗長な OpenSSH の出力は、読んだファイルをすべて絶対パスで名指しする。そのため、
// 接続試行で取り込んだ stderr は、そうしなければ、このアプリケーションを動かして
// いる人のアカウント名をレスポンス本文へ運んでしまう。テキスト自体は引き続き
// 表示する。失敗を理解するためにユーザーが必要とするからだ。取り除くのは、
// アカウントを特定する部分だけである。
//
// ホームが空またはルートの場合は無視する。"/" を書き換えれば、何も隠さないまま
// 出力中のあらゆる絶対パスを壊してしまう。
func SanitiseHomePaths(text, home string) string {
	cleaned := strings.TrimRight(home, "/")
	if cleaned == "" {
		return text
	}
	return strings.ReplaceAll(text, cleaned, "~")
}
