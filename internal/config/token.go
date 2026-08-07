package config

import (
	"errors"
	"strings"
)

// Argument は、ディレクティブの引数ひとつと、それを生んだ正確なバイト列の組。
// Lead は引数の前にある空白を保持するので、解析した行を 1 バイトも違わず
// レンダリングし直せる。
type Argument struct {
	Lead  string
	Raw   string
	Value string
}

// ErrUnquotableValue は、ssh_config で表現できない値を報告する。OpenSSH は引用符で
// 囲まれた引数の中にバックスラッシュエスケープを持たないので、二重引用符・改行・
// NUL を含む値には綴りがなく、壊すのではなく拒否する。
var ErrUnquotableValue = errors.New("value cannot be quoted for an OpenSSH configuration")

// RenderArgument は、OpenSSH の引用規則に従って値をひとつ書き出す。
func RenderArgument(lead, value string) (Argument, error) {
	if strings.ContainsAny(value, "\n\r\x00\"") {
		return Argument{}, ErrUnquotableValue
	}
	raw := value
	if value == "" || strings.ContainsAny(value, " \t") || strings.HasPrefix(value, "#") {
		raw = `"` + value + `"`
	}
	return Argument{Lead: lead, Raw: raw, Value: value}, nil
}

// splitArguments は、ディレクティブ行の引数部分を分割する。
//
// OpenSSH の argv_split は、トークンの先頭にある二重引用符を、次の二重引用符まで
// 続く引用文字列の始まりとして扱い、バックスラッシュエスケープには対応しない。
// そのルールの下で引用を再現できない入力は非構造化として報告され（ok == false）、
// 呼び出し側は意味を推測する代わりに、その行を逐語的に
// 保持する。
func splitArguments(input string) (arguments []Argument, trailing string, ok bool) {
	index := 0
	for {
		leadStart := index
		for index < len(input) && isSpace(input[index]) {
			index++
		}
		lead := input[leadStart:index]
		if index == len(input) {
			return arguments, lead, true
		}

		rawStart := index
		var value string
		if input[index] == '"' {
			index++
			closing := strings.IndexByte(input[index:], '"')
			if closing < 0 {
				return nil, "", false
			}
			value = input[index : index+closing]
			index += closing + 1
			if index < len(input) && !isSpace(input[index]) {
				return nil, "", false
			}
		} else {
			for index < len(input) && !isSpace(input[index]) {
				if input[index] == '"' {
					return nil, "", false
				}
				index++
			}
			value = input[rawStart:index]
		}

		arguments = append(arguments, Argument{
			Lead:  lead,
			Raw:   input[rawStart:index],
			Value: value,
		})
	}
}

func isSpace(character byte) bool {
	return character == ' ' || character == '\t'
}
