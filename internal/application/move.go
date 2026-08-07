package application

import (
	"errors"

	"sshc/internal/config"
)

var (
	ErrDuplicateDestinationAlias = errors.New("the destination file already declares this alias")
	ErrSameFileMove              = errors.New("source and destination are the same file")
	// ErrAliasAlreadyDeclared は、Include graph 内の他のブロックが既に
	// 主張している名前への rename を報告する。それを書き込んでも第 2 のホストが
	// 作られるわけではない。作られるのは 1 個の名前への第 2 の主張であり、
	// OpenSSH はその名前を最初に読んだブロックへ与える——そしてグループの生成領域が
	// エントリファイルの先頭に来るようになった今、ユーザーが見ていたものではないことが多い。
	ErrAliasAlreadyDeclared = errors.New("another block in the configuration already declares this alias")
)

// ExtractHostBlock は alias を宣言するブロックを取り除き、その行を返す。
//
// 取り除かれる範囲は、射影がブロックの生テキストとして示す
// 範囲そのものである。Host ヘッダー行から次の Host または Match ヘッダーの
// 手前の行までであり、そのブロックが持つ空行と、その上に付随する
// コメントを含むが、後続のブロックに付随するコメントは含まない。
//
// 付随するコメントはブロックと共に移動する。それを置き去りにすることは、
// それを失うことより悪い。ヘッダーの上のコメントの連なりはその下の
// ブロックに属するので、ソースファイルに残された説明は、後に続く
// どんなブロックの説明にも黙って成り代わってしまう。
func ExtractHostBlock(file *config.File, alias string) ([]config.Line, error) {
	block, ok := FindHostBlock(file, alias)
	if !ok {
		return nil, ErrHostNotFound
	}
	start := file.CommentRun(block.Header)
	// ブロックの範囲は次のヘッダーまで及ぶので、その末尾は後に続く
	// ブロックに属するコメントを保持している。範囲全体を取り出すと、
	// 次の connection の説明をこのブロックと一緒に持ち去ってしまう——これは
	// このブロックのコメントを置き去りにするのと鏡合わせであり、同じくらい間違っている。
	end := file.CommentRun(block.End)
	// 末尾は、どの connection にも属さない生成領域を保持している
	// こともある。
	start, end = ClampToRegion(file, start, end)
	extracted := make([]config.Line, 0, end-start)
	extracted = append(extracted, file.Lines[start:end]...)

	remaining := make([]config.Line, 0, len(file.Lines)-len(extracted))
	remaining = append(remaining, file.Lines[:start]...)
	remaining = append(remaining, file.Lines[end:]...)
	file.Lines = remaining
	return extracted, nil
}

// AppendHostBlock は取り出した行をファイルの末尾に追加し、ファイルが
// 既に空行で終わっていない場合は 1 個の空行で区切る。追加される行は
// 決して書き換えられないので、移動したブロックは、エンジンが分解
// できなかった行も含め、すべてのバイトを保つ。
func AppendHostBlock(file *config.File, lines []config.Line) {
	if len(lines) == 0 {
		return
	}
	if len(file.Lines) > 0 {
		ending := dominantEnding(file)
		last := &file.Lines[len(file.Lines)-1]
		if last.Ending == "" {
			last.Ending = ending
		}
		if last.Kind != config.LineBlank {
			file.Lines = append(file.Lines, config.Line{Kind: config.LineBlank, Ending: ending})
		}
	}
	file.Lines = append(file.Lines, lines...)
}

// MoveHostBlock は 1 個のホストブロックを source から destination へ移動する。
//
// destination を先にチェックすることで、拒否された move は両方のファイルを
// 元のままにする。両方のファイルは呼び出し側が読み込んだバイト列から
// 組み立てられるので、source はそのブロックの行だけを失い、destination は
// その行だけをそっくり得る。
func MoveHostBlock(source, destination *config.File, alias string) ([]config.Line, error) {
	if _, exists := FindHostBlock(destination, alias); exists {
		return nil, ErrDuplicateDestinationAlias
	}
	extracted, err := ExtractHostBlock(source, alias)
	if err != nil {
		return nil, err
	}
	AppendHostBlock(destination, extracted)
	return extracted, nil
}

// movedAliases は移動したブロックが宣言する具体的な alias を列挙し、呼び出し側が move
// の影響を受けるすべての alias について並び替えを説明できるようにする。wildcard と
// negation は、このエンジンがそれらを解決すると謳ったことは一度も無いので、スキップされる。
func movedAliases(lines []config.Line) []string {
	block := &config.File{Lines: lines}
	var aliases []string
	for _, candidate := range block.Blocks() {
		if candidate.Kind != config.BlockHost {
			continue
		}
		for _, pattern := range candidate.Patterns {
			if pattern.Negated || pattern.Wildcard {
				continue
			}
			aliases = append(aliases, pattern.Value)
		}
	}
	return aliases
}
