// これらのヘルパーはファイル全体のそのままの編集の正確なテキストを組み立てる。
// 自分が追加していないものを決して再整形しないため、ホストの作成・
// 複製・削除においてもサーバーのバイト単位の保証は保たれる。

function offsetOfLine(contents: string, line: number): number {
  let offset = 0;
  for (let current = 1; current < line; current += 1) {
    const next = contents.indexOf("\n", offset);
    if (next < 0) throw new Error("block_moved");
    offset = next + 1;
  }
  return offset;
}

export function appendHostBlock(contents: string, alias: string): string {
  const block = `Host ${alias}\n\tHostName ${alias}\n`;
  if (contents === "") return block;
  const terminated = contents.endsWith("\n") ? contents : `${contents}\n`;
  return `${terminated}\n${block}`;
}

export function duplicateHostBlock(
  contents: string,
  raw: string,
  alias: string,
  newAlias: string,
  line = 0,
  commentLines = 0,
): string {
  const lineBreak = raw.indexOf("\n");
  const header = lineBreak < 0 ? raw : raw.slice(0, lineBreak);
  const rest = lineBreak < 0 ? "" : raw.slice(lineBreak);
  const tokens = header.split(" ");
  const aliasIndex = tokens.indexOf(alias);
  if (aliasIndex < 0) throw new Error("block_moved");
  tokens[aliasIndex] = newAlias;
  const copied = `${tokens.join(" ")}${rest}`;
  // コピーは、それが何のコピーであるかの説明を運ぶ。それがなければ、
  // 複製は説明された元の隣に、説明のないまま現れてしまう。
  let comment = "";
  if (commentLines > 0 && line > 0) {
    const offset = offsetOfLine(contents, line);
    comment = contents.slice(commentOffset(contents, offset, commentLines), offset);
  }
  const terminated = contents.endsWith("\n") ? contents : `${contents}\n`;
  return `${terminated}\n${comment}${copied.endsWith("\n") ? copied : `${copied}\n`}`;
}

// commentOffset はブロック自身の offset から commentLines 分の物理行を
// 遡る。そこが付属する comment の始まる位置である。
//
// この数は comment のテキストからではなくパーサーから得る。テキストはマーカーと
// インデントが取り除かれているため、ファイルに対して測ることが
// できないからである。
function commentOffset(contents: string, offset: number, commentLines: number): number {
  let start = offset;
  for (let remaining = commentLines; remaining > 0; remaining--) {
    const previous = contents.lastIndexOf("\n", start - 2);
    start = previous < 0 ? 0 : previous + 1;
  }
  return start;
}

export function removeHostBlock(
  contents: string,
  line: number,
  raw: string,
  commentLines = 0,
): string {
  const offset = offsetOfLine(contents, line);
  if (!contents.startsWith(raw, offset)) throw new Error("block_moved");
  // comment はブロックと共に移動する。取り残されれば、後に続くどの
  // ブロックにも付着し、黙ってその接続の説明になってしまう。
  const start = commentOffset(contents, offset, commentLines);
  return contents.slice(0, start) + contents.slice(offset + raw.length);
}
