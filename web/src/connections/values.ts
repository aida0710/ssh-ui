// OpenSSH の argv_split は先頭の二重引用符を、次の二重引用符まで
// 続く引用トークンの開始として扱い、バックスラッシュエスケープには対応しない。
// エディタはその規則を正確に反映する。ユーザーが入力したものが
// そのままエンジンが書き込むものになるようにするためである。
export function parseValues(text: string): string[] {
  const values: string[] = [];
  let index = 0;
  while (index < text.length) {
    while (index < text.length && (text[index] === " " || text[index] === "\t")) index += 1;
    if (index >= text.length) break;

    if (text[index] === '"') {
      const closing = text.indexOf('"', index + 1);
      if (closing < 0) throw new Error("unbalanced_quote");
      values.push(text.slice(index + 1, closing));
      index = closing + 1;
      if (index < text.length && text[index] !== " " && text[index] !== "\t") {
        throw new Error("unbalanced_quote");
      }
      continue;
    }

    let end = index;
    while (end < text.length && text[end] !== " " && text[end] !== "\t") {
      if (text[end] === '"') throw new Error("unbalanced_quote");
      end += 1;
    }
    values.push(text.slice(index, end));
    index = end;
  }
  return values;
}

export function formatValues(values: string[]): string {
  return values
    .map((value) => (value === "" || /[ \t]/.test(value) || value.startsWith("#") ? `"${value}"` : value))
    .join(" ");
}
