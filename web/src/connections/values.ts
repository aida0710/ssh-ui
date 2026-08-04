// OpenSSH's argv_split treats a leading double quote as the start of a quoted
// token that runs to the next double quote and supports no backslash escapes.
// The editor mirrors that rule exactly so what the user types is what the
// engine will write.
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
