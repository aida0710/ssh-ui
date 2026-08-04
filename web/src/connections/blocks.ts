// These helpers compose the exact text of a whole-file raw edit. They never
// reformat anything they did not add, so the server's byte-for-byte guarantee
// still holds for creating, duplicating and deleting a host.

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

export function duplicateHostBlock(contents: string, raw: string, alias: string, newAlias: string): string {
  const lineBreak = raw.indexOf("\n");
  const header = lineBreak < 0 ? raw : raw.slice(0, lineBreak);
  const rest = lineBreak < 0 ? "" : raw.slice(lineBreak);
  const tokens = header.split(" ");
  const aliasIndex = tokens.indexOf(alias);
  if (aliasIndex < 0) throw new Error("block_moved");
  tokens[aliasIndex] = newAlias;
  const copied = `${tokens.join(" ")}${rest}`;
  const terminated = contents.endsWith("\n") ? contents : `${contents}\n`;
  return `${terminated}\n${copied.endsWith("\n") ? copied : `${copied}\n`}`;
}

export function removeHostBlock(contents: string, line: number, raw: string): string {
  const offset = offsetOfLine(contents, line);
  if (!contents.startsWith(raw, offset)) throw new Error("block_moved");
  return contents.slice(0, offset) + contents.slice(offset + raw.length);
}
