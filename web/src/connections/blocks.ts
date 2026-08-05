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
  // A copy carries the description of what it is a copy of. Without it the
  // duplicate arrives unexplained next to an original that is explained.
  let comment = "";
  if (commentLines > 0 && line > 0) {
    const offset = offsetOfLine(contents, line);
    comment = contents.slice(commentOffset(contents, offset, commentLines), offset);
  }
  const terminated = contents.endsWith("\n") ? contents : `${contents}\n`;
  return `${terminated}\n${comment}${copied.endsWith("\n") ? copied : `${copied}\n`}`;
}

// commentOffset walks back commentLines physical lines from the block's own
// offset, which is where its attached comment begins.
//
// The count comes from the parser rather than from the comment text, because
// the text has had its markers and indentation stripped and cannot be measured
// against the file.
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
  // The comment goes with the block. Left behind, it would attach to whichever
  // block follows and silently become that connection's description.
  const start = commentOffset(contents, offset, commentLines);
  return contents.slice(0, start) + contents.slice(offset + raw.length);
}
