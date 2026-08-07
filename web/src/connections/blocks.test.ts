import { describe, expect, it } from "vitest";
import { appendHostBlock, duplicateHostBlock, removeHostBlock } from "./blocks";

const contents = "# top\nHost bastion\n\tUser ops\n\nHost nas\n\tUser aida\n";

describe("appendHostBlock", () => {
  it("adds a block at the end and keeps every existing byte", () => {
    expect(appendHostBlock(contents, "build01")).toBe(
      "# top\nHost bastion\n\tUser ops\n\nHost nas\n\tUser aida\n\nHost build01\n\tHostName build01\n",
    );
  });

  it("adds the missing final newline before appending", () => {
    expect(appendHostBlock("Host nas\n\tUser aida", "build01")).toBe(
      "Host nas\n\tUser aida\n\nHost build01\n\tHostName build01\n",
    );
  });

  it("creates the first block of an empty file without a leading blank line", () => {
    expect(appendHostBlock("", "build01")).toBe("Host build01\n\tHostName build01\n");
  });
});

describe("duplicateHostBlock", () => {
  it("copies a block and renames only the alias on the header line", () => {
    const raw = "Host bastion jump.example.com\n\tUser bastion\n";
    expect(duplicateHostBlock(contents, raw, "bastion", "bastion-copy")).toBe(
      `${contents}\nHost bastion-copy jump.example.com\n\tUser bastion\n`,
    );
  });
});

describe("removeHostBlock", () => {
  it("removes exactly the block that starts at the given line", () => {
    expect(removeHostBlock(contents, 2, "Host bastion\n\tUser ops\n\n")).toBe("# top\nHost nas\n\tUser aida\n");
  });

  it("refuses to remove when the text at that line is not the block", () => {
    expect(() => removeHostBlock(contents, 2, "Host other\n")).toThrow("block_moved");
  });
});

// comment に意味を持たせたことで、ファイルを壊す新しい方法が生まれた。
// 削除されたブロックに取り残された comment は、後に続くどのブロックにも
// 付着し、黙ってその接続の説明になってしまう。
describe("a block's attached comment", () => {
  const contents =
    "# the production bastion\n" +
    "# ask infra first\n" +
    "Host bastion\n" +
    "\tPort 2222\n" +
    "\n" +
    "Host nas\n" +
    "\tPort 22\n";

  it("is removed with the block it belongs to", () => {
    const raw = "Host bastion\n\tPort 2222\n";
    const after = removeHostBlock(contents, 3, raw, 2);

    expect(after).toBe("\nHost nas\n\tPort 22\n");
    expect(after).not.toContain("the production bastion");
  });

  it("is left alone when the block has none", () => {
    const plain = "Host bastion\n\tPort 2222\nHost nas\n";
    expect(removeHostBlock(plain, 1, "Host bastion\n\tPort 2222\n", 0)).toBe("Host nas\n");
  });

  it("is copied with a duplicate, so the copy is explained too", () => {
    const after = duplicateHostBlock(contents, "Host bastion\n\tPort 2222\n", "bastion", "bastion-copy", 3, 2);

    expect(after).toContain("# the production bastion\n# ask infra first\nHost bastion-copy\n\tPort 2222\n");
    // 元は自分自身の comment を保つ。
    expect(after.match(/the production bastion/g)).toHaveLength(2);
  });

  it("removes a block that starts the file together with its comment", () => {
    // lastIndexOf はファイルの先頭を越えて進んではならない。
    const after = removeHostBlock("# only\nHost nas\n", 2, "Host nas\n", 1);
    expect(after).toBe("");
  });
});
