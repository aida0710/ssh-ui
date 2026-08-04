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
