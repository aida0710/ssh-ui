import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The palette is twenty tokens in index.css, given once per theme, and a
// component that reaches past them for `text-red-400` has no value in the other
// theme and no meaning in the colour rule: the accent is the screen's one
// action, amber is a notice, red destroys something, green is the live session.
//
// This test exists because saying so was not enough. Ten literals survived the
// sweep that was supposed to remove them — the check was a grep for four
// palette names and `red` was not among them — and three more arrived
// afterwards in code written since. A rule that only lives in a comment is a
// rule that decays.
const palettes = [
  "slate", "gray", "grey", "zinc", "neutral", "stone",
  "red", "orange", "amber", "yellow", "lime", "green", "emerald",
  "teal", "cyan", "sky", "blue", "indigo", "violet", "purple",
  "fuchsia", "pink", "rose",
];

const literal = new RegExp(
  String.raw`\b(?:bg|text|border|outline|ring|accent|fill|stroke|from|to|via|decoration|divide|shadow)-(?:${palettes.join("|")})-\d{2,3}\b`,
  "g",
);

function sources(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(path) ? [path] : [];
  });
}

describe("the palette", () => {
  it("is the only source of colour in the application", () => {
    const offenders: string[] = [];
    for (const path of sources(join(__dirname, ".."))) {
      // This file names every palette in order to look for them.
      if (path.endsWith("palette.test.ts")) continue;
      readFileSync(path, "utf8")
        .split("\n")
        .forEach((line, index) => {
          for (const found of line.match(literal) ?? []) {
            offenders.push(`${path.slice(path.indexOf("/src/") + 1)}:${index + 1} ${found}`);
          }
        });
    }

    // The message is the list, because "expected 13 to be 0" would send the
    // next person looking for the thirteen.
    expect(offenders, `use a token from index.css instead:\n${offenders.join("\n")}`).toEqual([]);
  });
});
