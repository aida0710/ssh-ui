import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// パレットは index.css にある 20 個のトークンで、テーマごとに一度だけ
// 与えられる。それらを飛び越えて `text-red-400` に手を伸ばすコンポーネントは、
// もう一方のテーマでは値を持たず、色のルールの中で意味も持たない。accent は
// 画面の唯一の操作、amber は注意、red は破壊、green は生きたセッションを指す。
//
// このテストが存在するのは、そう言うだけでは足りなかったからだ。
// それらを取り除くはずだったスイープを 10 個のリテラルが生き延びた
// ——チェックは 4 つのパレット名への grep で、`red` はその中になかった——
// そして以後に書かれたコードでさらに 3 個が現れた。コメントの中にしか
// 生きていないルールは、朽ちていくルールだ。
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
    // 対象は本番のソースのみだ。テストは色を扱うことそのものが対象で
    // あれば、色を名指してよい——たとえばホストが選んだ配色見本など。
    return /\.tsx?$/.test(path) && !/\.test\.tsx?$/.test(path) ? [path] : [];
  });
}

// 色を書き記す方法は Tailwind のクラスだけではない。任意の値——
// `text-[#ff0000]`——は上のパターンにマッチしないクラスであり、
// インラインスタイル中の 16 進数はそもそもクラスですらない。2 つ目の
// 穴は仮定の話ではなかった: あるグループの配色見本はハードコードされた
// `#3f3f46`——別名 zinc-700——にフォールバックしており、このテストはそれを見えなかった。
//
// 16 進数が許されるのは、それがユーザーデータかネイティブコントロール
// 自身の既定値である場合であり、それが下の 2 行が免除を持つ理由のすべてだ。
const arbitrary = /\b(?:bg|text|border|outline|ring|fill|stroke|shadow|from|to|via)-\[#[0-9a-fA-F]{3,8}\]/g;
const rawHex = /#[0-9a-fA-F]{6}\b/g;
const exemption = "palette-exempt";

describe("the palette", () => {
  it("is the only source of colour in the application", () => {
    const offenders: string[] = [];
    for (const path of sources(join(__dirname, ".."))) {
      // このファイルはすべてのパレットを名指し、それらを探す。
      if (path.endsWith("palette.test.ts")) continue;
      readFileSync(path, "utf8")
        .split("\n")
        .forEach((line, index) => {
          const where = `${path.slice(path.indexOf("/src/") + 1)}:${index + 1}`;
          for (const found of line.match(literal) ?? []) offenders.push(`${where} ${found}`);
          for (const found of line.match(arbitrary) ?? []) offenders.push(`${where} ${found}`);
          if (line.includes(exemption)) return;
          for (const found of line.match(rawHex) ?? []) offenders.push(`${where} ${found}`);
        });
    }

    // メッセージはリストそのものだ。「expected 13 to be 0」では、次の人に
    // その 13 個を探させてしまうからだ。
    expect(offenders, `use a token from index.css instead:\n${offenders.join("\n")}`).toEqual([]);
  });
});
