// ドラッグが何を運んでいるか、そしてどのドロップを提示する価値があるか。
//
// ここにあるすべての規則は、サーバーが既に行っている拒否を映している。これらが存在する
// のは、うまくいかない target を提示しないためであり、何かを強制するためではない。
// すべてのドロップは依然として API を通り、届いた拒否は依然として表示される。

export type DragPayload =
  | { kind: "connection"; path: string; alias: string; group: string }
  | { kind: "group"; name: string };

// dataTransfer 上のプライベート型により、このページの外で始まった
// ドラッグがこれらの一つと誤認されない。これは常に`types`からのみ
// 読む。dragover ハンドラはデータ自体を読めない。ドロップまで保護されているからである。
export const dragMimeType = "application/x-sshc-drag";

// internal/application/grouppath.go の MaxGroupSegments。この制限は
// ここにある何かではなく鍵スキャナーに由来する。スキャナーは
// ~/.ssh から八階層下まで辿り、"keys"がそのうち一つを使う。七つ目の
// グループセグメント内の鍵は depth_exceeded として報告され、インベントリから消えてしまう。
const maxGroupSegments = 6;

// 空文字列は"no group" target である。接続にとってはエントリ
// ファイルを、グループにとっては最上位を意味する。
const noGroup = "";

function segments(name: string): number {
  return name === noGroup ? 0 : name.split("/").length;
}

function basename(name: string): string {
  const index = name.lastIndexOf("/");
  return index < 0 ? name : name.slice(index + 1);
}

function isSelfOrDescendant(name: string, candidate: string): boolean {
  return candidate === name || candidate.startsWith(`${name}/`);
}

export function canDrop(payload: DragPayload, target: string, groups: string[]): boolean {
  // 接続が住む場所は一つだけであるため、何もしないドロップは
  // 既にそこにある場所へのドロップだけである。
  if (payload.kind === "connection") {
    return payload.group !== target;
  }
  // グループはどんな深さであれ、自分自身の内側に置くことはできない。
  if (isSelfOrDescendant(payload.name, target)) return false;
  const moved = target === noGroup ? basename(payload.name) : `${target}/${basename(payload.name)}`;
  if (moved === payload.name) return false;
  if (groups.includes(moved)) return false;
  return segments(moved) <= maxGroupSegments;
}
