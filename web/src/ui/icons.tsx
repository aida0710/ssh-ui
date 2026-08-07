import type { ReactNode } from "react";

// ストロークアイコンの 1 枚のスプライトを一度だけ定義し、`<use>` で参照する。
//
// アイコンフォントやスプライトファイルではなくインラインにしているのは、
// UI が埋め込みファイルシステムから配信され、何も fetch してはならず、
// フォントは読み込まれるまでの間、四角として描画されてしまうからだ。
//
// 形状はマークアップ文字列ではなく JSX だ。文字列にすると
// dangerouslySetInnerHTML を通じて DOM に届けることになり、この
// リポジトリは、誰かが読むたびにその呼び出しの隣の文字列がいまだに
// 定数のままだと証明せずに済むべきだ。
//
// ここにあるすべてのアイコンは自分自身のラベルの隣に座る。それらは
// 装飾なので accessibility tree から隠され、accessible name は語の方になる。
export const iconNames = [
  "connections",
  "config",
  "groups",
  "keys",
  "knownHosts",
  "remoteKeys",
  "diagnostics",
  "secrets",
  "sync",
  "history",
  "inspector",
] as const;

export type IconName = (typeof iconNames)[number];

const shapes: Record<IconName, ReactNode> = {
  connections: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
      <path d="M6.6 7.5h.01M6.6 16.5h.01" />
    </>
  ),
  config: (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5" />
    </>
  ),
  groups: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  keys: (
    <>
      <circle cx="7.5" cy="15.5" r="3.5" />
      <path d="M10 13L20 3M17 6l2 2M14 9l2 2" />
    </>
  ),
  knownHosts: (
    <>
      <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  remoteKeys: (
    <>
      <path d="M7.5 18a4 4 0 1 1 .6-7.95A5.5 5.5 0 0 1 18.6 11 3.5 3.5 0 0 1 18 18" />
      <path d="M12 21v-7M9.5 16.5L12 14l2.5 2.5" />
    </>
  ),
  diagnostics: <path d="M3 12h4l3 8 4-16 3 8h4" />,
  secrets: (
    <>
      <rect x="4" y="10" width="16" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </>
  ),
  sync: (
    <>
      <path d="M20 11a8 8 0 0 0-13.7-4.6L4 8.5" />
      <path d="M4 4.5v4h4" />
      <path d="M4 13a8 8 0 0 0 13.7 4.6L20 15.5" />
      <path d="M20 19.5v-4h-4" />
    </>
  ),
  history: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  inspector: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M15 4v16" />
    </>
  ),
};

export function IconSprite() {
  return (
    <svg aria-hidden="true" style={{ display: "none" }}>
      {iconNames.map((name) => (
        <symbol key={name} id={`icon-${name}`} viewBox="0 0 24 24">
          {shapes[name]}
        </symbol>
      ))}
    </svg>
  );
}

export function Icon({ name, className = "h-4 w-4" }: { name: IconName; className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={`shrink-0 ${className}`}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <use href={`#icon-${name}`} />
    </svg>
  );
}
