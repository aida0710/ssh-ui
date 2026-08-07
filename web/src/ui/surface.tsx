import type { ButtonHTMLAttributes, ReactNode } from "react";
import { dangerAction, hintText, primaryAction, secondaryAction } from "./form";

// macOS のシステム設定が関連する設定をグループ化するのと同じ、行の
// 差し込みカード: 行の間にヘアライン、グループの周りにボーダー、
// そしてグループ自身の説明は中ではなく下に置く。
export function Card({ children, padded = false }: { children: ReactNode; padded?: boolean }) {
  // 行は自前のパディングを持つので、カードは既定でパディングを持たない。
  // `padded` は別種の中身——さもなければボーダーに接してしまう、狭い
  // ペインの積み重なったフィールド——のためのものだ。両方の inspector が
  // このクラス文字列を、それを言う場所を持たずに手でコピーしていた。
  return (
    <div
      className={`overflow-hidden rounded-xl border border-line bg-card ${
        padded ? "flex flex-col gap-3 p-3" : ""
      }`}
    >
      {children}
    </div>
  );
}

// 1 つの設定: 左に名前、右にコントロール。
//
// label 要素は id で指し示すのではなくコントロールを包む。これは
// このアプリケーションのすべてのフォームが既に両者を関連付けている
// 方法なので、accessible name が一意であるために id は不要だ。
// 同じキーワードが 2 つのホストに表示されうるページでもそうだ。
export function Row({
  label,
  children,
  hint,
  warning,
  action,
}: {
  label: string;
  children: ReactNode;
  // `| undefined` を書き出しているのは、このプロジェクトが
  // exactOptionalPropertyTypes を設定しているからだ。これがなければ呼び出し側は、
  // 「ヒントなし」を計算して渡すことができず、属性を丸ごと省くしかない。
  hint?: string | undefined;
  // Amber であり、かつ告知される。hint は助言であり、warning はエンジンが
  // この行について何かを報告しているものだ。
  warning?: string | undefined;
  // 末尾のコントロール——「Remove」やその類。
  //
  // これは意図的に label 要素の外にある。中にあると、ボタンをクリック
  // することが label も発火させてフォーカスをフィールドへ移してしまい、
  // ボタン自身の語がフィールドの accessible name に加わってしまう。
  action?: ReactNode;
}) {
  return (
    <div className="border-t border-hairline first:border-t-0">
      <div className="flex items-center gap-3 px-3 py-2">
        <label className="flex min-w-0 flex-1 items-center gap-3">
          <span className="w-32 shrink-0 text-sm text-ink-muted">{label}</span>
          <span className="ml-auto flex min-w-0 flex-1 justify-end">{children}</span>
        </label>
        {action === undefined ? null : <span className="shrink-0">{action}</span>}
      </div>
      {hint === undefined ? null : <p className={`px-3 pb-2 ${hintText}`}>{hint}</p>}
      {warning === undefined ? null : (
        <p role="status" className="px-3 pb-2 text-xs text-notice-ink">
          {warning}
        </p>
      )}
    </div>
  );
}

// amber の帯。amber は notice で red は何かを破壊する。画面上で他に
// 色が付いているものはないので、これが読まれる前に目を引くものになる。
export function Notice({ children, tone = "notice" }: { children: ReactNode; tone?: "notice" | "danger" }) {
  const danger = tone === "danger";
  return (
    <p
      role={danger ? "alert" : "status"}
      className={
        danger
          ? "flex items-center gap-2 rounded-lg border border-control-line px-3 py-2 text-sm text-danger"
          : "flex items-center gap-2 rounded-lg border border-notice-line bg-notice px-3 py-2 text-sm text-notice-ink"
      }
    >
      {children}
    </p>
  );
}

// segmented control: 2 つか 3 つの排他的な選択肢を、別々のボタンではなく
// 1 つのコントロールとして示す。
//
// 押下状態は、ラジオグループではなく各セグメントの `aria-pressed`
// で表す。これはこのアプリケーションが既に同じコントロールに使っていた
// ものであり、そのテストが対象にしているものだ。
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <div role="group" aria-label={label} className="flex gap-0.5 rounded-md bg-select-fill p-0.5">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
          className={`rounded px-2.5 py-0.5 text-xs ${
            value === option.value ? "bg-card text-ink shadow-sm" : "text-ink-muted"
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

type ButtonProps = { kind?: "primary" | "secondary" | "danger" } & ButtonHTMLAttributes<HTMLButtonElement>;

// type="button" が既定なのは、このアプリケーションのすべてのボタンが
// そうだからだ: フォーム送信はどこにもなく、<form> の中で既定の
// 「submit」になるボタンがあれば、ページをリロードしてセッションを失ってしまう。
export function Button({ kind = "secondary", className = "", type = "button", ...rest }: ButtonProps) {
  const base = kind === "primary" ? primaryAction : kind === "danger" ? dangerAction : secondaryAction;
  return <button type={type} className={`${base} ${className}`} {...rest} />;
}
