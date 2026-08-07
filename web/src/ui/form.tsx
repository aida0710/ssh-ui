import type { ReactNode } from "react";

// すべてのフォームコントロールに共通する見た目。
//
// これが存在するのは、3 つのパネルがそれぞれ独自のものを育て、1 つは
// 何も持っていなかったからだ。暗い背景では、飾りのない <input> は
// 単に地味なのではなく見えない: ボーダーも背景もない暗いページの
// 黒い文字だ。Keys 画面はファイル名・コメント・パスフレーズを、誰にも
// 見えない 3 つのフィールドで求めていた。ここでの 1 つの定義が、それの再発を止める。
export const control =
  "w-full rounded-md border border-control-line bg-control px-2 py-1.5 text-sm text-ink " +
  "placeholder:text-ink-faint focus:border-accent focus:outline-none " +
  "disabled:border-line disabled:text-ink-faint";

// 伸びるべきではないコントロール: 数値、色、短い名前。
export const narrowControl = control.replace("w-full", "w-40");

// 自身の内容の幅を取るコントロール。
//
// `control` は `w-full` であり、行や列の中では正しいがツールバーでは
// 間違っている: ヘッダーの 2 つの select に与えると、それらを帯全体に
// 引き伸ばし、アプリケーションの名前を 3 行の折り返しへと押し込めてしまった。
export const autoControl = control.replace("w-full", "w-auto");

// ボタンのラベルは名前であって段落ではない。放っておくと「Remove office」は
// その行に余地がなくなった瞬間に 2 行に割れ、ボタンに 2 階分の高さが生えてしまった。
// 行を折り返すのは正しく、語を折り返すのは正しくない。
// アクセントはここにのみ存在する。画面には 1 つの主要なアクションがあり、
// それ以上の何か——選択された行、アイコン、値——にその色を使うことが、
// 色から意味を失わせる原因だった。
export const primaryAction =
  "whitespace-nowrap rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink " +
  "hover:brightness-110 disabled:bg-line disabled:text-ink-faint";

export const secondaryAction =
  "whitespace-nowrap rounded-md border border-control-line bg-card px-3 py-1.5 text-sm text-ink " +
  "hover:bg-select-fill disabled:text-ink-faint";

export const dangerAction =
  "whitespace-nowrap rounded-md border border-control-line px-3 py-1.5 text-sm text-danger " +
  "hover:bg-select-fill";

export const fieldLabel = "text-xs font-medium tracking-wide text-ink-muted";
export const hintText = "text-xs text-ink-muted";
export const sectionCard = "flex flex-col gap-4 rounded-xl border border-line bg-card p-4";
export const sectionHeading = "text-sm font-medium text-ink";

// テーブルセルにはパディングがまったくなかったので、ヘッダーは上の値に
// 密着し、列同士が混ざり合っていた。
export const tableHeadRow = "border-b border-line text-xs uppercase tracking-wide text-ink-muted";
export const tableHeadCell = "py-2 pr-3 text-left font-medium";

type FieldProps = {
  label: string;
  hint?: string;
  children: ReactNode;
};

// Field はキャプションと 1 つのコントロールを対にする。
//
// label 要素は id で指し示すのではなくコントロールを包む。これは
// このアプリケーションのすべてのフォームが既に両者を関連付けていた
// 方法なので、accessible name は変わらず、テストセレクタも動かない。
//
// ヒントは意図的にその label の外に置く。中に置くと、助言の文章丸ごとが
// コントロールの accessible name の一部になってしまい、「New group name」という
// キャプションのフィールドが自身を「New group name Use a slash to nest:
// work/eu is a group inside work.」と読み上げてしまった。
export function Field({ label, hint, children }: FieldProps) {
  return (
    <div className="flex flex-col gap-1">
      <label className="flex flex-col gap-1">
        <span className={fieldLabel}>{label}</span>
        {children}
      </label>
      {hint === undefined ? null : <span className={hintText}>{hint}</span>}
    </div>
  );
}

type CheckboxFieldProps = {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  // コントロールを拒否することは、静かに何もしないフラグよりも良い:
  // 自分自身の接続を保持しているグループは隠せず、呼び出し側はその
  // 理由を隣に示す。
  disabled?: boolean;
};

// CheckboxField はボックスを、余裕のある形でその文の隣に置き、
// 折り返された文がボックスを中央まで押し下げないよう、
// 両者を上端で揃える。
export function CheckboxField({ label, checked, onChange, disabled = false }: CheckboxFieldProps) {
  return (
    <label className={`flex items-start gap-2 text-sm ${disabled ? "text-ink-faint" : "text-ink"}`}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-0.5 h-4 w-4 shrink-0 accent-accent"
      />
      <span>{label}</span>
    </label>
  );
}
