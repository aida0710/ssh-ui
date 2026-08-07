import { useEffect, useState } from "react";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";

type CopyButtonProps = {
  // クリップボードに載る、そのままの文字列。ユーザーが見るものと
  // コピーされるものは同じ値から来るので、両者が食い違うことは決してない。
  value: string;
  // 何がコピーされるかを名指す。コピーボタンが複数ある画面には
  // 複数の異なる accessible name が必要で、「Copy」だけでは何も与えない。
  // これはテキストではなくメッセージキーだ。「Copy the command」と
  // 「コマンドをコピー」とでは名詞の位置が異なり、連結されたラベルは
  // 壊れた日本語として読めてしまうからだ。
  label: MessageKey;
  className?: string;
};

type CopyState = "idle" | "copied" | "failed";

// CopyButton は 1 つの値をシステムクリップボードに書き込む。
//
// 拒否された書き込みは、握りつぶさずに報告する。Clipboard API には
// secure context とユーザーのジェスチャーが必要だ。127.0.0.1 は
// secure context であり、クリックはジェスチャーなので、これは通常
// 成功する。だがブラウザのポリシーや拡張機能はそれでも拒否することがあり、
// 常に「Copied」と言うボタンは、値がどこに行き着いたかについて嘘をつくことになる。
//
// ここでは値を、渡された描画の間より長く保持しない: それを所有するのは
// 呼び出し側で、秘密鍵の場合は、そのダイアログが閉じたときに呼び出し側がそれを捨てる。
export function CopyButton({ value, label, className }: CopyButtonProps) {
  const t = useTranslate();
  const [state, setState] = useState<CopyState>("idle");

  // 最後に何が起きたかにかかわらず、新しい値はまだコピーされていない。
  // これがなければ、ボタンはもう画面上にないテキストについて成功を
  // 主張し続けてしまう——このコントロールの最悪版だ。ユーザーが
  // クリップボードには自分が見ているものが入っていると信じてしまうからだ。
  useEffect(() => {
    setState("idle");
  }, [value]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  return (
    <span className="inline-flex items-center gap-2">
      <button
        type="button"
        onClick={() => void copy()}
        className={className ?? "rounded border border-control-line px-2 py-1 text-xs"}
      >
        {t("copy.button", { label: t(label) })}
      </button>
      {/*
        role="status" ではなく aria-live: シェルが唯一のステータス
        領域を所有しており、2 つ目があるとそれと競合してしまう。
      */}
      <span aria-live="polite" className={state === "failed" ? "text-xs text-danger" : "text-xs text-ink-muted"}>
        {state === "copied" ? t("copy.done") : state === "failed" ? t("copy.refused") : ""}
      </span>
    </span>
  );
}
