import { useState } from "react";
import { CopyButton } from "../ui/CopyButton";
import { useTranslate } from "../i18n/context";
import type { KeysApi } from "./api";

type RevealDialogProps = {
  keyId: string;
  relativePath: string;
  api: Pick<KeysApi, "reveal">;
  onClose: () => void;
};

type DialogState = "confirm" | "loading" | "shown" | "error";

// RevealDialog は秘密鍵の実体を 1 つのコンポーネント状態値にのみ保持し、
// それ以外のどこにも保持しない。ストレージにもグローバルオブジェクトにも
// ロガーにも分析シンクにも書き込まず、ダイアログが閉じると参照を捨てるので、
// 鍵を再表示するには新たな確認が必要になる。
//
// ブラウザ拡張やクリップボード履歴ツールから鍵を守るとは、意図的に
// うたっていない。守れないからだ。
export function RevealDialog({ keyId, relativePath, api, onClose }: RevealDialogProps) {
  const t = useTranslate();
  const [state, setState] = useState<DialogState>("confirm");
  const [material, setMaterial] = useState("");

  function close() {
    setMaterial("");
    setState("confirm");
    onClose();
  }

  async function confirm() {
    setState("loading");
    try {
      const response = await api.reveal(keyId);
      setMaterial(response.privateKey);
      setState("shown");
    } catch {
      setMaterial("");
      setState("error");
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="reveal-heading"
      className="mt-6 rounded-xl border border-notice-line bg-control p-6"
    >
      <h3 id="reveal-heading" className="font-medium">
        {t("reveal.heading", { path: relativePath })}
      </h3>
      {state === "confirm" && (
        <>
          <p className="mt-2 text-sm text-ink-muted">{t("reveal.warning")}</p>
          <button
            type="button"
            className="mt-4 rounded-md border border-notice-line px-3 py-2"
            onClick={() => void confirm()}
          >
            {t("reveal.show")}
          </button>
        </>
      )}
      {state === "loading" && (
        // role="status" ではなく aria-live: シェルが唯一のステータス
        // 領域を所有しており、2 つ目があるとそれと競合してしまう。
        <p aria-live="polite" className="mt-2 text-sm text-ink-muted">
          {t("reveal.requesting")}
        </p>
      )}
      {state === "shown" && (
        <>
          <pre aria-label={t("reveal.privateKeyLabel")} className="mt-4 overflow-x-auto rounded-md bg-canvas p-4 text-xs">
            {material}
          </pre>
          {/*
            コピーを提供するのは design §6.3 がそれを求めているのと、代わりに
            手動選択をしても結局同じようにクリップボードに載ってしまうからだ。
            上の警告は既に、いったんそこに置かれた鍵をこのアプリケーションが
            守れないと述べている。ボタンがあってもそれが
            より真実になったりより真実でなくなったりはしない。
          */}
          <div className="mt-2">
            <CopyButton value={material} label="copy.privateKey" />
          </div>
        </>
      )}
      {state === "error" && (
        <p role="alert" className="mt-2 text-sm text-danger">
          {t("reveal.failed")}
        </p>
      )}
      <button type="button" className="mt-4 rounded-md border border-control-line px-3 py-2" onClick={close}>
        {t("reveal.close")}
      </button>
    </div>
  );
}
