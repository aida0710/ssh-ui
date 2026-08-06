import { useEffect, useState } from "react";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";

type CopyButtonProps = {
  // The exact text that goes on the clipboard. What the user sees and what is
  // copied come from the same value, so the two can never disagree.
  value: string;
  // Names what is being copied. A screen with several copy buttons needs
  // several distinct accessible names, and "Copy" alone gives none. It is a
  // message key rather than text, because "Copy the command" and "コマンドを
  // コピー" put the noun in different places and a concatenated label would
  // read as broken Japanese.
  label: MessageKey;
  className?: string;
};

type CopyState = "idle" | "copied" | "failed";

// CopyButton writes one value to the system clipboard.
//
// It reports a refused write instead of swallowing it. The Clipboard API needs
// a secure context and a user gesture; 127.0.0.1 is a secure context and a
// click is a gesture, so this normally succeeds, but a browser policy or an
// extension can still refuse, and a button that always said "Copied" would be
// lying about where the value ended up.
//
// Nothing here holds the value beyond the render that passed it in: the caller
// owns it, and for the private key that caller drops it when its dialog closes.
export function CopyButton({ value, label, className }: CopyButtonProps) {
  const t = useTranslate();
  const [state, setState] = useState<CopyState>("idle");

  // A new value has not been copied, whatever the last one did. Without this,
  // the button would keep claiming success for text that is no longer on
  // screen — the worst version of this control, since the user would believe
  // the clipboard holds the thing they are looking at.
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
        aria-live rather than role="status": the shell owns the single status
        region, and a second one would compete with it.
      */}
      <span aria-live="polite" className={state === "failed" ? "text-xs text-red-300" : "text-xs text-ink-muted"}>
        {state === "copied" ? t("copy.done") : state === "failed" ? t("copy.refused") : ""}
      </span>
    </span>
  );
}
