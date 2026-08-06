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

// RevealDialog holds private key material in one component state value and in
// nothing else. It writes to no storage, no global object, no logger and no
// analytics sink, and it drops its reference when the dialog closes, so showing
// the key again costs a fresh confirmation.
//
// It deliberately does not claim to protect the key from a browser extension or
// from a clipboard history tool, because it cannot.
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
        // aria-live rather than role="status": the shell owns the single status
        // region, and a second one would compete with it.
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
            Copying is offered because design §6.3 asks for it and because the
            alternative is a manual selection that lands on the clipboard just
            the same. The warning above already says this application cannot
            protect the key once it is there; a button does not make that
            truer or less true.
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
