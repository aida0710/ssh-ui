import { useState } from "react";
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
      className="mt-6 rounded-xl border border-amber-700 bg-zinc-900 p-6"
    >
      <h3 id="reveal-heading" className="font-medium">
        {`Show private key: ${relativePath}`}
      </h3>
      {state === "confirm" && (
        <>
          <p className="mt-2 text-sm text-zinc-300">
            The private key will be displayed in this page and can be copied by anyone who can read this
            window. This application cannot protect it from browser extensions or from clipboard history
            tools. Every reveal is recorded in history, without the key itself.
          </p>
          <button
            type="button"
            className="mt-4 rounded-md border border-amber-600 px-3 py-2"
            onClick={() => void confirm()}
          >
            Show private key
          </button>
        </>
      )}
      {state === "loading" && (
        // aria-live rather than role="status": the shell owns the single status
        // region, and a second one would compete with it.
        <p aria-live="polite" className="mt-2 text-sm text-zinc-300">
          Requesting a one-time confirmation…
        </p>
      )}
      {state === "shown" && (
        <pre aria-label="Private key" className="mt-4 overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
          {material}
        </pre>
      )}
      {state === "error" && (
        <p role="alert" className="mt-2 text-sm text-red-300">
          The private key could not be shown. Close this dialog and confirm again.
        </p>
      )}
      <button type="button" className="mt-4 rounded-md border border-zinc-700 px-3 py-2" onClick={close}>
        Close
      </button>
    </div>
  );
}
