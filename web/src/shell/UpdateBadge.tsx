import { useEffect, useState } from "react";
import { integrationsApi, type IntegrationsApi, type UpdateStatus } from "../api/integrations";
import { useTranslate } from "../i18n/context";

type UpdateBadgeProps = { api?: IntegrationsApi };

// The version, and the one control that changes it.
//
// The check is a request this application makes to GitHub — the only host it
// contacts other than itself — and it is made from the server rather than the
// page, so the page's connect-src stays 'self'. It runs when this mounts and
// otherwise only when pressed.
//
// What updating actually does is said before it is done: it replaces a named
// file on disk with bytes from a release, and what is already running goes on
// running until the application is started again.
export function UpdateBadge({ api = integrationsApi }: UpdateBadgeProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState("");

  useEffect(() => {
    let active = true;
    void api
      .updateStatus()
      .then((loaded) => {
        if (active) setStatus(loaded);
      })
      // A machine with no network still shows its version; it just cannot say
      // whether there is a newer one.
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [api]);

  if (status === null) {
    return null;
  }
  return (
    <div className="border-t border-line px-2 py-2 text-xs text-ink-muted">
      <p>{t("update.version", { version: status.current })}</p>
      {failed === "" ? null : (
        <p role="alert" className="mt-1 text-danger">
          {failed}
        </p>
      )}
      {status.restartRequired ? (
        <p className="mt-1 text-notice-ink">{t("update.restart")}</p>
      ) : status.available ? (
        <>
          <p className="mt-1 text-ink">{t("update.available", { version: status.latest ?? "" })}</p>
          {/*
            Named before it is pressed: this replaces a file, and which file it
            is should never be a surprise.
          */}
          {status.path === undefined ? null : (
            <p className="mt-1 break-all font-mono text-ink-faint">{status.path}</p>
          )}
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              setFailed("");
              void api
                .applyUpdate()
                .then(setStatus)
                .catch(() => setFailed(t("update.failed")))
                .finally(() => setBusy(false));
            }}
            className="mt-1 rounded border border-control-line px-2 py-1 text-xs text-ink hover:bg-select-fill"
          >
            {busy ? t("update.applying") : t("update.apply")}
          </button>
        </>
      ) : null}
    </div>
  );
}
