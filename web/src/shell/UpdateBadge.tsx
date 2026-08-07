import { useEffect, useState } from "react";
import { integrationsApi, type IntegrationsApi, type UpdateStatus } from "../api/integrations";
import { useTranslate } from "../i18n/context";

type UpdateBadgeProps = { api?: IntegrationsApi };

// The version, and whether a newer one has been published.
//
// The check is a request this application makes to GitHub — the only host it
// contacts other than itself — and it is made from the server rather than the
// page, so the page's connect-src stays 'self'. It runs when this mounts and
// not otherwise.
//
// It offers a link and not a button. Replacing the running binary with bytes
// from a release was here and is gone: the signature that guarded it needed a
// key the release workflow could read, which is a key anybody who controls the
// repository can read, so the defence and the attack had the same key. What is
// left is the useful half — knowing there is a newer version — with the
// decision left to a person.
export function UpdateBadge({ api = integrationsApi }: UpdateBadgeProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<UpdateStatus | null>(null);

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
      {!status.available || status.pageUrl === undefined ? null : (
        <p className="mt-1">
          <a
            href={status.pageUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="text-ink underline underline-offset-2"
          >
            {t("update.available", { version: status.latest ?? "" })}
          </a>
        </p>
      )}
    </div>
  );
}
