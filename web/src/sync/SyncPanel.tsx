import { useCallback, useEffect, useState } from "react";
import { failureCode } from "../api/client";
import {
  integrationsApi,
  type IntegrationsApi,
  type PullResponse,
  type SyncDirection,
  type SyncStatus,
} from "../api/integrations";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";
import {
  Field,
  control,
  hintText,
  primaryAction,
  secondaryAction,
  sectionCard,
  sectionHeading,
} from "../ui/form";
import { Notice } from "../ui/surface";

type SyncPanelProps = { api?: IntegrationsApi };

// The refusals this screen can meet, named. A code the server took the trouble
// to distinguish is a code the user can act on, and "that could not be done"
// sends them looking in the wrong place: a mistyped master password is not a
// bucket problem, and an endpoint with a path is not a credentials problem.
const refusals: Record<string, MessageKey> = {
  wrong_master_password: "sync.wrongMaster",
  bucket_refused: "sync.unreachable",
  sync_failed: "sync.unreachable",
  endpoint_must_have_no_path: "sync.endpointPath",
};

// The remote snapshot.
//
// Everything on this screen is a deliberate act. A pull previews first and
// applies only on a second press, which is the same shape every other write in
// this application takes, and a conflict is shown rather than resolved.
export function SyncPanel({ api = integrationsApi }: SyncPanelProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [endpoint, setEndpoint] = useState("");
  const [bucket, setBucket] = useState("");
  const [path, setPath] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [direction, setDirection] = useState<SyncDirection>("both");
  const [master, setMaster] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [preview, setPreview] = useState<PullResponse | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setStatus(await api.syncStatus());
    } catch {
      setError(t("sync.statusFailed"));
    }
  }, [api, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // explain turns a refusal the server named into the sentence for it, so a
  // caller that has more than one way to fail can say which one happened.
  async function run<T>(
    operation: () => Promise<T>,
    apply: (value: T) => void,
    failure: string,
    explain?: (code: string) => string,
  ) {
    setError("");
    setNotice("");
    setBusy(true);
    try {
      apply(await operation());
    } catch (caught) {
      const code = failureCode(caught);
      const named = refusals[code];
      setError(explain?.(code) || (named === undefined ? failure : t(named)));
    } finally {
      setBusy(false);
    }
  }

  if (status === null) {
    return <p role="status" className={hintText}>{t("sync.loading")}</p>;
  }

  // A shut vault cannot fill this form in, and neither push nor pull can run
  // without the settings it holds. Showing the form anyway would read as "your
  // bucket is gone" and invite the user to type the access key a second time,
  // which is the thing storing it was meant to stop.
  if (status.locked) {
    return (
      <div className="flex flex-col gap-4">
        <h2 className="font-medium">{t("sync.heading")}</h2>
        {error === "" ? null : <Notice tone="danger">{error}</Notice>}
        <section className={sectionCard}>
          <h3 className={sectionHeading}>{t("sync.bucketHeading")}</h3>
          <p className="text-sm text-ink-muted">{t("sync.sealed")}</p>
          <Field label={t("secrets.master")}>
            <input
              type="password"
              value={master}
              onChange={(event) => setMaster(event.target.value)}
              className={control}
            />
          </Field>
          <button
            type="button"
            disabled={busy || master === ""}
            onClick={() =>
              void run(
                () => api.unlockVault(master),
                () => {
                  setMaster("");
                  void reload();
                },
                // A machine that has never made a vault is not a machine whose
                // master password was wrong, and saying so would send someone
                // hunting for a password that does not exist.
                t("sync.unlockFailed"),
                (code) => (code === "vault_missing" ? t("sync.noVault") : ""),
              )
            }
            className={`self-start ${primaryAction}`}
          >
            {t("secrets.unlock")}
          </button>
        </section>
      </div>
    );
  }

  const conflicted = (preview?.conflicts ?? []).length > 0;

  return (
    <div className="flex flex-col gap-4">
      <h2 className="font-medium">{t("sync.heading")}</h2>
      {/*
        Said before the form, not after it. Everything in ~/.ssh travels,
        including the private keys, and the passphrase is the only thing
        between the bucket and them.
      */}
      <p className={hintText}>{t("sync.warning")}</p>
      {error === "" ? null : <Notice tone="danger">{error}</Notice>}
      {notice === "" ? null : <p role="status" className="text-sm text-ink-muted">{notice}</p>}

      <section className={sectionCard}>
        <h3 className={sectionHeading}>{t("sync.bucketHeading")}</h3>
        {status.configured ? (
          <p className="font-mono text-xs text-ink-muted">
            {[status.endpoint, status.bucket, status.path].filter((part) => part !== "" && part !== undefined).join("/")}
          </p>
        ) : (
          <p className="text-sm text-ink-muted">{t("sync.notConfigured")}</p>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("sync.endpoint")} hint={t("sync.endpointHint")}>
            <input
              value={endpoint}
              onChange={(event) => setEndpoint(event.target.value)}
              placeholder="https://<account>.r2.cloudflarestorage.com"
              className={control}
            />
          </Field>
          <Field label={t("sync.bucket")}>
            <input value={bucket} onChange={(event) => setBucket(event.target.value)} className={control} />
          </Field>
          {/*
            Empty means the bucket root, which is the common case: a bucket is
            usually named for this application already, and a folder inside it
            repeating the name is one level of nothing.
          */}
          <Field label={t("sync.path")} hint={t("sync.pathHint")}>
            <input value={path} onChange={(event) => setPath(event.target.value)} className={control} />
          </Field>
          <Field label={t("sync.accessKeyId")}>
            <input
              value={accessKeyId}
              onChange={(event) => setAccessKeyId(event.target.value)}
              className={control}
            />
          </Field>
          {/*
            The credentials are sealed with the master password and kept beside
            the vault rather than inside it. The vault travels; the key to the
            bucket must not, because anyone who obtained one snapshot could
            otherwise fetch every later one.
          */}
          <Field label={t("sync.secretAccessKey")} hint={t("sync.credentialsNote")}>
            <input
              type="password"
              value={secretAccessKey}
              onChange={(event) => setSecretAccessKey(event.target.value)}
              className={control}
            />
          </Field>
          {/*
            Which way this machine may move data. It governs the two writes: a
            machine set to send never has another machine's bytes applied to it,
            and one set to receive never writes to the bucket. The preview stays
            available either way, so a machine that may not apply can still be
            told how far behind it is.
          */}
          <Field label={t("sync.direction")} hint={t(`sync.direction.${direction}.hint`)}>
            <select
              value={direction}
              onChange={(event) => setDirection(event.target.value as SyncDirection)}
              className={control}
            >
              <option value="both">{t("sync.direction.both")}</option>
              <option value="push">{t("sync.direction.push")}</option>
              <option value="pull">{t("sync.direction.pull")}</option>
            </select>
          </Field>
        </div>
        <button
          type="button"
          disabled={busy || endpoint === "" || bucket === "" || accessKeyId === "" || secretAccessKey === ""}
          onClick={() =>
            void run(
              () => api.configureSync({ endpoint, bucket, path, accessKeyId, secretAccessKey, direction }),
              (next) => {
                setStatus(next);
                setAccessKeyId("");
                setSecretAccessKey("");
              },
              t("sync.configureFailed"),
            )
          }
          className={`self-start ${primaryAction}`}
        >
          {t("sync.configure")}
        </button>
      </section>

      <section className={sectionCard}>
        <h3 className={sectionHeading}>{t("sync.snapshotHeading")}</h3>
        <p className={hintText}>
          {status.synced
            ? t("sync.lastSynced", { at: status.lastSyncedAt ?? "", count: status.fileCount ?? 0 })
            : t("sync.neverSynced")}
        </p>
        <Field label={t("sync.passphrase")} hint={t("sync.passphraseLost")}>
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            className={control}
          />
        </Field>
        {status.direction === "both" ? null : (
          // The refusal is stated where the button is, not only when it is
          // pressed: a disabled control with no reason beside it reads as a
          // fault in the application rather than as a setting.
          <p role="status" className="text-sm text-notice-ink">
            {t(`sync.direction.${status.direction}.active`)}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={busy || !status.configured || passphrase === "" || status.direction === "pull"}
            onClick={() =>
              void run(
                () => api.pushSnapshot(passphrase),
                (next) => {
                  setStatus(next);
                  setPreview(null);
                  setNotice(t("sync.pushed"));
                },
                t("sync.pushFailed"),
              )
            }
            className={primaryAction}
          >
            {t("sync.push")}
          </button>
          <button
            type="button"
            disabled={busy || !status.configured || passphrase === ""}
            onClick={() =>
              void run(
                () => api.pullSnapshot(passphrase, false),
                (next) => {
                  setPreview(next);
                  setNotice(
                    next.written.length + next.removed.length + next.conflicts.length === 0
                      ? t("sync.alreadyMatches")
                      : "",
                  );
                },
                t("sync.pullFailed"),
              )
            }
            className={secondaryAction}
          >
            {t("sync.preview")}
          </button>
        </div>
      </section>

      {preview === null ? null : (
        <section className={sectionCard}>
          <h3 className={sectionHeading}>{t("sync.previewHeading")}</h3>
          {conflicted ? (
            <>
              {/*
                Two files that both changed have no correct merge. Guessing one
                would violate the byte-preservation promise the parser exists
                to keep, so this says which files and stops.
              */}
              <p className="text-sm text-notice-ink">{t("sync.conflictExplain")}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-notice-ink">
                {preview.conflicts.map((conflict) => (
                  <li key={conflict.path}>{conflict.path}</li>
                ))}
              </ul>
            </>
          ) : null}
          {preview.written.length === 0 ? null : (
            <>
              <p className={hintText}>{t("sync.wouldWrite", { count: preview.written.length })}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-ink-muted">
                {preview.written.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </>
          )}
          {preview.removed.length === 0 ? null : (
            <>
              <p className={hintText}>{t("sync.wouldRemove", { count: preview.removed.length })}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-danger">
                {preview.removed.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </>
          )}
          <button
            type="button"
            disabled={
              busy ||
              conflicted ||
              status.direction === "push" ||
              preview.written.length + preview.removed.length === 0
            }
            onClick={() =>
              void run(
                () => api.pullSnapshot(passphrase, true),
                (next) => {
                  setPreview(next);
                  setNotice(t("sync.applied"));
                  void reload();
                },
                t("sync.applyFailed"),
              )
            }
            className={`self-start ${primaryAction}`}
          >
            {t("sync.apply")}
          </button>
        </section>
      )}
    </div>
  );
}
