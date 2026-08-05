import { useCallback, useEffect, useState } from "react";
import {
  integrationsApi,
  type IntegrationsApi,
  type PullResponse,
  type SyncStatus,
} from "../api/integrations";
import { useTranslate } from "../i18n/context";
import {
  Field,
  control,
  hintText,
  primaryAction,
  secondaryAction,
  sectionCard,
  sectionHeading,
} from "../ui/form";

type SyncPanelProps = { api?: IntegrationsApi };

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
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
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

  async function run<T>(operation: () => Promise<T>, apply: (value: T) => void, failure: string) {
    setError("");
    setNotice("");
    setBusy(true);
    try {
      apply(await operation());
    } catch {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }

  if (status === null) {
    return <p role="status" className={hintText}>{t("sync.loading")}</p>;
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
      {error === "" ? null : <p role="alert" className="text-sm text-rose-300">{error}</p>}
      {notice === "" ? null : <p role="status" className="text-sm text-zinc-300">{notice}</p>}

      <section className={sectionCard}>
        <h3 className={sectionHeading}>{t("sync.bucketHeading")}</h3>
        {status.configured ? (
          <p className="font-mono text-xs text-zinc-400">{`${status.endpoint}/${status.bucket}`}</p>
        ) : (
          <p className="text-sm text-zinc-300">{t("sync.notConfigured")}</p>
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
          <Field label={t("sync.accessKeyId")}>
            <input
              value={accessKeyId}
              onChange={(event) => setAccessKeyId(event.target.value)}
              className={control}
            />
          </Field>
          {/*
            The credentials live in memory for this run and are never written
            into the workspace: a snapshot carrying the key to its own bucket
            would mean anyone who obtained one snapshot could fetch every later
            one.
          */}
          <Field label={t("sync.secretAccessKey")} hint={t("sync.credentialsNote")}>
            <input
              type="password"
              value={secretAccessKey}
              onChange={(event) => setSecretAccessKey(event.target.value)}
              className={control}
            />
          </Field>
        </div>
        <button
          type="button"
          disabled={busy || endpoint === "" || bucket === "" || accessKeyId === "" || secretAccessKey === ""}
          onClick={() =>
            void run(
              () => api.configureSync({ endpoint, bucket, accessKeyId, secretAccessKey }),
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
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={busy || !status.configured || passphrase === ""}
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
              <p className="text-sm text-amber-300">{t("sync.conflictExplain")}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-amber-200">
                {preview.conflicts.map((conflict) => (
                  <li key={conflict.path}>{conflict.path}</li>
                ))}
              </ul>
            </>
          ) : null}
          {preview.written.length === 0 ? null : (
            <>
              <p className={hintText}>{t("sync.wouldWrite", { count: preview.written.length })}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-zinc-300">
                {preview.written.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </>
          )}
          {preview.removed.length === 0 ? null : (
            <>
              <p className={hintText}>{t("sync.wouldRemove", { count: preview.removed.length })}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs text-rose-300">
                {preview.removed.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </>
          )}
          <button
            type="button"
            disabled={busy || conflicted || preview.written.length + preview.removed.length === 0}
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
