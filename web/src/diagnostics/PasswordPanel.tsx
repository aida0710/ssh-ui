import { useCallback, useEffect, useState } from "react";
import { integrationsApi, type IntegrationsApi, type PasswordVaultStatus } from "../api/integrations";
import { useTranslate } from "../i18n/context";
import { Field, control, dangerAction, hintText, primaryAction, secondaryAction, sectionCard, sectionHeading } from "../ui/form";

type PasswordPanelProps = {
  api?: IntegrationsApi;
  // The host this panel stores a password for. The panel is only rendered
  // inside a host editor, so there is always one.
  alias: string;
};

// The stored-password panel.
//
// Three things are true at once here and the panel has to say all of them: the
// vault may not exist, it may exist and be locked, and this host may or may not
// have a password in it. Collapsing those into one state would produce the
// classic "it says nothing is saved, but something is" confusion, because a
// locked vault genuinely cannot tell.
export function PasswordPanel({ api = integrationsApi, alias }: PasswordPanelProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<PasswordVaultStatus | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setStatus(await api.passwordVault());
    } catch {
      setError(t("password.statusFailed"));
    }
  }, [api, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Every typed secret is dropped when the host changes. A passphrase left in
  // a field while the user navigates is a secret sitting in the DOM for no
  // reason.
  useEffect(() => {
    setPassphrase("");
    setPassword("");
    setError("");
  }, [alias]);

  async function run(operation: () => Promise<PasswordVaultStatus>, failure: string) {
    setError("");
    setBusy(true);
    try {
      setStatus(await operation());
      setPassphrase("");
      setPassword("");
    } catch {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }

  if (status === null) {
    return <p role="status" className={hintText}>{t("password.loading")}</p>;
  }

  const stored = status.aliases.includes(alias);
  const minimum = status.minPassphraseLength ?? 12;

  return (
    <section aria-label={t("password.heading")} className={sectionCard}>
      <h3 className={sectionHeading}>{t("password.heading")}</h3>
      {/*
        The sentence that must not be a tooltip. A stored password is the
        remote account's credential, and a key is stronger; someone deciding
        whether to use this should read that before the field, not after.
      */}
      <p className={hintText}>{t("password.warning")}</p>
      {error === "" ? null : <p role="alert" className="text-sm text-rose-300">{error}</p>}

      {!status.exists ? (
        <>
          <p className="text-sm text-zinc-300">{t("password.noVault", { count: minimum })}</p>
          <Field label={t("password.newPassphrase")} hint={t("password.passphraseLost")}>
            <input
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              className={control}
            />
          </Field>
          <button
            type="button"
            disabled={busy || passphrase.length < minimum}
            onClick={() => void run(() => api.initialiseVault(passphrase), t("password.initialiseFailed"))}
            className={`self-start ${primaryAction}`}
          >
            {t("password.initialise")}
          </button>
        </>
      ) : !status.unlocked ? (
        <>
          {/*
            A locked vault cannot say whether this host has a password. Saying
            "none stored" here would be a guess, and a wrong one half the time.
          */}
          <p className="text-sm text-zinc-300">{t("password.locked")}</p>
          <Field label={t("password.passphrase")}>
            <input
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              className={control}
            />
          </Field>
          <button
            type="button"
            disabled={busy || passphrase === ""}
            onClick={() => void run(() => api.unlockVault(passphrase), t("password.unlockFailed"))}
            className={`self-start ${primaryAction}`}
          >
            {t("password.unlock")}
          </button>
        </>
      ) : stored ? (
        <>
          <p className="text-sm text-zinc-300">{t("password.stored", { alias })}</p>
          <p className={hintText}>{t("password.armedNote")}</p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => void run(() => api.forgetPassword(alias), t("password.forgetFailed"))}
              className={dangerAction}
            >
              {t("password.forget", { alias })}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void run(() => api.lockVault(), t("password.lockFailed"))}
              className={secondaryAction}
            >
              {t("password.lock")}
            </button>
          </div>
        </>
      ) : (
        <>
          <Field label={t("password.password", { alias })} hint={t("password.knownHostFirst")}>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className={control}
            />
          </Field>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy || password === ""}
              onClick={() => void run(() => api.storePassword(alias, password), t("password.storeFailed"))}
              className={primaryAction}
            >
              {t("password.store")}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void run(() => api.lockVault(), t("password.lockFailed"))}
              className={secondaryAction}
            >
              {t("password.lock")}
            </button>
          </div>
        </>
      )}
    </section>
  );
}
