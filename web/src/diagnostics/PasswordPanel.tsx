import { useCallback, useEffect, useState } from "react";
import {
  integrationsApi,
  type Credential,
  type IntegrationsApi,
  type PasswordEligibility,
  type PasswordVaultStatus,
} from "../api/integrations";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";
import { Field, control, dangerAction, hintText, primaryAction, secondaryAction, sectionCard, sectionHeading } from "../ui/form";
import { Notice } from "../ui/surface";

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
// The codes the server reports, mapped to what they mean for this host. An
// unknown code is shown as itself rather than swallowed: a rule added on the
// server and not here should be visible, not invisible.
const eligibilityKeys: Record<string, MessageKey> = {
  password_authentication_off: "password.blocker.authenticationOff",
  alias_not_simple: "password.blocker.aliasNotSimple",
  identity_file_configured: "password.warn.identityFile",
  host_key_unknown: "password.warn.hostKeyUnknown",
  hostname_unresolved: "password.warn.hostNameUnresolved",
};

function eligibilityText(translate: (key: MessageKey) => string, code: string): string {
  return code in eligibilityKeys ? translate(eligibilityKeys[code]!) : code;
}

export function PasswordPanel({ api = integrationsApi, alias }: PasswordPanelProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<PasswordVaultStatus | null>(null);
  const [eligibility, setEligibility] = useState<PasswordEligibility | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [chosen, setChosen] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      const vault = await api.passwordVault();
      setStatus(vault);
      // A shut vault is not asked for its names. Nothing is asked at startup
      // either: this panel asks for itself, when the host it belongs to is open.
      setCredentials(vault.unlocked ? (await api.credentials()).credentials : []);
    } catch {
      setError(t("password.statusFailed"));
    }
  }, [api, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // What stands between this host and a stored password is read from the
  // configuration and known_hosts. The panel used to state the host-key
  // precondition as prose under the field and check nothing, which is a
  // sentence the user has to verify by hand for every host.
  useEffect(() => {
    let active = true;
    setEligibility(null);
    void api
      .passwordEligibility(alias)
      .then((report) => {
        if (active) setEligibility(report);
      })
      .catch(() => {
        // A panel that cannot read the configuration says nothing about it
        // rather than claiming the host is fine.
        if (active) setEligibility(null);
      });
    return () => {
      active = false;
    };
  }, [api, alias]);

  // Every typed secret is dropped when the host changes. A passphrase left in
  // a field while the user navigates is a secret sitting in the DOM for no
  // reason.
  useEffect(() => {
    setPassphrase("");
    setPassword("");
    setChosen("");
    setError("");
  }, [alias]);

  // The vault status and the names are two documents, and an action on one of
  // them changes the other: storing a password adds a name, pointing a host at
  // a name adds a subject. So each action keeps the answer it was given and
  // fetches the other half, rather than re-reading both and contradicting the
  // answer it just got.
  async function run(operation: () => Promise<PasswordVaultStatus>, failure: string) {
    setError("");
    setBusy(true);
    try {
      const vault = await operation();
      setStatus(vault);
      setCredentials(vault.unlocked ? (await api.credentials()).credentials : []);
      setPassphrase("");
      setPassword("");
    } catch {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }

  async function runNames(operation: () => Promise<{ credentials: Credential[] }>, failure: string) {
    setError("");
    setBusy(true);
    try {
      setCredentials((await operation()).credentials);
      setStatus(await api.passwordVault());
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
  // Account passwords only. A picker that offered a key's passphrase would let
  // one press send that passphrase to a remote host as a login password, which
  // is the reason the two namespaces are two namespaces.
  const sharable = credentials.filter((credential) => credential.kind === "password");
  const uses = sharable.find((credential) => credential.uses.includes(alias));
  const blocked = (eligibility?.blockers ?? []).length > 0;

  return (
    <section aria-label={t("password.heading")} className={sectionCard}>
      <h3 className={sectionHeading}>{t("password.heading")}</h3>
      {/*
        The sentence that must not be a tooltip. A stored password is the
        remote account's credential, and a key is stronger; someone deciding
        whether to use this should read that before the field, not after.
      */}
      <p className={hintText}>{t("password.warning")}</p>
      {error === "" ? null : <Notice tone="danger">{error}</Notice>}

      {!status.exists ? (
        <>
          <p className="text-sm text-ink-muted">{t("password.noVault", { count: minimum })}</p>
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
          <p className="text-sm text-ink-muted">{t("password.locked")}</p>
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
          <p className="text-sm text-ink-muted">{t("password.stored", { alias })}</p>
          {/*
            Which name, when it is not this host's own. A shared secret is the
            reason names exist, and someone about to forget it here should know
            whether they are removing one host's password or their own reference
            to a password several hosts use.
          */}
          {uses === undefined || uses.name === alias ? null : (
            <p className={hintText}>{t("password.usesName", { name: uses.name })}</p>
          )}
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
          {(eligibility?.blockers ?? []).length === 0 ? null : (
            <div role="alert" className="flex flex-col gap-1 rounded border border-control-line bg-card/30 p-3">
              <p className="text-sm text-danger">{t("password.blocked", { alias })}</p>
              <ul className="flex flex-col gap-1">
                {(eligibility?.blockers ?? []).map((notice, index) => (
                  <li key={`${notice.code}-${index}`} className="text-xs text-danger">
                    {eligibilityText(t, notice.code)}
                    {notice.path === undefined ? "" : ` (${notice.path}${notice.line === undefined ? "" : `:${notice.line}`})`}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(eligibility?.warnings ?? []).length === 0 ? null : (
            <ul className="flex flex-col gap-1">
              {(eligibility?.warnings ?? []).map((notice, index) => (
                <li key={`${notice.code}-${index}`} className="text-xs text-notice-ink">
                  {eligibilityText(t, notice.code)}
                  {notice.detail === undefined ? "" : ` (${notice.detail})`}
                </li>
              ))}
            </ul>
          )}
          {/*
            An existing name first, because the second field makes a new secret
            and the first makes this host share one that already exists.
          */}
          {sharable.length === 0 ? null : (
            <div className="flex flex-wrap items-end gap-3">
              <Field label={t("password.useStored")} hint={t("password.shareNote")}>
                <select
                  value={chosen}
                  onChange={(event) => setChosen(event.target.value)}
                  disabled={blocked}
                  className={control}
                >
                  <option value="">{t("password.chooseName")}</option>
                  {sharable.map((credential) => (
                    <option key={credential.name} value={credential.name}>
                      {credential.name}
                    </option>
                  ))}
                </select>
              </Field>
              <button
                type="button"
                disabled={busy || chosen === "" || blocked}
                onClick={() =>
                  void runNames(
                    () => api.assignCredential("password", alias, chosen),
                    t("password.assignFailed"),
                  )
                }
                className={primaryAction}
              >
                {t("password.useThis", { alias })}
              </button>
            </div>
          )}
          <Field label={t("password.password", { alias })}>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={blocked}
              className={control}
            />
          </Field>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy || password === "" || blocked}
              onClick={() => void run(() => api.storePassword(alias, password), t("password.storeFailed"))}
              className={primaryAction}
            >
              {t("password.store", { alias })}
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
