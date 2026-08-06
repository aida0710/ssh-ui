import { useCallback, useEffect, useState } from "react";
import { failureCode } from "../api/client";
import {
  integrationsApi,
  type Credential,
  type CredentialKind,
  type IntegrationsApi,
  type LoginItem,
  type PasswordVaultStatus,
} from "../api/integrations";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";
import { PasswordField } from "../ui/PasswordField";
import {
  CheckboxField,
  Field,
  control,
  dangerAction,
  hintText,
  primaryAction,
  secondaryAction,
  sectionCard,
  sectionHeading,
} from "../ui/form";
import { Notice } from "../ui/surface";

type SecretsPanelProps = {
  api?: IntegrationsApi;
  // onLock lets the shell shut its own front door. Locking the vault locks the
  // application, so a panel that only refreshed itself would leave the user
  // inside a shell whose next request will be refused.
  onLock?: () => void;
};

// The two namespaces, drawn apart.
//
// They are apart in the format, the API and the types because one namespace
// would let a host's picker offer a key's passphrase, and picking it would send
// that passphrase to a remote host as a login password. Drawing them as one
// list here would put the choice back in front of the user that the format took
// away, so they are two lists that never hold each other's entries.
const kinds: {
  kind: CredentialKind;
  heading: MessageKey;
  nameLabel: MessageKey;
  valueLabel: MessageKey;
  store: MessageKey;
}[] = [
  {
    kind: "password",
    heading: "secrets.passwordsHeading",
    nameLabel: "secrets.newPasswordName",
    valueLabel: "secrets.newPasswordValue",
    store: "secrets.storePassword",
  },
  {
    kind: "key_passphrase",
    heading: "secrets.passphrasesHeading",
    nameLabel: "secrets.newPassphraseName",
    valueLabel: "secrets.newPassphraseValue",
    store: "secrets.storePassphrase",
  },
];

export function SecretsPanel({ api = integrationsApi, onLock }: SecretsPanelProps) {
  const t = useTranslate();
  const [status, setStatus] = useState<PasswordVaultStatus | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [master, setMaster] = useState("");
  const [currentMaster, setCurrentMaster] = useState("");
  const [nextMaster, setNextMaster] = useState("");
  const [confirmMaster, setConfirmMaster] = useState("");
  const [changed, setChanged] = useState("");
  const [drafts, setDrafts] = useState<Record<string, { name: string; secret: string }>>({});
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    try {
      const vault = await api.passwordVault();
      setStatus(vault);
      // A shut vault is not asked for its contents. Nothing is asked at
      // startup either: this screen asks for itself, when it needs to.
      if (!vault.unlocked) {
        setCredentials([]);
        return;
      }
      setCredentials((await api.credentials()).credentials);
    } catch (caught) {
      setError(failureCode(caught) || t("secrets.failed"));
    }
  }, [api, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function run(action: () => Promise<unknown>, fallback: string) {
    try {
      await action();
      setError("");
      await reload();
    } catch (caught) {
      // A refusal the server explains is shown as what it is. "In use" is the
      // one a person will meet, and it is the one they can act on.
      setError(failureCode(caught) === "credential_in_use" ? t("secrets.inUse") : fallback);
    }
  }

  function draftFor(kind: CredentialKind) {
    return drafts[kind] ?? { name: "", secret: "" };
  }

  if (status === null) {
    return <p className={hintText}>{t("secrets.loading")}</p>;
  }

  // Neither existing nor open means the same thing to this screen: there is
  // nothing to show and a master password is what changes that. What differs is
  // whether giving one creates the vault or opens it.
  if (!status.unlocked) {
    const creating = !status.exists;
    return (
      <section aria-label={t("secrets.heading")} className={sectionCard}>
        <h3 className={sectionHeading}>{t("secrets.heading")}</h3>
        <p className={hintText}>{creating ? t("secrets.explainNew") : t("secrets.explainLocked")}</p>
        {error === "" ? null : <Notice tone="danger">{error}</Notice>}
        <PasswordField label={t("secrets.master")} value={master} onChange={setMaster} />
        <div>
          <button
            type="button"
            className={primaryAction}
            onClick={() =>
              void run(
                () => (creating ? api.initialiseVault(master) : api.unlockVault(master)),
                creating ? t("secrets.createFailed") : t("secrets.unlockFailed"),
              ).then(() => setMaster(""))
            }
          >
            {creating ? t("secrets.create") : t("secrets.unlock")}
          </button>
        </div>
      </section>
    );
  }

  async function changeMaster() {
    setError("");
    setChanged("");
    try {
      const result = await api.changeMasterPassword(currentMaster, nextMaster);
      setCurrentMaster("");
      setNextMaster("");
      setConfirmMaster("");
      // What was re-sealed and what was not. The dated copies in the bucket
      // stay under the old password by design, and a live snapshot that could
      // not be reached stays under it by accident — the difference matters to
      // anybody who later restores from one.
      setChanged(
        result.snapshotResealed
          ? t("secrets.changedWithSnapshot")
          : t("secrets.changedWithoutSnapshot", { reason: result.snapshotProblem ?? "" }),
      );
    } catch (caught) {
      setError(
        failureCode(caught) === "wrong_passphrase" ? t("secrets.wrongCurrent") : t("secrets.changeFailed"),
      );
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {error === "" ? null : <Notice tone="danger">{error}</Notice>}
      {changed === "" ? null : <p role="status" className="text-sm text-live">{changed}</p>}
      <div>
        <button
          type="button"
          className={secondaryAction}
          onClick={() => void api.lockVault().then(() => onLock?.())}
        >
          {t("secrets.lock")}
        </button>
      </div>

      <LoginItemSection api={api} />

      <section aria-label={t("secrets.changeHeading")} className={sectionCard}>
        <h3 className={sectionHeading}>{t("secrets.changeHeading")}</h3>
        <p className={hintText}>{t("secrets.changeNote")}</p>
        <PasswordField label={t("secrets.currentMaster")} value={currentMaster} onChange={setCurrentMaster} />
        <PasswordField label={t("secrets.newMaster")} value={nextMaster} onChange={setNextMaster} />
        <PasswordField label={t("secrets.confirmMaster")} value={confirmMaster} onChange={setConfirmMaster} />
        <button
          type="button"
          className={`self-start ${primaryAction}`}
          disabled={currentMaster === "" || nextMaster.length < 12 || nextMaster !== confirmMaster}
          onClick={() => void changeMaster()}
        >
          {t("secrets.change")}
        </button>
      </section>

      {kinds.map((group) => {
        const draft = draftFor(group.kind);
        const mine = credentials.filter((credential) => credential.kind === group.kind);
        return (
          <section key={group.kind} aria-label={t(group.heading)} className={sectionCard}>
            <h3 className={sectionHeading}>{t(group.heading)}</h3>
            {mine.length === 0 ? (
              <p className={hintText}>{t("secrets.none")}</p>
            ) : (
              <ul className="flex flex-col gap-2">
                {mine.map((credential) => (
                  <li key={credential.name} className="flex flex-wrap items-center gap-3 text-sm">
                    <span className="font-medium">{credential.name}</span>
                    {/*
                      What points at it, which is what makes deleting it
                      refusable and what makes one entry worth having.
                    */}
                    <span className={hintText}>
                      {credential.uses.length === 0 ? t("secrets.unused") : credential.uses.join(", ")}
                    </span>
                    <button
                      type="button"
                      className={dangerAction}
                      onClick={() => void run(() => api.deleteCredential(group.kind, credential.name), t("secrets.deleteFailed"))}
                    >
                      {t("secrets.delete", { name: credential.name })}
                    </button>
                  </li>
                ))}
              </ul>
            )}

            <div className="flex flex-wrap items-end gap-3">
              <Field label={t(group.nameLabel)}>
                <input
                  value={draft.name}
                  onChange={(event) => setDrafts({ ...drafts, [group.kind]: { ...draft, name: event.target.value } })}
                  className={control}
                />
              </Field>
              <Field label={t(group.valueLabel)}>
                <input
                  type="password"
                  value={draft.secret}
                  onChange={(event) => setDrafts({ ...drafts, [group.kind]: { ...draft, secret: event.target.value } })}
                  className={control}
                />
              </Field>
              <button
                type="button"
                className={primaryAction}
                disabled={draft.name === "" || draft.secret === ""}
                onClick={() =>
                  void run(
                    () => api.storeCredential(group.kind, draft.name, draft.secret),
                    t("secrets.storeFailed"),
                  ).then(() => setDrafts({ ...drafts, [group.kind]: { name: "", secret: "" } }))
                }
              >
                {t(group.store)}
              </button>
            </div>
          </section>
        );
      })}
    </div>
  );
}

// Start at login, off unless asked for.
//
// It lives here because this screen is where the vault is, and what the setting
// really arranges is a process that holds the key to it. A background service
// nobody asked for is not something to arrange on somebody's behalf, so the
// switch starts off and nothing turns it on but this.
function LoginItemSection({ api }: { api: IntegrationsApi }) {
  const t = useTranslate();
  const [item, setItem] = useState<LoginItem | null>(null);
  const [failed, setFailed] = useState("");

  useEffect(() => {
    let active = true;
    void api
      .loginItem()
      .then((loaded) => {
        if (active) setItem(loaded);
      })
      .catch(() => {
        if (active) setItem({ enabled: false, supported: false });
      });
    return () => {
      active = false;
    };
  }, [api]);

  if (item === null || !item.supported) {
    return null;
  }
  return (
    <section aria-label={t("login.heading")} className={sectionCard}>
      <h3 className={sectionHeading}>{t("login.heading")}</h3>
      <p className={hintText}>{t("login.note")}</p>
      {failed === "" ? null : <Notice tone="danger">{failed}</Notice>}
      <CheckboxField
        label={t("login.enable")}
        checked={item.enabled}
        onChange={(next) => {
          setFailed("");
          void api
            .setLoginItem(next)
            .then(setItem)
            .catch(() => setFailed(t("login.failed")));
        }}
      />
    </section>
  );
}
