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
import { MetricCard, MetricGrid, PageHeader } from "../ui/page";

type SecretsPanelProps = {
  api?: IntegrationsApi;
  // onLock はシェル自身の玄関を閉じさせる。vault をロックすることは
  // アプリケーションをロックすることなので、自分自身を再読み込みするだけの
  // パネルでは、次のリクエストが拒否されるシェルの中にユーザーを取り残してしまう。
  onLock?: () => void;
};

// 2 つの名前空間を、引き離して描く。
//
// フォーマットでも API でも型でも分かれているのは、1 つの名前空間だと
// ホストのピッカーが鍵のパスフレーズを提供してしまい、それを選ぶと
// そのパスフレーズがログインパスワードとしてリモートホストに送られて
// しまうからだ。ここで 1 つのリストとして描けば、フォーマットが取り除いた
// はずの選択をユーザーの前に戻してしまう。だから互いのエントリを
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
      // 決して保持しない 2 つのリストになっている。
      // 閉じた vault にはその中身を尋ねない。起動時にも何も尋ねない:
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
      // この画面は必要になったときに自分自身のために尋ねる。
      // サーバーが説明する拒否は、そのままの姿で表示する。「使用中」が
      setError(failureCode(caught) === "credential_in_use" ? t("secrets.inUse") : fallback);
    }
  }

  function draftFor(kind: CredentialKind) {
    return drafts[kind] ?? { name: "", secret: "" };
  }

  if (status === null) {
    return <p className={hintText}>{t("secrets.loading")}</p>;
  }

  // 人が出会うものであり、それこそが対処できるものだ。
  // 存在することと開いていることは、この画面にとって同じ意味ではない:
  // 表示するものは何もなく、それを変えるのがマスターパスワードだ。異なるのは
  if (!status.unlocked) {
    const creating = !status.exists;
    return (
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
        <PageHeader title={t("secrets.heading")} description={t("secrets.pageDescription")} />
        <section aria-label={t("secrets.heading")} className={sectionCard}>
          <h3 className={sectionHeading}>{creating ? t("secrets.create") : t("secrets.unlock")}</h3>
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
      </div>
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
      // それを渡すことが vault を作るのか開くのかという点だ。
      // 何が再封印され、何がそうならなかったか。バケット内の日付付きコピーは
      // 設計上、古いパスワードの下にとどまり、届かなかったライブスナップショットは
      // 偶然にその下にとどまる——その違いは、後でそこから復元する誰にとっても重要だ。
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
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <PageHeader title={t("secrets.heading")} description={t("secrets.pageDescription")} />
      <MetricGrid>
        <MetricCard
          label={t("secrets.metricPasswords")}
          value={credentials.filter((credential) => credential.kind === "password").length}
        />
        <MetricCard
          label={t("secrets.metricPassphrases")}
          value={credentials.filter((credential) => credential.kind === "key_passphrase").length}
        />
        <MetricCard
          label={t("secrets.metricAssignments")}
          value={credentials.reduce((count, credential) => count + credential.uses.length, 0)}
        />
      </MetricGrid>
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
                      何がそれを指しているか。それが削除を拒否可能にし、
                      1 つのエントリを持つ価値にしているものだ。
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
    </div>
  );
}

// ログイン時に起動、求められない限りオフ。
//
// これがここにあるのは、この画面が vault の在り処だからで、この設定が
// 実際に手配するのはそれへの鍵を握るプロセスだ。誰も求めていない
// バックグラウンドサービスは、誰かの代わりに勝手に設定してよいものではない。
// だからスイッチは既定でオフになっており、これ以外の何もそれをオンにしない。
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
