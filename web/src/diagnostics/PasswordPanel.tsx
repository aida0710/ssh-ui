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
  // このパネルがパスワードを保存する対象のホスト。パネルはホストエディタの
  // 内側でしかレンダリングされないため、常に一つ存在する。
  alias: string;
};

// 保存済みパスワードのパネル。
//
// ここでは三つのことが同時に真であり得て、パネルはそのすべてを
// 述べなければならない。vault は存在しないかもしれず、存在して
// ロックされているかもしれず、このホストにはパスワードがあるかもしれないし、
// ないかもしれない。それらを一つの状態に潰せば、「何も保存されていないと言うが、
// 実は何かある」という典型的な混乱を生む。ロックされた vault は本当に分からないからである。
// サーバーが報告するコードを、このホストにとっての意味へ対応付ける。
// 未知のコードは飲み込まずそのまま表示する。サーバーには追加された
// がここにはない規則は、見えなくなるのではなく見える必要がある。
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
      // 閉じた vault には名前を尋ねない。起動時にも何も尋ねない。
      // このパネルは自分が属するホストが開かれたとき、自分自身で尋ねる。
      setCredentials(vault.unlocked ? (await api.credentials()).credentials : []);
    } catch {
      setError(t("password.statusFailed"));
    }
  }, [api, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // このホストと保存されたパスワードの間に何があるかは、設定
  // と known_hosts から読み取る。パネルは以前、ホスト鍵の事前条件
  // をフィールドの下の散文として述べるだけで何も検査しておらず、ユーザーが
  // すべてのホストについて手で確認しなければならない一文だった。
  useEffect(() => {
    let active = true;
    setEligibility(null);
    void api
      .passwordEligibility(alias)
      .then((report) => {
        if (active) setEligibility(report);
      })
      .catch(() => {
        // 設定を読めないパネルは、ホストが問題ないと主張するの
        // ではなく、それについて何も言わない。
        if (active) setEligibility(null);
      });
    return () => {
      active = false;
    };
  }, [api, alias]);

  // 入力されたすべての秘密は、ホストが変わると破棄される。ユーザーが
  // 移動する間フィールドに残されたパスフレーズは、理由もなく DOM 内に
  // 座っている秘密である。
  useEffect(() => {
    setPassphrase("");
    setPassword("");
    setChosen("");
    setError("");
  }, [alias]);

  // vault のステータスと名前は二つのドキュメントであり、片方への操作が
  // もう片方を変える。パスワードを保存すれば名前が増え、ホストを
  // 名前へ向ければ対象が増える。そのため各操作は、両方を
  // 読み直して今得たばかりの答えと矛盾するのではなく、与えられた
  // 答えを保ちながらもう半分だけを取得する。
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
  // アカウントパスワードのみ。鍵のパスフレーズを提示するピッカーでは、
  // 一度の押下でそのパスフレーズをリモートホストへログインパスワードとして
  // 送ってしまう。それこそが、二つの名前空間が二つに分かれている理由である。
  const sharable = credentials.filter((credential) => credential.kind === "password");
  const uses = sharable.find((credential) => credential.uses.includes(alias));
  const blocked = (eligibility?.blockers ?? []).length > 0;

  return (
    <section aria-label={t("password.heading")} className={sectionCard}>
      <h3 className={sectionHeading}>{t("password.heading")}</h3>
      {/*
        ツールチップにしてはならない一文。保存されたパスワードはリモート
        アカウントの資格情報であり、鍵の方が強い。これを使うか
        どうかを決める者は、フィールドの後ではなく前にそれを読むべきである。
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
            ロックされた vault は、このホストにパスワードがあるかどうかを
            言えない。ここで「none stored」と言えば推測になり、
            半分は外れる推測になる。
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
            自分自身のホストのものでない場合、どの名前か。共有された
            秘密こそが名前の存在理由であり、ここでそれを忘れようと
            している者は、一つのホストのパスワードを削除しているのか、
            複数のホストが使うパスワードへの自分自身の参照を削除
            しているのかを知っておくべきである。
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
            既存の名前をまず示す。二つ目のフィールドは新しい秘密を作り、
            一つ目はこのホストに既存の秘密を共有させるからである。
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
