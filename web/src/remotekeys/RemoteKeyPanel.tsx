import { useEffect, useState } from "react";
import { failureCode } from "../api/client";
import { keysApi, type KeyItem, type KeysApi } from "../keys/api";
import { useTranslate, type Translate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";
import {
  remoteKeysApi,
  type RemoteKeyPlan,
  type RemoteKeyRegisterResponse,
  type RemoteKeysApi,
} from "./api";
import { CopyButton } from "../ui/CopyButton";
import { Button, Card, Notice, Row } from "../ui/surface";
import { Field, control } from "../ui/form";

type RemoteKeyPanelProps = {
  api?: RemoteKeysApi;
  // 鍵を打ち込む代わりに選べるようにする鍵インベントリ。これを読んでも
  // 何も始まらず何にも接続しない。リモートホストに触れるのは
  // plan と registration だけだ。
  keys?: Pick<KeysApi, "inventory" | "publicKey">;
};

const outcomeLabels: Record<string, MessageKey> = {
  added: "rk.added",
  already_present: "rk.alreadyPresent",
};

// valuesFromLabels は、確認画面のアカウント詳細がどこから来たかを述べる。
// このアプリケーションがそれを読んだ場合と ssh 自身が報告した場合とでは
// 「deploy」の意味が異なるからだ。
const valuesFromLabels: Record<string, MessageKey> = {
  engine: "rk.valuesFromEngine",
  "ssh -G": "rk.valuesFromSshG",
};

// RemoteKeyPanel はリモートアカウントの authorized_keys に公開鍵を登録する。
//
// 登録は別のマシンの状態を変えるので、独立した確認済み操作となる:
// パネルはまずサーバーに変更内容を尋ね、alias・実効ユーザー・
// フィンガープリント・追記される正確な行を示し、その後で初めて
// 実行を申し出る。どの入力を編集しても plan は取り下げられるので、
// 確認画面が実際に送られるもの以外を記述することは決してない。
// このアプリケーションが自動化しないリモートには、ボタンの代わりに
// 手順が示される。
export function RemoteKeyPanel({ api = remoteKeysApi, keys = keysApi }: RemoteKeyPanelProps) {
  const t = useTranslate();
  const [alias, setAlias] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [plan, setPlan] = useState<RemoteKeyPlan | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [unsupported, setUnsupported] = useState(false);
  const [result, setResult] = useState<RemoteKeyRegisterResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [candidates, setCandidates] = useState<KeyItem[]>([]);
  const [chosen, setChosen] = useState("");

  // インベントリの読み取りに失敗すると、ピッカーは空のまま、下の
  // 2 つのフィールドは使える状態で残る。これが存在する前は手で鍵を
  // 打ち込むのが唯一の方法だった。それはエラーではなくフォールバックのままだ。
  useEffect(() => {
    let active = true;
    void keys
      .inventory()
      .then((inventory) => {
        if (active) setCandidates(inventory.items.filter((item) => item.kind === "public_key"));
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [keys]);

  // withdraw は、それまでの plan が正当化していたすべてを捨てる。
  // 編集のたびに実行されるので、確認画面が変わった値のまま残ることはない。
  function withdraw() {
    setPlan(null);
    setAcknowledged(false);
    setUnsupported(false);
    setResult(null);
  }

  function edit(apply: (value: string) => void) {
    return (value: string) => {
      withdraw();
      apply(value);
    };
  }

  // 選択すると 1 か所から両方のフィールドが埋まるので、ファイルパスと
  // 鍵の行が別の鍵を記述することはあり得ない——別々に入力させると
  // まさにそれが起きた。他の編集と同様、既存の plan も取り下げる。
  async function choose(keyId: string) {
    withdraw();
    setChosen(keyId);
    if (keyId === "") return;
    try {
      const key = await keys.publicKey(keyId);
      setKeyPath(key.relativePath);
      setPublicKey(key.publicKey.trimEnd());
      setError("");
    } catch {
      setError(t("rk.publicKeyUnreadable"));
    }
  }

  async function describe() {
    setError("");
    withdraw();
    setBusy(true);
    try {
      setPlan(await api.plan({ alias, keyPath, publicKey }));
    } catch (failure) {
      setError(describeFailure(failure, t, "rk.planFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function register() {
    if (plan === null) return;
    setError("");
    setBusy(true);
    try {
      setResult(await api.register({ alias, keyPath, publicKey, acknowledgeExecutable: acknowledged }));
    } catch (failure) {
      // サポートされていないリモートは、通信の失敗ではなく 1 つの答えだ:
      // 登録は提供されなくなり、手動の手順がその代わりを務める。
      if (failureCode(failure) === "unsupported_remote") setUnsupported(true);
      setError(describeFailure(failure, t, "rk.registerFailed"));
    } finally {
      setBusy(false);
    }
  }

  const unavoidable = (plan?.executableDirectives ?? []).filter((directive) => !directive.overridable);
  const manual = plan !== null && (!plan.supported || unsupported);
  const blocked = plan === null || busy || (unavoidable.length > 0 && !acknowledged);

  return (
    <section aria-labelledby="remote-keys-heading" className="flex flex-col gap-4">
      <h2 id="remote-keys-heading" className="font-medium">
        {t("rk.heading")}
      </h2>

      <p aria-live="polite" className="text-sm text-ink-muted">
        {busy ? t("rk.waiting") : t("rk.idle")}
      </p>
      {error ? (
        <Notice tone="danger">{error}</Notice>
      ) : null}

      {/*
        1 行設定が 3 つあるのは行としてで、鍵の行は違う: それは base64 の
        折り返されたかたまりであり、そこまで背の高いボックスの隣にキャプションを
        置くと、その下の隙間に対するキャプションのように読めてしまう。
      */}
      <Card>
        <Row label={t("rk.pickFromSsh")}>
          <select value={chosen} onChange={(event) => void choose(event.target.value)} className={control}>
            <option value="">{t("rk.typeInstead")}</option>
            {candidates.map((item) => (
              <option key={item.id} value={item.id}>
                {item.fingerprint === "" ? item.relativePath : `${item.relativePath} — ${item.fingerprint}`}
              </option>
            ))}
          </select>
        </Row>
        <Row label={t("rk.hostAlias")}>
          <input value={alias} onChange={(event) => edit(setAlias)(event.target.value)} className={control} />
        </Row>
        <Row label={t("rk.publicKeyFile")}>
          <input
            value={keyPath}
            onChange={(event) => {
              setChosen("");
              edit(setKeyPath)(event.target.value);
            }}
            className={control}
          />
        </Row>
      </Card>

      <Field label={t("rk.publicKeyLine")}>
        <textarea
          value={publicKey}
          onChange={(event) => {
            setChosen("");
            edit(setPublicKey)(event.target.value);
          }}
          rows={3}
          className={`${control} font-mono`}
        />
      </Field>

      {/*
        登録することがこの画面の目的なので、アクセントをまとうのはそれ 1 つだ。
        かつては amber のボーダーをまとっていたが、それはこのアプリケーションが
        アクションではなく notice のために取っておく色だ。
      */}
      <div className="flex gap-2">
        <Button onClick={() => void describe()}>{t("rk.showWhatWouldHappen")}</Button>
        {manual ? null : (
          <Button kind="primary" disabled={blocked} onClick={() => void register()}>
            {t("rk.register")}
          </Button>
        )}
      </div>

      {plan ? (
        <section aria-labelledby="remote-key-plan-heading" className="flex flex-col gap-3 text-sm">
          <h3 id="remote-key-plan-heading" className="font-medium">{t("rk.confirmHeading")}</h3>

          {/*
            行ではなく description list だ: これはどれも編集不可能であり、`Row` は
            中身をラベルで包む。保持するものすべてがラベルだからだ。
            カードとそのヘアラインは同じなので、両者は同じように読める。
          */}
          <Card>
            <dl className="text-sm">
              {[
                [t("rk.alias"), plan.alias],
                [t("rk.effectiveUser"), plan.user === "" ? t("rk.noUser") : plan.user],
                [t("rk.destination"), `${plan.hostname}:${plan.port}`],
                [
                  t("rk.valuesCameFrom"),
                  plan.valuesFrom in valuesFromLabels ? t(valuesFromLabels[plan.valuesFrom]!) : plan.valuesFrom,
                ],
                [t("rk.keyFile"), plan.keyPath],
                [t("rk.fingerprint"), plan.fingerprint],
              ].map(([caption, value]) => (
                <div
                  key={caption}
                  className="flex items-baseline gap-3 border-t border-hairline px-3 py-2 first:border-t-0"
                >
                  <dt className="w-44 shrink-0 text-ink-muted">{caption}</dt>
                  <dd className="min-w-0 break-all">{value}</dd>
                </div>
              ))}
            </dl>
          </Card>

          <p className="mt-3">
            {t("rk.appendTo", {
              remotePath: plan.remotePath,
              account: plan.user === "" ? t("rk.theRemoteAccount") : t("rk.usersAccount", { user: plan.user }),
              hostname: plan.hostname,
            })}
          </p>
          <pre
            aria-label={t("rk.keyLineLabel")}
            className="mt-1 overflow-x-auto rounded bg-canvas p-3 text-xs"
          >
            {plan.keyLine}
          </pre>
          <div className="mt-1">
            <CopyButton value={plan.keyLine} label="copy.keyLine" />
          </div>
          <p className="mt-3 text-ink-muted">{t("rk.remoteRuns")}</p>
          <pre aria-label={t("rk.remoteCommandLabel")} className="mt-1 overflow-x-auto rounded bg-canvas p-3 text-xs">
            {plan.routine}
          </pre>
          <div className="mt-1">
            <CopyButton value={plan.routine} label="copy.remoteCommand" />
          </div>

          {unavoidable.length > 0 ? (
            <div className="mt-3 rounded border border-notice-line p-2">
              <h4 className="font-medium text-notice-ink">{t("rk.connectingRuns")}</h4>
              <ul className="mt-1 flex flex-col gap-1">
                {unavoidable.map((directive) => (
                  <li key={`${directive.path}:${directive.line}:${directive.keyword}`}>
                    <span className="text-ink-muted">
                      {directive.keyword} at {directive.path}:{directive.line}
                    </span>
                    <pre className="whitespace-pre-wrap break-all text-ink">{directive.command}</pre>
                  </li>
                ))}
              </ul>
              <label className="mt-2 flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(event) => setAcknowledged(event.target.checked)}
                />
                <span>{t("rk.acknowledgeRuns")}</span>
              </label>
            </div>
          ) : null}

          {manual ? (
            <div className="mt-3">
              <h4 className="font-medium text-notice-ink">
                {t("rk.manualHeading")}
              </h4>
              <ol className="mt-1 list-decimal pl-5">
                {plan.manual.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </div>
          ) : null}
        </section>
      ) : null}

      {result ? (
        <div className="text-sm">
          <h3 className="font-medium">{t("rk.result")}</h3>
          <p>{result.outcome in outcomeLabels ? t(outcomeLabels[result.outcome]!) : result.outcome}</p>
          {result.stderr ? (
            <pre className="whitespace-pre-wrap break-all text-ink-muted">{result.stderr}</pre>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

// describeFailure は、サーバーが拒否に使ったコードをそのまま引用する。
// ユーザーが言い換えから推測するのではなく調べられるようにするためだ。
function describeFailure(failure: unknown, t: Translate, fallback: MessageKey): string {
  const code = failureCode(failure);
  return code === "" ? t(fallback) : t("rk.withCode", { message: t(fallback), code });
}
