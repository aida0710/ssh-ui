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

type RemoteKeyPanelProps = {
  api?: RemoteKeysApi;
  // The key inventory, so a key can be picked instead of typed. Reading it
  // starts nothing and contacts nothing; only the plan and the registration
  // touch the remote host.
  keys?: Pick<KeysApi, "inventory" | "publicKey">;
};

const outcomeLabels: Record<string, MessageKey> = {
  added: "rk.added",
  already_present: "rk.alreadyPresent",
};

// valuesFromLabels says where the account details in the confirmation came
// from, because "deploy" means something different if this application read it
// than if ssh itself reported it.
const valuesFromLabels: Record<string, MessageKey> = {
  engine: "rk.valuesFromEngine",
  "ssh -G": "rk.valuesFromSshG",
};

// RemoteKeyPanel registers a public key in a remote account's authorized_keys.
//
// Registration changes state on another machine, so it is an independent,
// confirmed operation: the panel first asks the server what the change would
// be, shows the alias, the effective user, the fingerprint and the exact line
// it would append, and only then offers to run it. Editing any input withdraws
// the plan, so the confirmation can never describe something other than what
// would be sent. A remote this application will not automate gets instructions
// instead of a button.
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

  // A failed inventory read leaves the picker empty and the two fields below
  // usable. Typing a key in by hand was the only way before this existed, and
  // it stays the fallback rather than becoming an error.
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

  // withdraw drops everything the previous plan justified. It runs on every
  // edit, so a confirmation is never left standing for values that changed.
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

  // Picking fills both fields from one place, so the file path and the key line
  // cannot describe different keys — which is exactly what typing them
  // separately allowed. It withdraws any standing plan, like every other edit.
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
      // An unsupported remote is an answer, not a transport failure: the
      // registration stops being offered and the manual steps take its place.
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
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}

      <div className="flex flex-col gap-2 text-sm">
        <label className="flex flex-col gap-1">
          <span>{t("rk.pickFromSsh")}</span>
          <select
            value={chosen}
            onChange={(event) => void choose(event.target.value)}
            className="rounded border border-control-line bg-control px-2 py-1"
          >
            <option value="">{t("rk.typeInstead")}</option>
            {candidates.map((item) => (
              <option key={item.id} value={item.id}>
                {item.fingerprint === "" ? item.relativePath : `${item.relativePath} — ${item.fingerprint}`}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span>{t("rk.hostAlias")}</span>
          <input
            value={alias}
            onChange={(event) => edit(setAlias)(event.target.value)}
            className="rounded border border-control-line bg-control px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span>{t("rk.publicKeyFile")}</span>
          <input
            value={keyPath}
            onChange={(event) => {
              setChosen("");
              edit(setKeyPath)(event.target.value);
            }}
            className="rounded border border-control-line bg-control px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span>{t("rk.publicKeyLine")}</span>
          <textarea
            value={publicKey}
            onChange={(event) => {
              setChosen("");
              edit(setPublicKey)(event.target.value);
            }}
            rows={3}
            className="rounded border border-control-line bg-control px-2 py-1 font-mono"
          />
        </label>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => void describe()}
            className="rounded border border-control-line px-3 py-1"
          >
            {t("rk.showWhatWouldHappen")}
          </button>
          {manual ? null : (
            <button
              type="button"
              disabled={blocked}
              onClick={() => void register()}
              className="rounded border border-notice-line px-3 py-1 disabled:border-line disabled:text-ink-faint"
            >
              {t("rk.register")}
            </button>
          )}
        </div>
      </div>

      {plan ? (
        <section
          aria-labelledby="remote-key-plan-heading"
          className="rounded border border-notice-line p-3 text-sm"
        >
          <h3 id="remote-key-plan-heading" className="font-medium text-notice-ink">
            {t("rk.confirmHeading")}
          </h3>
          <dl className="mt-2 grid grid-cols-[12rem_1fr] gap-x-3 gap-y-1">
            <dt className="text-ink-muted">{t("rk.alias")}</dt>
            <dd>{plan.alias}</dd>
            <dt className="text-ink-muted">{t("rk.effectiveUser")}</dt>
            <dd>{plan.user === "" ? t("rk.noUser") : plan.user}</dd>
            <dt className="text-ink-muted">{t("rk.destination")}</dt>
            <dd>{`${plan.hostname}:${plan.port}`}</dd>
            <dt className="text-ink-muted">{t("rk.valuesCameFrom")}</dt>
            <dd>{plan.valuesFrom in valuesFromLabels ? t(valuesFromLabels[plan.valuesFrom]!) : plan.valuesFrom}</dd>
            <dt className="text-ink-muted">{t("rk.keyFile")}</dt>
            <dd>{plan.keyPath}</dd>
            <dt className="text-ink-muted">{t("rk.fingerprint")}</dt>
            <dd>{plan.fingerprint}</dd>
          </dl>

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

// describeFailure quotes the code the server refused with, so the user can look
// it up rather than guess from a paraphrase.
function describeFailure(failure: unknown, t: Translate, fallback: MessageKey): string {
  const code = failureCode(failure);
  return code === "" ? t(fallback) : t("rk.withCode", { message: t(fallback), code });
}
