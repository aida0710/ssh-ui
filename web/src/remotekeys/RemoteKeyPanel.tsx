import { useState } from "react";
import { failureCode } from "../api/client";
import {
  remoteKeysApi,
  type RemoteKeyPlan,
  type RemoteKeyRegisterResponse,
  type RemoteKeysApi,
} from "./api";
import { CopyButton } from "../ui/CopyButton";

type RemoteKeyPanelProps = { api?: RemoteKeysApi };

const outcomeLabels: Record<string, string> = {
  added: "The key was added to the remote authorized_keys file.",
  already_present: "The key was already present; the remote file was left as it was.",
};

// valuesFromLabels says where the account details in the confirmation came
// from, because "deploy" means something different if this application read it
// than if ssh itself reported it.
const valuesFromLabels: Record<string, string> = {
  engine: "ssh-ui reading your configuration; ssh was not run",
  "ssh -G": "ssh -G, which OpenSSH itself resolved",
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
export function RemoteKeyPanel({ api = remoteKeysApi }: RemoteKeyPanelProps) {
  const [alias, setAlias] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [plan, setPlan] = useState<RemoteKeyPlan | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [unsupported, setUnsupported] = useState(false);
  const [result, setResult] = useState<RemoteKeyRegisterResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

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

  async function describe() {
    setError("");
    withdraw();
    setBusy(true);
    try {
      setPlan(await api.plan({ alias, keyPath, publicKey }));
    } catch (failure) {
      setError(describeFailure(failure, "The change could not be described. Nothing was contacted."));
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
      setError(describeFailure(failure, "The key was not registered. The remote host was left as it was."));
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
        Remote Keys
      </h2>

      <p aria-live="polite" className="text-sm text-zinc-400">
        {busy ? "Waiting for the server…" : "Nothing is sent to the remote host until you confirm it."}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      ) : null}

      <div className="flex flex-col gap-2 text-sm">
        <label className="flex flex-col gap-1">
          <span>Host alias</span>
          <input
            value={alias}
            onChange={(event) => edit(setAlias)(event.target.value)}
            className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span>Public key file</span>
          <input
            value={keyPath}
            onChange={(event) => edit(setKeyPath)(event.target.value)}
            className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span>Public key line</span>
          <textarea
            value={publicKey}
            onChange={(event) => edit(setPublicKey)(event.target.value)}
            rows={3}
            className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono"
          />
        </label>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => void describe()}
            className="rounded border border-zinc-700 px-3 py-1"
          >
            Show what this would do
          </button>
          {manual ? null : (
            <button
              type="button"
              disabled={blocked}
              onClick={() => void register()}
              className="rounded border border-amber-600 px-3 py-1 disabled:border-zinc-800 disabled:text-zinc-600"
            >
              Register the key
            </button>
          )}
        </div>
      </div>

      {plan ? (
        <section
          aria-labelledby="remote-key-plan-heading"
          className="rounded border border-amber-700 p-3 text-sm"
        >
          <h3 id="remote-key-plan-heading" className="font-medium text-amber-300">
            Confirm remote registration
          </h3>
          <dl className="mt-2 grid grid-cols-[12rem_1fr] gap-x-3 gap-y-1">
            <dt className="text-zinc-400">Alias</dt>
            <dd>{plan.alias}</dd>
            <dt className="text-zinc-400">Effective user</dt>
            <dd>{plan.user === "" ? "not set in your configuration; ssh will use your local account" : plan.user}</dd>
            <dt className="text-zinc-400">Destination</dt>
            <dd>{`${plan.hostname}:${plan.port}`}</dd>
            <dt className="text-zinc-400">These values came from</dt>
            <dd>{valuesFromLabels[plan.valuesFrom] ?? plan.valuesFrom}</dd>
            <dt className="text-zinc-400">Public key file</dt>
            <dd>{plan.keyPath}</dd>
            <dt className="text-zinc-400">Fingerprint</dt>
            <dd>{plan.fingerprint}</dd>
          </dl>

          <p className="mt-3">
            {`Append one line to ${plan.remotePath} in ${
              plan.user === "" ? "the remote account" : `${plan.user}'s account`
            } on ${plan.hostname}, if that exact line is not already there.`}
          </p>
          <pre
            aria-label="Public key line to append"
            className="mt-1 overflow-x-auto rounded bg-zinc-950 p-3 text-xs"
          >
            {plan.keyLine}
          </pre>
          <div className="mt-1">
            <CopyButton value={plan.keyLine} label="key line" />
          </div>
          <p className="mt-3 text-zinc-400">The remote host runs exactly this, with the key on standard input:</p>
          <pre aria-label="Remote command" className="mt-1 overflow-x-auto rounded bg-zinc-950 p-3 text-xs">
            {plan.routine}
          </pre>
          <div className="mt-1">
            <CopyButton value={plan.routine} label="remote command" />
          </div>

          {unavoidable.length > 0 ? (
            <div className="mt-3 rounded border border-amber-700 p-2">
              <h4 className="font-medium text-amber-300">Connecting to this host runs a command</h4>
              <ul className="mt-1 flex flex-col gap-1">
                {unavoidable.map((directive) => (
                  <li key={`${directive.path}:${directive.line}:${directive.keyword}`}>
                    <span className="text-zinc-400">
                      {directive.keyword} at {directive.path}:{directive.line}
                    </span>
                    <pre className="whitespace-pre-wrap break-all text-zinc-100">{directive.command}</pre>
                  </li>
                ))}
              </ul>
              <label className="mt-2 flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(event) => setAcknowledged(event.target.checked)}
                />
                <span>I have read this command and accept that connecting runs it</span>
              </label>
            </div>
          ) : null}

          {manual ? (
            <div className="mt-3">
              <h4 className="font-medium text-amber-300">
                ssh-ui will not register a key on this host. Do it yourself:
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
          <h3 className="font-medium">Result</h3>
          <p>{outcomeLabels[result.outcome] ?? result.outcome}</p>
          {result.stderr ? (
            <pre className="whitespace-pre-wrap break-all text-zinc-400">{result.stderr}</pre>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

// describeFailure quotes the code the server refused with, so the user can look
// it up rather than guess from a paraphrase.
function describeFailure(failure: unknown, fallback: string): string {
  const code = failureCode(failure);
  return code === "" ? fallback : `${fallback} (${code})`;
}
