import { useEffect, useState } from "react";
import {
  integrationsApi,
  type AuthenticationResponse,
  type ConfigCheckResponse,
  type EffectiveResponse,
  type IntegrationsApi,
  type ReachabilityResponse,
  type TerminalCommandResponse,
} from "../api/integrations";

type DiagnosticsPanelProps = {
  api?: IntegrationsApi;
  // The host to diagnose. The standalone section leaves it undefined and asks
  // for an alias; the Host editor already knows which connection is open, so it
  // passes one and no alias field is rendered. A fixed host also skips the
  // configuration read, which describes the file set rather than this host and
  // is what the Config section is for.
  host?: string;
};

// Every check on this screen is started by the user on purpose. Opening the
// panel reads the configuration, which runs nothing; each of the other
// operations spends a confirmation and may start a process.
export function DiagnosticsPanel({ api = integrationsApi, host }: DiagnosticsPanelProps) {
  const embedded = host !== undefined;
  const [typedAlias, setTypedAlias] = useState("");
  const alias = host ?? typedAlias;
  const [config, setConfig] = useState<ConfigCheckResponse | null>(null);
  const [effective, setEffective] = useState<EffectiveResponse | null>(null);
  const [reach, setReach] = useState<ReachabilityResponse | null>(null);
  const [auth, setAuth] = useState<AuthenticationResponse | null>(null);
  const [terminal, setTerminal] = useState<TerminalCommandResponse | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (embedded) return;
    let active = true;
    void api
      .configCheck()
      .then((result) => {
        if (active) setConfig(result);
      })
      .catch(() => {
        if (active) setError("The configuration could not be read.");
      });
    return () => {
      active = false;
    };
  }, [api, embedded]);

  // Every result on this panel is about one host. Opening a different one must
  // clear them, or a reachability verdict earned by the previous connection
  // would sit under the new one's name and read as its own.
  useEffect(() => {
    setEffective(null);
    setReach(null);
    setAuth(null);
    setTerminal(null);
    setError("");
  }, [host]);

  async function run<T>(operation: () => Promise<T>, apply: (value: T) => void, failure: string) {
    setError("");
    setBusy(true);
    try {
      apply(await operation());
    } catch {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }

  const directives = effective?.executableDirectives ?? [];

  return (
    <section
      aria-label={embedded ? `Diagnostics for ${host}` : undefined}
      aria-labelledby={embedded ? undefined : "diagnostics-heading"}
      className="flex flex-col gap-4"
    >
      {embedded ? null : (
        <h2 id="diagnostics-heading" className="font-medium">
          Diagnostics
        </h2>
      )}

      <p aria-live="polite" className="text-sm text-zinc-400">
        {busy ? "Running the requested check…" : "No check runs until you start it."}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      ) : null}

      <div className="flex flex-wrap items-end gap-2">
        {embedded ? null : (
          <label className="flex flex-col gap-1 text-sm">
            <span>Host alias</span>
            <input
              value={typedAlias}
              onChange={(event) => setTypedAlias(event.target.value)}
              className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"
            />
          </label>
        )}
        <button
          type="button"
          onClick={() => void run(() => api.effective(alias, false), setEffective, "The alias could not be explained.")}
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          Explain
        </button>
        <button
          type="button"
          onClick={() => void run(() => api.reachability(alias), setReach, "The reachability check could not be run.")}
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          Check reachability
        </button>
        <button
          type="button"
          onClick={() =>
            void run(
              () => api.authentication(alias, directives.some((directive) => !directive.overridable)),
              setAuth,
              "The authentication test could not be run.",
            )
          }
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          Test authentication
        </button>
        <button
          type="button"
          onClick={() => void run(() => api.terminalCommand(alias), setTerminal, "The command could not be built.")}
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          Terminal command
        </button>
      </div>

      {config ? (
        <div className="text-sm text-zinc-300">
          <h3 className="font-medium">Configuration</h3>
          <ul>
            {config.files.map((file) => (
              <li key={file.path}>
                {file.path}
                {file.missing ? " (missing)" : ""}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {directives.length > 0 ? (
        <div className="rounded border border-amber-700 p-3 text-sm">
          <h3 className="font-medium text-amber-300">This configuration can run a command</h3>
          <p className="text-zinc-300">{effective?.tokenWarning}</p>
          <ul className="mt-2 flex flex-col gap-1">
            {directives.map((directive) => (
              <li key={`${directive.path}:${directive.line}:${directive.keyword}`}>
                <span className="text-zinc-400">
                  {directive.keyword} at {directive.path}:{directive.line}
                </span>
                <pre className="whitespace-pre-wrap break-all text-zinc-100">{directive.command}</pre>
              </li>
            ))}
          </ul>
          {effective?.requiresConfirmation && !effective.evaluated ? (
            <button
              type="button"
              onClick={() =>
                void run(() => api.effective(alias, true), setEffective, "The alias could not be explained.")
              }
              className="mt-2 rounded border border-amber-600 px-3 py-1"
            >
              Run ssh -G anyway
            </button>
          ) : null}
        </div>
      ) : null}

      {effective && effective.sources.length > 0 ? (
        <table className="text-sm">
          <caption className="text-left text-zinc-400">Where each value comes from</caption>
          <tbody>
            {effective.sources
              .filter((source) => source.winner)
              .map((source) => (
                <tr key={`${source.path}:${source.line}:${source.keyword}`}>
                  <th scope="row" className="pr-3 text-left font-normal text-zinc-400">
                    {source.keyword}
                  </th>
                  <td className="pr-3">{source.value}</td>
                  <td className="text-zinc-500">{`${source.path}:${source.line}`}</td>
                </tr>
              ))}
          </tbody>
        </table>
      ) : null}

      {reach ? (
        <div className="text-sm">
          <h3 className="font-medium">Reachability</h3>
          <p>
            {reach.address} — {reach.outcome}
          </p>
          <p className="text-zinc-400">{reach.notice}</p>
        </div>
      ) : null}

      {auth ? (
        <div className="text-sm">
          <h3 className="font-medium">Authentication</h3>
          <p>{auth.outcome}</p>
          {auth.stderr ? <pre className="whitespace-pre-wrap break-all text-zinc-400">{auth.stderr}</pre> : null}
        </div>
      ) : null}

      {terminal ? (
        <div className="text-sm">
          <h3 className="font-medium">Terminal</h3>
          <pre className="whitespace-pre-wrap break-all text-zinc-100">{terminal.command}</pre>
          {terminal.launchable ? (
            <button
              type="button"
              onClick={() => void run(() => api.terminalLaunch(alias), () => undefined, "Terminal could not be opened.")}
              className="mt-2 rounded border border-zinc-700 px-3 py-1"
            >
              Open in Terminal
            </button>
          ) : (
            <p className="text-amber-300">{terminal.warning}</p>
          )}
        </div>
      ) : null}
    </section>
  );
}
