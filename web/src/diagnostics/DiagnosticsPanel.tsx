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
import { CopyButton } from "../ui/CopyButton";
import { useTranslate } from "../i18n/context";

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
  const t = useTranslate();
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
        if (active) setError(t("diag.configUnreadable"));
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
      aria-label={embedded ? t("diag.forHost", { host: host ?? "" }) : undefined}
      aria-labelledby={embedded ? undefined : "diagnostics-heading"}
      className="flex flex-col gap-4"
    >
      {embedded ? null : (
        <h2 id="diagnostics-heading" className="font-medium">
          {t("diag.heading")}
        </h2>
      )}

      <p aria-live="polite" className="text-sm text-zinc-400">
        {busy ? t("diag.running") : t("diag.idle")}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      ) : null}

      <div className="flex flex-wrap items-end gap-2">
        {embedded ? null : (
          <label className="flex flex-col gap-1 text-sm">
            <span>{t("diag.hostAlias")}</span>
            <input
              value={typedAlias}
              onChange={(event) => setTypedAlias(event.target.value)}
              className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"
            />
          </label>
        )}
        <button
          type="button"
          onClick={() => void run(() => api.effective(alias, false), setEffective, t("diag.explainFailed"))}
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          {t("diag.explain")}
        </button>
        <button
          type="button"
          onClick={() => void run(() => api.reachability(alias), setReach, t("diag.reachabilityFailed"))}
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          {t("diag.checkReachability")}
        </button>
        <button
          type="button"
          onClick={() =>
            void run(
              () => api.authentication(alias, directives.some((directive) => !directive.overridable)),
              setAuth,
              t("diag.authenticationFailed"),
            )
          }
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          {t("diag.testAuthentication")}
        </button>
        <button
          type="button"
          onClick={() => void run(() => api.terminalCommand(alias), setTerminal, t("diag.commandFailed"))}
          className="rounded border border-zinc-700 px-3 py-1 text-sm"
        >
          {t("diag.terminalCommand")}
        </button>
      </div>

      {config ? (
        <div className="text-sm text-zinc-300">
          <h3 className="font-medium">{t("diag.configuration")}</h3>
          <ul>
            {config.files.map((file) => (
              <li key={file.path}>
                {file.path}
                {file.missing ? t("diag.missingSuffix") : ""}
              </li>
            ))}
          </ul>
          {config.diagnostics.length > 0 ? (
            <ul className="mt-2 flex flex-col gap-1">
              {config.diagnostics.map((diagnostic, index) => (
                <li
                  key={`${diagnostic.code}-${index}`}
                  className={
                    diagnostic.severity === "error"
                      ? "text-red-300"
                      : diagnostic.severity === "warning"
                        ? "text-amber-300"
                        : "text-zinc-400"
                  }
                >
                  {`${diagnostic.code} ${diagnostic.path}${diagnostic.line > 0 ? `:${diagnostic.line}` : ""} ${diagnostic.detail}`}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {/*
        A failed `ssh -G` answers 200 with the reason inside it, so nothing
        throws and the panel used to render silence: the sources table is empty,
        there may be no executable directive, and every other block is
        conditional. Pressing Explain looked like it did nothing at all. What
        OpenSSH said about its own refusal is the only thing that explains it.
      */}
      {effective?.failure.failed ? (
        <div className="rounded border border-red-800 p-3 text-sm">
          <h3 className="font-medium text-red-300">{t("diag.refused")}</h3>
          <p className="text-zinc-300">{t("diag.exited", { code: effective.failure.exitCode })}</p>
          {effective.failure.stderr ? (
            <pre className="mt-1 whitespace-pre-wrap break-all text-zinc-400">{effective.failure.stderr}</pre>
          ) : (
            <p className="text-zinc-400">{t("diag.noStderr")}</p>
          )}
          {effective.failure.truncated ? (
            <p className="text-amber-300">{t("diag.outputTruncated")}</p>
          ) : null}
        </div>
      ) : null}

      {directives.length > 0 ? (
        <div className="rounded border border-amber-700 p-3 text-sm">
          <h3 className="font-medium text-amber-300">{t("diag.canRunCommand")}</h3>
          <p className="text-zinc-300">{effective?.tokenWarning}</p>
          <ul className="mt-2 flex flex-col gap-1">
            {directives.map((directive) => (
              <li key={`${directive.path}:${directive.line}:${directive.keyword}`}>
                <span className="text-zinc-400">
                  {t("diag.directiveAt", {
                    keyword: directive.keyword,
                    path: directive.path,
                    line: directive.line,
                  })}
                </span>
                <pre className="whitespace-pre-wrap break-all text-zinc-100">{directive.command}</pre>
              </li>
            ))}
          </ul>
          {effective?.requiresConfirmation && !effective.evaluated ? (
            <button
              type="button"
              onClick={() =>
                void run(() => api.effective(alias, true), setEffective, t("diag.explainFailed"))
              }
              className="mt-2 rounded border border-amber-600 px-3 py-1"
            >
              {t("diag.runAnyway")}
            </button>
          ) : null}
        </div>
      ) : null}

      {/*
        Every candidate is listed, not only the winner. OpenSSH keeps the first
        value it reads for a keyword, so "why is it this and not that" is a
        question about the lines that lost, and a table that hides them cannot
        answer it. The winner is marked rather than being the only row.
      */}
      {effective && effective.sources.length > 0 ? (
        <table className="text-sm">
          <caption className="text-left text-zinc-400">{t("diag.sourcesCaption")}</caption>
          <tbody>
            {effective.sources.map((source) => (
              <tr key={`${source.path}:${source.line}:${source.keyword}`} className={source.winner ? "" : "opacity-60"}>
                <th scope="row" className="pr-3 text-left font-normal text-zinc-400">
                  {source.keyword}
                </th>
                <td className="pr-3">{source.value}</td>
                <td className="pr-3 text-zinc-500">{`${source.path}:${source.line}`}</td>
                <td className="pr-3 text-zinc-500">{source.condition}</td>
                <td className="text-zinc-500">{source.winner ? t("diag.inEffect") : t("diag.superseded")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {/*
        Design §5.5 and §6.1 both ask for the connection route to be visible,
        and a hop this engine could not resolve is marked rather than guessed.
        Rendering only the resolved hops would turn "we do not know" into a
        confident-looking gap in the chain.
      */}
      {effective && effective.route.length > 0 ? (
        <div className="text-sm">
          <h3 className="font-medium">{t("diag.route")}</h3>
          <ol className="mt-1 flex flex-col gap-1">
            {effective.route.map((stage) => (
              <li key={`${stage.order}-${stage.hop}`} style={{ marginLeft: `${stage.depth}rem` }}>
                <span className="text-zinc-100">{stage.hop}</span>
                {stage.complex ? (
                  <span className="ml-2 text-amber-300">{t("diag.hopComplex")}</span>
                ) : (
                  <span className="ml-2 text-zinc-400">
                    {`${stage.user === "" ? "" : `${stage.user}@`}${stage.hostname}${
                      stage.port === "" ? "" : `:${stage.port}`
                    }`}
                  </span>
                )}
                {stage.parent === "" ? null : (
                  <span className="ml-2 text-zinc-500">{t("diag.reachedThrough", { parent: stage.parent })}</span>
                )}
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      {/*
        The engine refuses to invent a value it cannot derive. These notes are
        where it says so, and they are the difference between "this is the
        answer" and "OpenSSH is the authority for this one".
      */}
      {effective && effective.complexities.length > 0 ? (
        <div className="rounded border border-amber-700 p-3 text-sm">
          <h3 className="font-medium text-amber-300">{t("diag.notSimple")}</h3>
          <p className="text-zinc-300">{t("diag.notSimpleDetail")}</p>
          <ul className="mt-2 flex flex-col gap-1">
            {effective.complexities.map((note, index) => (
              <li key={`${note.code}-${note.path}-${note.line}-${index}`}>
                <span className="text-zinc-100">{note.code}</span>
                <span className="ml-2 text-zinc-400">{`${note.path}:${note.line}`}</span>
                {note.condition === "" ? null : <span className="ml-2 text-zinc-500">{t("diag.inside", { condition: note.condition })}</span>}
                {note.detail === "" ? null : <p className="text-zinc-400">{note.detail}</p>}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {reach ? (
        <div className="text-sm">
          <h3 className="font-medium">{t("diag.reachability")}</h3>
          <p>
            {reach.address} — {reach.outcome}
          </p>
          <p className="text-zinc-400">{reach.notice}</p>
        </div>
      ) : null}

      {auth ? (
        <div className="text-sm">
          <h3 className="font-medium">{t("diag.authentication")}</h3>
          <p>{auth.outcome}</p>
          {auth.stderr ? <pre className="whitespace-pre-wrap break-all text-zinc-400">{auth.stderr}</pre> : null}
        </div>
      ) : null}

      {terminal ? (
        <div className="text-sm">
          <h3 className="font-medium">{t("diag.terminal")}</h3>
          <pre className="whitespace-pre-wrap break-all text-zinc-100">{terminal.command}</pre>
          <div className="mt-2 flex items-center gap-2">
            <CopyButton value={terminal.command} label="copy.command" />
            {terminal.launchable ? (
              <button
                type="button"
                onClick={() =>
                  void run(() => api.terminalLaunch(alias), () => undefined, t("diag.terminalFailed"))
                }
                className="rounded border border-zinc-700 px-3 py-1"
              >
                {t("diag.openInTerminal")}
              </button>
            ) : null}
          </div>
          {/*
            An alias this application refuses to launch still gets its command,
            and copying is the whole point of showing it. Design §6.5 allows the
            copy and withholds only the launch.
          */}
          {terminal.launchable ? null : <p className="text-amber-300">{terminal.warning}</p>}
        </div>
      ) : null}
    </section>
  );
}
