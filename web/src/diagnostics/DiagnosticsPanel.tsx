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
import {
  Field,
  control,
  hintText,
  secondaryAction,
  sectionCard,
  sectionHeading,
  tableHeadCell,
  tableHeadRow,
} from "../ui/form";
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

  // Every check is one entry here rather than one hand-written button, because
  // the guard is the point: an alias is required and a second check must not
  // start while the first is still running. Written out four times, a fifth
  // check would eventually be added without one of them.
  const checks: { label: string; start: () => void }[] = [
    {
      label: t("diag.explain"),
      start: () => void run(() => api.effective(alias, false), setEffective, t("diag.explainFailed")),
    },
    {
      label: t("diag.checkReachability"),
      start: () => void run(() => api.reachability(alias), setReach, t("diag.reachabilityFailed")),
    },
    {
      label: t("diag.testAuthentication"),
      start: () =>
        void run(
          () => api.authentication(alias, directives.some((directive) => !directive.overridable)),
          setAuth,
          t("diag.authenticationFailed"),
        ),
    },
    {
      label: t("diag.terminalCommand"),
      start: () => void run(() => api.terminalCommand(alias), setTerminal, t("diag.commandFailed")),
    },
  ];
  const blocked = busy || alias === "";

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

      <p aria-live="polite" className={hintText}>
        {busy ? t("diag.running") : alias === "" ? t("diag.needsAlias") : t("diag.idle")}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}

      <div className="flex flex-wrap items-end gap-2">
        {embedded ? null : (
          <div className="w-56">
            <Field label={t("diag.hostAlias")}>
              <input
                value={typedAlias}
                onChange={(event) => setTypedAlias(event.target.value)}
                placeholder="bastion"
                className={control}
              />
            </Field>
          </div>
        )}
        {checks.map((check) => (
          <button
            key={check.label}
            type="button"
            onClick={check.start}
            disabled={blocked}
            className={secondaryAction}
          >
            {check.label}
          </button>
        ))}
      </div>

      {config ? (
        <div className={sectionCard}>
          <h3 className={sectionHeading}>{t("diag.configuration")}</h3>
          <ul className="flex flex-col gap-1">
            {config.files.map((file) => (
              <li key={file.path} className="font-mono text-xs text-ink-muted">
                {file.path}
                {file.missing ? <span className="text-notice-ink">{t("diag.missingSuffix")}</span> : null}
              </li>
            ))}
          </ul>
          {config.diagnostics.length > 0 ? (
            <ul className="flex flex-col gap-1">
              {config.diagnostics.map((diagnostic, index) => (
                <li
                  key={`${diagnostic.code}-${index}`}
                  className={`font-mono text-xs ${
                    diagnostic.severity === "error"
                      ? "text-danger"
                      : diagnostic.severity === "warning"
                        ? "text-notice-ink"
                        : "text-ink-muted"
                  }`}
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
        <div className="rounded border border-control-line p-3 text-sm">
          <h3 className="font-medium text-danger">{t("diag.refused")}</h3>
          <p className="text-ink-muted">{t("diag.exited", { code: effective.failure.exitCode })}</p>
          {effective.failure.stderr ? (
            <pre className="mt-1 whitespace-pre-wrap break-all text-ink-muted">{effective.failure.stderr}</pre>
          ) : (
            <p className="text-ink-muted">{t("diag.noStderr")}</p>
          )}
          {effective.failure.truncated ? (
            <p className="text-notice-ink">{t("diag.outputTruncated")}</p>
          ) : null}
        </div>
      ) : null}

      {directives.length > 0 ? (
        <div className="rounded border border-notice-line p-3 text-sm">
          <h3 className="font-medium text-notice-ink">{t("diag.canRunCommand")}</h3>
          <p className="text-ink-muted">{effective?.tokenWarning}</p>
          <ul className="mt-2 flex flex-col gap-1">
            {directives.map((directive) => (
              <li key={`${directive.path}:${directive.line}:${directive.keyword}`}>
                <span className="text-ink-muted">
                  {t("diag.directiveAt", {
                    keyword: directive.keyword,
                    path: directive.path,
                    line: directive.line,
                  })}
                </span>
                <pre className="whitespace-pre-wrap break-all text-ink">{directive.command}</pre>
              </li>
            ))}
          </ul>
          {effective?.requiresConfirmation && !effective.evaluated ? (
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void run(() => api.effective(alias, true), setEffective, t("diag.explainFailed"))
              }
              className="mt-2 rounded border border-notice-line px-3 py-1.5 text-sm text-notice-ink hover:bg-notice disabled:border-line disabled:text-ink-faint"
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
        // Five columns of paths and conditions do not fit a narrow window, and
        // the page must not be the thing that scrolls sideways.
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            {/*
              The caption explains the table; it never said what the columns
              were. A path, a condition and a verdict rendered as three
              unlabelled greys are not self-describing.
            */}
            <caption className={`mb-2 text-left ${hintText}`}>{t("diag.sourcesCaption")}</caption>
            <thead>
              <tr className={tableHeadRow}>
                <th scope="col" className={tableHeadCell}>{t("diag.columnKeyword")}</th>
                <th scope="col" className={tableHeadCell}>{t("diag.columnValue")}</th>
                <th scope="col" className={tableHeadCell}>{t("diag.columnWhere")}</th>
                <th scope="col" className={tableHeadCell}>{t("diag.columnCondition")}</th>
                <th scope="col" className={tableHeadCell}>{t("diag.columnState")}</th>
              </tr>
            </thead>
            <tbody>
              {effective.sources.map((source) => (
                <tr
                  key={`${source.path}:${source.line}:${source.keyword}`}
                  className={`border-b border-line ${source.winner ? "" : "opacity-60"}`}
                >
                  <th scope="row" className="py-1.5 pr-3 text-left font-normal text-ink-muted">
                    {source.keyword}
                  </th>
                  <td className="py-1.5 pr-3 font-mono text-xs text-ink">{source.value}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-ink-faint">{`${source.path}:${source.line}`}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-ink-faint">{source.condition}</td>
                  <td className="py-1.5 text-ink-faint">{source.winner ? t("diag.inEffect") : t("diag.superseded")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {/*
        Design §5.5 and §6.1 both ask for the connection route to be visible,
        and a hop this engine could not resolve is marked rather than guessed.
        Rendering only the resolved hops would turn "we do not know" into a
        confident-looking gap in the chain.
      */}
      {effective && effective.route.length > 0 ? (
        <div className={`${sectionCard} text-sm`}>
          <h3 className={sectionHeading}>{t("diag.route")}</h3>
          <ol className="flex flex-col gap-1">
            {effective.route.map((stage) => (
              <li key={`${stage.order}-${stage.hop}`} style={{ marginInlineStart: `${stage.depth}rem` }}>
                <span className="text-ink">{stage.hop}</span>
                {stage.complex ? (
                  <span className="ml-2 text-notice-ink">{t("diag.hopComplex")}</span>
                ) : (
                  <span className="ml-2 text-ink-muted">
                    {`${stage.user === "" ? "" : `${stage.user}@`}${stage.hostname}${
                      stage.port === "" ? "" : `:${stage.port}`
                    }`}
                  </span>
                )}
                {stage.parent === "" ? null : (
                  <span className="ml-2 text-ink-faint">{t("diag.reachedThrough", { parent: stage.parent })}</span>
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
        <div className="rounded border border-notice-line p-3 text-sm">
          <h3 className="font-medium text-notice-ink">{t("diag.notSimple")}</h3>
          <p className="text-ink-muted">{t("diag.notSimpleDetail")}</p>
          <ul className="mt-2 flex flex-col gap-1">
            {effective.complexities.map((note, index) => (
              <li key={`${note.code}-${note.path}-${note.line}-${index}`}>
                <span className="text-ink">{note.code}</span>
                <span className="ml-2 text-ink-muted">{`${note.path}:${note.line}`}</span>
                {note.condition === "" ? null : <span className="ml-2 text-ink-faint">{t("diag.inside", { condition: note.condition })}</span>}
                {note.detail === "" ? null : <p className="text-ink-muted">{note.detail}</p>}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {reach ? (
        <div className={`${sectionCard} text-sm`}>
          <h3 className={sectionHeading}>{t("diag.reachability")}</h3>
          {/*
            The address and the verdict were one sentence joined by a dash. They
            are two different facts — where it dialled, and what happened — and
            the address is the one worth reading in a fixed pitch.
          */}
          <p className="font-mono text-xs text-ink">{reach.address}</p>
          <p className="text-ink">{reach.outcome}</p>
          <p className={hintText}>{reach.notice}</p>
        </div>
      ) : null}

      {auth ? (
        <div className={`${sectionCard} text-sm`}>
          <h3 className={sectionHeading}>{t("diag.authentication")}</h3>
          <p className="text-ink">{auth.outcome}</p>
          {auth.stderr ? (
            <pre className="whitespace-pre-wrap break-all font-mono text-xs text-ink-muted">{auth.stderr}</pre>
          ) : null}
        </div>
      ) : null}

      {terminal ? (
        <div className={`${sectionCard} text-sm`}>
          <h3 className={sectionHeading}>{t("diag.terminal")}</h3>
          <pre className="whitespace-pre-wrap break-all rounded bg-control p-2 font-mono text-xs text-ink">
            {terminal.command}
          </pre>
          <div className="flex items-center gap-2">
            <CopyButton value={terminal.command} label="copy.command" />
            {terminal.launchable ? (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void run(() => api.terminalLaunch(alias), () => undefined, t("diag.terminalFailed"))
                }
                className={secondaryAction}
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
          {terminal.launchable ? null : <p className="text-notice-ink">{terminal.warning}</p>}
        </div>
      ) : null}
    </section>
  );
}
