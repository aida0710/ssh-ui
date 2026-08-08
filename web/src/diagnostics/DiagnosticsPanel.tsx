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
import { Notice } from "../ui/surface";
import { PageHeader } from "../ui/page";

type DiagnosticsPanelProps = {
  api?: IntegrationsApi;
  // 診断対象のホスト。独立した section はこれを undefined のままにして
  // alias を尋ねるが、ホストエディタは既にどの接続が開いているか
  // 知っているため、それを渡し alias フィールドはレンダリングされない。固定
  // されたホストは設定の読み込みも省く。それはこのホストでは
  // なくファイル集合を記述するものであり、Config section の役目である。
  host?: string;
};

// この画面のすべての検査はユーザーが意図して開始する。パネルを開く
// ことは設定を読むだけで何も実行しない。他の各操作は
// 確認を消費し、プロセスを起動し得る。
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

  // このパネルのすべての結果は一つのホストについてのものである。別の
  // ホストを開けばそれらを消さなければならない。さもなければ前の
  // 接続が得た到達性の判定が新しい名前の下に座り、自分のものであるかのように読めてしまう。
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

  // すべての検査は手書きのボタン一つずつではなく、ここでの一つの
  // エントリである。要点は防護にある。alias は必須であり、最初の
  // 検査が実行中は二つ目を始めてはならない。四回書き出せば、五つ目の
  // 検査がいずれそのどちらかを欠いたまま追加されてしまう。
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
      className={embedded ? "flex flex-col gap-4" : "mx-auto flex w-full max-w-5xl flex-col gap-6"}
    >
      {embedded ? null : (
        <PageHeader title={t("diag.heading")} description={t("diag.pageDescription")} />
      )}

      <p aria-live="polite" className={hintText}>
        {busy ? t("diag.running") : alias === "" ? t("diag.needsAlias") : t("diag.idle")}
      </p>
      {error ? (
        <Notice tone="danger">{error}</Notice>
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
        失敗した`ssh -G`は理由を内側に持つ 200 を返すため何も
        スローせず、パネルは以前沈黙をレンダリングしていた。ソース
        テーブルは空で、実行可能なディレクティブがないこともあり、
        他のどのブロックも条件付きである。Explain を押しても
        何もしていないように見えていた。OpenSSH が自身の拒否に
        ついて語ったことだけが、それを説明する唯一のものである。
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
        勝者だけでなくすべての候補を列挙する。OpenSSH は
        keyword について最初に読んだ値を保つため、「なぜこれで
        あってあれではないのか」は負けた行についての問いであり、
        それらを隠すテーブルはそれに答えられない。勝者は唯一の行に
        なるのではなく、印を付けられる。
      */}
      {effective && effective.sources.length > 0 ? (
        // パスと条件の五つの列は狭いウィンドウには収まらず、
        // ページが横にスクロールするものになってはならない。
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            {/*
              キャプションはテーブルを説明するが、列が何であるかは
              一度も述べていなかった。パス、条件、判定を
              三つの無ラベルな灰色として描いても、自己説明的にはならない。
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
        design §5.5 と§6.1 はどちらも接続経路が見えることを
        求めており、このエンジンが解決できなかったホップは推測される
        のではなく印が付けられる。解決できたホップだけを描けば、
        「分からない」ことが連鎖の中の自信ありげな空白に変わってしまう。
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
        エンジンは導出できない値を捏造することを拒否する。これらの
        注記はそう述べる場所であり、「これが答えである」ことと
        「これについては OpenSSH が権威である」ことの違いである。
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
            アドレスと判定はダッシュで繋いだ一つの文だった。これらは
            二つの異なる事実——どこへ発信したか、何が起きたか——であり、
            アドレスは等幅で読む価値のある方である。
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
            このアプリケーションが起動を拒否する alias にも、その
            コマンドは与えられる。それを見せる目的はコピーできる
            ことに尽きる。design §6.5 はコピーを許し、起動だけを差し止める。
          */}
          {terminal.launchable ? null : <p className="text-notice-ink">{terminal.warning}</p>}
        </div>
      ) : null}
    </section>
  );
}
