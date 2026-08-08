import { useEffect, useMemo, useState } from "react";
import { configApi, type HostEntry, type Overview } from "../api/config";
import { integrationsApi, type SyncStatus } from "../api/integrations";
import { useTranslate } from "../i18n/context";
import { control, hintText, secondaryAction } from "../ui/form";
import { Notice } from "../ui/surface";

export type OverviewDestination = "Connections" | "Diagnostics" | "Sync" | "History";

type OverviewPanelProps = {
  loadOverview?: () => Promise<Overview>;
  loadSync?: () => Promise<SyncStatus>;
  launch?: (alias: string) => Promise<unknown>;
  onNavigate: (destination: OverviewDestination) => void;
};

type HostCard = {
  host: HostEntry;
  alias: string;
  group: string;
  tags: string[];
  favourite: boolean;
  order: number;
};

const loadDefaultOverview = () => configApi.overview();
const loadDefaultSync = () => integrationsApi.syncStatus();
const launchDefault = (alias: string) => integrationsApi.terminalLaunch(alias);
const informationalNoticeCodes = new Set(["group_empty"]);

// Home は管理画面の要約ではなく接続の入口である。画面を開いただけでは
// DNS、TCP、ssh のどれにも触れず、Terminal を開く操作だけが明示的な
// action token を消費する。
export function OverviewPanel({
  loadOverview = loadDefaultOverview,
  loadSync = loadDefaultSync,
  launch = launchDefault,
  onNavigate,
}: OverviewPanelProps) {
  const t = useTranslate();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);
  const [sync, setSync] = useState<SyncStatus | null>(null);
  const [query, setQuery] = useState("");
  const [launching, setLaunching] = useState("");
  const [problem, setProblem] = useState("");

  useEffect(() => {
    let active = true;
    void Promise.allSettled([loadOverview(), loadSync()]).then(([workspace, remote]) => {
      if (!active) return;
      if (workspace.status === "fulfilled") setOverview(workspace.value);
      else setProblem(t("home.loadFailed"));
      if (remote.status === "fulfilled") setSync(remote.value);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [loadOverview, loadSync, t]);

  const hosts = useMemo<HostCard[]>(() => {
    if (overview === null) return [];
    const metadata = new Map(
      (overview.metadata.hosts ?? []).map((host) => [
        `${host.identity.path}\u0000${host.identity.alias}`,
        host,
      ]),
    );
    return overview.hosts
      .filter((host) => host.identity.alias !== "")
      .map((host) => {
        const display = metadata.get(`${host.identity.path}\u0000${host.identity.alias}`);
        return {
          host,
          alias: host.identity.alias,
          group: host.group ?? "",
          tags: display?.tags ?? [],
          favourite: display?.favourite === true,
          order: display?.order ?? 0,
        };
      })
      .sort((left, right) => {
        if (left.favourite !== right.favourite) return left.favourite ? -1 : 1;
        if (left.order !== right.order) return left.order - right.order;
        return left.alias.localeCompare(right.alias);
      });
  }, [overview]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (needle === "") return hosts;
    return hosts.filter(
      (host) =>
        host.alias.toLowerCase().includes(needle) ||
        host.group.toLowerCase().includes(needle) ||
        host.tags.some((tag) => tag.toLowerCase().includes(needle)),
    );
  }, [hosts, query]);

  async function connect(alias: string) {
    setLaunching(alias);
    setProblem("");
    try {
      await launch(alias);
    } catch {
      setProblem(t("home.launchFailed", { alias }));
    } finally {
      setLaunching("");
    }
  }

  const attention =
    overview === null
      ? 0
      : overview.diagnostics.filter((item) => item.severity === "error" || item.severity === "warning").length +
        overview.notices.filter((item) => !informationalNoticeCodes.has(item.code)).length +
        (overview.pending?.length ?? 0);

  return (
    <section aria-labelledby="home-heading" className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 id="home-heading" className="text-xl font-semibold">{t("home.heading")}</h2>
          <p className="mt-1 text-sm text-ink-muted">{t("home.intro")}</p>
        </div>
        <button type="button" className={secondaryAction} onClick={() => onNavigate("Connections")}>
          {t("home.manageConnections")}
        </button>
      </div>

      {problem === "" ? null : <Notice tone="danger">{problem}</Notice>}

      <div className="grid gap-3 sm:grid-cols-3">
        <Summary label={t("home.connections")} value={overview === null ? "—" : hosts.length} />
        <Summary label={t("home.groups")} value={overview === null ? "—" : overview.groups.length} />
        <Summary label={t("home.attention")} value={overview === null ? "—" : attention} attention={attention > 0} />
      </div>

      <section aria-labelledby="quick-connect-heading" className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 id="quick-connect-heading" className="font-medium">{t("home.quickConnect")}</h3>
            <p className={hintText}>{t("home.quickConnectHint")}</p>
          </div>
          <label className="w-full sm:w-72">
            <span className="sr-only">{t("home.search")}</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t("home.searchPlaceholder")}
              className={control}
            />
          </label>
        </div>

        {loading ? (
          <p aria-live="polite" className={hintText}>{t("home.loading")}</p>
        ) : overview === null ? null : visible.length === 0 ? (
          <p className="rounded-xl border border-line bg-card p-5 text-sm text-ink-muted">
            {hosts.length === 0 ? t("home.noConnections") : t("home.noMatches")}
          </p>
        ) : (
          <ul aria-label={t("home.connectionList")} className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {visible.map((item) => (
              <li key={`${item.host.identity.path}\u0000${item.alias}`} className="flex min-w-0 flex-col gap-3 rounded-xl border border-line bg-card p-4">
                <div className="flex min-w-0 items-start gap-2">
                  <div className="min-w-0 grow">
                    <p className="truncate font-medium text-ink">
                      {item.favourite ? <span aria-label={t("home.favourite")} className="mr-1 text-notice-ink">★</span> : null}
                      {item.alias}
                    </p>
                    <p className="truncate text-xs text-ink-muted">
                      {item.group === "" ? t("home.ungrouped") : item.group}
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={launching !== ""}
                    onClick={() => void connect(item.alias)}
                    className={secondaryAction}
                  >
                    {launching === item.alias ? t("home.opening") : t("home.connect")}
                  </button>
                </div>
                {item.tags.length === 0 ? null : (
                  <ul aria-label={t("home.tagsFor", { alias: item.alias })} className="flex flex-wrap gap-1">
                    {item.tags.map((tag) => (
                      <li key={tag} className="rounded bg-select-fill px-2 py-0.5 text-xs text-ink-muted">{tag}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="grid gap-3 md:grid-cols-2">
        <section className="rounded-xl border border-line bg-card p-4">
          <h3 className="font-medium">{t("home.workspace")}</h3>
          <p className="mt-1 text-sm text-ink-muted">
            {overview === null
              ? t("home.workspaceUnavailable")
              : attention === 0
                ? t("home.workspaceClean")
                : t("home.workspaceAttention", { count: attention })}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" className={secondaryAction} onClick={() => onNavigate("Diagnostics")}>{t("home.openDiagnostics")}</button>
            {(overview?.pending?.length ?? 0) === 0 ? null : (
              <button type="button" className={secondaryAction} onClick={() => onNavigate("History")}>{t("home.recoverChanges")}</button>
            )}
          </div>
        </section>
        <section className="rounded-xl border border-line bg-card p-4">
          <h3 className="font-medium">{t("home.sync")}</h3>
          <p className="mt-1 text-sm text-ink-muted">
            {sync === null
              ? t("home.syncUnavailable")
              : !sync.configured
                ? t("home.syncNotConfigured")
                : sync.synced
                  ? t("home.syncLast", { at: sync.lastSyncedAt ?? "—", count: sync.fileCount ?? 0 })
                  : t("home.syncNever")}
          </p>
          <button type="button" className={`${secondaryAction} mt-3`} onClick={() => onNavigate("Sync")}>{t("home.openSync")}</button>
        </section>
      </div>
    </section>
  );
}

function Summary({ label, value, attention = false }: { label: string; value: string | number; attention?: boolean }) {
  return (
    <div className={`rounded-xl border bg-card p-4 ${attention ? "border-notice-line" : "border-line"}`}>
      <p className="text-xs font-medium uppercase tracking-wide text-ink-muted">{label}</p>
      <p className={`mt-1 text-2xl font-semibold ${attention ? "text-notice-ink" : "text-ink"}`}>{value}</p>
    </div>
  );
}
