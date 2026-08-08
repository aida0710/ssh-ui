import { useCallback, useEffect, useState } from "react";
import { useTranslate } from "../i18n/context";
import { ApiError, type Problem } from "../api/client";
import { configApi, type HistoryEntry, type PendingTransaction } from "../api/config";
import { secondaryAction } from "../ui/form";
import { Notice } from "../ui/surface";
import { MetricCard, MetricGrid, PageHeader } from "../ui/page";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function HistoryPanel() {
  const t = useTranslate();
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [pending, setPending] = useState<PendingTransaction[]>([]);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [message, setMessage] = useState("");

  const reload = useCallback(async () => {
    try {
      const [history, overview] = await Promise.all([configApi.history(), configApi.overview()]);
      setEntries(history);
      setPending(overview.pending ?? []);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function restore(transactionId: string, path: string) {
    try {
      const result = await configApi.restore(transactionId, path);
      setMessage(t("history.restored", { path, id: result.transactionId }));
      setProblem(null);
      await reload();
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function recover(transactionId: string, action: "complete" | "rollback") {
    try {
      await configApi.recover(transactionId, action);
      setMessage(t(action === "complete" ? "history.completedTransaction" : "history.rolledBack"));
      setProblem(null);
      await reload();
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  if (entries === null) {
    return <p role="status" className="text-sm text-ink-muted">{t("history.loading")}</p>;
  }

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader title={t("history.pageTitle")} description={t("history.pageDescription")} />
      <MetricGrid>
        <MetricCard label={t("history.metricChanges")} value={entries.length} />
        <MetricCard
          label={t("history.metricInterrupted")}
          value={pending.length}
          attention={pending.length > 0}
        />
        <MetricCard
          label={t("history.metricRestorable")}
          value={entries.reduce((count, entry) => count + (entry.restorable?.length ?? 0), 0)}
        />
      </MetricGrid>
      {problem === null ? null : (
        <Notice tone="danger">{t("history.requestRejected", { code: problem.code })}</Notice>
      )}
      {message === "" ? null : <p role="status" className="text-sm text-live">{message}</p>}

      {pending.length === 0 ? null : (
        <section aria-labelledby="pending-heading" className="flex flex-col gap-3 rounded-xl border border-notice-line bg-notice p-4">
          <h3 id="pending-heading" className="text-sm font-medium text-notice-ink">{t("history.interrupted")}</h3>
          {pending.map((item) => (
            <div key={item.id} className="flex flex-col gap-1">
              <p className="text-xs text-ink-muted">
                {t("history.interruptedDetail", {
                  operation: item.operation,
                  startedAt: item.startedAt,
                  committed: item.committed,
                  total: item.paths.length,
                })}
              </p>
              <p className="text-xs text-ink-muted">{item.paths.join(", ")}</p>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={!item.canComplete}
                  onClick={() => void recover(item.id, "complete")}
                  className={secondaryAction}
                >
                  {t("history.complete")}
                </button>
                <button
                  type="button"
                  onClick={() => void recover(item.id, "rollback")}
                  className={secondaryAction}
                >
                  {t("history.rollBack")}
                </button>
              </div>
            </div>
          ))}
        </section>
      )}

      <section aria-labelledby="history-heading" className="flex flex-col gap-3">
        <h3 id="history-heading" className="font-medium">{t("history.completed")}</h3>
        {entries.length === 0 ? (
          <p className="rounded-xl border border-line bg-card p-5 text-sm text-ink-muted">{t("history.empty")}</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {entries.map((entry) => (
              <li key={entry.id} className="rounded-xl border border-line bg-card p-4">
                <p className="font-medium text-ink">{entry.operation}</p>
                <p className="text-xs text-ink-muted">{`${entry.startedAt} · ${entry.status} · ${entry.paths.join(", ")}`}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(entry.restorable ?? []).map((path) => (
                    <button
                      key={path}
                      type="button"
                      onClick={() => void restore(entry.id, path)}
                      className={secondaryAction}
                    >
                      {t("history.restorePath", { path })}
                    </button>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-ink-faint">{t("history.backupsKept")}</p>
      </section>
    </div>
  );
}
