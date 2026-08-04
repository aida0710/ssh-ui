import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type HistoryEntry, type PendingTransaction } from "../api/config";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function HistoryPanel() {
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
      setMessage(`Restored ${path} as transaction ${result.transactionId}.`);
      setProblem(null);
      await reload();
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function recover(transactionId: string, action: "complete" | "rollback") {
    try {
      await configApi.recover(transactionId, action);
      setMessage(action === "complete" ? "The interrupted transaction was completed." : "The interrupted transaction was rolled back.");
      setProblem(null);
      await reload();
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  if (entries === null) {
    return <p role="status" className="text-sm text-zinc-300">Loading history…</p>;
  }

  return (
    <div className="flex flex-col gap-4">
      {problem === null ? null : (
        <p role="alert" className="text-sm text-rose-300">{`The request was rejected (${problem.code}).`}</p>
      )}
      {message === "" ? null : <p role="status" className="text-sm text-emerald-300">{message}</p>}

      {pending.length === 0 ? null : (
        <section aria-labelledby="pending-heading" className="flex flex-col gap-2 rounded border border-amber-700 p-3">
          <h3 id="pending-heading" className="text-sm font-medium text-amber-300">Interrupted transactions</h3>
          {pending.map((item) => (
            <div key={item.id} className="flex flex-col gap-1">
              <p className="text-xs text-zinc-300">
                {`${item.operation} started ${item.startedAt}: ${item.committed} of ${item.paths.length} files were written.`}
              </p>
              <p className="text-xs text-zinc-400">{item.paths.join(", ")}</p>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={!item.canComplete}
                  onClick={() => void recover(item.id, "complete")}
                  className="rounded border border-zinc-700 px-2 py-1 text-xs disabled:text-zinc-500"
                >
                  Complete
                </button>
                <button
                  type="button"
                  onClick={() => void recover(item.id, "rollback")}
                  className="rounded border border-zinc-700 px-2 py-1 text-xs"
                >
                  Roll back
                </button>
              </div>
            </div>
          ))}
        </section>
      )}

      <section aria-labelledby="history-heading" className="flex flex-col gap-2">
        <h3 id="history-heading" className="text-sm font-medium">Completed changes</h3>
        {entries.length === 0 ? (
          <p className="text-xs text-zinc-500">No change has been made through this application yet.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {entries.map((entry) => (
              <li key={entry.id} className="rounded border border-zinc-800 p-3">
                <p className="text-sm text-zinc-200">{entry.operation}</p>
                <p className="text-xs text-zinc-400">{`${entry.startedAt} · ${entry.status} · ${entry.paths.join(", ")}`}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(entry.restorable ?? []).map((path) => (
                    <button
                      key={path}
                      type="button"
                      onClick={() => void restore(entry.id, path)}
                      className="rounded border border-zinc-700 px-2 py-1 text-xs"
                    >
                      {`Restore ${path}`}
                    </button>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-zinc-500">
          Generation backups are kept in ~/.ssh/ssh-ui/backups and are never deleted automatically. A restore is itself
          a new transaction, so it can be undone the same way.
        </p>
      </section>
    </div>
  );
}
