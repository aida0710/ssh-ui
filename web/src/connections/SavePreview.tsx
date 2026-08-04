import type { ConflictReport, DiffLine, FileDiff, Notice, SavePreview } from "../api/config";
import type { Problem } from "../api/client";

const noticeCopy: Record<string, string> = {
  complex_external_rule: "A wildcard, negation, Match block or duplicate alias makes this value come from a rule this editor will not simplify. The source is shown instead.",
  duplicate_alias: "Another block declares the same alias. OpenSSH uses the first one it reads.",
  wildcard_shadow: "A catch-all block can override values for this host.",
  negated_pattern: "A negated pattern applies here.",
  unnamed_host_block: "This block has no concrete alias and can only be edited as raw text.",
  match_block: "A Match block was found. It is never evaluated here because Match exec can run a command.",
  dangerous_directive: "This directive can run a command. It is saved as written and never executed by this application.",
  unstructured_line: "This line has unbalanced quoting and is preserved exactly as written.",
  external_file: "This file is outside ~/.ssh. It is shown but never written.",
  orphan_metadata: "The host this note belonged to is gone. Re-associate it deliberately.",
  group_cycle: "This group's parents form a cycle, so it was skipped.",
  group_member_missing: "This group member has no host block in the configuration.",
  explained_values_only: "These values explain what this engine reads. The authoritative ssh -G check arrives with the diagnostics subsystem.",
};

function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <pre className="max-h-72 overflow-auto rounded bg-zinc-950 p-3 text-xs leading-5">
      {lines.map((line, index) => (
        <div
          key={`${line.op}-${line.oldLine ?? 0}-${line.newLine ?? 0}-${index}`}
          className={
            line.op === "insert" ? "text-emerald-300" : line.op === "delete" ? "text-rose-300" : "text-zinc-400"
          }
        >
          {`${line.op === "insert" ? "+" : line.op === "delete" ? "-" : " "} ${line.text}`}
        </div>
      ))}
    </pre>
  );
}

function FileDiffView({ diff }: { diff: FileDiff }) {
  return (
    <section className="flex flex-col gap-1">
      <h4 className="text-xs font-semibold text-zinc-300">
        {diff.path}
        {diff.created === true ? " (new file)" : ""}
      </h4>
      {diff.truncated === true ? (
        <p className="text-xs text-amber-300">
          This file is too large for a line-by-line preview, so the whole file is shown as replaced.
        </p>
      ) : null}
      <DiffView lines={diff.lines} />
    </section>
  );
}

export function NoticeList({ notices }: { notices: Notice[] }) {
  if (notices.length === 0) return null;
  return (
    <ul className="flex flex-col gap-1">
      {notices.map((notice, index) => (
        <li key={`${notice.code}-${notice.path ?? ""}-${notice.line ?? 0}-${index}`} className="text-xs text-amber-300">
          {noticeCopy[notice.code] ?? notice.code}
          {notice.path === undefined ? "" : ` (${notice.path}${notice.line === undefined ? "" : `:${notice.line}`})`}
        </li>
      ))}
    </ul>
  );
}

export function SavePreviewPanel({
  preview,
  conflict,
  problem,
}: {
  preview: SavePreview | null;
  conflict: ConflictReport | null;
  problem: Problem | null;
}) {
  return (
    <section aria-labelledby="preview-heading" className="flex flex-col gap-3 rounded border border-zinc-800 p-4">
      <h3 id="preview-heading" className="text-sm font-medium">Save preview</h3>

      {problem === null ? null : (
        <p role="alert" className="text-sm text-rose-300">
          {problem.code === "config_syntax_error"
            ? `Syntax error in ${problem.path ?? "the file"} at line ${problem.line ?? 0}, column ${problem.column ?? 0}. The edit is kept here and was not written.`
            : problem.code === "config_graph_error"
              ? "This change would break the Include graph. Nothing was written."
              : problem.code === "config_conflict"
                ? "The file changed outside this application. Nothing was written."
                : `The request was rejected (${problem.code}). Nothing was written.`}
        </p>
      )}

      {problem?.diagnostics === undefined ? null : (
        <ul className="flex flex-col gap-1">
          {problem.diagnostics.map((diagnostic, index) => (
            <li key={`${diagnostic.code}-${index}`} className="text-xs text-rose-300">
              {`${diagnostic.severity}: ${diagnostic.code} ${diagnostic.path ?? ""}${diagnostic.line === undefined ? "" : `:${diagnostic.line}`}`}
            </li>
          ))}
        </ul>
      )}

      {conflict === null ? null : (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-semibold text-zinc-300">Changed on disk since you loaded it</h4>
          <DiffView lines={conflict.externalChange} />
          <h4 className="text-xs font-semibold text-zinc-300">Your pending change</h4>
          <DiffView lines={conflict.localChange} />
          <p className="text-xs text-zinc-400">
            Reload the file to merge the two changes by hand. Nothing was written.
          </p>
        </div>
      )}

      {preview === null ? (
        conflict === null && problem === null ? (
          <p className="text-xs text-zinc-400">Change a value to see exactly what would be written.</p>
        ) : null
      ) : (
        <div className="flex flex-col gap-3">
          {preview.diffs.map((diff) => (
            <FileDiffView key={diff.path} diff={diff} />
          ))}
          {(preview.effective ?? []).map((effective) => (
            <section key={effective.alias} className="flex flex-col gap-1">
              <h4 className="text-xs font-semibold text-zinc-300">{`Explained values for ${effective.alias}`}</h4>
              <ul>
                {effective.changes.map((change) => (
                  <li key={change.keyword} className="text-xs text-zinc-300">
                    {`${change.keyword}: ${change.before.join(", ") || "unset"} → ${change.after.join(", ") || "unset"}`}
                  </li>
                ))}
              </ul>
            </section>
          ))}
          <NoticeList notices={preview.notices ?? []} />
        </div>
      )}
    </section>
  );
}
