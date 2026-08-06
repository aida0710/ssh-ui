import type { ConflictReport, DiffLine, FileDiff, Notice, SavePreview } from "../api/config";
import type { Problem } from "../api/client";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";

const noticeKeys: Record<string, MessageKey> = {
  complex_external_rule: "notice.complex_external_rule",
  duplicate_alias: "notice.duplicate_alias",
  wildcard_shadow: "notice.wildcard_shadow",
  negated_pattern: "notice.negated_pattern",
  unnamed_host_block: "notice.unnamed_host_block",
  match_block: "notice.match_block",
  dangerous_directive: "notice.dangerous_directive",
  unstructured_line: "notice.unstructured_line",
  external_file: "notice.external_file",
  orphan_metadata: "notice.orphan_metadata",
  group_cycle: "notice.group_cycle",
  group_member_missing: "notice.group_member_missing",
  explained_values_only: "notice.explained_values_only",
  destination_not_included: "notice.destination_not_included",
  include_no_longer_matches: "notice.include_no_longer_matches",
  include_not_rewritten: "notice.include_not_rewritten",
  include_now_unreached: "notice.include_now_unreached",
  group_file_unreached: "notice.group_file_unreached",
  group_directory_leftover: "notice.group_directory_leftover",
  group_not_declared: "notice.group_not_declared",
  group_directory_missing: "notice.group_directory_missing",
  group_empty: "notice.group_empty",
  generated_region_damaged: "notice.generated_region_damaged",
};

function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <pre className="max-h-72 overflow-auto rounded bg-canvas p-3 text-xs leading-5">
      {lines.map((line, index) => (
        <div
          key={`${line.op}-${line.oldLine ?? 0}-${line.newLine ?? 0}-${index}`}
          className={
            line.op === "insert" ? "text-live" : line.op === "delete" ? "text-danger" : "text-ink-muted"
          }
        >
          {`${line.op === "insert" ? "+" : line.op === "delete" ? "-" : " "} ${line.text}`}
        </div>
      ))}
    </pre>
  );
}

function FileDiffView({ diff }: { diff: FileDiff }) {
  const t = useTranslate();
  return (
    <section className="flex flex-col gap-1">
      <h4 className="text-xs font-semibold text-ink-muted">
        {diff.path}
        {diff.created === true ? t("preview.newFile") : ""}
      </h4>
      {diff.truncated === true ? (
        <p className="text-xs text-notice-ink">{t("preview.tooLarge")}</p>
      ) : null}
      <DiffView lines={diff.lines} />
    </section>
  );
}

// The refusals worth a sentence rather than a code. A code the server took the
// trouble to distinguish is one the user can act on, and "rejected: x" sends
// them looking for what x means.
const refusalKeys: Record<string, MessageKey> = {
  directory_not_empty: "refusal.directory_not_empty",
  not_a_directory: "refusal.not_a_directory",
  group_is_declared: "refusal.group_is_declared",
  destination_exists: "refusal.destination_exists",
  region_damaged: "refusal.region_damaged",
};

export function NoticeList({ notices }: { notices: Notice[] }) {
  const t = useTranslate();
  if (notices.length === 0) return null;
  return (
    <ul className="flex flex-col gap-1">
      {notices.map((notice, index) => (
        <li key={`${notice.code}-${notice.path ?? ""}-${notice.line ?? 0}-${index}`} className="text-xs text-notice-ink">
          {notice.code in noticeKeys ? t(noticeKeys[notice.code]!) : notice.code}
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
  const t = useTranslate();
  return (
    <section aria-labelledby="preview-heading" className="flex flex-col gap-3 rounded border border-line p-4">
      <h3 id="preview-heading" className="text-sm font-medium">{t("preview.heading")}</h3>

      {problem === null ? null : (
        <p role="alert" className="text-sm text-danger">
          {problem.code === "config_syntax_error"
            ? t("preview.syntaxError", {
                path: problem.path ?? t("preview.theFile"),
                line: problem.line ?? 0,
                column: problem.column ?? 0,
              })
            : problem.code === "config_graph_error"
              ? t("preview.graphError")
              : problem.code === "config_conflict"
                ? t("preview.conflictError")
                : problem.code in refusalKeys
                  ? t(refusalKeys[problem.code]!, { detail: problem.detail ?? "" })
                  : t("preview.rejected", { code: problem.code })}
        </p>
      )}

      {problem?.diagnostics === undefined ? null : (
        <ul className="flex flex-col gap-1">
          {problem.diagnostics.map((diagnostic, index) => (
            <li key={`${diagnostic.code}-${index}`} className="text-xs text-danger">
              {`${diagnostic.severity}: ${diagnostic.code} ${diagnostic.path ?? ""}${diagnostic.line === undefined ? "" : `:${diagnostic.line}`}`}
            </li>
          ))}
        </ul>
      )}

      {conflict === null ? null : (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-semibold text-ink-muted">{t("preview.changedOnDisk")}</h4>
          <DiffView lines={conflict.externalChange} />
          <h4 className="text-xs font-semibold text-ink-muted">{t("preview.pendingChange")}</h4>
          <DiffView lines={conflict.localChange} />
          <p className="text-xs text-ink-muted">{t("preview.mergeByHand")}</p>
        </div>
      )}

      {preview === null ? (
        conflict === null && problem === null ? (
          <p className="text-xs text-ink-muted">{t("preview.nothingYet")}</p>
        ) : null
      ) : (
        <div className="flex flex-col gap-3">
          {preview.diffs.map((diff) => (
            <FileDiffView key={diff.path} diff={diff} />
          ))}
          {(preview.effective ?? []).map((effective) => (
            <section key={effective.alias} className="flex flex-col gap-1">
              <h4 className="text-xs font-semibold text-ink-muted">{t("preview.explainedFor", { alias: effective.alias })}</h4>
              <ul>
                {effective.changes.map((change) => (
                  <li key={change.keyword} className="text-xs text-ink-muted">
                    {`${change.keyword}: ${change.before.join(", ") || t("preview.unset")} → ${
                      change.after.join(", ") || t("preview.unset")
                    }`}
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
