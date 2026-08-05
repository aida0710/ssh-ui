import { useEffect, useMemo, useState } from "react";
import type { FieldEdit, FormField, GroupMetadata, HostDetail, HostMetadata, SavePreview } from "../api/config";
import type { Problem } from "../api/client";
import { integrationsApi, type IntegrationsApi } from "../api/integrations";
import { DiagnosticsPanel } from "../diagnostics/DiagnosticsPanel";
import { formatValues, parseValues } from "./values";
import { NoticeList, SavePreviewPanel } from "./SavePreview";
import { useTranslate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";

const tabs = ["Basic", "Jump", "Advanced", "Raw", "Effective", "Diagnostics"] as const;

// The tab identifiers stay English: they key the field categories and the
// rendering switch below, so translating them would make which tab is open
// depend on the display language.
const tabLabels: Record<(typeof tabs)[number], MessageKey> = {
  Basic: "host.tabBasic",
  Jump: "host.tabJump",
  Advanced: "host.tabAdvanced",
  Raw: "host.tabRaw",
  Effective: "host.tabEffective",
  Diagnostics: "host.tabDiagnostics",
};
type Tab = (typeof tabs)[number];

const categoryForTab: Record<string, string> = { Basic: "basic", Jump: "jump", Advanced: "advanced" };

type HostDetailPanelProps = {
  detail: HostDetail;
  groups: GroupMetadata[];
  preview: SavePreview | null;
  problem: Problem | null;
  onFieldEdits: (edits: FieldEdit[]) => void;
  onBlockRaw: (raw: string) => void;
  onRename: (newAlias: string) => void;
  onComment: (comment: string) => void;
  onMetadata: (metadata: HostMetadata) => void;
  // The Diagnostics tab runs the same checks as the Diagnostics section, so it
  // consumes the same client. It is a prop only so a test can inject one; the
  // panel falls back to the real client when it is absent.
  integrations?: IntegrationsApi;
};

function fieldKey(field: FormField): string {
  return `${field.line}-${field.keyword}`;
}

export function HostDetailPanel({
  detail,
  groups,
  preview,
  problem,
  onFieldEdits,
  onBlockRaw,
  onRename,
  onComment,
  onMetadata,
  integrations = integrationsApi,
}: HostDetailPanelProps) {
  const t = useTranslate();
  const [tab, setTab] = useState<Tab>("Basic");
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [removed, setRemoved] = useState<number[]>([]);
  const [additions, setAdditions] = useState<FieldEdit[]>([]);
  const [newKeyword, setNewKeyword] = useState("");
  const [newValue, setNewValue] = useState("");
  const [blockRaw, setBlockRaw] = useState(detail.form.raw);
  const [renameTo, setRenameTo] = useState(detail.form.entry.identity.alias);
  // A legacy note seeds the editor when the block has no comment yet, so the
  // first save moves it into the configuration instead of leaving the two to
  // disagree. Once written, the comment is the only source.
  const [comment, setComment] = useState(detail.form.comment || detail.metadata.note || "");
  const [localError, setLocalError] = useState("");

  // Opening a different host, or reloading the same one after a save, discards
  // every draft: the drafts describe line numbers that only make sense for the
  // block that produced them.
  const identityPath = detail.form.entry.identity.path;
  const identityAlias = detail.form.entry.identity.alias;
  const formRaw = detail.form.raw;
  useEffect(() => {
    setDrafts({});
    setRemoved([]);
    setAdditions([]);
    setNewKeyword("");
    setNewValue("");
    setBlockRaw(formRaw);
    setRenameTo(identityAlias);
    setComment(detail.form.comment || detail.metadata.note || "");
    setLocalError("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identityPath, identityAlias, formRaw]);

  const visibleFields = useMemo(
    () => detail.form.fields.filter((field) => field.category === categoryForTab[tab]),
    [detail.form.fields, tab],
  );

  function draftFor(field: FormField): string {
    return drafts[fieldKey(field)] ?? formatValues(field.values);
  }

  function submitFieldEdits() {
    const edits: FieldEdit[] = [];
    try {
      for (const field of detail.form.fields) {
        if (removed.includes(field.line)) {
          edits.push({ action: "remove", line: field.line });
          continue;
        }
        const draft = drafts[fieldKey(field)];
        if (draft === undefined) continue;
        edits.push({ action: "set", line: field.line, values: parseValues(draft) });
      }
      edits.push(...additions);
    } catch {
      setLocalError(t("host.unbalancedQuote"));
      return;
    }
    if (edits.length === 0) {
      setLocalError(t("host.nothingChanged"));
      return;
    }
    setLocalError("");
    onFieldEdits(edits);
  }

  function addDirective() {
    if (newKeyword === "") {
      setLocalError(t("host.needsKeyword"));
      return;
    }
    try {
      setAdditions([...additions, { action: "add", keyword: newKeyword, values: parseValues(newValue) }]);
    } catch {
      setLocalError(t("host.unbalancedQuote"));
      return;
    }
    setNewKeyword("");
    setNewValue("");
    setLocalError("");
  }

  return (
    <section className="flex flex-col gap-4">
      <header className="flex flex-col gap-1">
        <h2 className="text-lg font-medium">{detail.form.entry.identity.alias || detail.form.entry.patterns.join(" ")}</h2>
        <p className="text-xs text-zinc-400">
          {`${detail.form.entry.file.path ?? detail.form.entry.file.absolute}:${detail.form.entry.line}`}
        </p>
        <NoticeList notices={detail.form.notices ?? []} />
      </header>

      <div role="tablist" aria-label={t("host.editorLabel")} className="flex gap-1 border-b border-zinc-800">
        {tabs.map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
            className={`px-3 py-2 text-sm ${tab === name ? "border-b-2 border-zinc-200 text-zinc-100" : "text-zinc-400"}`}
          >
            {t(tabLabels[name])}
          </button>
        ))}
      </div>

      {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}

      {tab === "Basic" || tab === "Jump" || tab === "Advanced" ? (
        <div className="flex flex-col gap-3">
          {visibleFields.map((field) => (
            <div key={fieldKey(field)} className="flex flex-col gap-1">
              <label htmlFor={`field-${fieldKey(field)}`} className="text-xs text-zinc-400">
                {field.keyword}
              </label>
              <div className="flex gap-2">
                <input
                  id={`field-${fieldKey(field)}`}
                  value={draftFor(field)}
                  disabled={!field.editable || removed.includes(field.line)}
                  onChange={(event) => setDrafts({ ...drafts, [fieldKey(field)]: event.target.value })}
                  className="flex-1 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
                />
                <button
                  type="button"
                  onClick={() =>
                    setRemoved(removed.includes(field.line)
                      ? removed.filter((line) => line !== field.line)
                      : [...removed, field.line])
                  }
                  className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300"
                >
                  {removed.includes(field.line) ? t("host.keep") : t("host.remove")}
                </button>
              </div>
              {field.dangerous === true ? (
                <p className="text-xs text-amber-300">
                  {t("host.dangerousField", { keyword: field.keyword })}
                </p>
              ) : null}
              {field.duplicate === true ? (
                <p className="text-xs text-amber-300">
                  A previous line in this block uses the same keyword. OpenSSH keeps the first one.
                </p>
              ) : null}
            </div>
          ))}

          {tab === "Advanced" ? (
            <div className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
              <label htmlFor="new-directive" className="text-xs text-zinc-400">{t("host.newDirective")}</label>
              <input
                id="new-directive"
                value={newKeyword}
                onChange={(event) => setNewKeyword(event.target.value)}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
              />
              <label htmlFor="new-value" className="text-xs text-zinc-400">{t("host.newValue")}</label>
              <input
                id="new-value"
                value={newValue}
                onChange={(event) => setNewValue(event.target.value)}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
              />
              <button type="button" onClick={addDirective} className="self-start rounded bg-zinc-800 px-3 py-1 text-sm">
                {t("host.addDirective")}
              </button>
              {additions.length === 0 ? null : (
                <ul className="text-xs text-zinc-300">
                  {additions.map((addition, index) => (
                    <li key={`${addition.keyword ?? ""}-${index}`}>
                      {`${addition.keyword ?? ""} ${formatValues(addition.values ?? [])}`}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}

          <button type="button" onClick={submitFieldEdits} className="self-start rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900">
            {t("host.saveChanges")}
          </button>
        </div>
      ) : null}

      {tab === "Raw" ? (
        <div className="flex flex-col gap-2">
          <label htmlFor="block-raw" className="text-xs text-zinc-400">
            {t("host.blockText")}
          </label>
          <textarea
            id="block-raw"
            value={blockRaw}
            onChange={(event) => setBlockRaw(event.target.value)}
            rows={16}
            spellCheck={false}
            className="rounded border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs"
          />
          <button type="button" onClick={() => onBlockRaw(blockRaw)} className="self-start rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900">
            {t("host.saveBlock")}
          </button>
        </div>
      ) : null}

      {tab === "Effective" ? (
        <div className="flex flex-col gap-2">
          <p role="status" className="text-xs text-amber-300">
            {t("host.effectiveNote")}
          </p>
          <button
            type="button"
            onClick={() => setTab("Diagnostics")}
            className="self-start rounded border border-zinc-700 px-2 py-1 text-xs"
          >
            {t("host.openDiagnostics")}
          </button>
          <ul className="flex flex-col gap-1">
            {detail.effective.entries.map((entry, index) => (
              <li key={`${entry.keyword}-${index}`} className="text-xs text-zinc-300">
                {`${entry.keyword} ${entry.values.join(" ")} — ${entry.source.path ?? entry.source.absolute ?? ""}:${entry.source.line ?? 0}`}
              </li>
            ))}
          </ul>
          <NoticeList notices={detail.effective.notices ?? []} />
        </div>
      ) : null}

      {tab === "Diagnostics" ? (
        // A block that matches by pattern names no destination, so there is
        // nothing to dial, evaluate or open a Terminal for. ConnectionsPage
        // never routes one here, but an alias is what every check is addressed
        // by, so an empty one must not reach the panel from anywhere.
        identityAlias === "" ? (
          <p className="text-sm text-zinc-400">
            {t("host.noDestination")}
          </p>
        ) : (
          <DiagnosticsPanel api={integrations} host={identityAlias} />
        )
      ) : null}

      <section className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
        <h3 className="text-sm font-medium">{t("host.organisation")}</h3>
        <label htmlFor="host-group" className="text-xs text-zinc-400">{t("host.primaryGroup")}</label>
        <select
          id="host-group"
          value={detail.metadata.group ?? ""}
          onChange={(event) => onMetadata({ ...detail.metadata, group: event.target.value })}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          <option value="">{t("host.groupNone")}</option>
          {groups.map((group) => (
            <option key={group.name} value={group.name}>{group.name}</option>
          ))}
        </select>
        <label className="flex items-center gap-2 text-xs text-zinc-400">
          <input
            type="checkbox"
            checked={detail.metadata.favourite === true}
            onChange={(event) => onMetadata({ ...detail.metadata, favourite: event.target.checked })}
          />
          {t("host.favourite")}
        </label>
        <label htmlFor="host-comment" className="text-xs text-zinc-400">{t("host.comment")}</label>
        <textarea
          id="host-comment"
          value={comment}
          onChange={(event) => setComment(event.target.value)}
          rows={3}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <p className="text-xs text-zinc-500">
          {detail.form.comment === "" && (detail.metadata.note ?? "") !== ""
            ? t("host.commentFromNote")
            : t("host.commentNote")}
        </p>
        <button
          type="button"
          onClick={() => onComment(comment)}
          className="self-start rounded border border-zinc-700 px-2 py-1 text-xs"
        >
          {t("host.saveComment")}
        </button>
        <label htmlFor="host-colour" className="text-xs text-zinc-400">{t("host.colour")}</label>
        <div className="flex items-center gap-2">
          <input
            id="host-colour"
            type="color"
            // A colour input has no empty state, so "no colour" is the absence
            // of the value in metadata and this control shows a neutral swatch
            // for it. Clearing is a separate, explicit act.
            value={detail.metadata.colour === undefined || detail.metadata.colour === "" ? "#71717a" : detail.metadata.colour}
            onChange={(event) => onMetadata({ ...detail.metadata, colour: event.target.value })}
            className="h-7 w-12 rounded border border-zinc-700 bg-zinc-900"
          />
          {detail.metadata.colour === undefined || detail.metadata.colour === "" ? null : (
            <button
              type="button"
              onClick={() => onMetadata({ ...detail.metadata, colour: "" })}
              className="rounded border border-zinc-700 px-2 py-1 text-xs"
            >
              {t("host.clearColour")}
            </button>
          )}
        </div>
        <label htmlFor="host-order" className="text-xs text-zinc-400">
          {t("host.displayOrder")}
        </label>
        <input
          id="host-order"
          type="number"
          value={String(detail.metadata.order ?? 0)}
          onChange={(event) => onMetadata({ ...detail.metadata, order: Number(event.target.value) || 0 })}
          className="w-24 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="host-tags" className="text-xs text-zinc-400">{t("host.tags")}</label>
        <input
          id="host-tags"
          value={(detail.metadata.tags ?? []).join(", ")}
          onChange={(event) =>
            onMetadata({
              ...detail.metadata,
              tags: event.target.value
                .split(",")
                .map((tag) => tag.trim())
                .filter((tag) => tag !== ""),
            })
          }
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="host-rename" className="text-xs text-zinc-400">{t("host.renameAlias")}</label>
        <div className="flex gap-2">
          <input
            id="host-rename"
            value={renameTo}
            onChange={(event) => setRenameTo(event.target.value)}
            className="flex-1 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
          />
          <button type="button" onClick={() => onRename(renameTo)} className="rounded border border-zinc-700 px-2 py-1 text-xs">
            {t("host.rename")}
          </button>
        </div>
      </section>

      <SavePreviewPanel
        preview={preview}
        conflict={problem?.conflict ?? null}
        problem={problem}
      />
    </section>
  );
}
