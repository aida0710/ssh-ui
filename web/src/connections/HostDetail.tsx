import { useEffect, useMemo, useState } from "react";
import type { FieldEdit, FormField, GroupMetadata, HostDetail, HostMetadata, SavePreview } from "../api/config";
import type { Problem } from "../api/client";
import { integrationsApi, type IntegrationsApi } from "../api/integrations";
import { DiagnosticsPanel } from "../diagnostics/DiagnosticsPanel";
import { PasswordPanel } from "../diagnostics/PasswordPanel";
import { formatValues, parseValues } from "./values";
import { NoticeList, SavePreviewPanel } from "./SavePreview";
import { useTranslate } from "../i18n/context";
import {
  CheckboxField,
  control,
  fieldLabel,
  hintText,
  narrowControl,
  primaryAction,
  secondaryAction,
  sectionHeading,
} from "../ui/form";
import { Button, Card, Row } from "../ui/surface";
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
  // onMoveToGroup relocates the file rather than editing a field: a group is a
  // directory, so changing it is a move, and the caller sends the group name to
  // the server which derives the destination path from it.
  onMoveToGroup: (group: string) => void;
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
  onMoveToGroup,
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
  // Starts at the group the file is actually in, which the projection read from
  // its path, so the control shows where the connection is before it offers to
  // move it.
  const [moveTo, setMoveTo] = useState(detail.form.entry.group ?? "");
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
        <p className="text-xs text-ink-muted">
          {`${detail.form.entry.file.path ?? detail.form.entry.file.absolute}:${detail.form.entry.line}`}
        </p>
        <NoticeList notices={detail.form.notices ?? []} />
      </header>

      <div role="tablist" aria-label={t("host.editorLabel")} className="flex gap-1 border-b border-line">
        {tabs.map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
            className={`px-3 py-2 text-sm ${tab === name ? "border-b-2 border-accent text-ink" : "text-ink-muted"}`}
          >
            {t(tabLabels[name])}
          </button>
        ))}
      </div>

      {localError === "" ? null : <p role="alert" className="text-sm text-danger">{localError}</p>}

      {tab === "Basic" || tab === "Jump" || tab === "Advanced" ? (
        <div className="flex flex-col gap-3">
          {/*
            One directive to a row: its keyword on the left, its value on the
            right, hairlines between them and one border around the group. The
            "Remove" button is the row's action rather than one of its children,
            so it stays outside the label — inside it, pressing Remove would
            also focus the field.
          */}
          {visibleFields.length === 0 ? null : (
            <Card>
              {visibleFields.map((field) => (
                <Row
                  key={fieldKey(field)}
                  label={field.keyword}
                  warning={
                    [
                      field.dangerous === true ? t("host.dangerousField", { keyword: field.keyword }) : "",
                      field.duplicate === true ? t("host.duplicateKeyword") : "",
                    ]
                      .filter((part) => part !== "")
                      .join(" ") || undefined
                  }
                  action={
                    <Button
                      className="px-2 py-1 text-xs"
                      onClick={() =>
                        setRemoved(removed.includes(field.line)
                          ? removed.filter((line) => line !== field.line)
                          : [...removed, field.line])
                      }
                    >
                      {removed.includes(field.line) ? t("host.keep") : t("host.remove")}
                    </Button>
                  }
                >
                  <input
                    id={`field-${fieldKey(field)}`}
                    value={draftFor(field)}
                    disabled={!field.editable || removed.includes(field.line)}
                    onChange={(event) => setDrafts({ ...drafts, [fieldKey(field)]: event.target.value })}
                    className={control}
                  />
                </Row>
              ))}
            </Card>
          )}

          {tab === "Advanced" ? (
            <div className="flex flex-col gap-2 rounded border border-line p-3">
              <label htmlFor="new-directive" className="text-xs text-ink-muted">{t("host.newDirective")}</label>
              <input
                id="new-directive"
                value={newKeyword}
                onChange={(event) => setNewKeyword(event.target.value)}
                className="rounded border border-control-line bg-control px-2 py-1 text-sm"
              />
              <label htmlFor="new-value" className="text-xs text-ink-muted">{t("host.newValue")}</label>
              <input
                id="new-value"
                value={newValue}
                onChange={(event) => setNewValue(event.target.value)}
                className="rounded border border-control-line bg-control px-2 py-1 text-sm"
              />
              <button type="button" onClick={addDirective} className={`self-start ${secondaryAction}`}>
                {t("host.addDirective")}
              </button>
              {additions.length === 0 ? null : (
                <ul className="text-xs text-ink-muted">
                  {additions.map((addition, index) => (
                    <li key={`${addition.keyword ?? ""}-${index}`}>
                      {`${addition.keyword ?? ""} ${formatValues(addition.values ?? [])}`}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}

          <button type="button" onClick={submitFieldEdits} className={`self-start ${primaryAction}`}>
            {t("host.saveChanges")}
          </button>
        </div>
      ) : null}

      {tab === "Raw" ? (
        <div className="flex flex-col gap-2">
          <label htmlFor="block-raw" className="text-xs text-ink-muted">
            {t("host.blockText")}
          </label>
          <textarea
            id="block-raw"
            value={blockRaw}
            onChange={(event) => setBlockRaw(event.target.value)}
            rows={16}
            spellCheck={false}
            className="rounded border border-control-line bg-canvas p-3 font-mono text-xs"
          />
          <button type="button" onClick={() => onBlockRaw(blockRaw)} className={`self-start ${primaryAction}`}>
            {t("host.saveBlock")}
          </button>
        </div>
      ) : null}

      {tab === "Effective" ? (
        <div className="flex flex-col gap-2">
          <p role="status" className="text-xs text-notice-ink">
            {t("host.effectiveNote")}
          </p>
          <button
            type="button"
            onClick={() => setTab("Diagnostics")}
            className="self-start rounded border border-control-line px-2 py-1 text-xs"
          >
            {t("host.openDiagnostics")}
          </button>
          <ul className="flex flex-col gap-1">
            {detail.effective.entries.map((entry, index) => (
              <li key={`${entry.keyword}-${index}`} className="text-xs text-ink-muted">
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
          <p className="text-sm text-ink-muted">
            {t("host.noDestination")}
          </p>
        ) : (
          <div className="flex flex-col gap-4">
            <DiagnosticsPanel api={integrations} host={identityAlias} />
            {/*
              The stored password sits with the checks rather than with the
              directives, because it is not part of the configuration: this
              feature writes no ssh_config byte.
            */}
            <PasswordPanel api={integrations} alias={identityAlias} />
          </div>
        )
      ) : null}

      {/*
        Everything here is one property of the connection, and they were laid
        out as a single column of alternating captions and controls with no
        grouping — a wall in which the caption for the next control read as the
        hint for the last. Each property is now its own row with its own gap.

        What is left writes to a file: a group is a directory, so changing it
        moves the block; a comment is the line above `Host`; a rename is the
        `Host` line itself. The colour, the tags, the favourite flag and the
        display order exist only in metadata.json, so they moved to the
        inspector — which is the whole point of that pane.
      */}
      <section className="flex flex-col gap-5 rounded-xl border border-line p-4">
        <h3 className={sectionHeading}>{t("host.organisation")}</h3>

        {/*
          The group and the alias are one line each, so they are rows. The
          comment is not: it is three lines of prose, and a caption beside a
          box that tall reads as a caption for the gap under it.
        */}
        <Card>
          <Row
            label={t("host.primaryGroup")}
            hint={`${t("host.groupIsADirectory")} ${t("host.groupNoneMeans")}`}
            action={
              <Button
                // Disabled only when the choice is where the connection already
                // is. "None" used to be disabled too, which left no way at all —
                // by mouse or by keyboard — to take a connection back out of a
                // group.
                disabled={moveTo === (detail.form.entry.group ?? "")}
                onClick={() => onMoveToGroup(moveTo)}
              >
                {t("host.moveToGroup")}
              </Button>
            }
          >
            <select
              id="host-group"
              value={moveTo}
              onChange={(event) => setMoveTo(event.target.value)}
              className={narrowControl}
            >
              <option value="">{t("host.groupNone")}</option>
              {groups.map((group) => (
                <option key={group.name} value={group.name}>{group.name}</option>
              ))}
            </select>
          </Row>
          <Row
            label={t("host.renameAlias")}
            action={<Button onClick={() => onRename(renameTo)}>{t("host.rename")}</Button>}
          >
            <input
              id="host-rename"
              value={renameTo}
              onChange={(event) => setRenameTo(event.target.value)}
              className={control}
            />
          </Row>
        </Card>

        <div className="flex flex-col gap-2">
          <label htmlFor="host-comment" className={fieldLabel}>{t("host.comment")}</label>
          <textarea
            id="host-comment"
            value={comment}
            onChange={(event) => setComment(event.target.value)}
            rows={3}
            className={control}
          />
          <p className={hintText}>
            {detail.form.comment === "" && (detail.metadata.note ?? "") !== ""
              ? t("host.commentFromNote")
              : t("host.commentNote")}
          </p>
          <Button className="self-start" onClick={() => onComment(comment)}>
            {t("host.saveComment")}
          </Button>
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
