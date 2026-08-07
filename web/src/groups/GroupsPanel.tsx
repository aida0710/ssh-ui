import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type GroupMetadata, type Metadata, type Overview, type SavePreview } from "../api/config";
import { NoticeList, SavePreviewPanel } from "../connections/SavePreview";
import { formatValues, parseValues } from "../connections/values";
import {
  Field,
  control,
  dangerAction,
  fieldLabel,
  hintText,
  narrowControl,
  primaryAction,
  secondaryAction,
  sectionCard,
  sectionHeading,
} from "../ui/form";
import { useTranslate } from "../i18n/context";
import { Notice } from "../ui/surface";
import type { InspectorContent } from "../ui/Inspector";
import { GroupInspector } from "./GroupInspector";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

// depthOf counts the directories in a group name. The name carries the
// hierarchy, so nothing else has to be consulted to draw the tree, and a
// parent field can never disagree with where the files actually are.
export function depthOf(name: string): number {
  return name.split("/").length;
}

// treeOrder puts a parent before its children, and siblings in their display
// order, which is what a tree has to read like.
//
// It is deliberately not the order the Include lines take. OpenSSH keeps the
// first value it reads, so on disk the deepest group must come first or a
// parent's setting would beat its own child's. This panel used that order on
// screen, which floated every child above its parent and put the parent last —
// and the result reads as though nesting were not working at all.
export function treeOrder(groups: GroupMetadata[]): GroupMetadata[] {
  const orderOf = new Map(groups.map((group) => [group.name, group.order ?? 0]));
  // The key interleaves each ancestor's display order with its own segment, so
  // two siblings are compared by order and then by name at the level where
  // their paths actually diverge, not at their first character.
  const keyOf = (name: string): (number | string)[] => {
    const key: (number | string)[] = [];
    let prefix = "";
    for (const segment of name.split("/")) {
      prefix = prefix === "" ? segment : `${prefix}/${segment}`;
      key.push(orderOf.get(prefix) ?? 0, segment);
    }
    return key;
  };
  return [...groups].sort((left, right) => {
    const leftKey = keyOf(left.name);
    const rightKey = keyOf(right.name);
    for (let index = 0; index < Math.min(leftKey.length, rightKey.length); index += 1) {
      const first = leftKey[index]!;
      const second = rightKey[index]!;
      if (first === second) continue;
      return typeof first === "number" && typeof second === "number"
        ? first - second
        : String(first).localeCompare(String(second));
    }
    // One name is a prefix of the other, so it is the ancestor and comes first.
    return leftKey.length - rightKey.length;
  });
}

// A group name is a relative directory path, so the panel refuses locally what
// the server refuses too. Doing it here as well is not duplication for its own
// sake: it is what lets the panel say which character is wrong before a
// round trip that would only say "invalid_request".
const segmentPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function isValidGroupName(name: string): boolean {
  const segments = name.split("/");
  if (segments.length === 0 || segments.length > 6) return false;
  const reserved = new Set(["ssh-ui", "config", "known_hosts", "authorized_keys", "connections", "keys"]);
  return segments.every(
    (segment) => segmentPattern.test(segment) && !reserved.has(segment.toLowerCase()),
  );
}

type GroupsPanelProps = {
  // The inspector's contents, offered up to the shell — the same arrangement
  // the connections screen uses. A panel rendered on its own in a test passes
  // nothing and simply has no pane.
  onInspector?: (content: InspectorContent) => void;
};

export function GroupsPanel({ onInspector }: GroupsPanelProps = {}) {
  const t = useTranslate();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [metadata, setMetadata] = useState<Metadata | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newName, setNewName] = useState("");
  const [settingKeyword, setSettingKeyword] = useState("");
  const [settingValue, setSettingValue] = useState("");
  const [renaming, setRenaming] = useState<Record<string, string>>({});
  const [removing, setRemoving] = useState<Record<string, string>>({});
  const [confirmingRemove, setConfirmingRemove] = useState<Record<string, boolean>>({});
  const [localError, setLocalError] = useState("");
  // Which group the inspector is describing. Nothing is selected until a row
  // is, so the pane is not offered on a screen you have only just opened.
  const [selected, setSelected] = useState("");

  const reload = useCallback(async () => {
    try {
      const loaded = await configApi.overview();
      setOverview(loaded);
      setMetadata(loaded.metadata);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  // The pane follows the selected group. This sits above the early return
  // because a hook has to: the draft and the projection are read defensively
  // here rather than from the constants below, which only exist once there is
  // something to show.
  useEffect(() => {
    if (onInspector === undefined) return;
    const group = (metadata?.groups ?? []).find((candidate) => candidate.name === selected);
    if (group === undefined) {
      onInspector(null);
      return;
    }
    onInspector({
      // A declaration with no directory, or a directory nothing declares, is
      // worth the dot. An empty group is not — that is the state every group
      // is in the moment after it is made.
      attention: (overview?.notices ?? []).some(
        (notice) =>
          notice.detail === group.name &&
          ["group_not_declared", "group_directory_missing"].includes(notice.code),
      ),
      body: (
        <GroupInspector
          group={group}
          members={(overview?.hosts ?? [])
            .filter((host) => host.group === group.name)
            .map((host) => host.identity.alias)}
          onUpdate={(patch) => updateGroup(group.name, patch)}
        />
      ),
    });
    // updateGroup closes over the draft, which changes with metadata; the body
    // is rebuilt with it rather than memoised, so the pane never edits a stale
    // document.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, metadata, overview, onInspector]);

  if (overview === null || metadata === null) {
    return <p role="status" className="text-sm text-ink-muted">{t("groups.loading")}</p>;
  }

  // Hoisted function declarations do not inherit the narrowing above, so the
  // loaded document is captured once as a non-null const the closures can use.
  const loaded: Metadata = metadata;
  const hosts = overview.hosts;
  const groups = treeOrder(loaded.groups ?? []);

  // This panel has two kinds of control and used to show no difference between
  // them. Colour, display order, a new group and a new setting are edits to a
  // draft that only reaches the disk on Save; rename and remove write files the
  // moment they are pressed. So a group could be added, coloured, given
  // settings, and lost by navigating away — while the Remove button beside it
  // had already been committing to disk all along.
  //
  // The draft is compared against what the server last returned, which is the
  // only honest source for "this is not written yet".
  // `group_empty` is deliberately not among them.
  //
  // A declared group with nothing in it is not a fault, it is the state every
  // group is in for the moment after it is made and again when its last
  // connection moves out. OpenSSH is untroubled by an Include that matches no
  // file. Reporting it in amber beside two genuine faults — a declaration with
  // no directory, and a directory nothing declares — spent the colour that is
  // supposed to mean something happened, on nothing happening. The emptiness
  // was never hidden by dropping it either: each group's own row already reads
  // "Members: none", so the notice was saying it a second time in amber.
  const groupNotices = (overview.notices ?? []).filter((notice) =>
    ["group_not_declared", "group_directory_missing"].includes(notice.code),
  );
  const savedGroups = new Set((overview.metadata.groups ?? []).map((group) => group.name));
  const unsaved = JSON.stringify(loaded) !== JSON.stringify(overview.metadata);

  // Membership is where the file sits, and the projection already read that
  // from the path. Nothing here counts a metadata field.
  function membersOf(name: string): string[] {
    return hosts.filter((host) => host.group === name).map((host) => host.identity.alias);
  }

  function addGroup() {
    if (!isValidGroupName(newName)) {
      setLocalError(t("groups.invalidName"));
      return;
    }
    if (groups.some((group) => group.name.toLowerCase() === newName.toLowerCase())) {
      setLocalError(t("groups.nameTaken"));
      return;
    }
    const added: GroupMetadata = { name: newName };
    setMetadata({ ...loaded, groups: [...groups, added] });
    setNewName("");
    setLocalError("");
  }

  // The group is the selected one. It used to be a third picker on a page
  // that lists every group already.
  function addSetting() {
    if (selected === "" || settingKeyword === "") {
      setLocalError(t("groups.chooseGroupAndKeyword"));
      return;
    }
    let values: string[];
    try {
      values = parseValues(settingValue);
    } catch {
      setLocalError(t("groups.unbalancedQuote"));
      return;
    }
    setMetadata({
      ...loaded,
      groups: groups.map((group) =>
        group.name === selected
          ? { ...group, settings: [...(group.settings ?? []), { keyword: settingKeyword, values }] }
          : group,
      ),
    });
    setSettingKeyword("");
    setSettingValue("");
    setLocalError("");
  }

  function updateGroup(name: string, change: Partial<GroupMetadata>) {
    setMetadata({
      ...loaded,
      groups: (loaded.groups ?? []).map((group) => (group.name === name ? { ...group, ...change } : group)),
    });
  }

  // A group is a directory, so renaming it is N file moves plus the Include
  // region plus every IdentityFile naming its keys — one transaction the client
  // cannot assemble. It is a server operation, applied immediately, not an edit
  // to the document this panel holds.
  async function renameGroup(from: string) {
    const target = (renaming[from] ?? "").trim();
    if (target === "" || target === from) {
      setLocalError(t("groups.renameNeedsName"));
      return;
    }
    if (!isValidGroupName(target)) {
      setLocalError(t("groups.invalidName"));
      return;
    }
    if (groups.some((group) => group.name === target)) {
      // Renaming onto an existing group would merge two sets of settings, and
      // nothing here knows which should win. The server refuses it too.
      setLocalError(t("groups.renameCollides", { name: target }));
      return;
    }
    try {
      const result = await configApi.renameGroup(from, target);
      setPreview(result.preview);
      setProblem(null);
      setLocalError("");
      setRenaming({ ...renaming, [from]: "" });
      await reload();
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  async function removeGroup(name: string) {
    try {
      const result = await configApi.deleteGroup(name, removing[name] ?? "");
      setConfirmingRemove({ ...confirmingRemove, [name]: false });
      setPreview(result.preview);
      setProblem(null);
      setLocalError("");
      await reload();
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  async function run(action: "preview" | "save") {
    try {
      if (action === "preview") {
        setPreview(await configApi.preview({ kind: "groups", metadata: loaded }));
        setProblem(null);
        return;
      }
      const result = await configApi.save({ kind: "groups", metadata: loaded });
      setPreview(result.preview);
      setProblem(null);
      await reload();
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs text-ink-muted">
        {t("groups.directoryNote", { connections: "connections", keys: "keys" })}
      </p>
      <p className="text-xs text-ink-muted">
        {t("groups.compileNote", { file: loaded.groupsFile ?? "groups.ssh-ui.conf" })}
      </p>
      <p className="text-xs text-ink-faint">{t("groups.orderNote")}</p>
      {localError === "" ? null : <Notice tone="danger">{localError}</Notice>}
      {/*
        What the declaration and the disk say about each other. A directory
        under connections/ that no Include names is the one worth showing here
        above all: it looks like a group, and nothing in it is ever read.
      */}
      <NoticeList notices={groupNotices} />

      <ul aria-label={t("groups.listLabel")} className="flex flex-col gap-3">
        {groups.map((group) => (
          <li
            key={group.name}
            // Selecting a group is what fills the inspector, so the row says
            // which one is open the way the connection tree does.
            onFocus={() => setSelected(group.name)}
            onClick={() => setSelected(group.name)}
            className={`rounded-lg border p-3 ${
              selected === group.name ? "border-line bg-select-fill" : "border-line"
            }`}
            style={{ marginInlineStart: `${(depthOf(group.name) - 1) * 1.5}rem` }}
          >
            {/*
              What the group *is* — its name, its colour, where its files are
              and who is in it — is the header. Everything that changes it is
              below a rule. The two used to be one undifferentiated stack of
              six labelled boxes per group, which for four groups is a page of
              controls with the facts buried in it.

              The heading is still the whole path, so it stays the group's one
              name for a screen reader and for the rename button beside it. Only
              the ancestor part is dimmed, which is what makes the tree readable
              without inventing a second identifier.
            */}
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <h3 className="flex items-baseline gap-2 text-sm font-medium">
                <span
                  aria-hidden="true"
                  className="h-2 w-2 shrink-0 self-center rounded-full"
                  style={{ backgroundColor: group.colour === undefined || group.colour === "" ? "var(--ui-ink-faint)" : group.colour }}
                />
                {depthOf(group.name) === 1 ? null : (
                  <span className="text-ink-faint">{group.name.slice(0, group.name.lastIndexOf("/") + 1)}</span>
                )}
                <span>{group.name.slice(group.name.lastIndexOf("/") + 1)}</span>
              </h3>
              {/*
                Outside the heading. Inside it the badge joined the heading's
                accessible name with no separator — "labNot saved" — because
                adjacent elements concatenate. The heading is the group's name
                and nothing else.
              */}
              {savedGroups.has(group.name) ? null : (
                <span className="rounded border border-notice-line px-1.5 py-0.5 text-[10px] font-normal text-notice-ink">
                  {t("groups.unsaved")}
                </span>
              )}
              <p className="font-mono text-xs text-ink-faint">
                {t("groups.directories", {
                  connections: `connections/${group.name}`,
                  keys: `keys/${group.name}`,
                })}
              </p>
              {/*
                Colour, display order and hiding are how the group looks to this
                application and nothing else — they are in metadata.json, not in
                any configuration file — so they are in the inspector, the same
                place a connection's colour and tags went. What is left on the
                row is what the group *is*.
              */}
            </div>
            <p className="mt-1 text-xs text-ink-muted">
              {t("groups.members")}{" "}
              <span>{membersOf(group.name).length === 0 ? t("groups.noMembers") : membersOf(group.name).join(", ")}</span>
            </p>
            {/*
              An empty settings list still rendered its <ul>, so every group
              carried an empty row nobody had asked for.
            */}
            {(group.settings ?? []).length === 0 ? null : (
              <ul className="mt-2 flex flex-col gap-0.5 font-mono text-xs text-ink-muted">
                {(group.settings ?? []).map((setting, index) => (
                  <li key={`${setting.keyword}-${index}`}>{`${setting.keyword} ${formatValues(setting.values)}`}</li>
                ))}
              </ul>
            )}

            {/*
              Only for the group you have selected. These three rewrite files,
              and every group carrying its own copy of them meant a page whose
              controls outnumbered its facts four to one — which is what made
              this screen read as a wall.
            */}
            {selected !== group.name ? null : (
            <div className="mt-3 flex flex-wrap items-end gap-x-4 gap-y-3 border-t border-line pt-3">
              {/*
                The visible captions are short and the group's name lives in the
                accessible name instead. Spelled out on screen, four groups
                repeated "Rename <name> to" and "Move the connections of <name>
                into" eight times between them, which is most of what made this
                panel a wall of words. The visible text is still a substring of
                the accessible name, so the two never disagree.
              */}
              <label htmlFor={`group-rename-${group.name}`} className="flex flex-col gap-1">
                <span className={fieldLabel}>{t("groups.renameShort")}</span>
                <span className="flex items-end gap-2">
                  <input
                    id={`group-rename-${group.name}`}
                    aria-label={t("groups.renameTo", { name: group.name })}
                    value={renaming[group.name] ?? ""}
                    onChange={(event) => setRenaming({ ...renaming, [group.name]: event.target.value })}
                    className={narrowControl}
                  />
                  <button
                    type="button"
                    onClick={() => void renameGroup(group.name)}
                    disabled={!savedGroups.has(group.name)}
                    className={secondaryAction}
                  >
                    {t("groups.rename", { name: group.name })}
                  </button>
                </span>
              </label>
              {/*
                The destination used to be a select sitting on its own between
                the rename button and the remove button, labelled only "Move
                connections to". Nothing on screen tied it to removal, so it
                read as a third independent action that silently did nothing —
                and a user asked, reasonably, what it was for.

                It now lives inside the removal, after a sentence that says what
                removal actually does: the declaration goes, the connections
                move, and no file is deleted. The question is asked at the
                moment it is being answered.
              */}
              {confirmingRemove[group.name] !== true ? (
                <button
                  type="button"
                  onClick={() => setConfirmingRemove({ ...confirmingRemove, [group.name]: true })}
                  disabled={!savedGroups.has(group.name)}
                  className={secondaryAction}
                >
                  {t("groups.remove", { name: group.name })}
                </button>
              ) : null}
              {/*
                Nesting was discoverable only through a sentence about slashes
                under a text box at the bottom of the page. This puts it where
                the group is, and prefills the path so the user types the child
                name and nothing else.
              */}
              <button
                type="button"
                onClick={() => setNewName(`${group.name}/`)}
                className={secondaryAction}
              >
                {t("groups.addChild", { name: group.name })}
              </button>
            </div>
            )}
            {savedGroups.has(group.name) ? null : (
              <p className="mt-2 text-xs text-notice-ink">{t("groups.newGroupNote")}</p>
            )}

            {confirmingRemove[group.name] !== true ? null : (
              <div
                role="group"
                aria-label={t("groups.removeInto", { name: group.name })}
                className="mt-3 flex flex-col gap-2 rounded border border-control-line bg-card/30 p-3"
              >
                <p className="text-sm text-ink">
                  {membersOf(group.name).length === 0
                    ? t("groups.removeExplainEmpty", { name: group.name })
                    : t("groups.removeExplain", { name: group.name, count: membersOf(group.name).length })}
                </p>
                {membersOf(group.name).length === 0 ? null : (
                  <label htmlFor={`group-move-${group.name}`} className="flex flex-col gap-1">
                    <span className={fieldLabel}>{t("groups.removeIntoShort")}</span>
                    <select
                      id={`group-move-${group.name}`}
                      value={removing[group.name] ?? ""}
                      onChange={(event) => setRemoving({ ...removing, [group.name]: event.target.value })}
                      className={`${control} w-56`}
                    >
                      <option value="">{t("groups.removeIntoNone")}</option>
                      {groups
                        .filter(
                          (candidate) =>
                            candidate.name !== group.name && !candidate.name.startsWith(`${group.name}/`),
                        )
                        .map((candidate) => (
                          <option key={candidate.name} value={candidate.name}>
                            {candidate.name}
                          </option>
                        ))}
                    </select>
                  </label>
                )}
                {/*
                  What is not lost matters as much as what is. Saying it here is
                  the difference between a decision and a dare.
                */}
                <p className={hintText}>{t("groups.removeKeepsFiles")}</p>
                <div className="flex flex-wrap gap-2">
                  <button type="button" onClick={() => void removeGroup(group.name)} className={dangerAction}>
                    {t("groups.removeConfirm", { name: group.name })}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmingRemove({ ...confirmingRemove, [group.name]: false })}
                    className={secondaryAction}
                  >
                    {t("groups.removeCancel")}
                  </button>
                </div>
              </div>
            )}
          </li>
        ))}
      </ul>

      <section className={sectionCard}>
        <h3 className={sectionHeading}>{t("groups.addHeading")}</h3>
        <Field label={t("groups.newName")} hint={t("groups.nestingNote")}>
          <input
            id="group-name"
            value={newName}
            onChange={(event) => setNewName(event.target.value)}
            placeholder="work/eu"
            className={control}
          />
        </Field>
        <button type="button" onClick={addGroup} disabled={newName === ""} className={`self-start ${secondaryAction}`}>
          {t("groups.add")}
        </button>
      </section>

      {/*
        Scoped to the group you have selected, so the picker that used to sit
        here — a third "Choose a group" on a page that already shows them all —
        is gone. Asking which group, on a screen where one is already open, was
        asking a question the screen had answered.
      */}
      {selected === "" ? null : (
      <section className={sectionCard}>
        <h3 className={sectionHeading}>{t("groups.settingHeadingFor", { name: selected })}</h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("groups.directive")}>
            <input
              id="setting-keyword"
              value={settingKeyword}
              onChange={(event) => setSettingKeyword(event.target.value)}
              placeholder="ServerAliveInterval"
              className={control}
            />
          </Field>
          <Field label={t("groups.value")}>
            <input
              id="setting-value"
              value={settingValue}
              onChange={(event) => setSettingValue(event.target.value)}
              placeholder="30"
              className={control}
            />
          </Field>
        </div>
        <button type="button" onClick={addSetting} className={`self-start ${secondaryAction}`}>
          {t("groups.addSetting")}
        </button>
      </section>
      )}

      {/*
        Which controls on this page write, and when, was not stated anywhere.
        It is stated once, here, beside the button that does the writing.
      */}
      <p className={unsaved ? "text-sm text-notice-ink" : hintText}>
        {unsaved ? t("groups.unsavedNote") : t("groups.savedNote")}
      </p>

      <div className="flex gap-2">
        <button type="button" onClick={() => void run("preview")} className={secondaryAction}>
          {t("groups.previewChanges")}
        </button>
        <button type="button" onClick={() => void run("save")} className={primaryAction}>
          {t("groups.save")}
        </button>
      </div>

      <SavePreviewPanel preview={preview} conflict={problem?.conflict ?? null} problem={problem} />
    </div>
  );
}
