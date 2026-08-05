import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type GroupMetadata, type Metadata, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";
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

export function GroupsPanel() {
  const t = useTranslate();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [metadata, setMetadata] = useState<Metadata | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newName, setNewName] = useState("");
  const [settingGroup, setSettingGroup] = useState("");
  const [settingKeyword, setSettingKeyword] = useState("");
  const [settingValue, setSettingValue] = useState("");
  const [renaming, setRenaming] = useState<Record<string, string>>({});
  const [removing, setRemoving] = useState<Record<string, string>>({});
  const [confirmingRemove, setConfirmingRemove] = useState<Record<string, boolean>>({});
  const [localError, setLocalError] = useState("");

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

  if (overview === null || metadata === null) {
    return <p role="status" className="text-sm text-zinc-300">{t("groups.loading")}</p>;
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

  function addSetting() {
    if (settingGroup === "" || settingKeyword === "") {
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
        group.name === settingGroup
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
      <p className="text-xs text-zinc-400">
        {t("groups.directoryNote", { connections: "connections", keys: "keys" })}
      </p>
      <p className="text-xs text-zinc-400">
        {t("groups.compileNote", { file: loaded.groupsFile ?? "groups.ssh-ui.conf" })}
      </p>
      <p className="text-xs text-zinc-500">{t("groups.orderNote")}</p>
      {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}

      <ul aria-label={t("groups.listLabel")} className="flex flex-col gap-3">
        {groups.map((group) => (
          <li
            key={group.name}
            className="rounded border border-zinc-800 p-3"
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
                  style={{ backgroundColor: group.colour === undefined || group.colour === "" ? "#3f3f46" : group.colour }}
                />
                {depthOf(group.name) === 1 ? null : (
                  <span className="text-zinc-500">{group.name.slice(0, group.name.lastIndexOf("/") + 1)}</span>
                )}
                <span>{group.name.slice(group.name.lastIndexOf("/") + 1)}</span>
                {savedGroups.has(group.name) ? null : (
                  <span className="rounded border border-amber-700 px-1.5 py-0.5 text-[10px] font-normal text-amber-300">
                    {t("groups.unsaved")}
                  </span>
                )}
              </h3>
              <p className="font-mono text-xs text-zinc-500">
                {t("groups.directories", {
                  connections: `connections/${group.name}`,
                  keys: `keys/${group.name}`,
                })}
              </p>
              {/*
                Colour and display order are how the group looks, not what
                happens to it, so they sit with the name and leave the strip
                below to the three actions that rewrite files.
              */}
              <div className="ms-auto flex items-end gap-3">
                <label htmlFor={`group-colour-${group.name}`} className="flex flex-col gap-1">
                  <span className={fieldLabel}>{t("groups.colour")}</span>
                  <span className="flex items-center gap-2">
                    <input
                      id={`group-colour-${group.name}`}
                      type="color"
                      value={group.colour === undefined || group.colour === "" ? "#71717a" : group.colour}
                      onChange={(event) => updateGroup(group.name, { colour: event.target.value })}
                      className="h-8 w-12 rounded border border-zinc-700 bg-zinc-900"
                    />
                    {group.colour === undefined || group.colour === "" ? null : (
                      <button
                        type="button"
                        onClick={() => updateGroup(group.name, { colour: "" })}
                        className={secondaryAction}
                      >
                        {t("groups.clearColour", { name: group.name })}
                      </button>
                    )}
                  </span>
                </label>
                <label htmlFor={`group-order-${group.name}`} className="flex flex-col gap-1">
                  <span className={fieldLabel}>{t("groups.displayOrder")}</span>
                  <input
                    id={`group-order-${group.name}`}
                    type="number"
                    value={String(group.order ?? 0)}
                    onChange={(event) => updateGroup(group.name, { order: Number(event.target.value) || 0 })}
                    className={`${control} w-20`}
                  />
                </label>
              </div>
            </div>
            <p className="mt-1 text-xs text-zinc-400">
              {t("groups.members")}{" "}
              <span>{membersOf(group.name).length === 0 ? t("groups.noMembers") : membersOf(group.name).join(", ")}</span>
            </p>
            {/*
              An empty settings list still rendered its <ul>, so every group
              carried an empty row nobody had asked for.
            */}
            {(group.settings ?? []).length === 0 ? null : (
              <ul className="mt-2 flex flex-col gap-0.5 font-mono text-xs text-zinc-300">
                {(group.settings ?? []).map((setting, index) => (
                  <li key={`${setting.keyword}-${index}`}>{`${setting.keyword} ${formatValues(setting.values)}`}</li>
                ))}
              </ul>
            )}

            <div className="mt-3 flex flex-wrap items-end gap-x-4 gap-y-3 border-t border-zinc-800 pt-3">
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
            {savedGroups.has(group.name) ? null : (
              <p className="mt-2 text-xs text-amber-300">{t("groups.newGroupNote")}</p>
            )}

            {confirmingRemove[group.name] !== true ? null : (
              <div
                role="group"
                aria-label={t("groups.removeInto", { name: group.name })}
                className="mt-3 flex flex-col gap-2 rounded border border-rose-900 bg-rose-950/30 p-3"
              >
                <p className="text-sm text-zinc-200">
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

      <section className={sectionCard}>
        <h3 className={sectionHeading}>{t("groups.settingHeading")}</h3>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label={t("groups.group")}>
            <select
              id="setting-group"
              value={settingGroup}
              onChange={(event) => setSettingGroup(event.target.value)}
              className={control}
            >
              <option value="">{t("groups.chooseGroup")}</option>
              {groups.map((group) => (
                <option key={group.name} value={group.name}>{group.name}</option>
              ))}
            </select>
          </Field>
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

      {/*
        Which controls on this page write, and when, was not stated anywhere.
        It is stated once, here, beside the button that does the writing.
      */}
      <p className={unsaved ? "text-sm text-amber-300" : hintText}>
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
