import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type GroupMetadata, type Metadata, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";
import { formatValues, parseValues } from "../connections/values";
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
  // Deepest first, then by the order the user gave, then by name: the same rule
  // that decides which Include line comes first, so what the panel shows is the
  // order OpenSSH will read.
  const groups = [...(loaded.groups ?? [])].sort((left, right) => {
    const depth = depthOf(right.name) - depthOf(left.name);
    if (depth !== 0) return depth;
    if ((left.order ?? 0) !== (right.order ?? 0)) return (left.order ?? 0) - (right.order ?? 0);
    return left.name.localeCompare(right.name);
  });

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
      {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}

      <ul className="flex flex-col gap-3">
        {groups.map((group) => (
          <li
            key={group.name}
            className="rounded border border-zinc-800 p-3"
            style={{ marginInlineStart: `${(depthOf(group.name) - 1) * 1.5}rem` }}
          >
            <h3 className="text-sm font-medium">{group.name}</h3>
            <p className="font-mono text-xs text-zinc-400">
              {t("groups.directories", {
                connections: `connections/${group.name}`,
                keys: `keys/${group.name}`,
              })}
            </p>
            <ul className="mt-1 text-xs text-zinc-300">
              {(group.settings ?? []).map((setting, index) => (
                <li key={`${setting.keyword}-${index}`}>{`${setting.keyword} ${formatValues(setting.values)}`}</li>
              ))}
            </ul>
            <p className="mt-1 text-xs text-zinc-400">
              {t("groups.members")}{" "}
              <span>{membersOf(group.name).length === 0 ? t("groups.noMembers") : membersOf(group.name).join(", ")}</span>
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <label htmlFor={`group-colour-${group.name}`} className="text-xs text-zinc-400">
                {t("groups.colour")}
              </label>
              <input
                id={`group-colour-${group.name}`}
                type="color"
                value={group.colour === undefined || group.colour === "" ? "#71717a" : group.colour}
                onChange={(event) => updateGroup(group.name, { colour: event.target.value })}
                className="h-7 w-12 rounded border border-zinc-700 bg-zinc-900"
              />
              {group.colour === undefined || group.colour === "" ? null : (
                <button
                  type="button"
                  onClick={() => updateGroup(group.name, { colour: "" })}
                  className="rounded border border-zinc-700 px-2 py-1 text-xs"
                >
                  {t("groups.clearColour", { name: group.name })}
                </button>
              )}
              <label htmlFor={`group-order-${group.name}`} className="text-xs text-zinc-400">
                {t("groups.displayOrder")}
              </label>
              <input
                id={`group-order-${group.name}`}
                type="number"
                value={String(group.order ?? 0)}
                onChange={(event) => updateGroup(group.name, { order: Number(event.target.value) || 0 })}
                className="w-20 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs"
              />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <label htmlFor={`group-rename-${group.name}`} className="text-xs text-zinc-400">
                {t("groups.renameTo", { name: group.name })}
              </label>
              <input
                id={`group-rename-${group.name}`}
                value={renaming[group.name] ?? ""}
                onChange={(event) => setRenaming({ ...renaming, [group.name]: event.target.value })}
                className="w-40 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs"
              />
              <button
                type="button"
                onClick={() => void renameGroup(group.name)}
                className="rounded border border-zinc-700 px-2 py-1 text-xs"
              >
                {t("groups.rename", { name: group.name })}
              </button>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <label htmlFor={`group-move-${group.name}`} className="text-xs text-zinc-400">
                {t("groups.removeInto", { name: group.name })}
              </label>
              <select
                id={`group-move-${group.name}`}
                value={removing[group.name] ?? ""}
                onChange={(event) => setRemoving({ ...removing, [group.name]: event.target.value })}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs"
              >
                <option value="">{t("groups.removeIntoNone")}</option>
                {groups
                  .filter((candidate) => candidate.name !== group.name && !candidate.name.startsWith(`${group.name}/`))
                  .map((candidate) => (
                    <option key={candidate.name} value={candidate.name}>
                      {candidate.name}
                    </option>
                  ))}
              </select>
              <button
                type="button"
                onClick={() => void removeGroup(group.name)}
                className="rounded border border-zinc-700 px-2 py-1 text-xs"
              >
                {t("groups.remove", { name: group.name })}
              </button>
            </div>
          </li>
        ))}
      </ul>

      <section className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
        <label htmlFor="group-name" className="text-xs text-zinc-400">{t("groups.newName")}</label>
        <input
          id="group-name"
          value={newName}
          onChange={(event) => setNewName(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <p className="text-xs text-zinc-500">{t("groups.nestingNote")}</p>
        <button type="button" onClick={addGroup} className="self-start rounded bg-zinc-800 px-3 py-1 text-sm">
          {t("groups.add")}
        </button>
      </section>

      <section className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
        <label htmlFor="setting-group" className="text-xs text-zinc-400">{t("groups.group")}</label>
        <select
          id="setting-group"
          value={settingGroup}
          onChange={(event) => setSettingGroup(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          <option value="">{t("groups.chooseGroup")}</option>
          {groups.map((group) => (
            <option key={group.name} value={group.name}>{group.name}</option>
          ))}
        </select>
        <label htmlFor="setting-keyword" className="text-xs text-zinc-400">{t("groups.directive")}</label>
        <input
          id="setting-keyword"
          value={settingKeyword}
          onChange={(event) => setSettingKeyword(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="setting-value" className="text-xs text-zinc-400">{t("groups.value")}</label>
        <input
          id="setting-value"
          value={settingValue}
          onChange={(event) => setSettingValue(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <button type="button" onClick={addSetting} className="self-start rounded bg-zinc-800 px-3 py-1 text-sm">
          {t("groups.addSetting")}
        </button>
      </section>

      <div className="flex gap-2">
        <button type="button" onClick={() => void run("preview")} className="rounded border border-zinc-700 px-3 py-1 text-sm">
          {t("groups.previewChanges")}
        </button>
        <button type="button" onClick={() => void run("save")} className="rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900">
          {t("groups.save")}
        </button>
      </div>

      <SavePreviewPanel preview={preview} conflict={problem?.conflict ?? null} problem={problem} />
    </div>
  );
}
