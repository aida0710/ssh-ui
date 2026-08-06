import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import {
  configApi,
  type EditRequest,
  type FieldEdit,
  type HostDetail,
  type HostEntry,
  type HostMetadata,
  type Metadata,
  type Overview,
  type SavePreview,
} from "../api/config";
import { ConnectionTree, type HostSelection } from "./ConnectionTree";
import type { DragPayload } from "./dragdrop";
import { HostDetailPanel } from "./HostDetail";
import { NoticeList } from "./SavePreview";
import { OrphanPanel } from "./OrphanPanel";
import { useTranslate } from "../i18n/context";
import type { InspectorContent } from "../ui/Inspector";
import { appendHostBlock, duplicateHostBlock, removeHostBlock } from "./blocks";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

type ConnectionsPageProps = {
  // Opens a configuration file in the file view at a line. The tree needs it
  // for pattern rules, which have no identity and so no host detail to open.
  onOpenFile: (path: string, line: number) => void;
  // The right-hand pane's contents, offered up to the shell. Null while no
  // connection is open: there is nothing to inspect until one is.
  onInspector: (content: InspectorContent) => void;
};

export function ConnectionsPage({ onOpenFile, onInspector }: ConnectionsPageProps) {
  const t = useTranslate();
  const [overview, setOverview] = useState<Overview | null>(null);
  // Where a connection goes when it belongs to no group. The server reports the
  // entry file rather than this page assuming it, and "config" is only the
  // fallback for the moment before the first overview arrives.
  const entryPath = overview?.entry.path ?? "config";
  const [selection, setSelection] = useState<HostSelection | null>(null);
  const [detail, setDetail] = useState<HostDetail | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newAlias, setNewAlias] = useState("");
  const [targetFile, setTargetFile] = useState("config");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [localError, setLocalError] = useState("");
  const [moveTarget, setMoveTarget] = useState("");

  const reload = useCallback(async () => {
    try {
      setOverview(await configApi.overview());
    } catch (error) {
      setProblem(toProblem(error));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Nothing to inspect until a connection is open. Task by task this becomes
  // the metadata, the notices and the inherited values; for now it is what
  // says the toggle should not be drawn.
  useEffect(() => {
    onInspector(null);
  }, [onInspector]);

  // The dependencies are the two values and not the selection object, because
  // a save reselects the host it has just written. An equal object with a new
  // identity re-ran this effect, which fetched a detail submit was already
  // fetching and, when its answer arrived, discarded the preview the save had
  // just produced. The diff of what was written was on screen for as long as
  // one request took and then vanished.
  const selectedPath = selection === null ? "" : selection.path;
  const selectedAlias = selection === null ? "" : selection.alias;
  useEffect(() => {
    if (selectedAlias === "") return;
    let active = true;
    void configApi
      .host(selectedPath, selectedAlias)
      .then((loaded) => {
        if (active) {
          setDetail(loaded);
          setProblem(null);
        }
      })
      .catch((error: unknown) => {
        if (active) setProblem(toProblem(error));
      });
    return () => {
      active = false;
    };
  }, [selectedPath, selectedAlias]);

  // reselect is false when the edit removed the host that is open, so the page
  // does not immediately ask the server for a block it just deleted.
  async function submit(request: EditRequest, reselect = true) {
    try {
      const result = await configApi.save(request);
      setPreview(result.preview);
      setProblem(null);
      await reload();
      if (reselect && selection !== null) {
        const nextAlias = request.kind === "rename" ? request.newAlias ?? selection.alias : selection.alias;
        setSelection({ path: selection.path, alias: nextAlias });
        setDetail(await configApi.host(selection.path, nextAlias));
      }
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  // The guard stays: an entry without a concrete alias has no identity, and the
  // host endpoint answers invalid_request for one. The tree never routes such a
  // block here, it routes it to the file view, but a selection without an alias
  // must never reach the server even if some future caller builds one.
  function onSelect(host: HostEntry) {
    if (host.identity.alias === "") return;
    // Choosing a different connection discards the last save's diff, because it
    // describes bytes in a block that is no longer open. A save reselects
    // through submit rather than here, and keeps its diff on screen.
    setPreview(null);
    setSelection({ path: host.identity.path, alias: host.identity.alias });
  }

  function onFieldEdits(fields: FieldEdit[]) {
    if (detail === null || selection === null) return;
    void submit({
      kind: "host_fields",
      path: selection.path,
      alias: selection.alias,
      base: detail.file.contents,
      fields,
    });
  }

  function onBlockRaw(raw: string) {
    if (detail === null || selection === null) return;
    void submit({ kind: "block_raw", path: selection.path, alias: selection.alias, base: detail.file.contents, raw });
  }

  function onRename(newName: string) {
    if (detail === null || selection === null) return;
    void submit({
      kind: "rename",
      path: selection.path,
      alias: selection.alias,
      base: detail.file.contents,
      newAlias: newName,
    });
  }

  // Moving a connection into a group is a file move, so the request names the
  // group and the server derives the destination path from it. Sending a path
  // as well would let the two disagree, which the server refuses outright.
  //
  // An empty group means "out of every group", which is not a move into a
  // directory but a move back to the entry file. That form needs the entry
  // file's bytes, so the destination is held to its own precondition the way a
  // file-to-file move is.
  async function onMoveToGroup(group: string) {
    if (detail === null) return;
    const path = detail.form.entry.file.path ?? "";
    const alias = detail.form.entry.identity.alias;
    if (group !== "") {
      void submit({ kind: "move", path, base: detail.file.contents, alias, destinationGroup: group });
      return;
    }
    try {
      const destination = await configApi.file(entryPath);
      await submit({
        kind: "move",
        path,
        base: detail.file.contents,
        alias,
        destinationPath: entryPath,
        destinationBase: destination.contents,
      }, false);
      setSelection({ path: entryPath, alias });
      setDetail(await configApi.host(entryPath, alias));
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  // A drop is one of the moves this page already performs, chosen by what was
  // dragged. Nothing new reaches the server: a connection is a move, and a
  // group changing parent is a rename to a new path.
  //
  // A dragged connection is not necessarily the selected one, so its file's
  // bytes are read here rather than taken from the open detail, and submit is
  // told not to reselect: the user dropped something, they did not ask to open
  // it.
  async function onTreeDrop(payload: DragPayload, target: string) {
    try {
      if (payload.kind === "group") {
        const base = payload.name.slice(payload.name.lastIndexOf("/") + 1);
        const result = await configApi.renameGroup(payload.name, target === "" ? base : `${target}/${base}`);
        setPreview(result.preview);
        setProblem(null);
        await reload();
        return;
      }
      const file = await configApi.file(payload.path);
      if (target !== "") {
        await submit({
          kind: "move",
          path: payload.path,
          base: file.contents,
          alias: payload.alias,
          destinationGroup: target,
        }, false);
        return;
      }
      const destination = await configApi.file(entryPath);
      await submit({
        kind: "move",
        path: payload.path,
        base: file.contents,
        alias: payload.alias,
        destinationPath: entryPath,
        destinationBase: destination.contents,
      }, false);
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  // The comment is written into the configuration file, so it goes through the
  // same base-and-precondition path as every other edit to that file.
  function onComment(comment: string) {
    if (detail === null || selection === null) return;
    void submit({
      kind: "comment",
      path: selection.path,
      alias: selection.alias,
      base: detail.file.contents,
      comment,
    });
  }

  function onMetadata(host: HostMetadata) {
    if (overview === null) return;
    const others = (overview.metadata.hosts ?? []).filter(
      (entry) => entry.identity.path !== host.identity.path || entry.identity.alias !== host.identity.alias,
    );
    const metadata: Metadata = { ...overview.metadata, hosts: [...others, host] };
    void submit({ kind: "metadata", metadata });
  }

  async function createHost() {
    if (newAlias === "") {
      setLocalError(t("conn.needsAlias"));
      return;
    }
    try {
      const current = await configApi.file(targetFile);
      await submit({
        kind: "file_raw",
        path: targetFile,
        base: current.contents,
        raw: appendHostBlock(current.contents, newAlias),
      });
      setNewAlias("");
      setLocalError("");
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  function duplicateHost() {
    if (detail === null || selection === null) return;
    try {
      void submit({
        kind: "file_raw",
        path: selection.path,
        base: detail.file.contents,
        raw: duplicateHostBlock(
          detail.file.contents,
          detail.form.raw,
          selection.alias,
          `${selection.alias}-copy`,
          detail.form.entry.line,
          detail.form.commentLines,
        ),
      });
      setLocalError("");
    } catch {
      setLocalError(t("conn.blockMoved"));
    }
  }

  // The move carries both loaded bases so the server can hold each file to its
  // own precondition. Reselection is done here rather than by submit, because
  // the host lives at a new path once the move commits.
  async function moveHost() {
    if (detail === null || selection === null || moveTarget === "") return;
    try {
      const destination = await configApi.file(moveTarget);
      const source = selection;
      await submit({
        kind: "move",
        path: source.path,
        base: detail.file.contents,
        alias: source.alias,
        destinationPath: moveTarget,
        destinationBase: destination.contents,
      }, false);
      setSelection({ path: moveTarget, alias: source.alias });
      setDetail(await configApi.host(moveTarget, source.alias));
      setMoveTarget("");
      setLocalError("");
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function deleteHost() {
    if (detail === null || selection === null) return;
    let raw: string;
    try {
      raw = removeHostBlock(
        detail.file.contents,
        detail.form.entry.line,
        detail.form.raw,
        detail.form.commentLines,
      );
    } catch {
      setLocalError(t("conn.blockMoved"));
      return;
    }
    const path = selection.path;
    const base = detail.file.contents;
    setSelection(null);
    setDetail(null);
    setConfirmingDelete(false);
    setLocalError("");
    await submit({ kind: "file_raw", path, base, raw }, false);
  }

  if (overview === null) {
    return <p role="status" className="text-sm text-zinc-300">{t("conn.loading")}</p>;
  }

  return (
    <div className="grid grid-cols-[18rem_1fr] gap-6">
      <div className="flex flex-col gap-2">
        <label htmlFor="new-alias" className="text-xs text-zinc-400">{t("conn.newAlias")}</label>
        <input
          id="new-alias"
          value={newAlias}
          onChange={(event) => setNewAlias(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="new-file" className="text-xs text-zinc-400">{t("conn.targetFile")}</label>
        <select
          id="new-file"
          value={targetFile}
          onChange={(event) => setTargetFile(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        >
          {overview.files
            .filter((node) => node.editable && node.file.path !== undefined)
            .map((node) => (
              <option key={node.file.absolute} value={node.file.path}>{node.file.path}</option>
            ))}
        </select>
        <button type="button" onClick={() => void createHost()} className="rounded bg-zinc-800 px-3 py-1 text-sm">
          {t("conn.create")}
        </button>
        <ConnectionTree
          overview={overview}
          selected={selection}
          onSelect={onSelect}
          onOpenPatternRule={onOpenFile}
          onDrop={(payload, target) => void onTreeDrop(payload, target)}
        />
      </div>
      <div className="flex flex-col gap-4">
        <NoticeList notices={overview.notices} />
        <OrphanPanel
          metadata={overview.metadata}
          hosts={overview.hosts}
          onSave={(metadata) => void submit({ kind: "metadata", metadata })}
        />
        {detail === null ? (
          <p role="status" className="text-sm text-zinc-400">{t("conn.select")}</p>
        ) : (
          <>
            {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}
            <div className="flex gap-2">
              <button type="button" onClick={duplicateHost} className="rounded border border-zinc-700 px-2 py-1 text-xs">
                {t("conn.duplicate")}
              </button>
              <label htmlFor="move-target" className="sr-only">{t("conn.moveToFile")}</label>
              <select
                id="move-target"
                value={moveTarget}
                onChange={(event) => setMoveTarget(event.target.value)}
                className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs"
              >
                <option value="">{t("conn.moveToFilePlaceholder")}</option>
                {overview.files
                  .filter((node) => node.editable && node.file.path !== undefined && node.file.path !== selection?.path)
                  .map((node) => (
                    <option key={node.file.absolute} value={node.file.path}>{node.file.path}</option>
                  ))}
              </select>
              <button type="button" onClick={() => void moveHost()} className="rounded border border-zinc-700 px-2 py-1 text-xs">
                {t("conn.move")}
              </button>
              {confirmingDelete ? (
                <button type="button" onClick={() => void deleteHost()} className="rounded bg-rose-700 px-2 py-1 text-xs text-zinc-100">
                  {t("conn.confirmDelete")}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmingDelete(true)}
                  className="rounded border border-rose-700 px-2 py-1 text-xs text-rose-300"
                >
                  {t("conn.delete")}
                </button>
              )}
            </div>
            <HostDetailPanel
              detail={detail}
              groups={overview.metadata.groups ?? []}
              preview={preview}
              problem={problem}
              onFieldEdits={onFieldEdits}
              onBlockRaw={onBlockRaw}
              onRename={onRename}
              onComment={onComment}
              onMoveToGroup={(group) => void onMoveToGroup(group)}
              onMetadata={onMetadata}
            />
          </>
        )}
      </div>
    </div>
  );
}
