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
import { ConnectionTree, type Grouping, type HostSelection } from "./ConnectionTree";
import type { DragPayload } from "./dragdrop";
import { HostDetailPanel } from "./HostDetail";
import { NoticeList } from "./SavePreview";
import { OrphanPanel } from "./OrphanPanel";
import { useTranslate } from "../i18n/context";
import type { InspectorContent } from "../ui/Inspector";
import { HostInspector, hostNeedsAttention } from "./HostInspector";
import { control, fieldLabel, narrowControl } from "../ui/form";
import { Button, Notice, Segmented } from "../ui/surface";
import type { ReactNode } from "react";
import { appendHostBlock, duplicateHostBlock, removeHostBlock } from "./blocks";

// What the Groups screen reports, and this one does not.
//
// `group_empty` is not in it because it is not reported anywhere as a notice
// any more: a declared group holding nothing is the state every group is in
// the moment after it is made, and the Groups screen says "Members: none" on
// the row itself.
const groupNoticeCodes = new Set([
  "group_not_declared",
  "group_directory_missing",
  "group_empty",
  "group_directory_leftover",
]);

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
  // Controls this screen puts in the window's toolbar. Same arrangement as the
  // inspector: the shell owns the chrome, the section says what goes in it.
  onToolbar: (content: ReactNode) => void;
};

export function ConnectionsPage({ onOpenFile, onInspector, onToolbar }: ConnectionsPageProps) {
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
  // The tree's arrangement, held here rather than in the tree, because the
  // control that changes it is in the window's toolbar.
  const [grouping, setGrouping] = useState<Grouping>("groups");

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

  useEffect(() => {
    onToolbar(
      <Segmented
        label={t("tree.arrangeBy")}
        value={grouping}
        options={[
          { value: "groups", label: t("tree.byGroups") },
          { value: "files", label: t("tree.byFiles") },
        ]}
        onChange={setGrouping}
      />,
    );
  }, [grouping, onToolbar, t]);

  // The pane follows the open connection, and is empty until there is one — a
  // toggle with nothing behind it is worse than no toggle.
  //
  // The body is rebuilt on every overview as well as every detail, because
  // onMetadata closes over the overview to preserve the other hosts' entries.
  // A memoised body would keep editing a stale metadata document.
  useEffect(() => {
    if (detail === null || overview === null) {
      onInspector(null);
      return;
    }
    onInspector({
      attention: hostNeedsAttention(detail),
      body: <HostInspector detail={detail} onMetadata={onMetadata} />,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail, overview, onInspector]);

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
    return <p role="status" className="text-sm text-ink-muted">{t("conn.loading")}</p>;
  }

  return (
    // Two panes that reach the window's edges, not two columns floating in a
    // padded box: the list has its own surface, its own border and its own
    // scrolling, the way a source list does.
    //
    // minmax(0,…) on the detail so it can narrow when the inspector opens. A
    // bare 1fr is minmax(auto,1fr) and would keep its content's width, pushing
    // the buttons out under the pane.
    <div className="grid h-full grid-cols-[18rem_minmax(0,1fr)] grid-rows-[minmax(0,1fr)]">
      <div className="flex min-h-0 flex-col border-r border-line bg-tree">
        <div className="min-h-0 flex-1 overflow-y-auto p-3">
          <ConnectionTree
            overview={overview}
            selected={selection}
            onSelect={onSelect}
            onOpenPatternRule={onOpenFile}
            onDrop={(payload, target) => void onTreeDrop(payload, target)}
            grouping={grouping}
          />
        </div>
        {/*
          Making a connection is the one thing you do *to* the list rather than
          to something in it, so it sits at the list's foot — where a source
          list keeps its "+" — instead of above the list and pushing it down.
        */}
        <div className="flex shrink-0 flex-col gap-2 border-t border-line p-3">
          <label htmlFor="new-alias" className={fieldLabel}>{t("conn.newAlias")}</label>
          <input
            id="new-alias"
            value={newAlias}
            onChange={(event) => setNewAlias(event.target.value)}
            className={control}
          />
          <label htmlFor="new-file" className={fieldLabel}>{t("conn.targetFile")}</label>
          <select
            id="new-file"
            value={targetFile}
            onChange={(event) => setTargetFile(event.target.value)}
            className={control}
          >
            {overview.files
              .filter((node) => node.editable && node.file.path !== undefined)
              .map((node) => (
                <option key={node.file.absolute} value={node.file.path}>{node.file.path}</option>
              ))}
          </select>
          <Button onClick={() => void createHost()}>{t("conn.create")}</Button>
        </div>
      </div>
      <div className="flex min-h-0 flex-col gap-4 overflow-y-auto p-6">
        {/*
          The group-scoped notices are the Groups screen's, and the README says
          so: they describe what a declaration and the disk say about each
          other, which is not something this screen can act on. They were
          arriving here because this list was handed every notice the overview
          carried.
        */}
        <NoticeList notices={overview.notices.filter((notice) => !groupNoticeCodes.has(notice.code))} />
        <OrphanPanel
          metadata={overview.metadata}
          hosts={overview.hosts}
          onSave={(metadata) => void submit({ kind: "metadata", metadata })}
        />
        {detail === null ? (
          <p role="status" className="text-sm text-ink-muted">{t("conn.select")}</p>
        ) : (
          <>
            {localError === "" ? null : <Notice tone="danger">{localError}</Notice>}
            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={duplicateHost}>{t("conn.duplicate")}</Button>
              <label htmlFor="move-target" className="sr-only">{t("conn.moveToFile")}</label>
              <select
                id="move-target"
                value={moveTarget}
                onChange={(event) => setMoveTarget(event.target.value)}
                className={narrowControl}
              >
                <option value="">{t("conn.moveToFilePlaceholder")}</option>
                {overview.files
                  .filter((node) => node.editable && node.file.path !== undefined && node.file.path !== selection?.path)
                  .map((node) => (
                    <option key={node.file.absolute} value={node.file.path}>{node.file.path}</option>
                  ))}
              </select>
              <Button onClick={() => void moveHost()}>{t("conn.move")}</Button>
              {/*
                Both states are the danger button: the confirmation is a
                different word, not a different kind of act.
              */}
              {confirmingDelete ? (
                <Button kind="danger" onClick={() => void deleteHost()}>{t("conn.confirmDelete")}</Button>
              ) : (
                <Button kind="danger" onClick={() => setConfirmingDelete(true)}>{t("conn.delete")}</Button>
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
