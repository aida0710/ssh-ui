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
import { HostDetailPanel } from "./HostDetail";
import { NoticeList } from "./SavePreview";
import { appendHostBlock, duplicateHostBlock, removeHostBlock } from "./blocks";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function ConnectionsPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [selection, setSelection] = useState<HostSelection | null>(null);
  const [detail, setDetail] = useState<HostDetail | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newAlias, setNewAlias] = useState("");
  const [targetFile, setTargetFile] = useState("config");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [localError, setLocalError] = useState("");

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
    if (selection === null) return;
    let active = true;
    void configApi
      .host(selection.path, selection.alias)
      .then((loaded) => {
        if (active) {
          setDetail(loaded);
          setPreview(null);
          setProblem(null);
        }
      })
      .catch((error: unknown) => {
        if (active) setProblem(toProblem(error));
      });
    return () => {
      active = false;
    };
  }, [selection]);

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

  function onSelect(host: HostEntry) {
    if (host.identity.alias === "") return;
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
      setLocalError("A new connection needs an alias.");
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
        raw: duplicateHostBlock(detail.file.contents, detail.form.raw, selection.alias, `${selection.alias}-copy`),
      });
      setLocalError("");
    } catch {
      setLocalError("This block moved on disk. Reload the connection and try again.");
    }
  }

  async function deleteHost() {
    if (detail === null || selection === null) return;
    let raw: string;
    try {
      raw = removeHostBlock(detail.file.contents, detail.form.entry.line, detail.form.raw);
    } catch {
      setLocalError("This block moved on disk. Reload the connection and try again.");
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
    return <p role="status" className="text-sm text-zinc-300">Loading connections…</p>;
  }

  return (
    <div className="grid grid-cols-[18rem_1fr] gap-6">
      <div className="flex flex-col gap-2">
        <label htmlFor="new-alias" className="text-xs text-zinc-400">New connection alias</label>
        <input
          id="new-alias"
          value={newAlias}
          onChange={(event) => setNewAlias(event.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
        />
        <label htmlFor="new-file" className="text-xs text-zinc-400">Target file</label>
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
          Create connection
        </button>
        <ConnectionTree overview={overview} selected={selection} onSelect={onSelect} />
      </div>
      <div className="flex flex-col gap-4">
        <NoticeList notices={overview.notices} />
        {detail === null ? (
          <p role="status" className="text-sm text-zinc-400">Select a connection to edit it.</p>
        ) : (
          <>
            {localError === "" ? null : <p role="alert" className="text-sm text-rose-300">{localError}</p>}
            <div className="flex gap-2">
              <button type="button" onClick={duplicateHost} className="rounded border border-zinc-700 px-2 py-1 text-xs">
                Duplicate connection
              </button>
              {confirmingDelete ? (
                <button type="button" onClick={() => void deleteHost()} className="rounded bg-rose-700 px-2 py-1 text-xs text-zinc-100">
                  Confirm delete
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmingDelete(true)}
                  className="rounded border border-rose-700 px-2 py-1 text-xs text-rose-300"
                >
                  Delete connection
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
              onMetadata={onMetadata}
            />
          </>
        )}
      </div>
    </div>
  );
}
