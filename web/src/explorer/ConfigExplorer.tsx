import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type FileContents, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

export function ConfigExplorer() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [file, setFile] = useState<FileContents | null>(null);
  const [draft, setDraft] = useState("");
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newPath, setNewPath] = useState("");

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

  async function open(path: string) {
    try {
      const loaded = await configApi.file(path);
      setFile(loaded);
      setDraft(loaded.contents);
      setPreview(null);
      setProblem(null);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function createFile() {
    if (newPath === "") return;
    const path = newPath;
    try {
      await configApi.save({ kind: "file_raw", path, base: "", raw: "# created by ssh-ui\n" });
      setNewPath("");
      setProblem(null);
      await reload();
      await open(path);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function run(action: "preview" | "save") {
    if (file === null || file.file.path === undefined) return;
    const request = {
      kind: "file_raw" as const,
      path: file.file.path,
      base: file.contents,
      raw: draft,
    };
    try {
      if (action === "preview") {
        setPreview(await configApi.preview(request));
        setProblem(null);
        return;
      }
      const result = await configApi.save(request);
      setPreview(result.preview);
      setProblem(null);
      await reload();
      await open(request.path);
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  if (overview === null) {
    return <p role="status" className="text-sm text-zinc-300">Loading configuration files…</p>;
  }

  return (
    <div className="grid grid-cols-[22rem_1fr] gap-6">
      <section aria-labelledby="explorer-heading" className="flex flex-col gap-3">
        <h3 id="explorer-heading" className="text-sm font-medium">Include hierarchy</h3>
        <ul className="flex flex-col gap-2">
          {overview.files.map((node) => (
            <li key={node.file.absolute} className="rounded border border-zinc-800 p-2">
              {node.file.path === undefined ? (
                <p className="text-sm text-zinc-400">
                  {node.file.absolute}
                  <span className="block text-xs text-amber-300">
                    This file is outside ~/.ssh. It is read and shown, never written.
                  </span>
                </p>
              ) : (
                <button
                  type="button"
                  onClick={() => void open(node.file.path ?? "")}
                  className="text-left text-sm text-zinc-200 hover:underline"
                >
                  {node.file.path}
                </button>
              )}
              <p className="text-xs text-zinc-500">
                {`${node.missing === true ? "missing · " : ""}${node.loads > 1 ? `read ${node.loads} times · ` : ""}${node.editable ? "editable" : "read only"}`}
              </p>
              {(node.includes ?? []).map((include) => (
                <div key={`${node.file.absolute}:${include.line}:${include.pattern}`} className="mt-1 text-xs text-zinc-400">
                  <span className="font-mono">{include.pattern}</span>
                  {include.condition === undefined ? null : (
                    <span className="ml-1 text-amber-300">{`inside ${include.condition}`}</span>
                  )}
                  <ul className="ml-3">
                    {(include.matches ?? []).map((match) => (
                      <li key={match.absolute} className="font-mono">
                        {`→ ${match.path ?? match.absolute}`}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </li>
          ))}
        </ul>

        <div className="flex flex-col gap-1 rounded border border-zinc-800 p-2">
          <label htmlFor="new-file-path" className="text-xs text-zinc-400">New file path</label>
          <input
            id="new-file-path"
            value={newPath}
            onChange={(event) => setNewPath(event.target.value)}
            placeholder="conf.d/30-lab.conf"
            className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
          />
          <button type="button" onClick={() => void createFile()} className="self-start rounded bg-zinc-800 px-2 py-1 text-xs">
            Create file
          </button>
          <p className="text-xs text-zinc-500">
            A new file is only read once an Include in ~/.ssh/config points at it. Add that line in the entry file
            below. Moving, renaming and deleting files needs journalled delete and rename primitives this version does
            not have yet.
          </p>
        </div>

        <h3 className="text-sm font-medium">Diagnostics</h3>
        {overview.diagnostics.length === 0 ? (
          <p className="text-xs text-zinc-500">No Include problem detected.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {overview.diagnostics.map((diagnostic, index) => (
              <li
                key={`${diagnostic.code}-${index}`}
                className={`text-xs ${diagnostic.severity === "error" ? "text-rose-300" : diagnostic.severity === "warning" ? "text-amber-300" : "text-zinc-400"}`}
              >
                {`${diagnostic.code} ${diagnostic.path ?? diagnostic.absolute ?? ""}${diagnostic.line === undefined ? "" : `:${diagnostic.line}`} ${diagnostic.detail ?? ""}`}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-3">
        {file === null ? (
          <p role="status" className="text-sm text-zinc-400">Select a file to edit its full text.</p>
        ) : (
          <div className="flex flex-col gap-2">
            <label htmlFor="file-raw" className="text-xs text-zinc-400">
              {`File text — ${file.file.path ?? file.file.absolute}. Every byte is written back exactly as typed.`}
            </label>
            <textarea
              id="file-raw"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              rows={24}
              spellCheck={false}
              disabled={!file.editable}
              className="rounded border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs"
            />
            <div className="flex gap-2">
              <button type="button" onClick={() => void run("preview")} className="rounded border border-zinc-700 px-3 py-1 text-sm">
                Preview
              </button>
              <button
                type="button"
                onClick={() => void run("save")}
                disabled={!file.editable}
                className="rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900 disabled:bg-zinc-700 disabled:text-zinc-400"
              >
                Save file
              </button>
            </div>
          </div>
        )}
        <SavePreviewPanel preview={preview} conflict={problem?.conflict ?? null} problem={problem} />
      </section>
    </div>
  );
}
