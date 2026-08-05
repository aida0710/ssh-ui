import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslate } from "../i18n/context";
import { ApiError, type Problem } from "../api/client";
import { configApi, type FileContents, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";

// FileTarget asks the explorer to open one file and put the caret on one line.
// The line is 1-based, as every line the API reports is.
export type FileTarget = { path: string; line: number };

type ConfigExplorerProps = {
  target?: FileTarget | null;
};

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

// lineRange is the offset span of a 1-based line inside the file text. A line
// past the end clamps to the last one, so a stale target still lands somewhere
// sensible instead of throwing.
function lineRange(contents: string, line: number): { start: number; end: number } {
  const lines = contents.split("\n");
  const index = Math.min(Math.max(line, 1), lines.length) - 1;
  const start = lines.slice(0, index).reduce((total, text) => total + text.length + 1, 0);
  return { start, end: start + (lines[index]?.length ?? 0) };
}

export function ConfigExplorer({ target = null }: ConfigExplorerProps) {
  const t = useTranslate();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [file, setFile] = useState<FileContents | null>(null);
  const [draft, setDraft] = useState("");
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newPath, setNewPath] = useState("");
  const [jump, setJump] = useState("");
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const jumped = useRef<FileTarget | null>(null);

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

  // A target arrives from another view, so the file it names has to be loaded
  // here before anything can be shown.
  useEffect(() => {
    if (target === null) return;
    void open(target.path);
  }, [target]);

  // The caret can only be placed once the loaded file is on screen. Each target
  // is applied once, so opening the same file by hand afterwards does not drag
  // the caret back.
  useEffect(() => {
    if (target === null || jumped.current === target) return;
    if (file === null || file.file.path !== target.path) return;
    const editor = editorRef.current;
    if (editor === null) return;
    jumped.current = target;
    const range = lineRange(file.contents, target.line);
    editor.focus();
    editor.setSelectionRange(range.start, range.end);
    setJump(t("explorer.opened", { path: target.path, line: target.line }));
  }, [file, target]);

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
    return <p role="status" className="text-sm text-zinc-300">{t("explorer.loading")}</p>;
  }

  return (
    <div className="grid grid-cols-[22rem_1fr] gap-6">
      <section aria-labelledby="explorer-heading" className="flex flex-col gap-3">
        <h3 id="explorer-heading" className="text-sm font-medium">{t("explorer.hierarchy")}</h3>
        <ul className="flex flex-col gap-2">
          {overview.files.map((node) => (
            <li key={node.file.absolute} className="rounded border border-zinc-800 p-2">
              {node.file.path === undefined ? (
                <p className="text-sm text-zinc-400">
                  {node.file.absolute}
                  <span className="block text-xs text-amber-300">
                    {t("explorer.externalFile")}
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
                {t("explorer.fileState", {
                  missing: node.missing === true ? t("explorer.missing") : "",
                  loads: node.loads > 1 ? t("explorer.readTimes", { count: node.loads }) : "",
                  editable: node.editable ? t("explorer.editable") : t("explorer.readOnly"),
                })}
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
          <label htmlFor="new-file-path" className="text-xs text-zinc-400">{t("explorer.newFilePath")}</label>
          <input
            id="new-file-path"
            value={newPath}
            onChange={(event) => setNewPath(event.target.value)}
            placeholder="conf.d/30-lab.conf"
            className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
          />
          <button type="button" onClick={() => void createFile()} className="self-start rounded bg-zinc-800 px-2 py-1 text-xs">
            {t("explorer.createFile")}
          </button>
          <p className="text-xs text-zinc-500">{t("explorer.newFileNote")}</p>
        </div>

        <h3 className="text-sm font-medium">{t("explorer.diagnostics")}</h3>
        {overview.diagnostics.length === 0 ? (
          <p className="text-xs text-zinc-500">{t("explorer.noIncludeProblem")}</p>
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
        <p aria-live="polite" className="text-xs text-zinc-400">{jump}</p>
        {file === null ? (
          <p role="status" className="text-sm text-zinc-400">{t("explorer.selectFile")}</p>
        ) : (
          <div className="flex flex-col gap-2">
            <label htmlFor="file-raw" className="text-xs text-zinc-400">
              {t("explorer.fileText", { path: file.file.path ?? file.file.absolute })}
            </label>
            <textarea
              id="file-raw"
              ref={editorRef}
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              rows={24}
              spellCheck={false}
              disabled={!file.editable}
              className="rounded border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs"
            />
            <div className="flex gap-2">
              <button type="button" onClick={() => void run("preview")} className="rounded border border-zinc-700 px-3 py-1 text-sm">
                {t("explorer.preview")}
              </button>
              <button
                type="button"
                onClick={() => void run("save")}
                disabled={!file.editable}
                className="rounded bg-zinc-200 px-3 py-1 text-sm text-zinc-900 disabled:bg-zinc-700 disabled:text-zinc-400"
              >
                {t("explorer.saveFile")}
              </button>
            </div>
          </div>
        )}
        <SavePreviewPanel preview={preview} conflict={problem?.conflict ?? null} problem={problem} />
      </section>
    </div>
  );
}
