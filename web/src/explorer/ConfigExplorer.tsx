import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslate } from "../i18n/context";
import { ApiError, type Problem } from "../api/client";
import { configApi, type FileContents, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";
import {
  control,
  fieldLabel,
  hintText,
  primaryAction,
  secondaryAction,
  sectionHeading,
} from "../ui/form";

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
  const [renameTo, setRenameTo] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
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
      setRenameTo("");
      setConfirmingDelete(false);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  // Renaming and deleting are file operations, not edits, so they send the
  // bytes that were read as the precondition rather than the draft. A draft
  // that has not been saved is not what is on disk, and moving a file on the
  // strength of it would move something the user never looked at.
  async function renameFile() {
    if (file === null || file.file.path === undefined || renameTo === "") return;
    try {
      const result = await configApi.save({
        kind: "file_rename",
        path: file.file.path,
        base: file.contents,
        destinationPath: renameTo,
      });
      setPreview(result.preview);
      setProblem(null);
      setRenameTo("");
      await reload();
      await open(renameTo);
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }

  async function deleteFile() {
    if (file === null || file.file.path === undefined) return;
    try {
      const result = await configApi.save({
        kind: "file_delete",
        path: file.file.path,
        base: file.contents,
      });
      setPreview(result.preview);
      setProblem(null);
      setConfirmingDelete(false);
      setFile(null);
      setDraft("");
      await reload();
    } catch (error) {
      setPreview(null);
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

  const openPath = file?.file.path ?? file?.file.absolute ?? "";
  const modified = file !== null && draft !== file.contents;

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[22rem_1fr]">
      <section aria-labelledby="explorer-heading" className="flex flex-col gap-3">
        <h3 id="explorer-heading" className={sectionHeading}>{t("explorer.hierarchy")}</h3>
        <ul className="flex flex-col gap-2">
          {overview.files.map((node) => {
            // Which file the editor is showing was not marked anywhere. With
            // several files of similar names in the list, the only way to tell
            // was to read the label above the text box.
            const current = (node.file.path ?? node.file.absolute) === openPath;
            return (
              <li
                key={node.file.absolute}
                className={`rounded border p-2 ${current ? "border-zinc-500 bg-zinc-900" : "border-zinc-800"}`}
              >
                {node.file.path === undefined ? (
                  <p className="text-sm text-zinc-400">
                    <span className="font-mono text-xs">{node.file.absolute}</span>
                    <span className="block text-xs text-amber-300">
                      {t("explorer.externalFile")}
                    </span>
                  </p>
                ) : (
                  <button
                    type="button"
                    aria-current={current ? "true" : "false"}
                    onClick={() => void open(node.file.path ?? "")}
                    className={`text-left font-mono text-sm hover:underline ${current ? "text-zinc-50" : "text-zinc-200"}`}
                  >
                    {node.file.path}
                  </button>
                )}
                <p className={hintText}>
                  {t("explorer.fileState", {
                    missing: node.missing === true ? t("explorer.missing") : "",
                    loads: node.loads > 1 ? t("explorer.readTimes", { count: node.loads }) : "",
                    editable: node.editable ? t("explorer.editable") : t("explorer.readOnly"),
                  })}
                </p>
                {(node.includes ?? []).map((include) => (
                  <div key={`${node.file.absolute}:${include.line}:${include.pattern}`} className="mt-1 text-xs text-zinc-400">
                    <span className="font-mono">{include.pattern}</span>
                    {/*
                      This was the one string on the screen that was never
                      translated: an English "inside …" in the middle of a
                      Japanese panel.
                    */}
                    {include.condition === undefined ? null : (
                      <span className="ml-1 text-amber-300">
                        {t("explorer.insideCondition", { condition: include.condition })}
                      </span>
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
            );
          })}
        </ul>

        <div className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
          <label htmlFor="new-file-path" className={fieldLabel}>{t("explorer.newFilePath")}</label>
          <input
            id="new-file-path"
            value={newPath}
            onChange={(event) => setNewPath(event.target.value)}
            placeholder="conf.d/30-lab.conf"
            className={control}
          />
          {/*
            The button used to be live with an empty box and the handler
            returned without doing anything, so the click was a no-op the
            interface had promised would work.
          */}
          <button
            type="button"
            onClick={() => void createFile()}
            disabled={newPath === ""}
            className={`self-start ${secondaryAction}`}
          >
            {t("explorer.createFile")}
          </button>
          <p className={hintText}>{t("explorer.newFileNote")}</p>
        </div>

        <h3 className={sectionHeading}>{t("explorer.diagnostics")}</h3>
        {overview.diagnostics.length === 0 ? (
          <p className={hintText}>{t("explorer.noIncludeProblem")}</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {overview.diagnostics.map((diagnostic, index) => (
              <li
                key={`${diagnostic.code}-${index}`}
                className={`font-mono text-xs ${diagnostic.severity === "error" ? "text-rose-300" : diagnostic.severity === "warning" ? "text-amber-300" : "text-zinc-400"}`}
              >
                {`${diagnostic.code} ${diagnostic.path ?? diagnostic.absolute ?? ""}${diagnostic.line === undefined ? "" : `:${diagnostic.line}`} ${diagnostic.detail ?? ""}`}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <p aria-live="polite" className={hintText}>{jump}</p>
        {file === null ? (
          <p role="status" className="text-sm text-zinc-400">{t("explorer.selectFile")}</p>
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex items-baseline justify-between gap-2">
              <label htmlFor="file-raw" className={fieldLabel}>
                {t("explorer.fileText", { path: file.file.path ?? file.file.absolute })}
              </label>
              {/*
                Opening another file replaces the draft without asking. Saying
                the draft differs from what was read is the least this can do
                before that happens.
              */}
              {modified ? <span className="text-xs text-amber-300">{t("explorer.unsaved")}</span> : null}
            </div>
            <textarea
              id="file-raw"
              ref={editorRef}
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              rows={24}
              spellCheck={false}
              disabled={!file.editable}
              className="w-full resize-y rounded border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs text-zinc-100 focus:border-zinc-400 focus:outline-none disabled:border-zinc-800 disabled:text-zinc-500"
            />
            <div className="flex gap-2">
              <button type="button" onClick={() => void run("preview")} className={secondaryAction}>
                {t("explorer.preview")}
              </button>
              <button
                type="button"
                onClick={() => void run("save")}
                disabled={!file.editable}
                className={primaryAction}
              >
                {t("explorer.saveFile")}
              </button>
            </div>

            {file.file.path === undefined || !file.editable ? null : (
              <div className="flex flex-col gap-2 rounded border border-zinc-800 p-3">
                <h4 className={sectionHeading}>{t("explorer.fileOperations")}</h4>
                {/*
                  The Include lines that name this file travel with it. That is
                  the whole reason to do this here rather than with mv: a file
                  moved out from under its Include still parses and quietly
                  stops applying.
                */}
                <p className={hintText}>{t("explorer.fileOperationsNote")}</p>
                <label htmlFor="rename-file-path" className={fieldLabel}>{t("explorer.renameTo")}</label>
                <input
                  id="rename-file-path"
                  value={renameTo}
                  onChange={(event) => setRenameTo(event.target.value)}
                  placeholder={file.file.path}
                  className={control}
                />
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => void renameFile()}
                    disabled={renameTo === "" || renameTo === file.file.path || modified}
                    className={secondaryAction}
                  >
                    {t("explorer.renameFile")}
                  </button>
                  {confirmingDelete ? (
                    <>
                      <button
                        type="button"
                        onClick={() => void deleteFile()}
                        className="rounded border border-rose-700 px-2 py-1 text-xs text-rose-200 hover:bg-rose-950"
                      >
                        {t("explorer.confirmDelete")}
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmingDelete(false)}
                        className={secondaryAction}
                      >
                        {t("explorer.cancelDelete")}
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmingDelete(true)}
                      disabled={modified}
                      className={secondaryAction}
                    >
                      {t("explorer.deleteFile")}
                    </button>
                  )}
                </div>
                {/*
                  Deleting keeps a generational backup, so History offers the
                  file back. Saying so is what makes the confirmation a
                  decision rather than a dare.
                */}
                <p className={hintText}>
                  {modified ? t("explorer.saveOrDiscardFirst") : t("explorer.deleteIsRecoverable")}
                </p>
              </div>
            )}
          </div>
        )}
        <SavePreviewPanel preview={preview} conflict={problem?.conflict ?? null} problem={problem} />
      </section>
    </div>
  );
}
