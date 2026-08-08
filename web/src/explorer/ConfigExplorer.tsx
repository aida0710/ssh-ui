import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslate } from "../i18n/context";
import { ApiError, type Problem } from "../api/client";
import { configApi, type FileContents, type Overview, type SavePreview } from "../api/config";
import { SavePreviewPanel } from "../connections/SavePreview";
import {
  dangerAction,
  control,
  fieldLabel,
  hintText,
  primaryAction,
  secondaryAction,
  sectionCard,
  sectionHeading,
} from "../ui/form";
import { MetricCard, MetricGrid, PageHeader } from "../ui/page";

// FileTarget はエクスプローラに一つのファイルを開き、キャレットを一行に置くよう
// 求める。行番号は 1 始まりであり、API が報告するすべての行と同じである。
export type FileTarget = { path: string; line: number };

type ConfigExplorerProps = {
  target?: FileTarget | null;
};

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

// lineRange はファイルテキスト内の 1 始まりの行の offset 範囲である。
// 末尾を越えた行は最後の行に丸められるため、古びた target でも
// スローせず妥当な場所に落ち着く。
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
  const openRequest = useRef(0);
  const autoOpened = useRef(false);

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

  // target は別のビューから届くため、それが名指すファイルは何かを表示する
  // 前にここで読み込まなければならない。
  useEffect(() => {
    if (target === null) return;
    void open(target.path);
  }, [target]);

  // Config を開いた直後に右側を空のままにしない。entry file はこの
  // workspace の起点であり、読み取るだけなら副作用も外部接続もない。
  // 別画面から明示的な target が届いた場合は、そちらを優先する。
  useEffect(() => {
    if (autoOpened.current || target !== null || overview === null || file !== null) return;
    if (overview.entry.path === undefined) return;
    autoOpened.current = true;
    void open(overview.entry.path);
  }, [file, overview, target]);

  // キャレットは読み込んだファイルが画面に出て初めて置ける。各 target は
  // 一度だけ適用されるため、その後で同じファイルを手動で開いても
  // キャレットを引き戻すことはない。
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
    const request = ++openRequest.current;
    // 別ファイルの本文と操作欄を残したまま次の読み込みを待つと、利用者は
    // 新しいファイルを選んだつもりで古いファイルを編集できてしまう。
    setFile(null);
    setDraft("");
    try {
      const loaded = await configApi.file(path);
      // entry file の自動読み込みと手動選択が重なっても、最後に選んだ
      // ファイルだけを採用する。遅く返った古い応答は画面を巻き戻さない。
      if (request !== openRequest.current) return;
      setFile(loaded);
      setDraft(loaded.contents);
      setPreview(null);
      setProblem(null);
      setRenameTo("");
      setConfirmingDelete(false);
    } catch (error) {
      if (request !== openRequest.current) return;
      setProblem(toProblem(error));
    }
  }

  // 名前変更と削除は編集ではなくファイル操作であるため、draft ではなく
  // 読み込んだ時のバイトを事前条件として送る。保存されていない
  // draft はディスク上のものではなく、それを根拠にファイルを移動すれば、
  // ユーザーが一度も見ていないものを移動してしまう。
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
      await configApi.save({ kind: "file_raw", path, base: "", raw: "# created by sshc\n" });
      setNewPath("");
      setProblem(null);
      await reload();
      await open(path);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  // ディレクトリもここで作成・削除する。ディレクトリはファイルが行く場所で
  // あり、エクスプローラはファイルが住む場所だからである。どちらもグループを
  // 宣言しない。それはエントリファイルの生成領域を変えることであり、
  // Groups 画面に属する。そしてサーバーは生成された Include が名指すディレクトリを拒否する。
  async function createDirectory() {
    if (newPath === "") return;
    try {
      await configApi.save({ kind: "directory_create", path: newPath });
      setNewPath("");
      setProblem(null);
      await reload();
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function deleteDirectory() {
    if (newPath === "") return;
    try {
      await configApi.save({ kind: "directory_delete", path: newPath });
      setNewPath("");
      setProblem(null);
      await reload();
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
    return <p role="status" className="text-sm text-ink-muted">{t("explorer.loading")}</p>;
  }

  const openPath = file?.file.path ?? file?.file.absolute ?? "";
  const modified = file !== null && draft !== file.contents;
  const editableFiles = overview.files.filter((node) => node.editable).length;

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader title={t("explorer.pageTitle")} description={t("explorer.pageDescription")} />
      <MetricGrid>
        <MetricCard label={t("explorer.metricFiles")} value={overview.files.length} />
        <MetricCard label={t("explorer.metricEditable")} value={editableFiles} />
        <MetricCard
          label={t("explorer.metricDiagnostics")}
          value={overview.diagnostics.length}
          attention={overview.diagnostics.length > 0}
        />
      </MetricGrid>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[20rem_minmax(0,1fr)]">
      <section aria-labelledby="explorer-heading" className={`${sectionCard} self-start`}>
        <h3 id="explorer-heading" className={sectionHeading}>{t("explorer.hierarchy")}</h3>
        <ul className="flex flex-col gap-2">
          {overview.files.map((node) => {
            // エディタがどのファイルを表示しているかは、どこにも印がなかった。
            // リストに似た名前のファイルが複数あると、それを知る唯一の方法は
            // テキストボックス上のラベルを読むことだった。
            const current = (node.file.path ?? node.file.absolute) === openPath;
            return (
              <li
                key={node.file.absolute}
                className={`rounded border p-2 ${current ? "border-control-line bg-control" : "border-line"}`}
              >
                {node.file.path === undefined ? (
                  <p className="text-sm text-ink-muted">
                    <span className="font-mono text-xs">{node.file.absolute}</span>
                    <span className="block text-xs text-notice-ink">
                      {t("explorer.externalFile")}
                    </span>
                  </p>
                ) : (
                  <button
                    type="button"
                    aria-current={current ? "true" : "false"}
                    onClick={() => void open(node.file.path ?? "")}
                    className={`text-left font-mono text-sm hover:underline ${current ? "font-semibold text-ink" : "text-ink-muted"}`}
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
                  <div key={`${node.file.absolute}:${include.line}:${include.pattern}`} className="mt-1 text-xs text-ink-muted">
                    <span className="font-mono">{include.pattern}</span>
                    {/*
                      これは画面上で一度も翻訳されなかった唯一の
                      文字列だった。日本語のパネルの真ん中に英語の
                      "inside …"。
                    */}
                    {include.condition === undefined ? null : (
                      <span className="ml-1 text-notice-ink">
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

        <div className="flex flex-col gap-2 rounded-lg border border-line bg-canvas p-3">
          <h3 className={sectionHeading}>{t("explorer.workspaceActions")}</h3>
          <label htmlFor="new-file-path" className={fieldLabel}>{t("explorer.newFilePath")}</label>
          <input
            id="new-file-path"
            value={newPath}
            onChange={(event) => setNewPath(event.target.value)}
            placeholder="conf.d/30-lab.conf"
            className={control}
          />
          {/*
            以前はボタンが空の箱でも有効であり、ハンドラは何もせずに
            戻っていた。そのためクリックは、インターフェースが動くと約束して
            いたはずの no-op だった。
          */}
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void createFile()}
              disabled={newPath === ""}
              className={secondaryAction}
            >
              {t("explorer.createFile")}
            </button>
            <button
              type="button"
              onClick={() => void createDirectory()}
              disabled={newPath === ""}
              className={secondaryAction}
            >
              {t("explorer.createDirectory")}
            </button>
            <button
              type="button"
              onClick={() => void deleteDirectory()}
              disabled={newPath === ""}
              className={dangerAction}
            >
              {t("explorer.deleteDirectory")}
            </button>
          </div>
          <p className={hintText}>{t("explorer.newFileNote")}</p>
          <details className="text-xs text-ink-muted">
            <summary className="cursor-pointer text-ink">{t("explorer.directoryHelp")}</summary>
            <p className="mt-2 leading-5">{t("explorer.directoryNote")}</p>
          </details>
        </div>

        <h3 className={sectionHeading}>{t("explorer.diagnostics")}</h3>
        {overview.diagnostics.length === 0 ? (
          <p className={hintText}>{t("explorer.noIncludeProblem")}</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {overview.diagnostics.map((diagnostic, index) => (
              <li
                key={`${diagnostic.code}-${index}`}
                className={`font-mono text-xs ${diagnostic.severity === "error" ? "text-danger" : diagnostic.severity === "warning" ? "text-notice-ink" : "text-ink-muted"}`}
              >
                {`${diagnostic.code} ${diagnostic.path ?? diagnostic.absolute ?? ""}${diagnostic.line === undefined ? "" : `:${diagnostic.line}`} ${diagnostic.detail ?? ""}`}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-3">
        {jump === "" ? null : <p aria-live="polite" className={hintText}>{jump}</p>}
        {file === null ? (
          <div role="status" className={`${sectionCard} min-h-64 items-center justify-center text-center`}>
            <h3 className={sectionHeading}>{t("explorer.emptyHeading")}</h3>
            <p className={hintText}>{t("explorer.selectFile")}</p>
          </div>
        ) : (
          <div className={sectionCard}>
            <div className="flex items-baseline justify-between gap-2">
              <label htmlFor="file-raw" className={fieldLabel}>
                {t("explorer.fileText", { path: file.file.path ?? file.file.absolute })}
              </label>
              {/*
                別のファイルを開くと draft は尋ねられることなく置き換わる。
                draft が読み込んだものと異なると告げることは、それが
                起きる前にできる最低限のことである。
              */}
              {modified ? <span className="text-xs text-notice-ink">{t("explorer.unsaved")}</span> : null}
            </div>
            <textarea
              id="file-raw"
              ref={editorRef}
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              rows={24}
              spellCheck={false}
              disabled={!file.editable}
              className="w-full resize-y rounded border border-control-line bg-canvas p-3 font-mono text-xs text-ink focus:border-accent focus:outline-none disabled:border-line disabled:text-ink-faint"
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
              <div className="flex flex-col gap-2 rounded border border-line p-3">
                <h4 className={sectionHeading}>{t("explorer.fileOperations")}</h4>
                {/*
                  このファイルを名指す Include 行はファイルと共に移動する。
                  それこそが、mv ではなくここでこれを行う理由のすべて
                  である。Include の足元から動かされたファイルは依然として
                  パースされるが、静かに適用されなくなる。
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
                        className={dangerAction}
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
                  削除は世代バックアップを保つため、History が
                  ファイルを取り戻すことができる。そう伝えることが、
                  確認を無謀な賭けではなく決断にする。
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
    </div>
  );
}
