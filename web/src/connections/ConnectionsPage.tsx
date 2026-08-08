import { useCallback, useEffect, useState } from "react";
import { ApiError, failureCode, type Problem } from "../api/client";
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
import { HostInspector, hostNeedsAttention } from "./HostInspector";
import { control, fieldLabel, narrowControl } from "../ui/form";
import { Button, Notice } from "../ui/surface";
import { appendHostBlock, duplicateHostBlock, removeHostBlock } from "./blocks";
import { integrationsApi, type TerminalID, type TerminalOptionsResponse } from "../api/integrations";
import { Icon } from "../ui/icons";

// Groups 画面が報告し、この画面は報告しないもの。
//
// `group_empty` がここに無いのは、もはやどこでも notice として報告
// されないからだ。宣言済みグループが何も持たない状態は、作られた直後
// のすべてのグループがある状態そのものであり、Groups 画面はその行自体
// に "Members: none" と表示している。
const groupNoticeCodes = new Set([
  "group_not_declared",
  "group_directory_missing",
  "group_empty",
  "group_directory_leftover",
]);

type TerminalOption = TerminalOptionsResponse["terminals"][number];
type TerminalApplication = TerminalOptionsResponse["applications"][number];
type CustomTerminal = NonNullable<Metadata["customTerminal"]>;

// 端末の表示名。ID は語彙であって、画面に出す名前ではない。custom だけは
// 翻訳される——それはアプリケーションの名前ではなく、選び方の名前だからだ。
const terminalNames: Record<Exclude<TerminalID, "custom">, string> = {
  terminal: "Terminal.app",
  iterm2: "iTerm2",
  kitty: "kitty",
  ghostty: "Ghostty",
  wezterm: "WezTerm",
};

// 引数は空白で区切られた語であり、シェルの文字列ではない。引用も展開もない
// ので、語の中に空白を持たせる方法は無い。
const splitArguments = (value: string) => value.split(/\s+/).filter((word) => word !== "");

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

type ConnectionsPageProps = {
  // configuration ファイルを file view で指定行から開く。ツリーはパター
  // ンルールのためにこれを必要とする——identity が無く、開くべき host detail も無いからだ。
  onOpenFile: (path: string, line: number) => void;
  // 右側ペインの中身を、シェルへ差し出す。connection が開いていない間は
  // null——何か開くまでは、調べるものが何も無いからだ。
  onInspector: (content: InspectorContent) => void;
};

export function ConnectionsPage({ onOpenFile, onInspector }: ConnectionsPageProps) {
  const t = useTranslate();
  const [overview, setOverview] = useState<Overview | null>(null);
  // どのグループにも属さない connection が向かう先。このページが決め
  // つけるのではなく、サーバーがエントリファイルを報告する。"config" は
  // 最初の overview が届くまでの、あくまで暫定のフォールバックである。
  const entryPath = overview?.entry.path ?? "config";
  // 開く先は metadata が正本である。サーバーの起動経路も同じ値を読むので、
  // ここが表示するものと実際に開くものは同じである。
  const selectedTerminal: TerminalID = overview?.metadata.terminal ?? "terminal";
  const [selection, setSelection] = useState<HostSelection | null>(null);
  const [detail, setDetail] = useState<HostDetail | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newAlias, setNewAlias] = useState("");
  // 空文字は「サーバーが報告した entry file」を意味する。entry file は通常
  // config だが、固定すると別の root を使う構成で存在しないファイルへ
  // 新規接続を書こうとしてしまう。
  const [targetFile, setTargetFile] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [localError, setLocalError] = useState("");
  const [moveTarget, setMoveTarget] = useState("");
  const [creating, setCreating] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [managing, setManaging] = useState(false);
  const [savingTerminal, setSavingTerminal] = useState(false);
  // このマシンにどの端末があるか。答えが届くまでは、選択肢を疑わない。
  // 分からないことを「無い」として見せる画面は、無いことより悪い。
  const [terminals, setTerminals] = useState<TerminalOption[]>([]);
  // custom として選べるアプリケーション。ここに出たものだけが選べる。
  const [applications, setApplications] = useState<TerminalApplication[]>([]);
  // 引数はテキストとして編集し、保存するときに語へ分ける。入力の途中に
  // ある空白で語が消えると、打っている本人には何が起きたか分からない。
  const [customArguments, setCustomArguments] = useState<string | null>(null);
  // custom を選んだが、まだ開く先を選んでいない状態。保存はされていない。
  const [pendingCustom, setPendingCustom] = useState(false);

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

  // 一覧が届く前と、届かなかったときの選択肢。語彙そのものであり、どれも
  // 見つからなかったとは言わない。
  const terminalOptions: TerminalOption[] =
    terminals.length === 0
      ? ([...Object.keys(terminalNames), "custom"] as TerminalID[]).map((id) => ({ id, installed: true }))
      : terminals;
  const custom: CustomTerminal | undefined = overview?.metadata.customTerminal;
  const customArgumentText = customArguments ?? (custom?.arguments ?? []).join(" ");

  // 画面に出す名前。custom は選ばれているアプリケーションの名前で呼ぶ。
  // 「その他のアプリ」では、開けなかったときに何が開けなかったか分からない。
  function terminalLabel(id: TerminalID): string {
    if (id !== "custom") return terminalNames[id];
    const chosen = applications.find((application) => application.path === custom?.application);
    return chosen?.name ?? custom?.application ?? t("conn.otherApplication");
  }

  // 端末の一覧は設定を変えず、何も起動しない。読み取りに失敗しても画面は
  // そのまま使えるので、ここでは何も報告しない。
  useEffect(() => {
    let active = true;
    void integrationsApi
      .terminalOptions()
      .then((options) => {
        if (!active) return;
        setTerminals(options.terminals);
        setApplications(options.applications);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  // ペインは開いている connection に追従し、開くまでは空である——背後
  // に何も無いトグルは、トグルが無いことより悪い。
  //
  // body はすべての overview とすべての detail のたびに再構築される。
  // onMetadata が他のホストのエントリを保つために overview をクロージャ
  // に取り込んでいるためだ。memo 化した body では古い metadata 文書を編集し続けてしまう。
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

  // 依存配列にしているのは selection オブジェクトではなく二つの値その
  // ものである。保存すると、たった今書き込んだホストを再選択するからだ。
  // 中身が等しくても identity が新しいオブジェクトはこの effect を再実
  // 行させてしまい、submit が既に取得中の detail を再度取得し、その答え
  // が届いた時点で、保存が直後に作ったプレビューを破棄してしまっていた。
  // 書き込んだ内容の diff は、リクエスト一回分の時間だけ画面に出て、その後消えていた。
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

  // 編集で開いているホストが削除された場合、reselect は false になる
  // ——消したばかりのブロックをサーバーへすぐに問い合わせずに済ませるためだ。
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

  // この防護は残す——具体的な alias を持たないエントリには identity が
  // 無く、host エンドポイントはそれに invalid_request を返す。ツリーは
  // そのようなブロックをここへは決してルーティングせず、ファイルビューへ送る。
  // alias の無い selection は将来の呼び出し元が作っても、サーバーへ届いてはならない。
  function onSelect(host: HostEntry) {
    if (host.identity.alias === "") return;
    // 別の connection を選ぶと、直前の保存の diff は破棄される——それは
    // もう開いていないブロックのバイトを記述しているからだ。保存はここで
    // はなく submit を通じて再選択を行い、その diff は画面に残しておく。
    setPreview(null);
    setManaging(false);
    setConfirmingDelete(false);
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

  // connection をグループへ移動するのはファイル移動であるため、リクエ
  // ストはグループ名を渡し、サーバーがそこから移動先パスを導く。パスも
  // 併せて送ってしまうと両者が食い違い得るため、サーバーはそれを即座に拒否する。
  //
  // 空のグループは「どのグループの外にも」を意味し、これはディレクト
  // リへの移動ではなくエントリファイルへ戻す移動である。この形には
  // エントリファイルのバイトが要るため、移動先はファイル間移動と同じ
  // ように、自分自身の事前条件で守られる。
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

  // ドロップは、このページが既に行っている移動のどれか一つを、ドラッ
  // グされたものに応じて選ぶだけである。サーバーに新しいものは何も届
  // かない——connection は移動であり、親が変わるグループは新しいパスへのリネームである。
  //
  // ドラッグされた connection は選択中のものとは限らないため、そのファ
  // イルのバイトは開いている detail から取るのではなくここで読む。そし
  // て submit には再選択しないよう伝える——ユーザーは何かをドロップし
  // ただけで、それを開くよう求めたわけではないからだ。
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

  // このコメントは configuration ファイルに書き込まれるため、そのファイ
  // ルへの他のあらゆる編集と同じ base と事前条件の経路を通る。
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
      const destination = targetFile || entryPath;
      const current = await configApi.file(destination);
      await submit({
        kind: "file_raw",
        path: destination,
        base: current.contents,
        raw: appendHostBlock(current.contents, newAlias),
      });
      setNewAlias("");
      setLocalError("");
      setCreating(false);
    } catch (error) {
      setProblem(toProblem(error));
    }
  }

  async function connectHost() {
    if (selection === null || launching) return;
    setLaunching(true);
    setLocalError("");
    try {
      await integrationsApi.terminalLaunch(selection.alias);
    } catch (error) {
      // 「入っていない」と「開けなかった」は別の答えである。前者は選び直すか
      // インストールすれば直り、それは画面が言えることの中でいちばん役に立つ。
      setLocalError(
        failureCode(error) === "terminal_not_installed"
          ? t("conn.terminalMissing", { terminal: terminalLabel(selectedTerminal) })
          : t("conn.launchFailed", { alias: selection.alias }),
      );
    } finally {
      setLaunching(false);
    }
  }

  async function chooseTerminal(terminal: TerminalID) {
    if (overview === null) return;
    // custom は開く先を持って初めて選択になる。アプリケーションを選ぶまでは
    // 保存せず、欄だけを出す。保存できない状態を保存しに行くと、
    // 「選んだのに戻った」だけが残る。
    if (terminal === "custom" && custom === undefined) {
      setCustomArguments("");
      setLocalError("");
      setPendingCustom(true);
      return;
    }
    setPendingCustom(false);
    await saveTerminal(terminal, terminal === "custom" ? custom : undefined);
  }

  async function saveTerminal(terminal: TerminalID, customTerminal: CustomTerminal | undefined) {
    if (overview === null) return;
    setSavingTerminal(true);
    const metadata: Metadata = { ...overview.metadata, terminal };
    if (customTerminal === undefined) delete metadata.customTerminal;
    else metadata.customTerminal = customTerminal;
    await submit({ kind: "metadata", metadata });
    setSavingTerminal(false);
  }

  // 開く先のアプリケーションを選ぶことが、custom を選ぶことである。
  async function chooseApplication(application: string) {
    if (application === "") return;
    setPendingCustom(false);
    await saveTerminal("custom", { application, arguments: splitArguments(customArgumentText) });
  }

  async function saveCustomArguments() {
    if (custom === undefined) return;
    await saveTerminal("custom", { application: custom.application, arguments: splitArguments(customArgumentText) });
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

  // この移動は読み込み済みの base を両方運び、サーバーが各ファイルをそ
  // れぞれの事前条件で守れるようにする。再選択は submit ではなくここで
  // 行う——移動がコミットされた時点で、ホストは新しいパスに存在するからだ。
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
    // ウィンドウの端まで届く二つのペインであり、padding の付いた箱に浮
    // かぶ二つの column ではない——source list と同じように、リストは
    // 自前の面、自前の border、自前のスクロールを持つ。
    //
    // detail に付けた minmax(0,…) は、inspector が開いたときに狭められる
    // ようにするためだ。素の 1fr は minmax(auto,1fr) であり、コンテンツの
    // 幅を保ち続けてしまい、ボタンをペインの下へ押し出してしまう。
    <div className="grid h-full grid-cols-[19rem_minmax(0,1fr)] grid-rows-[minmax(0,1fr)]">
      <div className="flex min-h-0 flex-col border-r border-line bg-tree">
        <div className="flex shrink-0 items-center justify-between gap-3 border-b border-line px-3 py-3">
          <div className="min-w-0">
            <h2 className="font-semibold">{t("conn.heading")}</h2>
            <p className="text-xs text-ink-muted">
              {t("conn.count", { count: overview.hosts.filter((host) => host.identity.alias !== "").length })}
            </p>
          </div>
          <Button
            kind="primary"
            className="shrink-0 px-2.5 py-1.5 text-xs"
            onClick={() => setCreating((current) => !current)}
          >
            {creating ? t("conn.cancelCreate") : t("conn.new")}
          </Button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-3">
          <ConnectionTree
            overview={overview}
            selected={selection}
            onSelect={onSelect}
            onOpenPatternRule={onOpenFile}
            onDrop={(payload, target) => void onTreeDrop(payload, target)}
          />
        </div>
        {/*
          connection を作ることは、リストの中の何かにではなくリスト自体に
          対して行う唯一の操作であり、だからこそ source list が "+" を置くの
          と同じ足元に置く——リストの上に置いて下へ押し出すのではなく。
        */}
        {creating ? <div className="flex shrink-0 flex-col gap-2 border-t border-line bg-card p-3">
          <p className="text-sm font-medium">{t("conn.new")}</p>
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
            value={targetFile || entryPath}
            onChange={(event) => setTargetFile(event.target.value)}
            className={control}
          >
            {overview.files
              .filter((node) => node.editable && node.file.path !== undefined)
              .map((node) => (
                <option key={node.file.absolute} value={node.file.path}>{node.file.path}</option>
              ))}
          </select>
          <Button kind="primary" onClick={() => void createHost()}>{t("conn.create")}</Button>
        </div> : null}
      </div>
      <div className="flex min-h-0 flex-col gap-4 overflow-y-auto p-6">
        {/*
          グループ単位の notice は Groups 画面のものであり、README にもそう
          書いてある——それらは宣言とディスクが互いについて何を語っているか
          を記述するもので、この画面が対処できることではない。ここに届いて
          いたのは、overview が運ぶすべての notice をこのリストへ渡していた
          からにすぎない。
        */}
        <NoticeList notices={overview.notices.filter((notice) => !groupNoticeCodes.has(notice.code))} />
        <OrphanPanel
          metadata={overview.metadata}
          hosts={overview.hosts}
          onSave={(metadata) => void submit({ kind: "metadata", metadata })}
        />
        {detail === null ? (
          <section className="m-auto flex max-w-sm flex-col items-center text-center" role="status">
            <span
              aria-hidden="true"
              className="mb-4 flex size-14 items-center justify-center rounded-2xl border border-line bg-card text-ink-muted shadow-sm"
            >
              <Icon name="connections" className="size-7" />
            </span>
            <h2 className="text-lg font-semibold text-ink">{t("conn.emptyHeading")}</h2>
            <p className="mt-1 text-sm leading-6 text-ink-muted">{t("conn.emptyHint")}</p>
            <Button kind="primary" className="mt-4" onClick={() => setCreating(true)}>{t("conn.createAnother")}</Button>
          </section>
        ) : (
          <>
            {localError === "" ? null : <Notice tone="danger">{localError}</Notice>}
            {terminals.some((option) => option.id === selectedTerminal && !option.installed) ? (
              <Notice>{t("conn.terminalMissing", { terminal: terminalLabel(selectedTerminal) })}</Notice>
            ) : null}
            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-line bg-card p-3 shadow-sm">
              <label className="flex items-center gap-2 text-sm text-ink-muted">
                <span>{t("conn.openWith")}</span>
                <select
                  aria-label={t("conn.openWith")}
                  value={pendingCustom ? "custom" : selectedTerminal}
                  disabled={savingTerminal}
                  onChange={(event) => void chooseTerminal(event.target.value as TerminalID)}
                  className={narrowControl}
                >
                  {/*
                    入っていない端末も一覧から消さない。これから入れる人には理由
                    の分からない欠落になり、既に選んでいる人は自分の設定が消えた
                    ように見えるからだ。開けないことは名前の横に書く。
                  */}
                  {terminalOptions.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.id === "custom" ? t("conn.otherApplication") : terminalNames[option.id]}
                      {option.installed || option.id === "custom" ? "" : ` — ${t("conn.notInstalled")}`}
                    </option>
                  ))}
                </select>
              </label>
              {/*
                開く先は、このマシンで見つかったアプリケーションの中からしか
                選べない。引数はシェルの文字列ではなく argv の語であり、
                空白で区切る以外の構文を持たない。
              */}
              {selectedTerminal === "custom" || pendingCustom ? (
                <>
                  <label className="flex items-center gap-2 text-sm text-ink-muted">
                    <span>{t("conn.application")}</span>
                    <select
                      aria-label={t("conn.application")}
                      value={custom?.application ?? ""}
                      disabled={savingTerminal}
                      onChange={(event) => void chooseApplication(event.target.value)}
                      className={narrowControl}
                    >
                      <option value="">{t("conn.chooseApplication")}</option>
                      {applications.map((application) => (
                        <option key={application.path} value={application.path}>{application.name}</option>
                      ))}
                    </select>
                  </label>
                  <label className="flex items-center gap-2 text-sm text-ink-muted">
                    <span>{t("conn.terminalArguments")}</span>
                    <input
                      aria-label={t("conn.terminalArguments")}
                      placeholder="-e"
                      value={customArgumentText}
                      disabled={savingTerminal}
                      onChange={(event) => setCustomArguments(event.target.value)}
                      onBlur={() => void saveCustomArguments()}
                      className={narrowControl}
                    />
                  </label>
                </>
              ) : null}
              <Button kind="primary" disabled={launching || savingTerminal} onClick={() => void connectHost()}>
                {launching ? t("conn.opening") : t("conn.connect")}
              </Button>
              <Button aria-expanded={managing} onClick={() => setManaging((current) => !current)}>
                {t("conn.manage")}
              </Button>
              {managing ? <div className="flex w-full flex-wrap items-center gap-2 border-t border-line pt-3">
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
                どちらの状態も danger button である——確認とは別の単語であって、
                別の種類の行為ではない。
              */}
              {confirmingDelete ? (
                <Button kind="danger" onClick={() => void deleteHost()}>{t("conn.confirmDelete")}</Button>
              ) : (
                <Button kind="danger" onClick={() => setConfirmingDelete(true)}>{t("conn.delete")}</Button>
              )}
              </div> : null}
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
            />
          </>
        )}
      </div>
    </div>
  );
}
