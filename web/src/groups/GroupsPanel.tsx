import { useCallback, useEffect, useState } from "react";
import { ApiError, type Problem } from "../api/client";
import { configApi, type GroupMetadata, type Metadata, type Overview, type SavePreview } from "../api/config";
import { NoticeList, SavePreviewPanel } from "../connections/SavePreview";
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
import { Notice } from "../ui/surface";
import type { InspectorContent } from "../ui/Inspector";
import { GroupInspector } from "./GroupInspector";
import { MetricCard, MetricGrid, PageHeader } from "../ui/page";

function toProblem(error: unknown): Problem {
  if (error instanceof ApiError && error.problem !== null) return error.problem;
  if (error instanceof ApiError) return { code: error.code, message: "request rejected" };
  return { code: "request_failed", message: "request rejected" };
}

// depthOf はグループ名の中のディレクトリの数を数える。名前が階層を
// 運ぶため、ツリーを描くのに他の何かを参照する必要はなく、
// 親フィールドがファイルの実際の位置と食い違うことは決してない。
export function depthOf(name: string): number {
  return name.split("/").length;
}

// treeOrder は親をその子の前に置き、兄弟を display order で並べる。
// ツリーとはそう読めるべきものである。
//
// これは意図的に Include 行の順序とは違う。OpenSSH は最初に読んだ
// 値を保つため、ディスク上では最も深いグループが先に来なければ、親の
// 設定が自分の子のものに勝ってしまう。このパネルは以前その
// 順序を画面でも使っており、すべての子が親の上に浮かび親が
// 最後に来ていた——結果はネストがまるで機能していないかのように読めていた。
export function treeOrder(groups: GroupMetadata[]): GroupMetadata[] {
  const orderOf = new Map(groups.map((group) => [group.name, group.order ?? 0]));
  // key は各祖先の display order を自分自身のセグメントと交互に並べる。
  // これにより二つの兄弟は、先頭の文字ではなく、パスが実際に分岐する
  // 階層で order と名前によって比較される。
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
    // 一方の名前がもう一方の接頭辞であれば、それは祖先であり先に来る。
    return leftKey.length - rightKey.length;
  });
}

// グループ名は相対的なディレクトリパスであるため、パネルはサーバーも
// 拒否するものをローカルに拒否する。ここでも行うのは重複のための
// 重複ではない。"invalid_request"としか言わない往復通信の前に、
// パネルがどの文字が間違っているかを言えるようにするためである。
const segmentPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function isValidGroupName(name: string): boolean {
  const segments = name.split("/");
  if (segments.length === 0 || segments.length > 6) return false;
  const reserved = new Set(["sshc", "config", "known_hosts", "authorized_keys", "connections", "keys"]);
  return segments.every(
    (segment) => segmentPattern.test(segment) && !reserved.has(segment.toLowerCase()),
  );
}

type GroupsPanelProps = {
  // インスペクターの中身を、シェルへ差し出す——接続画面が使うのと
  // 同じ配置である。テストで単独でレンダリングされるパネルは何も渡さず、
  // 単にペインを持たないだけである。
  onInspector?: (content: InspectorContent) => void;
};

export function GroupsPanel({ onInspector }: GroupsPanelProps = {}) {
  const t = useTranslate();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [metadata, setMetadata] = useState<Metadata | null>(null);
  const [preview, setPreview] = useState<SavePreview | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [newName, setNewName] = useState("");
  const [settingKeyword, setSettingKeyword] = useState("");
  const [settingValue, setSettingValue] = useState("");
  const [renaming, setRenaming] = useState<Record<string, string>>({});
  const [removing, setRemoving] = useState<Record<string, string>>({});
  const [confirmingRemove, setConfirmingRemove] = useState<Record<string, boolean>>({});
  const [localError, setLocalError] = useState("");
  // インスペクターがどのグループを記述しているか。行が選ばれるまで何も
  // 選択されていないため、開いたばかりの画面ではペインは提示されない。
  const [selected, setSelected] = useState("");

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

  // ペインは選択されたグループに追従する。これが early return より上に
  // あるのは hook がそうしなければならないからである。draft と
  // 射影はここで防御的に読まれ、下の定数からではない。
  // 定数は表示するものがあって初めて存在するからである。
  useEffect(() => {
    if (onInspector === undefined) return;
    const group = (metadata?.groups ?? []).find((candidate) => candidate.name === selected);
    if (group === undefined) {
      onInspector(null);
      return;
    }
    onInspector({
      // ディレクトリのない宣言、あるいは何も宣言しないディレクトリはドットに
      // 値する。空のグループはそうではない——それは作られた直後の
      // すべてのグループが置かれる状態である。
      attention: (overview?.notices ?? []).some(
        (notice) =>
          notice.detail === group.name &&
          ["group_not_declared", "group_directory_missing"].includes(notice.code),
      ),
      body: (
        <GroupInspector
          group={group}
          members={(overview?.hosts ?? [])
            .filter((host) => host.group === group.name)
            .map((host) => host.identity.alias)}
          onUpdate={(patch) => updateGroup(group.name, patch)}
        />
      ),
    });
    // updateGroup は draft を閉じ込め、それはメタデータと共に変わる。
    // 本体はメモ化されるのではなくそれと共に再構築されるため、ペインが
    // 古びたドキュメントを編集することは決してない。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, metadata, overview, onInspector]);

  if (overview === null || metadata === null) {
    return <p role="status" className="text-sm text-ink-muted">{t("groups.loading")}</p>;
  }

  // ホイストされた関数宣言は上の絞り込みを引き継がないため、
  // 読み込まれたドキュメントはクロージャが使える non-null な const として一度だけ捕捉する。
  const loaded: Metadata = metadata;
  const hosts = overview.hosts;
  const groups = treeOrder(loaded.groups ?? []);

  // このパネルには二種類のコントロールがあり、以前はその違いを何も
  // 示していなかった。Colour、display order、新しいグループ、新しい
  // 設定は Save して初めてディスクに届く draft への編集であり、名前変更
  // と削除は押した瞬間にファイルを書き込む。そのためグループは追加され、
  // 色を付けられ、設定を与えられた末に、離れることで失われ得た
  // ——その隣の Remove ボタンは、その間ずっとディスクへコミットし続けていたにもかかわらず。
  //
  // draft はサーバーが最後に返したものと比較される。それが「まだ
  // 書き込まれていない」ことについての唯一の正直な由来である。
  // `group_empty`は意図的にその中に含まれていない。
  //
  // 何も入っていない宣言済みグループは不具合ではない。それは作られた
  // 直後、そして最後の接続が出て行ったときに、すべてのグループが
  // 置かれる状態である。OpenSSH は一致するファイルのない Include があっても
  // 困らない。それを、ディレクトリのない宣言と何も宣言しないディレクトリ
  // という二つの本物の不具合の隣にアンバーで報告することは、何かが
  // 起きたことを意味するはずの colour を、何も起きていないことに
  // 費やしてしまう。この空虚さは、落とすことでも隠されてはいなかった。各グループの行は既に
  // "Members: none"と読めており、通知はそれをアンバーでもう一度言っていただけだった。
  const groupNotices = (overview.notices ?? []).filter((notice) =>
    ["group_not_declared", "group_directory_missing"].includes(notice.code),
  );
  const savedGroups = new Set((overview.metadata.groups ?? []).map((group) => group.name));
  const unsaved = JSON.stringify(loaded) !== JSON.stringify(overview.metadata);

  // 所属はファイルが置かれている場所であり、射影は既にそれを
  // パスから読み取っている。ここでメタデータフィールドを数えるものは何もない。
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

  // グループは選択されたものである。以前はこれが、既にすべてのグループを
  // 列挙しているページ上の三つ目のピッカーだった。
  function addSetting() {
    if (selected === "" || settingKeyword === "") {
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
        group.name === selected
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

  // グループはディレクトリであるため、名前変更は N 個のファイル移動に加え
  // Include 領域、さらにその鍵を名指すすべての IdentityFile に及ぶ
  // ——クライアントには組み立てられない一つのトランザクションである。これは
  // サーバー操作であり即座に適用される。このパネルが保持するドキュメントへの編集ではない。
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
      // 既存のグループへ名前変更することは二組の設定をマージすることに
      // なるが、ここには誰もどちらが勝つべきか知らない。サーバーもそれを拒否する。
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
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader title={t("groups.pageTitle")} description={t("groups.pageDescription")} />
      <MetricGrid>
        <MetricCard label={t("groups.metricGroups")} value={groups.length} />
        <MetricCard
          label={t("groups.metricConnections")}
          value={hosts.filter((host) => host.identity.alias !== "").length}
        />
        <MetricCard label={t("groups.metricDraft")} value={unsaved ? 1 : 0} attention={unsaved} />
      </MetricGrid>
      <details className="rounded-xl border border-line bg-card p-4">
        <summary className="cursor-pointer text-sm font-medium text-ink">{t("groups.howItWorks")}</summary>
        <div className="mt-3 border-t border-line pt-3">
          <p className="text-sm text-ink-muted">
            {t("groups.directoryNote", { connections: "connections", keys: "keys" })}
          </p>
          <p className="mt-1 text-xs text-ink-muted">
            {t("groups.compileNote", { file: loaded.groupsFile ?? "groups.sshc.conf" })}
          </p>
          <p className="mt-1 text-xs text-ink-faint">{t("groups.orderNote")}</p>
        </div>
      </details>
      {localError === "" ? null : <Notice tone="danger">{localError}</Notice>}
      {/*
        宣言とディスクが互いについて何を語るか。connections/下にあり、
        どの Include も名指さないディレクトリは、何よりもここで示す
        価値があるものである。グループのように見えるが、その中身は
        一度も読まれない。
      */}
      <NoticeList notices={groupNotices} />

      {groups.length === 0 ? (
        <p className="rounded-xl border border-line bg-card p-5 text-sm text-ink-muted">{t("groups.empty")}</p>
      ) : null}
      <ul aria-label={t("groups.listLabel")} className="flex flex-col gap-3">
        {groups.map((group) => (
          <li
            key={group.name}
            // グループを選択することがインスペクターを満たす。そのため行は、
            // 接続ツリーと同じ方法でどれが開いているかを示す。
            onFocus={() => setSelected(group.name)}
            onClick={() => setSelected(group.name)}
            className={`rounded-xl border bg-card p-4 transition-colors ${
              selected === group.name ? "border-control-line bg-select-fill shadow-sm" : "border-line hover:bg-select-fill"
            }`}
            style={{ marginInlineStart: `${(depthOf(group.name) - 1) * 1.5}rem` }}
          >
            {/*
              グループが*何であるか*——その名前、色、ファイルがどこにあり
              誰がいるか——がヘッダーである。それを変えるものはすべて
              罫線の下にある。この二つは以前、グループ一つにつき六つの
              ラベル付きの箱を無差別に積んだ一つのスタックであり、四つの
              グループに対しては事実がコントロールに埋もれたページになっていた。

              見出しは依然として完全なパスであり、スクリーンリーダーと
              その横の名前変更ボタンにとって、グループの唯一の名前であり
              続ける。祖先の部分だけが薄く表示され、それが二つ目の
              識別子を作ることなくツリーを読みやすくしている。
            */}
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <h3 className="flex items-baseline gap-2 text-sm font-medium">
                <span
                  aria-hidden="true"
                  className="h-2 w-2 shrink-0 self-center rounded-full"
                  style={{ backgroundColor: group.colour === undefined || group.colour === "" ? "var(--ui-ink-faint)" : group.colour }}
                />
                {depthOf(group.name) === 1 ? null : (
                  <span className="text-ink-faint">{group.name.slice(0, group.name.lastIndexOf("/") + 1)}</span>
                )}
                <span>{group.name.slice(group.name.lastIndexOf("/") + 1)}</span>
              </h3>
              {/*
                見出しの外側に。内側に置くとバッジが見出しの
                アクセシブルネームと区切りなしに結合してしまう——
                "labNot saved"——隣接する要素は連結されるからである。
                見出しはグループの名前であり、それ以外の何ものでもない。
              */}
              {savedGroups.has(group.name) ? null : (
                <span className="rounded border border-notice-line px-1.5 py-0.5 text-[10px] font-normal text-notice-ink">
                  {t("groups.unsaved")}
                </span>
              )}
              <p className="font-mono text-xs text-ink-faint">
                {t("groups.directories", {
                  connections: `connections/${group.name}`,
                  keys: `keys/${group.name}`,
                })}
              </p>
              {/*
                Colour、display order、hiding は、このアプリケー
                ションにとってグループがどう見えるかであり、それ以外
                の何ものでもない——これらはどの設定ファイル
                にもなく metadata.json にある——そのためインスペクターに
                ある。接続の colour と tags が行った先と同じ場所
                である。行に残るのは、グループが*何であるか*である。
              */}
            </div>
            <p className="mt-1 text-xs text-ink-muted">
              {t("groups.members")}{" "}
              <span>{membersOf(group.name).length === 0 ? t("groups.noMembers") : membersOf(group.name).join(", ")}</span>
            </p>
            {/*
              空の設定一覧でも<ul>はレンダリングされていたため、
              すべてのグループが誰も求めていない空の行を運んでいた。
            */}
            {(group.settings ?? []).length === 0 ? null : (
              <ul className="mt-2 flex flex-col gap-0.5 font-mono text-xs text-ink-muted">
                {(group.settings ?? []).map((setting, index) => (
                  <li key={`${setting.keyword}-${index}`}>{`${setting.keyword} ${formatValues(setting.values)}`}</li>
                ))}
              </ul>
            )}

            {/*
              選択したグループに対してのみ。これら三つはファイルを書き
              換える操作であり、すべてのグループがそれぞれ自分自身の
              コピーを持てば、コントロールが事実を四対一で上回るページに
              なる——それがこの画面を壁のように読ませていた原因である。
            */}
            {selected !== group.name ? null : (
            <div className="mt-3 flex flex-wrap items-end gap-x-4 gap-y-3 border-t border-line pt-3">
              {/*
                目に見えるキャプションは短く、グループの名前は代わりに
                アクセシブルネームに宿る。画面に全て書き出せば、四つの
                グループが"Rename <name> to"と"Move the connections of
                <name> into"を合わせて八回繰り返すことになり、それが
                このパネルを言葉の壁にしていたことの大半である。目に
                見えるテキストは依然としてアクセシブルネームの部分文字列で
                あるため、両者が食い違うことは決してない。
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
                以前、宛先は名前変更ボタンと削除ボタンの間に単独で
                座るプルダウンであり、"Move connections to"とだけ
                ラベルされていた。画面上の何もそれを削除に結び付けて
                おらず、静かに何もしない三つ目の独立したアクションの
                ように読め、ユーザーはもっともなことに、それが何のため
                のものか尋ねた。

                今ではそれは削除の中、削除が実際に何をするかを
                述べる一文の後に置かれている——宣言が消え、接続
                が移動し、ファイルは削除されない。その問いは、それが答え
                られる瞬間に問われる。
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
                ネストは以前、ページ下部のテキストボックスの下にある
                スラッシュについての一文を通してしか発見できなかった。
                これはそれをグループがある場所に置き、ユーザーが子の
                名前だけを入力すればよいようパスを事前に入力する。
              */}
              <button
                type="button"
                onClick={() => setNewName(`${group.name}/`)}
                className={secondaryAction}
              >
                {t("groups.addChild", { name: group.name })}
              </button>
            </div>
            )}
            {savedGroups.has(group.name) ? null : (
              <p className="mt-2 text-xs text-notice-ink">{t("groups.newGroupNote")}</p>
            )}

            {confirmingRemove[group.name] !== true ? null : (
              <div
                role="group"
                aria-label={t("groups.removeInto", { name: group.name })}
                className="mt-3 flex flex-col gap-2 rounded border border-control-line bg-card/30 p-3"
              >
                <p className="text-sm text-ink">
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
                  失われないものは、失われるものと同じくらい重要
                  である。ここでそれを述べることが、決断と無謀な
                  賭けの違いになる。
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

      {/*
        選択したグループに絞られているため、以前ここにあったピッカー
        ——既にすべてを表示しているページ上の三つ目の"Choose a group"
        ——はなくなった。既に一つが開いている画面でどのグループかを
        尋ねることは、画面が既に答えていた問いを尋ねることだった。
      */}
      {selected === "" ? null : (
      <section className={sectionCard}>
        <h3 className={sectionHeading}>{t("groups.settingHeadingFor", { name: selected })}</h3>
        <div className="grid gap-3 sm:grid-cols-2">
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
      )}

      {/*
        このページ上のどのコントロールがいつ書き込むかは、どこにも述べ
        られていなかった。それはここで一度だけ、書き込みを行う
        ボタンの横で述べられる。
      */}
      <p className={unsaved ? "text-sm text-notice-ink" : hintText}>
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
