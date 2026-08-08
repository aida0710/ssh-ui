import { Fragment, useMemo, useState, type DragEvent, type ReactNode } from "react";
import type { HostEntry, Overview } from "../api/config";
import { useTranslate } from "../i18n/context";
import { control } from "../ui/form";
import { canDrop, dragMimeType, type DragPayload } from "./dragdrop";
import { Segmented } from "../ui/surface";

export type HostSelection = { path: string; alias: string };

// 装飾済みの一つの connection。射影のエントリに、metadata ドキュメント
// が運ぶ表示情報を足したものである。
type Decorated = {
  host: HostEntry;
  group: string;
  tags: string[];
  favourite: boolean;
  colour: string;
  order: number;
};

// ツリー内の一つのグループ。name は宣言された完全な名前で、すべての
// コールバックとすべてのドロップターゲットがこれを使う。label はその最後の
// セグメントで、見出しに出すのはこれだけだ——残りは読み手が既に辿った経路だからである。
type GroupNode = {
  name: string;
  label: string;
  hidden: boolean;
  items: Decorated[];
  children: GroupNode[];
};

type ConnectionTreeProps = {
  overview: Overview;
  selected: HostSelection | null;
  onSelect: (host: HostEntry) => void;
  // Host 行に具体的な alias を持たないブロックには identity が無いため、
  // host エンドポイントはそれを指し示せない。ツリーは代わりにパスと行で
  // それをファイルビューへ渡す。コールバックを必須にしているのは、その
  // ような行が背後に何も持たないコントロールとして描画されることを、決して許さないためだ。
  onOpenPatternRule: (path: string, line: number) => void;
  // ドラッグした connection やグループがドロップされた先。ターゲットは
  // グループ名か、"no group" 見出しを表す空文字列のいずれかである。
  onDrop: (payload: DragPayload, target: string) => void;
};

type Grouping = "groups" | "files";

function hostLabel(host: HostEntry): string {
  return host.identity.alias === "" ? `Host ${host.patterns.join(" ")}` : host.identity.alias;
}

function matchesQuery(host: HostEntry, group: string, tags: string[], query: string): boolean {
  if (query === "") return true;
  const needle = query.toLowerCase();
  if (host.identity.alias.toLowerCase().includes(needle)) return true;
  if (host.patterns.some((pattern) => pattern.toLowerCase().includes(needle))) return true;
  if (group.toLowerCase().includes(needle)) return true;
  return tags.some((tag) => tag.toLowerCase().includes(needle));
}

export function ConnectionTree({
  overview,
  selected,
  onSelect,
  onOpenPatternRule,
  onDrop,
}: ConnectionTreeProps) {
  const t = useTranslate();
  // ツリーの並び順を表す、このコンポーネント自身の state である。これを
  // 変えるコントロールがウィンドウのツールバーにあった間は page 側の state
  // だったが、コントロールがフィルタの上に戻ってきたので、state もそれに伴って移ってきた。
  const [grouping, setGrouping] = useState<Grouping>("groups");
  const [query, setQuery] = useState("");
  const [favouritesOnly, setFavouritesOnly] = useState(false);
  // 何がドラッグされているかを、イベントから読み戻すのではなくここで
  // 保持する。dragover ハンドラは dataTransfer.types は読めても getData
  // は読めない——データはドロップされるまで保護されている——ので、
  // ターゲットはドラッグを覗いて受け入れるか判断することができず、
  // state から判断するのがその実現方法になる。dataTransfer 上のプライ
  // ベートな型は、これらのドラッグをページ外で始まったものと区別するためだけに使う。
  const [dragging, setDragging] = useState<DragPayload | null>(null);
  // 折りたたみは一時的なもので、書き残さない。永続化すると、configuration
  // を記述する設定の隣に interface の state を metadata.json へ持ち込む
  // ことになる。再読み込みで全展開されるツリーの方が、まだ安く済む誤りである。
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set());

  const groupNames = useMemo(
    () => (overview.metadata.groups ?? []).map((group) => group.name),
    [overview.metadata.groups],
  );

  function startDrag(event: DragEvent, payload: DragPayload) {
    event.dataTransfer.setData(dragMimeType, JSON.stringify(payload));
    event.dataTransfer.effectAllowed = "move";
    setDragging(payload);
  }

  // ドロップターゲットが存在するのは group で並べている間だけだ。file は
  // connection を置ける場所ではない——move API が受け取るのはグループ
  // かパスであって、ユーザーがたまたま指したファイルではないからだ。
  function accepts(target: string): boolean {
    return grouping === "groups" && dragging !== null && canDrop(dragging, target, groupNames);
  }


  const metadataByAlias = useMemo(() => {
    const index = new Map<
      string,
      { tags: string[]; favourite: boolean; colour: string; order: number }
    >();
    for (const host of overview.metadata.hosts ?? []) {
      index.set(`${host.identity.path}\u0000${host.identity.alias}`, {
        tags: host.tags ?? [],
        favourite: host.favourite === true,
        colour: host.colour ?? "",
        order: host.order ?? 0,
      });
    }
    return index;
  }, [overview.metadata.hosts]);

  // 並び順はまず order、次に configuration が与える位置による。等しい
  // キーは Array.prototype.sort がそのまま保つ。ゼロは「ファイルが置いた
  // 場所のままにする」という意味であり、手を加えていないワークスペース
  // はファイル順に読め、一つのホストを固定しても周囲の番号が振り直されることはない。
  const decorated = useMemo(
    () =>
      overview.hosts
        .map((host) => {
          const entry = metadataByAlias.get(`${host.identity.path}\u0000${host.identity.alias}`);
          return {
            host,
            // 所属はファイルが置かれているディレクトリで決まり、それはサーバーが
            // パスから既に読み取っている。metadata に発言権は無い。
            group: host.group ?? "",
            tags: entry?.tags ?? [],
            favourite: entry?.favourite ?? false,
            colour: entry?.colour ?? "",
            order: entry?.order ?? 0,
          };
        })
        .sort((left, right) => left.order - right.order),
    [overview.hosts, metadataByAlias],
  );

  const visible = decorated.filter(
    (item) => (!favouritesOnly || item.favourite) && matchesQuery(item.host, item.group, item.tags, query),
  );
  const fileSections = useMemo(
    () =>
      overview.files.map((file) => ({
        title: file.file.path ?? file.file.absolute,
        items: visible.filter((item) => item.host.file.absolute === file.file.absolute),
      })),
    [overview.files, visible],
  );

  // グループ名はそれ自体が階層である——work/eu は work の中にある——の
  // で、ツリーは宣言された名前を横に並べるのではなく、それらから組み立
  // てる。フラットに描画すると、他のグループを保持するためだけに作った
  // グループが、自分の子の空の兄弟のように見えてしまうが、実際はそうではない。
  const groupTree = useMemo(() => {
    const declared = [...(overview.metadata.groups ?? [])].sort(
      (left, right) => (left.order ?? 0) - (right.order ?? 0),
    );
    const nodes = new Map<string, GroupNode>();
    for (const group of declared) {
      nodes.set(group.name, {
        name: group.name,
        label: group.name.slice(group.name.lastIndexOf("/") + 1),
        hidden: group.hidden === true,
        items: visible.filter((item) => item.group === group.name),
        children: [],
      });
    }
    const roots: GroupNode[] = [];
    for (const group of declared) {
      const node = nodes.get(group.name);
      if (node === undefined) continue;
      // 最も近い宣言済みの祖先が親になる。祖先がすべて未宣言のグループは
      // root である——どの Include 行も名指ししないディレクトリはグループ
      // ではなく、ここで一つでっち上げてしまうと、存在しないものに対して
      // 見出しを描くことになる。
      let parent: GroupNode | undefined;
      let candidate = group.name;
      while (parent === undefined) {
        const cut = candidate.lastIndexOf("/");
        if (cut < 0) break;
        candidate = candidate.slice(0, cut);
        parent = nodes.get(candidate);
      }
      if (parent === undefined) roots.push(node);
      else parent.children.push(node);
    }
    return roots;
  }, [overview.metadata.groups, visible]);

  const ungroupedItems = useMemo(() => visible.filter((item) => item.group === ""), [visible]);

  // 行のリストは render から切り出してある。再帰的なグループレンダラー
  // と by-file ビューが、二つのコピーではなく同じ一つのものを描くためだ。
  function renderItems(items: Decorated[]) {
    return (
            <ul>
              {items.map((item) => {
                const active =
                  selected !== null &&
                  selected.path === item.host.identity.path &&
                  selected.alias === item.host.identity.alias;
                const descriptionId = `host-${item.host.file.absolute}-${item.host.line}-description`;
                // パターンルールはファイルと行によってのみ指し示せる。しかもそれは
                // そのファイルが root の内側にある場合に限られる——外側のファイルには
                // 相対パスが無く、このアプリケーションのどのビューも開くことができない。
                const rulePath = item.host.identity.alias === "" ? item.host.file.path : undefined;
                return (
                  <li key={`${item.host.file.absolute}:${item.host.line}`}>
                    {item.host.identity.alias === "" ? (
                      rulePath === undefined ? (
                        <p aria-describedby={descriptionId} className="w-full rounded px-2 py-1 text-sm text-ink-muted">
                          <span className="block">{hostLabel(item.host)}</span>
                          <span className="block text-xs text-ink-faint">
                            {t("tree.patternRuleExternal", { path: item.host.file.absolute })}
                          </span>
                        </p>
                      ) : (
                        <button
                          type="button"
                          onClick={() => onOpenPatternRule(rulePath, item.host.line)}
                          aria-describedby={descriptionId}
                          className="w-full rounded px-2 py-1 text-left text-sm hover:bg-select-fill"
                        >
                          <span className="block">{hostLabel(item.host)}</span>
                          <span className="block text-xs text-ink-faint">
                            {t("tree.patternRuleOpen", { path: rulePath, line: item.host.line })}
                          </span>
                        </button>
                      )
                    ) : (
                      <button
                        type="button"
                        onClick={() => onSelect(item.host)}
                        // 具体的な alias を持つブロックだけがドラッグ可能である。move API は
                        // alias によってブロックを指し示すが、パターンルールには alias が無
                        // い。そのような行は上の分岐でレンダリングされ、ここでは何もしない
                        // ままにしてある。
                        draggable={grouping === "groups"}
                        onDragStart={(event) => {
                          if (grouping !== "groups") return;
                          startDrag(event, {
                            kind: "connection",
                            path: item.host.identity.path,
                            alias: item.host.identity.alias,
                            group: item.group,
                          });
                        }}
                        onDragEnd={() => setDragging(null)}
                        aria-current={active ? "true" : undefined}
                        aria-describedby={descriptionId}
                        className={`w-full rounded-lg border px-2.5 py-2 text-left text-sm transition-colors ${
                          active
                            ? "border-control-line bg-select-fill shadow-sm"
                            : "border-transparent hover:border-line hover:bg-card"
                        }`}
                      >
                        <span className="flex items-center gap-1">
                          {/*
                            色、星、重複マーカーは下の description にのみ書き込まれていて
                            他には無い。なので晴眼のユーザーがお気に入りを設定した後、
                            それを見つけられなくなることがあり得た。ここで aria-hidden
                            にしているのは、その description がスクリーンリーダー向けに
                            依然としてそれらを伝えており、二重に読み上げる方が
                            一度も見えないより悪いからだ。
                          */}
                          {item.colour === "" ? null : (
                            <span
                              aria-hidden="true"
                              className="inline-block size-2 shrink-0 rounded-full"
                              style={{ backgroundColor: item.colour }}
                            />
                          )}
                          {item.favourite ? (
                            <span aria-hidden="true" className="text-notice-ink">
                              ★
                            </span>
                          ) : null}
                          <span className="truncate">{hostLabel(item.host)}</span>
                          {item.host.duplicate === true ? (
                            <span aria-hidden="true" className="text-notice-ink">
                              ⧉
                            </span>
                          ) : null}
                        </span>
                        {item.tags.length === 0 ? null : (
                          <span aria-hidden="true" className="mt-0.5 flex flex-wrap gap-1">
                            {item.tags.map((tag) => (
                              <span key={tag} className="rounded bg-select-fill px-1 text-[0.65rem] text-ink-muted">
                                {tag}
                              </span>
                            ))}
                          </span>
                        )}
                      </button>
                    )}
                    <span id={descriptionId} className="sr-only">
                      {[
                        item.favourite ? t("tree.favourite") : "",
                        item.host.duplicate === true ? t("tree.duplicateAlias") : "",
                        item.host.wildcard === true ? t("tree.patternRule") : "",
                        item.host.file.path ?? item.host.file.absolute,
                      ]
                        .filter((part) => part !== "")
                        .join(", ")}
                    </span>
                  </li>
                );
              })}
            </ul>
    );
  }

  // すべてのグループブロックと ungrouped バケットが共有する、ドロップの挙動。
  //
  // ドロップを受けるのは見出しだけでなくブロック全体である。セクションは
  // 今では入れ子になっているため、受理する最も内側のものがイベントを止
  // める——そうしないと子へのドロップが親へのドロップにもなってしまい、
  // どちらが勝つかはバブリングの順序という偶然に左右されてしまう。
  function dropHandlers(target: string) {
    return {
      onDragOver: (event: DragEvent) => {
        if (!accepts(target)) return;
        event.preventDefault();
        event.stopPropagation();
        event.dataTransfer.dropEffect = "move";
      },
      onDrop: (event: DragEvent) => {
        if (dragging === null || !accepts(target)) return;
        event.preventDefault();
        event.stopPropagation();
        onDrop(dragging, target);
        setDragging(null);
      },
    };
  }

  function blockClass(target: string) {
    return `flex flex-col gap-1 rounded ${
      accepts(target) ? "bg-select-fill outline outline-1 outline-accent" : ""
    }`;
  }

  // 一つのグループと、その配下にあるすべて。
  //
  // 自身に何も持たない非表示グループは見出しもセクションも描かない——
  // その子が一段浅い位置に代わりに現れる。connections を保持している間
  // はこのフラグを無視する。metadata.json はユーザーが手で編集し得るファ
  // イルであり、connections を抱えたまま見出しが消えてしまうのは、まさ
  // にこの防護が防ごうとしている失敗だからだ。
  function renderGroup(node: GroupNode): ReactNode {
    if (node.hidden && node.items.length === 0) {
      return <Fragment key={node.name}>{node.children.map((child) => renderGroup(child))}</Fragment>;
    }
    const shut = collapsed.has(node.name);
    return (
      <section key={node.name} aria-label={node.name} {...dropHandlers(node.name)} className={blockClass(node.name)}>
        <div className="flex items-center gap-1">
          {node.children.length === 0 ? null : (
            <button
              type="button"
              aria-label={t(shut ? "tree.expand" : "tree.collapse", { name: node.name })}
              aria-expanded={!shut}
              onClick={() =>
                setCollapsed((current) => {
                  const next = new Set(current);
                  if (next.has(node.name)) next.delete(node.name);
                  else next.add(node.name);
                  return next;
                })
              }
              className="rounded px-1 text-xs text-ink-faint hover:text-ink"
            >
              <span aria-hidden="true">{shut ? "\u25b8" : "\u25be"}</span>
            </button>
          )}
          {/*
            見出しはドラッグハンドルである。ブロック全体をつかめるように
            すると、その中の connection をつかむ操作が曖昧になってしまう。
          */}
          <h2
            draggable={grouping === "groups"}
            onDragStart={(event) => startDrag(event, { kind: "group", name: node.name })}
            onDragEnd={() => setDragging(null)}
            className="rounded px-1 text-xs font-semibold uppercase tracking-wide text-ink-faint"
          >
            {node.label}
          </h2>
        </div>
        {shut ? null : (
          <>
            {node.items.length > 0
              ? renderItems(node.items)
              : node.children.length === 0
                ? <p className="px-2 py-1 text-xs text-ink-faint">{t("tree.groupEmpty")}</p>
                : null}
            {node.children.length === 0 ? null : (
              <div className="ms-2 flex flex-col gap-1 border-s border-line ps-2">
                {node.children.map((child) => renderGroup(child))}
              </div>
            )}
          </>
        )}
      </section>
    );
  }

  return (
    // それ自体は chrome を持たない——背景と border を描くのは、それを
    // 囲むペインの役目である。
    //
    // 並び替えコントロールはフィルタの上、ペインの先頭に置く。これと
    // フィルタは同じ種類のことをしている——どの connection を画面に出し、
    // どの順にするかを決める点で。ウィンドウのツールバーにあった頃は、
    // セクションを切り替えるたびにシェルがクリアする chrome だったため、
    // このリストではなくウィンドウに属するものとして読め、他のどこかに
    // 目を向けた瞬間に消えてしまっていた。
    //
    // 目に見えるキャプションは無い——"Groups" と "Files" がそれ自体で
    // 用途を語っており、残りはグループに付けた `aria-label` がスクリーンリーダーへ伝える。
    //
    // pill を二語ぶんの幅に保っているのは、それを包む flex row である。
    // この column は子要素を引き伸ばすため、15rem にわたって描かれた
    // segmented control は、片端に二つのボタン、もう片端に空の余白が伸び
    // るバーになってしまう——ヘッダーの select 群が自前の幅を与えられる
    // 前に、同じように伸びてしまっていたのと同様だ。
    <nav aria-label={t("tree.navLabel")} className="flex h-full flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <Segmented
          label={t("tree.arrangeBy")}
          value={grouping}
          options={[
            { value: "groups", label: t("tree.byGroups") },
            { value: "files", label: t("tree.byFiles") },
          ]}
          onChange={setGrouping}
        />
        <button
          type="button"
          aria-pressed={favouritesOnly}
          onClick={() => setFavouritesOnly((current) => !current)}
          className={`rounded-md border px-2.5 py-1 text-xs ${
            favouritesOnly
              ? "border-notice-line bg-notice text-notice-ink"
              : "border-control-line bg-card text-ink-muted hover:text-ink"
          }`}
        >
          <span aria-hidden="true" className="me-1 text-notice-ink">★</span>
          {t("tree.favouritesOnly")}
        </button>
      </div>
      <label className="text-xs text-ink-muted" htmlFor="connection-filter">
        {t("tree.filter")}
      </label>
      <input
        id="connection-filter"
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={t("tree.filterPlaceholder")}
        className={`${control} rounded-lg`}
      />

      {visible.length === 0 ? (
        <p role="status" className="text-sm text-ink-muted">
          {t("tree.noMatch")}
        </p>
      ) : null}

      {/*
        宣言済みのグループは、何も持っていなくても表示される。空のグルー
        プを隠すと、Groups パネルで作ったグループは何かが入るまでここに
        現れないことになり——connection はグループ間をドラッグできるの
        で——あるグループを空にしてしまうと、ドラッグして戻せる唯一の
        場所を失うことになる。file はこれと違う。connection を置ける
        場所ではないので、空の file はただのノイズでしかない。
      */}      {grouping === "files" ? (
        fileSections.map((section) =>
          section.items.length === 0 ? null : (
            <section key={section.title} className="flex flex-col gap-1">
              <h2 className="rounded px-1 text-xs font-semibold uppercase tracking-wide text-ink-faint">
                {section.title}
              </h2>
              {renderItems(section.items)}
            </section>
          ),
        )
      ) : (
        <>
          {groupTree.map((node) => renderGroup(node))}
          {/*
            ungrouped バケットは宣言済みグループではなく子も持たないため、
            再帰ではなくここで描画する。それでもドロップターゲットでは
            あり、そこへのドロップは connection をエントリファイルへ戻す。
          */}
          <section aria-label={t("tree.ungrouped")} {...dropHandlers("")} className={blockClass("")}>
            <h2 className="rounded px-1 text-xs font-semibold uppercase tracking-wide text-ink-faint">
              {t("tree.ungrouped")}
            </h2>
            {ungroupedItems.length === 0 ? (
              <p className="px-2 py-1 text-xs text-ink-faint">{t("tree.groupEmpty")}</p>
            ) : (
              renderItems(ungroupedItems)
            )}
          </section>
        </>
      )}
    </nav>
  );
}
