import { Fragment, useMemo, useState, type DragEvent, type ReactNode } from "react";
import type { HostEntry, Overview } from "../api/config";
import { useTranslate } from "../i18n/context";
import { control } from "../ui/form";
import { canDrop, dragMimeType, type DragPayload } from "./dragdrop";

export type HostSelection = { path: string; alias: string };

// One decorated connection: the projection's entry plus the presentation the
// metadata document carries for it.
type Decorated = {
  host: HostEntry;
  group: string;
  tags: string[];
  favourite: boolean;
  colour: string;
  order: number;
};

// One group in the tree. name is the full declared name, which every callback
// and every drop target uses; label is its last segment, which is all the
// heading shows, because the rest is the route the reader already walked.
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
  // A block whose Host line carries no concrete alias has no identity, so the
  // host endpoint cannot address it. The tree hands it to the file view by
  // path and line instead; the callback is required so such a row can never be
  // rendered as a control with nothing behind it.
  onOpenPatternRule: (path: string, line: number) => void;
  // Where a dragged connection or group was dropped. The target is a group
  // name, or the empty string for the "no group" heading.
  onDrop: (payload: DragPayload, target: string) => void;
  // Whether the tree is arranged by group or by file.
  //
  // The state is the page's rather than this component's, because the control
  // that changes it lives in the window's toolbar — the tree is one pane of a
  // screen now, not a rail that owns its own header.
  grouping: Grouping;
};

export type Grouping = "groups" | "files";

// The ungrouped bucket is keyed by a constant that never reaches the screen:
// its label is translated, but matching a host to it must not depend on the
// display language.
const ungrouped = "\u0000ungrouped";

function hostLabel(host: HostEntry): string {
  return host.identity.alias === "" ? `Host ${host.patterns.join(" ")}` : host.identity.alias;
}

function matchesQuery(host: HostEntry, tags: string[], query: string): boolean {
  if (query === "") return true;
  const needle = query.toLowerCase();
  if (host.identity.alias.toLowerCase().includes(needle)) return true;
  if (host.patterns.some((pattern) => pattern.toLowerCase().includes(needle))) return true;
  return tags.some((tag) => tag.toLowerCase().includes(needle));
}

export function ConnectionTree({
  overview,
  selected,
  onSelect,
  onOpenPatternRule,
  onDrop,
  grouping,
}: ConnectionTreeProps) {
  const t = useTranslate();
  const [query, setQuery] = useState("");
  // What is being dragged, held here rather than read back from the event. A
  // dragover handler may read dataTransfer.types but not getData — the data is
  // protected until the drop — so a target cannot inspect the drag in order to
  // decide whether to accept it, and deciding from state is how that is done.
  // The private type on dataTransfer is then only good for telling one of these
  // drags from one that began outside the page.
  const [dragging, setDragging] = useState<DragPayload | null>(null);
  // Collapse is momentary and is not written down. Persisting it would put an
  // interface state into metadata.json beside the settings that describe the
  // configuration; a tree that opens fully on reload is the cheaper wrong.
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

  // A drop target exists only while grouping by group. A file is not a place a
  // connection can be put: the move API takes a group or a path, not a file the
  // user happened to point at.
  function accepts(target: string): boolean {
    return grouping === "groups" && dragging !== null && canDrop(dragging, target, groupNames);
  }

  function targetOf(title: string): string {
    return title === ungrouped ? "" : title;
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

  // Sorting is by order and then by the position the configuration gives, which
  // Array.prototype.sort preserves for equal keys. Zero means "leave it where
  // the file puts it", so an untouched workspace reads in file order and
  // pinning one host does not renumber everything around it.
  const decorated = useMemo(
    () =>
      overview.hosts
        .map((host) => {
          const entry = metadataByAlias.get(`${host.identity.path}\u0000${host.identity.alias}`);
          return {
            host,
            // Membership is the directory the file sits in, which the server
            // already read from the path. Metadata has no say in it.
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

  const visible = decorated.filter((item) => matchesQuery(item.host, item.tags, query));
  const fileSections = useMemo(
    () =>
      overview.files.map((file) => ({
        title: file.file.path ?? file.file.absolute,
        items: visible.filter((item) => item.host.file.absolute === file.file.absolute),
      })),
    [overview.files, visible],
  );

  // A group name is its own hierarchy — work/eu is inside work — so the tree is
  // built from the declared names rather than listed beside them. Drawn flat, a
  // group made only to hold other groups read as an empty sibling of its own
  // children, which is what it is not.
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
      // The nearest declared ancestor is the parent. A group whose ancestors
      // are all undeclared is a root: a directory no Include line names is not
      // a group, and inventing one here would draw a heading for something that
      // does not exist.
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

  // The row list, lifted out of the render so the recursive group renderer and
  // the by-file view draw one thing rather than two copies of it.
  function renderItems(items: Decorated[]) {
    return (
            <ul>
              {items.map((item) => {
                const active =
                  selected !== null &&
                  selected.path === item.host.identity.path &&
                  selected.alias === item.host.identity.alias;
                const descriptionId = `host-${item.host.file.absolute}-${item.host.line}-description`;
                // A pattern rule is addressable only by file and line, and only
                // when its file lives inside the root: a file outside it has no
                // relative path, so no view of this application can open it.
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
                        // Only a block with a concrete alias is draggable: the
                        // move API addresses a block by alias, and a pattern
                        // rule has none. Those rows are rendered by the branch
                        // above and are left alone.
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
                        className={`w-full rounded px-2 py-1 text-left text-sm ${active ? "bg-select-fill" : "hover:bg-select-fill"}`}
                      >
                        <span className="flex items-center gap-1">
                          {/*
                            The colour, the star and the duplicate marker were
                            written into the description below and nowhere else,
                            so a sighted user could set a favourite and then not
                            find it. aria-hidden here because that description
                            still carries them for a screen reader, and hearing
                            each one twice is worse than not seeing it once.
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

  // The drop behaviour every group block and the ungrouped bucket share.
  //
  // The whole block takes the drop, not only the heading. Sections nest now, so
  // the innermost one to accept stops the event: otherwise a drop into a child
  // would also be a drop into its parent, and which one won would be an
  // accident of bubbling order.
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

  // One group, and everything under it.
  //
  // A hidden group with nothing of its own draws no heading and no section: its
  // children take its place, one level shallower. The flag is ignored while it
  // holds connections, because metadata.json is a file a user may edit by hand
  // and a heading that vanished with connections under it is the failure this
  // guards against.
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
            The heading is the drag handle. A whole block that could be picked
            up would make picking up a connection inside it ambiguous.
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
    // No chrome of its own. The pane around it draws the background and the
    // border now, and the control that switches groups for files is in the
    // window's toolbar.
    <nav aria-label={t("tree.navLabel")} className="flex h-full flex-col gap-3">
      <label className="text-xs text-ink-muted" htmlFor="connection-filter">
        {t("tree.filter")}
      </label>
      <input
        id="connection-filter"
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={t("tree.filterPlaceholder")}
        className={control}
      />

      {visible.length === 0 ? (
        <p role="status" className="text-sm text-ink-muted">
          {t("tree.noMatch")}
        </p>
      ) : null}

      {/*
        A declared group is shown whether or not it holds anything. Hiding an
        empty one meant a group made in the Groups panel was absent here until
        something was put in it, and — since a connection can be dragged between
        groups — that emptying a group removed the only thing it could be
        dragged back onto. A file is different: it is not a place a connection
        can be put, so an empty one is only noise.
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
            The ungrouped bucket is not a declared group and has no children, so
            it is drawn here rather than by the recursion. It is still a drop
            target: dropping on it moves a connection back into the entry file.
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
