import { useMemo, useState } from "react";
import type { HostEntry, Overview } from "../api/config";
import { useTranslate } from "../i18n/context";

export type HostSelection = { path: string; alias: string };

type ConnectionTreeProps = {
  overview: Overview;
  selected: HostSelection | null;
  onSelect: (host: HostEntry) => void;
  // A block whose Host line carries no concrete alias has no identity, so the
  // host endpoint cannot address it. The tree hands it to the file view by
  // path and line instead; the callback is required so such a row can never be
  // rendered as a control with nothing behind it.
  onOpenPatternRule: (path: string, line: number) => void;
};

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

export function ConnectionTree({ overview, selected, onSelect, onOpenPatternRule }: ConnectionTreeProps) {
  const t = useTranslate();
  const [query, setQuery] = useState("");
  const [grouping, setGrouping] = useState<"groups" | "files">("groups");

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

  const sections = useMemo(() => {
    if (grouping === "files") {
      return overview.files.map((file) => ({
        title: file.file.path ?? file.file.absolute,
        items: visible.filter((item) => item.host.file.absolute === file.file.absolute),
      }));
    }
    const names = [
      ...[...(overview.metadata.groups ?? [])]
        .sort((left, right) => (left.order ?? 0) - (right.order ?? 0))
        .map((group) => group.name),
      ungrouped,
    ];
    return names.map((name) => ({
      title: name,
      items: visible.filter((item) => (item.group === "" ? name === ungrouped : item.group === name)),
    }));
  }, [grouping, overview.files, overview.metadata.groups, visible]);

  return (
    <nav aria-label={t("tree.navLabel")} className="flex h-full flex-col gap-3 border-r border-zinc-800 p-4">
      <div className="flex gap-2">
        {(["groups", "files"] as const).map((mode) => (
          <button
            key={mode}
            type="button"
            onClick={() => setGrouping(mode)}
            aria-pressed={grouping === mode}
            className={`rounded px-2 py-1 text-xs ${grouping === mode ? "bg-zinc-800 text-zinc-100" : "text-zinc-400"}`}
          >
            {mode === "groups" ? t("tree.byGroups") : t("tree.byFiles")}
          </button>
        ))}
      </div>
      <label className="text-xs text-zinc-400" htmlFor="connection-filter">
        {t("tree.filter")}
      </label>
      <input
        id="connection-filter"
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={t("tree.filterPlaceholder")}
        className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
      />

      {visible.length === 0 ? (
        <p role="status" className="text-sm text-zinc-400">
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
      */}
      {sections.map((section) => (
        section.items.length === 0 && grouping === "files" ? null : (
          <section key={section.title} className="flex flex-col gap-1">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
              {section.title === ungrouped ? t("tree.ungrouped") : section.title}
            </h2>
            {section.items.length === 0 ? (
              <p className="px-2 py-1 text-xs text-zinc-500">{t("tree.groupEmpty")}</p>
            ) : (
            <ul>
              {section.items.map((item) => {
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
                        <p aria-describedby={descriptionId} className="w-full rounded px-2 py-1 text-sm text-zinc-400">
                          <span className="block">{hostLabel(item.host)}</span>
                          <span className="block text-xs text-zinc-500">
                            {t("tree.patternRuleExternal", { path: item.host.file.absolute })}
                          </span>
                        </p>
                      ) : (
                        <button
                          type="button"
                          onClick={() => onOpenPatternRule(rulePath, item.host.line)}
                          aria-describedby={descriptionId}
                          className="w-full rounded px-2 py-1 text-left text-sm hover:bg-zinc-900"
                        >
                          <span className="block">{hostLabel(item.host)}</span>
                          <span className="block text-xs text-zinc-500">
                            {t("tree.patternRuleOpen", { path: rulePath, line: item.host.line })}
                          </span>
                        </button>
                      )
                    ) : (
                      <button
                        type="button"
                        onClick={() => onSelect(item.host)}
                        aria-current={active ? "true" : undefined}
                        aria-describedby={descriptionId}
                        className={`w-full rounded px-2 py-1 text-left text-sm ${active ? "bg-zinc-800" : "hover:bg-zinc-900"}`}
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
                            <span aria-hidden="true" className="text-amber-300">
                              ★
                            </span>
                          ) : null}
                          <span className="truncate">{hostLabel(item.host)}</span>
                          {item.host.duplicate === true ? (
                            <span aria-hidden="true" className="text-amber-300">
                              ⧉
                            </span>
                          ) : null}
                        </span>
                        {item.tags.length === 0 ? null : (
                          <span aria-hidden="true" className="mt-0.5 flex flex-wrap gap-1">
                            {item.tags.map((tag) => (
                              <span key={tag} className="rounded bg-zinc-800 px-1 text-[0.65rem] text-zinc-300">
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
            )}
          </section>
        )
      ))}
    </nav>
  );
}
