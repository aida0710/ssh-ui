import { useMemo, useState } from "react";
import type { HostEntry, Overview } from "../api/config";

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

const ungrouped = "Ungrouped";

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
  const [query, setQuery] = useState("");
  const [grouping, setGrouping] = useState<"groups" | "files">("groups");

  const metadataByAlias = useMemo(() => {
    const index = new Map<string, { group: string; tags: string[]; favourite: boolean }>();
    for (const host of overview.metadata.hosts ?? []) {
      index.set(`${host.identity.path}\u0000${host.identity.alias}`, {
        group: host.group ?? "",
        tags: host.tags ?? [],
        favourite: host.favourite === true,
      });
    }
    return index;
  }, [overview.metadata.hosts]);

  const decorated = useMemo(
    () =>
      overview.hosts.map((host) => {
        const entry = metadataByAlias.get(`${host.identity.path}\u0000${host.identity.alias}`);
        return {
          host,
          group: entry?.group ?? "",
          tags: entry?.tags ?? [],
          favourite: entry?.favourite ?? false,
        };
      }),
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
    const names = [...(overview.metadata.groups ?? []).map((group) => group.name), ungrouped];
    return names.map((name) => ({
      title: name,
      items: visible.filter((item) => (item.group === "" ? name === ungrouped : item.group === name)),
    }));
  }, [grouping, overview.files, overview.metadata.groups, visible]);

  return (
    <nav aria-label="Connections" className="flex h-full flex-col gap-3 border-r border-zinc-800 p-4">
      <div className="flex gap-2">
        {(["groups", "files"] as const).map((mode) => (
          <button
            key={mode}
            type="button"
            onClick={() => setGrouping(mode)}
            aria-pressed={grouping === mode}
            className={`rounded px-2 py-1 text-xs ${grouping === mode ? "bg-zinc-800 text-zinc-100" : "text-zinc-400"}`}
          >
            {mode === "groups" ? "Groups" : "Files"}
          </button>
        ))}
      </div>
      <label className="text-xs text-zinc-400" htmlFor="connection-filter">
        Filter connections
      </label>
      <input
        id="connection-filter"
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="alias, pattern or tag"
        className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm"
      />

      {visible.length === 0 ? (
        <p role="status" className="text-sm text-zinc-400">
          No connection matches this filter.
        </p>
      ) : null}

      {sections.map((section) => (
        section.items.length === 0 ? null : (
          <section key={section.title} className="flex flex-col gap-1">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">{section.title}</h2>
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
                            {`Pattern rule in ${item.host.file.absolute}, a file this editor only reads.`}
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
                            {`Pattern rule — open it in the Config file view (${rulePath}:${item.host.line})`}
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
                        {hostLabel(item.host)}
                      </button>
                    )}
                    <span id={descriptionId} className="sr-only">
                      {[
                        item.favourite ? "favourite" : "",
                        item.host.duplicate === true ? "duplicate alias" : "",
                        item.host.wildcard === true ? "pattern rule" : "",
                        item.host.file.path ?? item.host.file.absolute,
                      ]
                        .filter((part) => part !== "")
                        .join(", ")}
                    </span>
                  </li>
                );
              })}
            </ul>
          </section>
        )
      ))}
    </nav>
  );
}
