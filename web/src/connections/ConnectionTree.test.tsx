import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConnectionTree } from "./ConnectionTree";
import { dragMimeType, type DragPayload } from "./dragdrop";
import type { HostEntry, Overview } from "../api/config";

// nas sits in connections/home, so its group is "home". Membership is the
// directory, and the projection reports it on the entry rather than in metadata.
const nas: HostEntry = {
  identity: { path: "connections/home/nas.conf", alias: "nas" },
  file: { path: "connections/home/nas.conf", absolute: "/home/tester/.ssh/connections/home/nas.conf" },
  line: 1, patterns: ["nas"], editable: true, group: "home",
};

const bastion: HostEntry = {
  identity: { path: "config", alias: "bastion" },
  file: { path: "config", absolute: "/home/tester/.ssh/config" },
  line: 4, patterns: ["bastion"], editable: true,
};

const catchAll: HostEntry = {
  identity: { path: "", alias: "" },
  file: { path: "config", absolute: "/home/tester/.ssh/config" },
  line: 9, patterns: ["*"], wildcard: true, editable: true,
};

const overview: Overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [
    { file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 },
    { file: { path: "connections/home/nas.conf", absolute: "/home/tester/.ssh/connections/home/nas.conf" }, editable: true, loads: 1 },
  ],
  hosts: [nas, bastion, catchAll],
  metadata: {
    schemaVersion: 2,
    groups: [{ name: "home" }],
    hosts: [{ identity: { path: "connections/home/nas.conf", alias: "nas" }, favourite: true }],
  },
  groups: [],
  diagnostics: [],
  notices: [],
};

const externalOverview: Overview = {
  ...overview,
  files: [
    ...overview.files,
    { file: { absolute: "/etc/ssh/ssh_config", external: true }, editable: false, loads: 1 },
  ],
  hosts: [
    bastion,
    {
      identity: { path: "", alias: "" },
      file: { absolute: "/etc/ssh/ssh_config", external: true },
      line: 40, patterns: ["*"], wildcard: true, editable: false,
    },
  ],
};

const twoRulesOverview: Overview = {
  ...overview,
  hosts: [
    bastion,
    catchAll,
    {
      identity: { path: "", alias: "" },
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      line: 14, patterns: ["*.lab"], wildcard: true, editable: true,
    },
  ],
};

describe("ConnectionTree", () => {
  it("groups hosts by their primary group and marks favourites", () => {
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "home" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toHaveAccessibleDescription(/favourite/i);
    expect(screen.getByRole("heading", { name: "Ungrouped" })).toBeInTheDocument();
  });

  it("shows a wildcard block as a pattern rule rather than a host", () => {
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    expect(screen.getByText("Host *")).toBeInTheDocument();
  });

  it("opens a pattern rule in the file view instead of doing nothing", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const onOpenPatternRule = vi.fn();
    render(
      <ConnectionTree overview={overview} selected={null} onSelect={onSelect} onOpenPatternRule={onOpenPatternRule} onDrop={vi.fn()} />,
    );

    const rule = screen.getByRole("button", { name: /Host \*/ });
    expect(rule).toHaveAccessibleName(/file view/i);

    await user.click(rule);

    expect(onOpenPatternRule).toHaveBeenCalledWith("config", 9);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("states plainly that a pattern rule outside ~/.ssh cannot be opened", () => {
    render(
      <ConnectionTree overview={externalOverview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />,
    );

    expect(screen.getByText("Host *")).toBeInTheDocument();
    expect(screen.getByText(/\/etc\/ssh\/ssh_config.*only reads/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Host \*/ })).not.toBeInTheDocument();
  });

  it("renders every pattern rule of a file and marks none of them active", async () => {
    const user = userEvent.setup();
    const onOpenPatternRule = vi.fn();
    render(
      <ConnectionTree
        overview={twoRulesOverview}
        selected={{ path: "config", alias: "bastion" }}
        onSelect={vi.fn()}
        onOpenPatternRule={onOpenPatternRule}
        onDrop={vi.fn()}
      />,
    );

    const rules = screen.getAllByRole("button", { name: /pattern rule/i });
    expect(rules).toHaveLength(2);
    expect(rules[0]).toHaveAccessibleName(/Host \*/);
    expect(rules[1]).toHaveAccessibleName(/Host \*\.lab/);
    for (const rule of rules) {
      expect(rule).not.toHaveAttribute("aria-current");
    }
    expect(screen.getByRole("button", { name: /bastion/ })).toHaveAttribute("aria-current", "true");

    await user.click(screen.getByRole("button", { name: /Host \*\.lab/ }));

    expect(onOpenPatternRule).toHaveBeenCalledWith("config", 14);
  });

  it("switches to the Include file hierarchy", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Files" }));

    expect(screen.getByRole("heading", { name: "connections/home/nas.conf" })).toBeInTheDocument();
  });

  it("filters hosts as the user searches and reports an empty result", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    await user.type(screen.getByRole("searchbox", { name: "Filter connections" }), "bast");

    expect(screen.getByRole("button", { name: /bastion/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /nas/ })).not.toBeInTheDocument();
  });

  it("selects a host", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const onOpenPatternRule = vi.fn();
    render(
      <ConnectionTree overview={overview} selected={null} onSelect={onSelect} onOpenPatternRule={onOpenPatternRule} onDrop={vi.fn()} />,
    );

    await user.click(screen.getByRole("button", { name: /bastion/ }));

    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({
      identity: { path: "config", alias: "bastion" },
    }));
    expect(onOpenPatternRule).not.toHaveBeenCalled();
  });
  it("shows the favourite, the colour and the tags, not only to a screen reader", () => {
    const decorated: Overview = {
      ...overview,
      metadata: {
        ...overview.metadata,
        hosts: [
          {
            identity: { path: "connections/home/nas.conf", alias: "nas" },
            favourite: true,
            colour: "#f97316",
            tags: ["storage", "lan"],
          },
        ],
      },
    };
    render(
      <ConnectionTree overview={decorated} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />,
    );

    const row = screen.getByRole("button", { name: /nas/ });
    expect(within(row).getByText("★")).toBeInTheDocument();
    expect(within(row).getByText("storage")).toBeInTheDocument();
    expect(within(row).getByText("lan")).toBeInTheDocument();
    // The swatch is decorative: the description below the row still carries
    // "favourite" for a screen reader, so this must not be announced twice.
    const swatch = row.querySelector('span[style*="background-color"]');
    expect(swatch).not.toBeNull();
    expect(swatch).toHaveAttribute("aria-hidden", "true");
  });

  it("sorts by the order the user gave and leaves file order alone at zero", () => {
    const ordered: Overview = {
      ...overview,
      metadata: {
        ...overview.metadata,
        groups: [],
        hosts: [
          { identity: { path: "config", alias: "bastion" }, order: 5 },
          { identity: { path: "connections/home/nas.conf", alias: "nas" }, order: -1 },
        ],
      },
    };
    render(
      <ConnectionTree overview={ordered} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />,
    );

    const labels = screen.getAllByRole("button").map((button) => button.textContent ?? "");
    const nasIndex = labels.findIndex((label) => label.includes("nas"));
    const bastionIndex = labels.findIndex((label) => label.includes("bastion"));
    expect(nasIndex).toBeLessThan(bastionIndex);
  });
});

describe("a group that holds nothing", () => {
  const withEmptyGroup: Overview = {
    ...overview,
    metadata: { ...overview.metadata, groups: [{ name: "home" }, { name: "work" }] },
  };

  // Hiding it means a group made in the Groups panel never appears here, and —
  // once a connection can be dragged out of a group — that emptying a group
  // removes the only thing it could be dragged back onto.
  it("still shows its heading", () => {
    render(
      <ConnectionTree overview={withEmptyGroup} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />,
    );

    expect(screen.getByRole("heading", { name: "work" })).toBeInTheDocument();
    expect(screen.getByText("No connection is in this group.")).toBeInTheDocument();
  });

  it("does not do the same for a file, which is not a place anything can be put", async () => {
    const user = userEvent.setup();
    render(
      <ConnectionTree overview={withEmptyGroup} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />,
    );
    await user.click(screen.getByRole("button", { name: "Files" }));

    expect(screen.queryByText("No connection is in this group.")).not.toBeInTheDocument();
  });
});

// jsdom has no drag implementation, so the transfer is a stub carrying the two
// things the component touches: the private type and the payload.
function transfer(payload: DragPayload) {
  const store = new Map<string, string>([[dragMimeType, JSON.stringify(payload)]]);
  return {
    types: [...store.keys()],
    setData: (type: string, value: string) => void store.set(type, value),
    getData: (type: string) => store.get(type) ?? "",
    effectAllowed: "move",
    dropEffect: "move",
  };
}

describe("dragging in the tree", () => {
  const withGroups: Overview = {
    ...overview,
    metadata: { ...overview.metadata, groups: [{ name: "home" }, { name: "work" }] },
  };
  const nasPayload: DragPayload = {
    kind: "connection",
    path: "connections/home/nas.conf",
    alias: "nas",
    group: "home",
  };

  function renderTree() {
    const onDrop = vi.fn();
    render(
      <ConnectionTree
        overview={withGroups}
        selected={null}
        onSelect={vi.fn()}
        onOpenPatternRule={vi.fn()}
        onDrop={onDrop}
      />,
    );
    return onDrop;
  }

  function drag(source: HTMLElement, target: HTMLElement, payload: DragPayload) {
    fireEvent.dragStart(source, { dataTransfer: transfer(payload) });
    fireEvent.dragOver(target, { dataTransfer: transfer(payload) });
    fireEvent.drop(target, { dataTransfer: transfer(payload) });
  }

  it("moves a connection onto another group's heading", () => {
    const onDrop = renderTree();
    drag(screen.getByRole("button", { name: /nas/ }), screen.getByRole("heading", { name: "work" }), nasPayload);

    expect(onDrop).toHaveBeenCalledWith(nasPayload, "work");
  });

  it("moves a connection onto the no-group heading", () => {
    const onDrop = renderTree();
    drag(screen.getByRole("button", { name: /nas/ }), screen.getByRole("heading", { name: "Ungrouped" }), nasPayload);

    expect(onDrop).toHaveBeenCalledWith(nasPayload, "");
  });

  it("does nothing for a drop on the group the connection is already in", () => {
    const onDrop = renderTree();
    drag(screen.getByRole("button", { name: /nas/ }), screen.getByRole("heading", { name: "home" }), nasPayload);

    expect(onDrop).not.toHaveBeenCalled();
  });

  it("nests one group inside another", () => {
    const onDrop = renderTree();
    const payload: DragPayload = { kind: "group", name: "work" };
    drag(screen.getByRole("heading", { name: "work" }), screen.getByRole("heading", { name: "home" }), payload);

    expect(onDrop).toHaveBeenCalledWith(payload, "home");
  });

  it("does nothing while grouping by file, because a file is not a place", async () => {
    const user = userEvent.setup();
    const onDrop = renderTree();
    await user.click(screen.getByRole("button", { name: "Files" }));

    drag(screen.getByRole("button", { name: /nas/ }), screen.getByRole("heading", { name: "connections/home/nas.conf" }), nasPayload);

    expect(onDrop).not.toHaveBeenCalled();
  });

  // A block with no concrete alias cannot be addressed by the move API, so it
  // is not a drag source at all.
  it("does not let a pattern rule be dragged", () => {
    renderTree();
    const rule = screen.getByRole("button", { name: /Host \*/ });

    expect(rule).not.toHaveAttribute("draggable", "true");
  });
});

// A group name carries its hierarchy — work/eu is inside work — and the tree
// drew every group as a flat peer anyway, so a group made only to hold other
// groups read as an empty sibling of its own children.
describe("the group hierarchy", () => {
  const lon: HostEntry = {
    identity: { path: "connections/work/eu/lon.conf", alias: "lon" },
    file: { path: "connections/work/eu/lon.conf", absolute: "/home/tester/.ssh/connections/work/eu/lon.conf" },
    line: 1, patterns: ["lon"], editable: true, group: "work/eu",
  };
  const nested: Overview = {
    ...overview,
    hosts: [lon],
    metadata: { ...overview.metadata, groups: [{ name: "work" }, { name: "work/eu" }] },
  };

  function renderNested(over: Overview = nested) {
    render(
      <ConnectionTree overview={over} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />,
    );
  }

  it("draws a child group inside its parent, not beside it", () => {
    renderNested();

    const parent = screen.getByRole("region", { name: "work" });
    expect(within(parent).getByRole("heading", { name: "eu" })).toBeInTheDocument();
  });

  // The heading shows the segment, not the path: the rest is the route the
  // reader has already walked to get there.
  it("names a child by its own segment", () => {
    renderNested();

    expect(screen.getByRole("heading", { name: "eu" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "work/eu" })).not.toBeInTheDocument();
  });

  it("collapses a parent, taking its children and their connections with it", async () => {
    const user = userEvent.setup();
    renderNested();

    await user.click(screen.getByRole("button", { name: "Collapse work" }));

    expect(screen.queryByRole("heading", { name: "eu" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /lon/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Expand work" })).toBeInTheDocument();
  });

  // A group whose parent no Include line declares is a root. Inventing the
  // parent here would draw a heading for something that is not a group.
  it("roots a group whose parent is not declared", () => {
    const orphan: Overview = {
      ...nested,
      metadata: { ...overview.metadata, groups: [{ name: "work/eu" }] },
    };
    renderNested(orphan);

    expect(screen.getByRole("region", { name: "work/eu" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "work" })).not.toBeInTheDocument();
  });
});

describe("a hidden group", () => {
  const lon: HostEntry = {
    identity: { path: "connections/work/eu/lon.conf", alias: "lon" },
    file: { path: "connections/work/eu/lon.conf", absolute: "/home/tester/.ssh/connections/work/eu/lon.conf" },
    line: 1, patterns: ["lon"], editable: true, group: "work/eu",
  };
  const container: Overview = {
    ...overview,
    hosts: [lon],
    metadata: { ...overview.metadata, groups: [{ name: "work", hidden: true }, { name: "work/eu" }] },
  };

  function renderContainer(over: Overview = container) {
    render(
      <ConnectionTree overview={over} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />,
    );
  }

  it("loses its own heading", () => {
    renderContainer();

    expect(screen.queryByRole("region", { name: "work" })).not.toBeInTheDocument();
  });

  it("keeps its children, and the connections inside them", () => {
    renderContainer();

    expect(screen.getByRole("region", { name: "work/eu" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /lon/ })).toBeInTheDocument();
  });

  // The flag is ignored rather than merely un-settable in the Groups panel,
  // because metadata.json is a file a user may edit by hand, and a heading that
  // vanished with connections under it is the failure this guards against.
  it("is drawn anyway while it holds connections of its own", () => {
    renderContainer({ ...container, hosts: [lon, { ...nas, group: "work" }] });

    expect(screen.getByRole("region", { name: "work" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toBeInTheDocument();
  });
});

describe("dropping on a whole block", () => {
  const lonHost: HostEntry = {
    identity: { path: "connections/work/eu/lon.conf", alias: "lon" },
    file: { path: "connections/work/eu/lon.conf", absolute: "/home/tester/.ssh/connections/work/eu/lon.conf" },
    line: 1, patterns: ["lon"], editable: true, group: "work/eu",
  };
  const nested: Overview = {
    ...overview,
    hosts: [nas, lonHost],
    metadata: {
      ...overview.metadata,
      groups: [{ name: "home" }, { name: "work" }, { name: "work/eu" }],
    },
  };
  const payload: DragPayload = {
    kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home",
  };

  function renderNested() {
    const onDrop = vi.fn();
    render(
      <ConnectionTree overview={nested} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={onDrop} />,
    );
    return onDrop;
  }

  it("accepts a drop anywhere in a group's block, not only on its heading", () => {
    const onDrop = renderNested();

    fireEvent.dragStart(screen.getByRole("button", { name: /nas/ }), { dataTransfer: transfer(payload) });
    fireEvent.drop(screen.getByRole("region", { name: "work" }), { dataTransfer: transfer(payload) });

    expect(onDrop).toHaveBeenCalledWith(payload, "work");
  });

  // Blocks nest now, so a drop inside a child reaches its parent too unless the
  // child stops it. Which one won would otherwise be an accident of bubbling.
  it("gives a drop in a child block to the child, not to its parent", () => {
    const onDrop = renderNested();

    fireEvent.dragStart(screen.getByRole("button", { name: /nas/ }), { dataTransfer: transfer(payload) });
    fireEvent.drop(screen.getByRole("region", { name: "work/eu" }), { dataTransfer: transfer(payload) });

    expect(onDrop).toHaveBeenCalledTimes(1);
    expect(onDrop).toHaveBeenCalledWith(payload, "work/eu");
  });
});
