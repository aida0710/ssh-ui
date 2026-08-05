import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConnectionTree } from "./ConnectionTree";
import type { HostEntry, Overview } from "../api/config";

const nas: HostEntry = {
  identity: { path: "conf.d/10-home.conf", alias: "nas" },
  file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" },
  line: 1, patterns: ["nas"], editable: true,
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
    { file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }, editable: true, loads: 1 },
  ],
  hosts: [nas, bastion, catchAll],
  metadata: {
    schemaVersion: 1,
    groups: [{ name: "home" }],
    hosts: [{ identity: { path: "conf.d/10-home.conf", alias: "nas" }, group: "home", favourite: true }],
  },
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
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "home" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toHaveAccessibleDescription(/favourite/i);
    expect(screen.getByRole("heading", { name: "Ungrouped" })).toBeInTheDocument();
  });

  it("shows a wildcard block as a pattern rule rather than a host", () => {
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />);

    expect(screen.getByText("Host *")).toBeInTheDocument();
  });

  it("opens a pattern rule in the file view instead of doing nothing", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const onOpenPatternRule = vi.fn();
    render(
      <ConnectionTree overview={overview} selected={null} onSelect={onSelect} onOpenPatternRule={onOpenPatternRule} />,
    );

    const rule = screen.getByRole("button", { name: /Host \*/ });
    expect(rule).toHaveAccessibleName(/file view/i);

    await user.click(rule);

    expect(onOpenPatternRule).toHaveBeenCalledWith("config", 9);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("states plainly that a pattern rule outside ~/.ssh cannot be opened", () => {
    render(
      <ConnectionTree overview={externalOverview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />,
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
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Files" }));

    expect(screen.getByRole("heading", { name: "conf.d/10-home.conf" })).toBeInTheDocument();
  });

  it("filters hosts as the user searches and reports an empty result", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />);

    await user.type(screen.getByRole("searchbox", { name: "Filter connections" }), "bast");

    expect(screen.getByRole("button", { name: /bastion/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /nas/ })).not.toBeInTheDocument();
  });

  it("selects a host", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const onOpenPatternRule = vi.fn();
    render(
      <ConnectionTree overview={overview} selected={null} onSelect={onSelect} onOpenPatternRule={onOpenPatternRule} />,
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
            identity: { path: "conf.d/10-home.conf", alias: "nas" },
            group: "home",
            favourite: true,
            colour: "#f97316",
            tags: ["storage", "lan"],
          },
        ],
      },
    };
    render(
      <ConnectionTree overview={decorated} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />,
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
          { identity: { path: "conf.d/10-home.conf", alias: "nas" }, order: -1 },
        ],
      },
    };
    render(
      <ConnectionTree overview={ordered} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />,
    );

    const labels = screen.getAllByRole("button").map((button) => button.textContent ?? "");
    const nasIndex = labels.findIndex((label) => label.includes("nas"));
    const bastionIndex = labels.findIndex((label) => label.includes("bastion"));
    expect(nasIndex).toBeLessThan(bastionIndex);
  });
});
