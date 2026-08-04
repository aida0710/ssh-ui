import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConnectionTree } from "./ConnectionTree";
import type { Overview } from "../api/config";

const overview: Overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [
    { file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 },
    { file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }, editable: true, loads: 1 },
  ],
  hosts: [
    {
      identity: { path: "conf.d/10-home.conf", alias: "nas" },
      file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" },
      line: 1, patterns: ["nas"], editable: true,
    },
    {
      identity: { path: "config", alias: "bastion" },
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      line: 4, patterns: ["bastion"], editable: true,
    },
    {
      identity: { path: "", alias: "" },
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      line: 9, patterns: ["*"], wildcard: true, editable: true,
    },
  ],
  metadata: {
    schemaVersion: 1,
    groups: [{ name: "home" }],
    hosts: [{ identity: { path: "conf.d/10-home.conf", alias: "nas" }, group: "home", favourite: true }],
  },
  diagnostics: [],
  notices: [],
};

describe("ConnectionTree", () => {
  it("groups hosts by their primary group and marks favourites", () => {
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "home" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nas/ })).toHaveAccessibleDescription(/favourite/i);
    expect(screen.getByRole("heading", { name: "Ungrouped" })).toBeInTheDocument();
  });

  it("shows a wildcard block as a pattern rule rather than a host", () => {
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    expect(screen.getByText("Host *")).toBeInTheDocument();
  });

  it("switches to the Include file hierarchy", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Files" }));

    expect(screen.getByRole("heading", { name: "conf.d/10-home.conf" })).toBeInTheDocument();
  });

  it("filters hosts as the user searches and reports an empty result", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} />);

    await user.type(screen.getByRole("searchbox", { name: "Filter connections" }), "bast");

    expect(screen.getByRole("button", { name: /bastion/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /nas/ })).not.toBeInTheDocument();
  });

  it("selects a host", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<ConnectionTree overview={overview} selected={null} onSelect={onSelect} />);

    await user.click(screen.getByRole("button", { name: /bastion/ }));

    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({
      identity: { path: "config", alias: "bastion" },
    }));
  });
});
