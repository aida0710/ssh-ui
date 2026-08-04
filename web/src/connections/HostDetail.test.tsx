import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HostDetailPanel } from "./HostDetail";
import type { HostDetail } from "../api/config";

const detail: HostDetail = {
  form: {
    entry: {
      identity: { path: "config", alias: "bastion" },
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      line: 1,
      patterns: ["bastion"],
      editable: true,
    },
    fields: [
      { line: 2, keyword: "HostName", values: ["203.0.113.10"], category: "basic", editable: true },
      { line: 3, keyword: "ProxyJump", values: ["edge"], category: "jump", editable: true },
      { line: 4, keyword: "UnknownFutureDirective", values: ["yes"], category: "advanced", editable: true },
      { line: 5, keyword: "ProxyCommand", values: ["/usr/bin/nc %h %p"], category: "jump", dangerous: true, editable: true },
    ],
    raw: "Host bastion\n\tHostName 203.0.113.10\n",
    notices: [{ code: "dangerous_directive", path: "config", line: 5, detail: "ProxyCommand" }],
  },
  metadata: { identity: { path: "config", alias: "bastion" }, group: "work", favourite: false },
  effective: {
    alias: "bastion",
    approximate: true,
    entries: [{ keyword: "HostName", values: ["203.0.113.10"], source: { path: "config", line: 2 } }],
  },
  file: {
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    contents: "Host bastion\n\tHostName 203.0.113.10\n",
    digest: "digest",
    editable: true,
    exists: true,
  },
};

function renderPanel(overrides: Partial<Parameters<typeof HostDetailPanel>[0]> = {}) {
  const handlers = {
    detail,
    groups: [{ name: "work" }],
    preview: null,
    problem: null,
    onFieldEdits: vi.fn(),
    onBlockRaw: vi.fn(),
    onRename: vi.fn(),
    onMetadata: vi.fn(),
    ...overrides,
  };
  render(<HostDetailPanel {...handlers} />);
  return handlers;
}

describe("HostDetailPanel", () => {
  it("shows basic fields first and keeps unknown directives editable", async () => {
    const user = userEvent.setup();
    renderPanel();

    expect(screen.getByLabelText("HostName")).toHaveValue("203.0.113.10");

    await user.click(screen.getByRole("tab", { name: "Advanced" }));

    expect(screen.getByLabelText("UnknownFutureDirective")).toHaveValue("yes");
  });

  it("marks executable directives instead of hiding them", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("tab", { name: "Jump" }));

    expect(screen.getByText(/ProxyCommand can run a command/i)).toBeInTheDocument();
  });

  it("sends a set edit with the parsed values", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    const input = screen.getByLabelText("HostName");
    await user.clear(input);
    await user.type(input, "198.51.100.7");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(handlers.onFieldEdits).toHaveBeenCalledWith([
      { action: "set", line: 2, values: ["198.51.100.7"] },
    ]);
  });

  it("sends an add edit for a new arbitrary directive", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    await user.click(screen.getByRole("tab", { name: "Advanced" }));
    await user.type(screen.getByLabelText("New directive"), "SetEnv");
    await user.type(screen.getByLabelText("New value"), "EDITOR=vi");
    await user.click(screen.getByRole("button", { name: "Add directive" }));
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(handlers.onFieldEdits).toHaveBeenCalledWith([
      { action: "add", keyword: "SetEnv", values: ["EDITOR=vi"] },
    ]);
  });

  it("keeps an unbalanced quote in the editor and refuses to submit it", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    const input = screen.getByLabelText("HostName");
    await user.clear(input);
    await user.type(input, '"unbalanced');
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(handlers.onFieldEdits).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/quote/i);
    expect(input).toHaveValue('"unbalanced');
  });

  it("labels the explained values as not being ssh -G", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("tab", { name: "Effective" }));

    expect(screen.getByRole("status")).toHaveTextContent(/ssh -G/);
  });

  it("submits the block raw editor unchanged", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    await user.click(screen.getByRole("tab", { name: "Raw" }));
    await user.click(screen.getByRole("button", { name: "Save block" }));

    expect(handlers.onBlockRaw).toHaveBeenCalledWith("Host bastion\n\tHostName 203.0.113.10\n");
  });
});
