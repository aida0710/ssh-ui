import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GroupsPanel } from "./GroupsPanel";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), preview: vi.fn(), save: vi.fn() } };
});

const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [],
  hosts: [{
    identity: { path: "config", alias: "build01" },
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    line: 1, patterns: ["build01"], editable: true,
  }],
  metadata: {
    schemaVersion: 1,
    groups: [{ name: "company", settings: [{ keyword: "ServerAliveInterval", values: ["30"] }] }],
    hosts: [{ identity: { path: "config", alias: "build01" }, group: "company" }],
  },
  diagnostics: [],
  notices: [],
};

beforeEach(() => {
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.preview).mockResolvedValue({
    operation: "config.groups",
    diffs: [{ path: "groups.ssh-ui.conf", created: true, lines: [{ op: "insert", text: "Host build01", newLine: 1 }] }],
    effective: [{ alias: "build01", changes: [{ keyword: "Port", before: [], after: ["2222"] }] }],
  } as never);
});

describe("GroupsPanel", () => {
  it("lists groups with their members and settings", async () => {
    render(<GroupsPanel />);

    expect(await screen.findByRole("heading", { name: "company" })).toBeInTheDocument();
    expect(screen.getByText("ServerAliveInterval 30")).toBeInTheDocument();
    expect(screen.getByText("build01")).toBeInTheDocument();
  });

  it("adds a child group and previews the effective value change before saving", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("New group name"), "work");
    await user.selectOptions(screen.getByLabelText("Parent group"), "company");
    await user.click(screen.getByRole("button", { name: "Add group" }));
    await user.click(screen.getByRole("button", { name: "Preview group changes" }));

    await waitFor(() => expect(configApi.preview).toHaveBeenCalledWith(expect.objectContaining({ kind: "groups" })));
    expect(await screen.findByText(/Port: unset → 2222/)).toBeInTheDocument();

    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1",
      written: ["groups.ssh-ui.conf"],
      preview: { operation: "config.groups", diffs: [] },
    } as never);
    await user.click(screen.getByRole("button", { name: "Save groups" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith(expect.objectContaining({
      kind: "groups",
      metadata: expect.objectContaining({
        groups: expect.arrayContaining([expect.objectContaining({ name: "work", parent: "company" })]),
      }),
    })));
  });
});
