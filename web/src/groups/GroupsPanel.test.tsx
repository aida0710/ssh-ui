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
  it("renames a group and carries its members and children with it", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: {
        ...overview.metadata,
        groups: [
          { name: "company", settings: [{ keyword: "ServerAliveInterval", values: ["30"] }] },
          { name: "build", parent: "company" },
        ],
      },
    } as never);
    vi.mocked(configApi.save).mockResolvedValue({ preview: { operation: "config.groups", diffs: [] } } as never);
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("Rename company to"), "corp");
    await user.click(screen.getByRole("button", { name: "Rename company" }));
    await user.click(screen.getByRole("button", { name: "Save groups" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalled());
    // The mocked client is module-level, so its calls accumulate across tests:
    // the last one is this test's.
    const saved = vi.mocked(configApi.save).mock.calls.at(-1)![0] as { metadata: {
      groups: { name: string; parent?: string }[];
      hosts: { group?: string }[];
    } };
    // The name is the group's only identifier, so all three references move
    // together: the group itself, the child that names it as a parent, and the
    // host that names it as its group.
    expect(saved.metadata.groups.map((group) => group.name)).toEqual(["corp", "build"]);
    expect(saved.metadata.groups.find((group) => group.name === "build")?.parent).toBe("corp");
    expect(saved.metadata.hosts.every((host) => host.group !== "company")).toBe(true);
    expect(saved.metadata.hosts.some((host) => host.group === "corp")).toBe(true);
  });

  it("refuses a rename onto a group that already exists instead of merging", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: {
        ...overview.metadata,
        groups: [{ name: "company" }, { name: "lab" }],
      },
    } as never);
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("Rename company to"), "lab");
    await user.click(screen.getByRole("button", { name: "Rename company" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("lab already exists");
    // Nothing was staged, so a later save cannot carry the merge through.
    expect(screen.getByRole("heading", { name: "company" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "lab" })).toBeInTheDocument();
  });

  it("refuses an empty rename", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.click(await screen.findByRole("button", { name: "Rename company" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("needs a name of its own");
  });
});
