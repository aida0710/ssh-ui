import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GroupsPanel, treeOrder } from "./GroupsPanel";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return {
    ...actual,
    configApi: {
      overview: vi.fn(),
      preview: vi.fn(),
      save: vi.fn(),
      renameGroup: vi.fn(),
      deleteGroup: vi.fn(),
    },
  };
});

// build01 sits in connections/company, so it is in the "company" group. The
// projection reports that on the entry; nothing here reads a metadata field,
// because there is no longer one to read.
const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [],
  hosts: [
    {
      identity: { path: "connections/company/build.conf", alias: "build01" },
      file: { path: "connections/company/build.conf", absolute: "/home/tester/.ssh/connections/company/build.conf" },
      line: 1,
      patterns: ["build01"],
      editable: true,
      group: "company",
    },
  ],
  metadata: {
    schemaVersion: 2,
    groups: [{ name: "company", settings: [{ keyword: "ServerAliveInterval", values: ["30"] }] }],
    hosts: [{ identity: { path: "connections/company/build.conf", alias: "build01" } }],
  },
  groups: [],
  diagnostics: [],
  notices: [],
};

beforeEach(() => {
  // The mocked client is module-level, so its recorded calls would otherwise
  // accumulate across tests and "was not called" would be about the wrong test.
  vi.clearAllMocks();
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.preview).mockResolvedValue({
    operation: "config.groups",
    diffs: [{ path: "groups.ssh-ui.conf", created: true, lines: [{ op: "insert", text: "Host build01", newLine: 1 }] }],
    effective: [{ alias: "build01", changes: [{ keyword: "Port", before: [], after: ["2222"] }] }],
  } as never);
});

describe("GroupsPanel", () => {
  it("lists groups with their directories, members and settings", async () => {
    render(<GroupsPanel />);

    expect(await screen.findByRole("heading", { name: "company" })).toBeInTheDocument();
    expect(screen.getByText("ServerAliveInterval 30")).toBeInTheDocument();
    expect(screen.getByText("build01")).toBeInTheDocument();
    // The directory is the group, so the panel says where it is rather than
    // leaving the user to infer it.
    expect(screen.getByText("connections/company/ · keys/company/")).toBeInTheDocument();
  });

  it("adds a nested group by naming its path and saves it", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    // A slash is the whole of the nesting syntax: the name carries the
    // hierarchy, so there is no parent field that could disagree with it.
    await user.type(await screen.findByLabelText("New group name"), "company/work");
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

    await waitFor(() =>
      expect(configApi.save).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "groups",
          metadata: expect.objectContaining({
            groups: expect.arrayContaining([expect.objectContaining({ name: "company/work" })]),
          }),
        }),
      ),
    );
  });

  it("refuses a name that is not a safe relative directory", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("New group name"), "../escape");
    await user.click(screen.getByRole("button", { name: "Add group" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("relative directory path");
    expect(configApi.save).not.toHaveBeenCalled();
  });

  it("renames a group through the server rather than editing the document", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.renameGroup).mockResolvedValue({
      transactionId: "t1",
      written: ["config"],
      preview: { operation: "config.group_rename", diffs: [] },
    } as never);
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("Rename company to"), "corp");
    await user.click(screen.getByRole("button", { name: "Rename company" }));

    // A group is a directory, so a rename is N file moves plus the Include
    // region plus every IdentityFile naming its keys: one transaction the
    // client cannot assemble, so it asks the server to do it.
    await waitFor(() => expect(configApi.renameGroup).toHaveBeenCalledWith("company", "corp"));
    expect(configApi.save).not.toHaveBeenCalled();
  });

  it("refuses a rename onto a group that already exists instead of merging", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: { ...overview.metadata, groups: [{ name: "company" }, { name: "lab" }] },
    } as never);
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("Rename company to"), "lab");
    await user.click(screen.getByRole("button", { name: "Rename company" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("lab already exists");
    // Nothing was asked of the server, so the merge cannot happen by accident.
    expect(configApi.renameGroup).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "company" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "lab" })).toBeInTheDocument();
  });

  it("refuses an empty rename", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.click(await screen.findByRole("button", { name: "Rename company" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("needs a name of its own");
  });

  it("removes a group by naming where its connections go", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: { ...overview.metadata, groups: [{ name: "company" }, { name: "archive" }] },
    } as never);
    vi.mocked(configApi.deleteGroup).mockResolvedValue({
      transactionId: "t1",
      written: ["config"],
      preview: { operation: "config.group_delete", diffs: [] },
    } as never);
    render(<GroupsPanel />);

    // Removing a group relocates its connections; nothing is deleted. The
    // destination is asked for inside the removal, after a sentence that says
    // what removal does, rather than by a select sitting on its own with a
    // label that never mentioned removal.
    await user.click(await screen.findByRole("button", { name: "Remove company" }));
    expect(screen.getByText(/takes away its Include line/)).toBeInTheDocument();
    expect(screen.getByText(/No configuration file is deleted/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Move its connections to"), "archive");
    await user.click(screen.getByRole("button", { name: "Remove company" }));

    await waitFor(() => expect(configApi.deleteGroup).toHaveBeenCalledWith("company", "archive"));
  });
  it("marks a group that is only in the draft, and will not write files for it", async () => {
    // The panel has two kinds of control and used to show no difference. A
    // group added here exists only on screen until Save, but it looked exactly
    // like one with a directory, and offered Rename and Remove — which write
    // files, for a group that has none.
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText(/New group name/i), "lab");
    await user.click(screen.getByRole("button", { name: "Add group" }));

    expect(await screen.findByText("Not saved")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove lab" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Rename lab" })).toBeDisabled();
    expect(screen.getByText(/no directory yet/)).toBeInTheDocument();
    // And the page says which half of it needs Save at all.
    expect(screen.getByText(/until you press Save/)).toBeInTheDocument();
  });

  // The bug: the panel sorted by the rule that decides the Include order —
  // deepest group first — and then indented as though that were a tree. Every
  // child floated above its parent and the parent came last, which reads as
  // nesting not working at all.
  it("lists a parent before its children", async () => {
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: {
        ...overview.metadata,
        groups: [{ name: "office/tokyo" }, { name: "hpc" }, { name: "office" }, { name: "office/osaka" }],
      },
    } as never);
    render(<GroupsPanel />);

    await screen.findByRole("heading", { name: "hpc" });
    const list = screen.getByRole("list", { name: "Groups, parent before child" });
    const headings = within(list)
      .getAllByRole("heading", { level: 3 })
      .map((heading) => heading.textContent);
    expect(headings).toEqual(["hpc", "office", "office/osaka", "office/tokyo"]);
  });

  it("orders siblings by display order and keeps them under their own parent", () => {
    const ordered = treeOrder([
      { name: "office/tokyo" },
      { name: "office", order: 2 },
      { name: "hpc", order: 1 },
      { name: "office/osaka", order: -1 },
    ]).map((group) => group.name);

    // hpc before office by their own order; osaka before tokyo by theirs; and
    // neither child escapes to the top, which is what the file order would do.
    expect(ordered).toEqual(["hpc", "office", "office/osaka", "office/tokyo"]);
  });

  it("offers a child group from the group it would sit inside", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.click(await screen.findByRole("button", { name: "Add a group inside company" }));

    // The path is prefilled, so the user types the child's name and nothing
    // else — nesting was previously discoverable only from a sentence about
    // slashes at the bottom of the page.
    expect(screen.getByLabelText("New group name")).toHaveValue("company/");
  });
});

describe("hiding a group from the connections tree", () => {
  // "company" holds build01 directly; "company/eu" holds nothing, which is what
  // a group made to contain other groups looks like.
  const withContainer = {
    ...overview,
    metadata: {
      ...overview.metadata,
      groups: [{ name: "company" }, { name: "company/eu" }],
    },
  };

  it("offers it for a group that holds no connections of its own", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue(withContainer as never);
    render(<GroupsPanel />);

    const toggle = await screen.findByLabelText("Hide company/eu from Connections");
    expect(toggle).toBeEnabled();

    await user.click(toggle);
    expect(toggle).toBeChecked();
  });

  // Hiding a group that holds connections would take them out of view with it.
  // Refusing the control is better than a flag that quietly does nothing.
  it("refuses it for a group that holds connections, and says why", async () => {
    vi.mocked(configApi.overview).mockResolvedValue(withContainer as never);
    render(<GroupsPanel />);

    expect(await screen.findByLabelText("Hide company from Connections")).toBeDisabled();
    expect(screen.getByText(/holds connections of its own/)).toBeInTheDocument();
  });

  // A directory under connections/ that no Include names looks like a group and
  // is read by nothing. The engine has always known; nothing showed it.
  it("shows a directory that looks like a group but is declared by nothing", async () => {
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      notices: [
        { code: "group_not_declared", detail: "scratch", path: "connections/scratch" },
        { code: "group_empty", detail: "archive", path: "connections/archive" },
      ],
    } as never);
    render(<GroupsPanel />);

    expect(await screen.findByText(/no Include line names it/)).toBeInTheDocument();

    // An empty group is not one of them. It is the state every group is in for
    // the moment after it is made, and the row below already reads
    // "Members: none" — reporting it again in amber spent the colour that is
    // supposed to mean something happened, on nothing happening.
    expect(screen.queryByText(/declared and holds nothing/)).toBeNull();
  });
});
