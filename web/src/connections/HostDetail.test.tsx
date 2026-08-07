import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HostDetailPanel } from "./HostDetail";
import type { HostDetail } from "../api/config";
import type { IntegrationsApi } from "../api/integrations";

// The Diagnostics tab runs the same checks as the Diagnostics section, so this
// injects the same client. Every method is a mock: a test that reached the real
// one would dial a host, and no test in this suite may start a process.
function buildIntegrations(overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return {
    configCheck: vi.fn(),
    effective: vi.fn(),
    reachability: vi.fn().mockResolvedValue({
      address: "203.0.113.10:22",
      outcome: "reached",
      elapsedMs: 12,
      detail: "",
      notice: "This check dialled the destination directly.",
    }),
    authentication: vi.fn(),
    terminalCommand: vi.fn(),
    terminalLaunch: vi.fn(),
    knownHosts: vi.fn(),
    deleteKnownHosts: vi.fn(),
    scanKnownHosts: vi.fn(),
    addKnownHost: vi.fn(),
    passwordVault: vi.fn().mockResolvedValue({ exists: false, unlocked: false, aliases: [] }),
    initialiseVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    unlockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    lockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: false, aliases: [] }),
    changeMasterPassword: vi.fn(),
    loginItem: vi.fn().mockResolvedValue({ enabled: false, supported: true }),
    updateStatus: vi.fn().mockResolvedValue({ current: "dev", available: false, restartRequired: false }),
    setLoginItem: vi.fn().mockResolvedValue({ enabled: true, supported: true }),
    credentials: vi.fn().mockResolvedValue({ credentials: [] }),
    storeCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    deleteCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    assignCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    unassignCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    passwordEligibility: vi.fn().mockResolvedValue({
      alias: "bastion", storable: true, blockers: [], warnings: [],
    }),
    storePassword: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    forgetPassword: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    syncStatus: vi.fn().mockResolvedValue({ configured: false, endpoint: "", bucket: "", synced: false }),
    configureSync: vi.fn().mockResolvedValue({ configured: true, endpoint: "", bucket: "", synced: false }),
    pushSnapshot: vi.fn().mockResolvedValue({ configured: true, endpoint: "", bucket: "", synced: true }),
    pullSnapshot: vi.fn().mockResolvedValue({ applied: false, conflicts: [], written: [], removed: [] }),
    ...overrides,
  };
}

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
    comment: "",
    commentLines: 0,
    notices: [{ code: "dangerous_directive", path: "config", line: 5, detail: "ProxyCommand" }],
  },
  metadata: { identity: { path: "config", alias: "bastion" }, favourite: false },
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
    onComment: vi.fn(),
    onMoveToGroup: vi.fn(),
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

  it("sends the Effective tab to the authoritative check rather than describing it", async () => {
    const user = userEvent.setup();
    renderPanel({ integrations: buildIntegrations() });

    await user.click(screen.getByRole("tab", { name: "Effective" }));
    await user.click(screen.getByRole("button", { name: "Open the Diagnostics tab" }));

    expect(screen.getByRole("tab", { name: "Diagnostics" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("region", { name: "Diagnostics for bastion" })).toBeInTheDocument();
  });

  it("runs the real checks on the Diagnostics tab, against this host and only when asked", async () => {
    const user = userEvent.setup();
    const integrations = buildIntegrations();
    renderPanel({ integrations });

    await user.click(screen.getByRole("tab", { name: "Diagnostics" }));

    // The tab is addressed by the open connection, so it asks for no alias.
    expect(screen.queryByLabelText("Host alias")).not.toBeInTheDocument();
    expect(integrations.reachability).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Check reachability" }));

    await waitFor(() => expect(integrations.reachability).toHaveBeenCalledWith("bastion"));
  });

  it("has nothing to diagnose for a block that names no destination", async () => {
    const user = userEvent.setup();
    const patternDetail: HostDetail = {
      ...detail,
      form: {
        ...detail.form,
        entry: { ...detail.form.entry, identity: { path: "config", alias: "" }, patterns: ["*"] },
      },
    };
    const integrations = buildIntegrations();
    renderPanel({ detail: patternDetail, integrations });

    await user.click(screen.getByRole("tab", { name: "Diagnostics" }));

    expect(screen.getByText(/names no destination of its own/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check reachability" })).not.toBeInTheDocument();
  });
  // The colour, the tags, the favourite flag and the display order moved to
  // the inspector; HostInspector.test.tsx holds what used to be asserted here.
  it("writes a comment into the configuration rather than into metadata", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    await user.type(screen.getByLabelText("Comment"), "the production bastion");
    await user.click(screen.getByRole("button", { name: "Save comment" }));

    expect(handlers.onComment).toHaveBeenCalledWith("the production bastion");
    // That the comment is a configuration edit and not metadata used to be
    // asserted here, by watching an onMetadata that was never called. The
    // panel has no such prop any more — the metadata controls are the
    // inspector's — so the type says it and the assertion would be watching
    // a callback nothing could reach.
  });

  it("seeds the editor from a legacy note and says the save retires it", () => {
    renderPanel({
      detail: { ...detail, metadata: { ...detail.metadata, note: "written before comments existed" } },
    });

    expect(screen.getByLabelText("Comment")).toHaveValue("written before comments existed");
    expect(screen.getByText(/retires the note/)).toBeInTheDocument();
  });

  it("prefers the configuration comment over a stale note", () => {
    renderPanel({
      detail: {
        ...detail,
        form: { ...detail.form, comment: "in the file" },
        metadata: { ...detail.metadata, note: "left over" },
      },
    });

    // Once the comment exists it is the only source; the note is on its way out
    // and must never win over what the file says.
    expect(screen.getByLabelText("Comment")).toHaveValue("in the file");
    expect(screen.queryByText(/retires the note/)).not.toBeInTheDocument();
  });
});

describe("taking a connection out of every group", () => {
  // The button was disabled for the empty choice, so there was no way at all to
  // take a connection back out of a group without a mouse — and, before
  // dragging existed, no way with one either.
  const grouped: HostDetail = {
    ...detail,
    form: { ...detail.form, entry: { ...detail.form.entry, group: "work" } },
  };

  it("offers the empty choice for a connection that is in a group", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel({ detail: grouped });

    await user.selectOptions(screen.getByLabelText("Primary group"), "");
    const button = screen.getByRole("button", { name: "Move to this group" });
    expect(button).toBeEnabled();

    await user.click(button);
    expect(handlers.onMoveToGroup).toHaveBeenCalledWith("");
  });

  it("offers nothing to do for a connection that is in no group already", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.selectOptions(screen.getByLabelText("Primary group"), "");
    expect(screen.getByRole("button", { name: "Move to this group" })).toBeDisabled();
  });

  it("still offers nothing to do for the group the connection is already in", async () => {
    const user = userEvent.setup();
    renderPanel({ detail: grouped });

    await user.selectOptions(screen.getByLabelText("Primary group"), "work");
    expect(screen.getByRole("button", { name: "Move to this group" })).toBeDisabled();
  });
});
