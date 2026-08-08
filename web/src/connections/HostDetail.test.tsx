import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HostDetailPanel } from "./HostDetail";
import type { HostDetail } from "../api/config";
import type { IntegrationsApi } from "../api/integrations";

// Diagnostics タブは Diagnostics section と同じ検査を行うため、
// これは同じクライアントを注入する。どのメソッドもモックである。実物に届く
// テストはホストへ発信してしまい、このスイートのどのテストもプロセスを起動してはならない。
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
    terminalOptions: vi.fn().mockResolvedValue({
      selected: "terminal",
      terminals: [
        { id: "terminal", installed: true },
        { id: "iterm2", installed: true },
        { id: "kitty", installed: true },
      ],
    }),
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

    // このタブは開いている接続によって指定されるため、alias を求めない。
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
  // colour、tags、favourite flag、display order はインスペクターへ
  // 移った。以前ここで検証されていたものは HostInspector.test.tsx にある。
  it("writes a comment into the configuration rather than into metadata", async () => {
    const user = userEvent.setup();
    const handlers = renderPanel();

    await user.type(screen.getByLabelText("Comment"), "the production bastion");
    await user.click(screen.getByRole("button", { name: "Save comment" }));

    expect(handlers.onComment).toHaveBeenCalledWith("the production bastion");
    // comment がメタデータではなく設定への編集であることは、
    // 以前ここで、決して呼ばれない onMetadata を監視することで
    // 検証されていた。パネルにはもうそうしたプロパティはない——メタデータ
    // コントロールはインスペクターのものである——ため型がそれを示しており、
    // その検証はどこにも届かないコールバックを監視することになってしまう。
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

    // comment が存在すればそれが唯一の由来となる。note は廃止に
    // 向かっており、ファイルが述べることに勝ってはならない。
    expect(screen.getByLabelText("Comment")).toHaveValue("in the file");
    expect(screen.queryByText(/retires the note/)).not.toBeInTheDocument();
  });
});

describe("taking a connection out of every group", () => {
  // ボタンは空の選択に対して無効化されていたため、マウスなしで
  // 接続をグループから外に戻す方法がまったくなかった——そして
  // ドラッグ操作が存在する前は、マウスを使っても方法がなかった。
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
