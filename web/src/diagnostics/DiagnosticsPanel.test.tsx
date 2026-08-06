import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DiagnosticsPanel } from "./DiagnosticsPanel";
import type { IntegrationsApi } from "../api/integrations";

afterEach(() => {
  vi.restoreAllMocks();
});

function buildApi(overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return {
    configCheck: vi.fn().mockResolvedValue({
      root: "~/.ssh/config",
      files: [{ path: "~/.ssh/config", editable: true, missing: false, loads: 1, includes: 0 }],
      diagnostics: [],
    }),
    effective: vi.fn().mockResolvedValue({
      alias: "bastion",
      evaluated: true,
      requiresConfirmation: false,
      tokenWarning: "OpenSSH does not shell-escape the tokens it expands.",
      executableDirectives: [],
      values: [{ keyword: "hostname", values: ["203.0.113.10"] }],
      sources: [
        { keyword: "HostName", value: "203.0.113.10", path: "~/.ssh/config", line: 2, condition: "Host bastion", kind: "exact", winner: true },
      ],
      complexities: [],
      route: [],
      failure: { failed: false, exitCode: 0, stderr: "", truncated: false },
    }),
    reachability: vi.fn().mockResolvedValue({
      address: "203.0.113.10:22",
      outcome: "reached",
      elapsedMs: 12,
      detail: "",
      notice: "This check dialled the destination directly. ProxyJump, ProxyCommand and any jump-host firewall were not used.",
    }),
    authentication: vi.fn().mockResolvedValue({
      outcome: "authenticated",
      authenticated: true,
      exitCode: 0,
      stderr: "",
      truncated: false,
      elapsedMs: 40,
    }),
    terminalCommand: vi.fn().mockResolvedValue({ command: "ssh -- bastion", launchable: true, warning: "" }),
    terminalLaunch: vi.fn().mockResolvedValue({ launched: true }),
    knownHosts: vi.fn().mockResolvedValue({ path: "~/.ssh/known_hosts", entries: [] }),
    deleteKnownHosts: vi.fn().mockResolvedValue({ changed: true, transactionId: "tx" }),
    scanKnownHosts: vi.fn().mockResolvedValue({ notice: "unverified", candidates: [] }),
    addKnownHost: vi.fn().mockResolvedValue({ changed: true, transactionId: "tx" }),
    passwordVault: vi.fn().mockResolvedValue({ exists: false, unlocked: false, aliases: [] }),
    initialiseVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    unlockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    lockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: false, aliases: [] }),
    changeMasterPassword: vi.fn(),
    loginItem: vi.fn().mockResolvedValue({ enabled: false, supported: true }),
    updateStatus: vi.fn().mockResolvedValue({ current: "dev", available: false, restartRequired: false }),
    applyUpdate: vi.fn().mockResolvedValue({ current: "dev", available: false, restartRequired: true }),
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

describe("DiagnosticsPanel", () => {
  it("runs no check until the user asks for one", async () => {
    const api = buildApi();
    render(<DiagnosticsPanel api={api} />);

    await waitFor(() => expect(api.configCheck).toHaveBeenCalled());
    expect(api.effective).not.toHaveBeenCalled();
    expect(api.reachability).not.toHaveBeenCalled();
    expect(api.authentication).not.toHaveBeenCalled();
    expect(api.terminalLaunch).not.toHaveBeenCalled();
  });

  it("offers no check until an alias is typed", async () => {
    // With an empty box every button was live, and pressing one asked the
    // server to explain the empty alias.
    const api = buildApi();
    render(<DiagnosticsPanel api={api} />);

    expect(screen.getByRole("button", { name: "Explain" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Check reachability" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Test authentication" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Terminal command" })).toBeDisabled();

    await userEvent.type(screen.getByLabelText("Host alias"), "bastion");

    expect(screen.getByRole("button", { name: "Explain" })).toBeEnabled();
  });

  it("names the columns of the sources table", async () => {
    // A path, a condition and a verdict rendered as three unlabelled greys are
    // not self-describing, however good the caption is.
    const api = buildApi();
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "bastion");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    expect(await screen.findByRole("columnheader", { name: "Keyword" })).toBeInTheDocument();
    for (const column of ["Value", "Read from", "Under", "State"]) {
      expect(screen.getByRole("columnheader", { name: column })).toBeInTheDocument();
    }
  });

  it("explains an alias and shows where each value came from", async () => {
    const api = buildApi();
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "bastion");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    await waitFor(() => expect(api.effective).toHaveBeenCalledWith("bastion", false));
    expect(await screen.findByText("203.0.113.10")).toBeInTheDocument();
    expect(screen.getByText(/~\/\.ssh\/config:2/)).toBeInTheDocument();
  });

  it("requires an explicit confirmation before evaluating a configuration that can run a command", async () => {
    const api = buildApi({
      effective: vi.fn().mockResolvedValue({
        alias: "risky",
        evaluated: false,
        requiresConfirmation: true,
        tokenWarning: "OpenSSH does not shell-escape the tokens it expands.",
        executableDirectives: [
          {
            keyword: "Match exec",
            command: "test -f /tmp/at-work",
            path: "~/.ssh/config",
            line: 6,
            condition: "",
            onEvaluate: true,
            onConnect: true,
            overridable: false,
          },
        ],
        values: [],
        sources: [],
        complexities: [],
        route: [],
        failure: { failed: false, exitCode: 0, stderr: "", truncated: false },
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "risky");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    // The exact command and the token-escaping warning are both displayed.
    expect(await screen.findByText("test -f /tmp/at-work")).toBeInTheDocument();
    expect(screen.getByText(/does not shell-escape/)).toBeInTheDocument();
    expect(api.effective).toHaveBeenCalledTimes(1);
    expect(api.effective).toHaveBeenLastCalledWith("risky", false);

    await userEvent.click(screen.getByRole("button", { name: "Run ssh -G anyway" }));
    await waitFor(() => expect(api.effective).toHaveBeenLastCalledWith("risky", true));
  });

  it("offers a copyable command instead of a launch for an unsafe alias", async () => {
    const api = buildApi({
      terminalCommand: vi.fn().mockResolvedValue({
        command: `ssh -- weird "alias"`,
        launchable: false,
        warning: "This alias contains characters that could change the meaning of a command line.",
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "weird");
    await userEvent.click(screen.getByRole("button", { name: "Terminal command" }));

    expect(await screen.findByText(`ssh -- weird "alias"`)).toBeInTheDocument();
    expect(screen.getByText(/could change the meaning/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open in Terminal" })).not.toBeInTheDocument();
    expect(api.terminalLaunch).not.toHaveBeenCalled();
  });

  it("says that a reachability check ignored ProxyJump", async () => {
    const api = buildApi();
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "bastion");
    await userEvent.click(screen.getByRole("button", { name: "Check reachability" }));

    expect(await screen.findByText(/ProxyJump, ProxyCommand and any jump-host firewall were not used/)).toBeInTheDocument();
  });

  it("reports a failed check without claiming success", async () => {
    const api = buildApi({
      reachability: vi.fn().mockRejectedValue(new Error("api_mutation_failed")),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "bastion");
    await userEvent.click(screen.getByRole("button", { name: "Check reachability" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not/i);
  });

  it("shows what OpenSSH said when it refused, instead of rendering nothing", async () => {
    // A failed `ssh -G` is a 200 with the reason inside it. Nothing throws, so
    // the panel used to render silence and the click looked like a no-op.
    const api = buildApi({
      effective: vi.fn().mockResolvedValue({
        alias: "broken",
        evaluated: false,
        requiresConfirmation: false,
        tokenWarning: "",
        executableDirectives: [],
        values: [],
        sources: [],
        complexities: [],
        route: [],
        failure: {
          failed: true,
          exitCode: 255,
          stderr: "/home/tester/.ssh/config line 12: Bad configuration option: HostNam",
          truncated: false,
        },
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "broken");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    expect(await screen.findByText(/ssh -G exited with 255/)).toBeInTheDocument();
    expect(screen.getByText(/Bad configuration option: HostNam/)).toBeInTheDocument();
  });

  it("says when the captured output was cut off rather than presenting it whole", async () => {
    const api = buildApi({
      effective: vi.fn().mockResolvedValue({
        alias: "broken",
        evaluated: false,
        requiresConfirmation: false,
        tokenWarning: "",
        executableDirectives: [],
        values: [],
        sources: [],
        complexities: [],
        route: [],
        failure: { failed: true, exitCode: 255, stderr: "the first 64 KiB", truncated: true },
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "broken");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    expect(await screen.findByText(/hit the capture limit and was cut off/)).toBeInTheDocument();
  });

  it("marks the rules it will not project instead of answering for them", async () => {
    const api = buildApi({
      effective: vi.fn().mockResolvedValue({
        alias: "lab",
        evaluated: true,
        requiresConfirmation: false,
        tokenWarning: "",
        executableDirectives: [],
        values: [],
        sources: [],
        complexities: [
          {
            code: "negated_pattern",
            path: "~/.ssh/config",
            line: 21,
            condition: "Host *,!lab",
            detail: "A negated pattern does not project onto a single host.",
          },
        ],
        route: [],
        failure: { failed: false, exitCode: 0, stderr: "", truncated: false },
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "lab");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    expect(await screen.findByText("negated_pattern")).toBeInTheDocument();
    expect(screen.getByText(/~\/\.ssh\/config:21/)).toBeInTheDocument();
    expect(screen.getByText(/inside Host \*,!lab/)).toBeInTheDocument();
    expect(screen.getByText(/does not project onto a single host/)).toBeInTheDocument();
  });

  it("shows the multi-hop route and marks a hop it did not resolve", async () => {
    const api = buildApi({
      effective: vi.fn().mockResolvedValue({
        alias: "deep",
        evaluated: true,
        requiresConfirmation: false,
        tokenWarning: "",
        executableDirectives: [],
        values: [],
        sources: [],
        complexities: [],
        route: [
          { order: 0, depth: 0, parent: "", hop: "edge", hostname: "198.51.100.1", user: "ops", port: "22", complex: false },
          { order: 1, depth: 1, parent: "edge", hop: "inner-*", hostname: "", user: "", port: "", complex: true },
        ],
        failure: { failed: false, exitCode: 0, stderr: "", truncated: false },
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "deep");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    expect(await screen.findByText("edge")).toBeInTheDocument();
    expect(screen.getByText("ops@198.51.100.1:22")).toBeInTheDocument();
    expect(screen.getByText("inner-*")).toBeInTheDocument();
    expect(screen.getByText(/not a simple alias/)).toBeInTheDocument();
    expect(screen.getByText(/reached through edge/)).toBeInTheDocument();
  });

  it("keeps the lines that lost, because they are the answer to why not", async () => {
    const api = buildApi({
      effective: vi.fn().mockResolvedValue({
        alias: "bastion",
        evaluated: true,
        requiresConfirmation: false,
        tokenWarning: "",
        executableDirectives: [],
        values: [],
        sources: [
          { keyword: "Port", value: "2222", path: "~/.ssh/config", line: 4, condition: "Host bastion", kind: "exact", winner: true },
          { keyword: "Port", value: "22", path: "~/.ssh/config", line: 11, condition: "Host *", kind: "wildcard", winner: false },
        ],
        complexities: [],
        route: [],
        failure: { failed: false, exitCode: 0, stderr: "", truncated: false },
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    await userEvent.type(screen.getByLabelText("Host alias"), "bastion");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));

    const superseded = await screen.findByRole("row", { name: /Host \*/ });
    expect(within(superseded).getByText("22")).toBeInTheDocument();
    expect(within(superseded).getByText("superseded")).toBeInTheDocument();
    expect(within(screen.getByRole("row", { name: /Host bastion/ })).getByText("in effect")).toBeInTheDocument();
  });

  it("shows the configuration diagnostics it already read", async () => {
    const api = buildApi({
      configCheck: vi.fn().mockResolvedValue({
        root: "~/.ssh/config",
        files: [{ path: "~/.ssh/config", editable: true, missing: false, loads: 1, includes: 1 }],
        diagnostics: [
          {
            severity: "error",
            code: "include_cycle",
            path: "~/.ssh/conf.d/10-home.conf",
            line: 3,
            detail: "This file includes itself.",
          },
        ],
      }),
    });
    render(<DiagnosticsPanel api={api} />);

    expect(await screen.findByText(/include_cycle/)).toBeInTheDocument();
    expect(screen.getByText(/This file includes itself/)).toBeInTheDocument();
  });

  it("diagnoses a fixed host without asking for an alias", async () => {
    const api = buildApi();
    render(<DiagnosticsPanel api={api} host="bastion" />);

    expect(screen.queryByLabelText("Host alias")).not.toBeInTheDocument();
    // The file list belongs to the Config section; a fixed host does not read it.
    expect(api.configCheck).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Check reachability" }));

    await waitFor(() => expect(api.reachability).toHaveBeenCalledWith("bastion"));
    expect(await screen.findByText(/203\.0\.113\.10:22/)).toBeInTheDocument();
  });

  it("starts no check of its own when a fixed host is opened", async () => {
    const api = buildApi();
    render(<DiagnosticsPanel api={api} host="bastion" />);

    expect(api.effective).not.toHaveBeenCalled();
    expect(api.reachability).not.toHaveBeenCalled();
    expect(api.authentication).not.toHaveBeenCalled();
    expect(api.terminalCommand).not.toHaveBeenCalled();
    expect(api.terminalLaunch).not.toHaveBeenCalled();
  });

  it("drops the previous host's results when the fixed host changes", async () => {
    const api = buildApi();
    const { rerender } = render(<DiagnosticsPanel api={api} host="bastion" />);

    await userEvent.click(screen.getByRole("button", { name: "Check reachability" }));
    expect(await screen.findByText(/203\.0\.113\.10:22/)).toBeInTheDocument();

    // A verdict earned by bastion must not sit under nas and read as its own.
    rerender(<DiagnosticsPanel api={api} host="nas" />);

    await waitFor(() => expect(screen.queryByText(/203\.0\.113\.10:22/)).not.toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "Reachability" })).not.toBeInTheDocument();
  });
});
