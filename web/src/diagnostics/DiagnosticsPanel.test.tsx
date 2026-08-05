import { render, screen, waitFor } from "@testing-library/react";
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
