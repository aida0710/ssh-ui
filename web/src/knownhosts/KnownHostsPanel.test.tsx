import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KnownHostsPanel } from "./KnownHostsPanel";
import type { IntegrationsApi } from "../api/integrations";

afterEach(() => {
  vi.restoreAllMocks();
});

const entry = {
  line: 2,
  digest: "a".repeat(64),
  marker: "",
  hosts: ["bastion.example.com", "203.0.113.10"],
  hashed: false,
  keyType: "ssh-ed25519",
  fingerprint: "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs",
  comment: "admin@example",
};

function buildApi(overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return {
    configCheck: vi.fn().mockResolvedValue({ root: "", files: [], diagnostics: [] }),
    effective: vi.fn(),
    reachability: vi.fn(),
    authentication: vi.fn(),
    terminalCommand: vi.fn(),
    terminalLaunch: vi.fn(),
    knownHosts: vi.fn().mockResolvedValue({ path: "~/.ssh/known_hosts", entries: [entry] }),
    deleteKnownHosts: vi.fn().mockResolvedValue({ changed: true, transactionId: "tx-1" }),
    scanKnownHosts: vi.fn().mockResolvedValue({
      notice:
        "ssh-keyscan proves only that something answered at this address. It does not prove the host's identity.",
      candidates: [
        {
          host: "new.example.com",
          port: 22,
          keyType: "ssh-ed25519",
          key: "AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS",
          fingerprint: "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs",
          verified: false,
        },
      ],
    }),
    ...overrides,
  };
}

describe("KnownHostsPanel", () => {
  it("lists entries with their fingerprints", async () => {
    render(<KnownHostsPanel api={buildApi()} />);

    const row = await screen.findByRole("row", { name: /bastion\.example\.com/ });
    expect(within(row).getByText(/SHA256:bytFrSjx/)).toBeInTheDocument();
  });

  it("confirms before deleting and sends the digest of the line that was shown", async () => {
    const api = buildApi();
    render(<KnownHostsPanel api={api} />);

    const row = await screen.findByRole("row", { name: /bastion\.example\.com/ });
    await userEvent.click(within(row).getByRole("button", { name: "Delete" }));
    // The first click asks; nothing is removed yet.
    expect(api.deleteKnownHosts).not.toHaveBeenCalled();

    await userEvent.click(await screen.findByRole("button", { name: "Confirm delete" }));
    await waitFor(() =>
      expect(api.deleteKnownHosts).toHaveBeenCalledWith([{ line: 2, digest: "a".repeat(64) }], "~/.ssh/known_hosts"),
    );
  });

  it("marks every scanned key unverified and refuses to call it trusted", async () => {
    const api = buildApi();
    render(<KnownHostsPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Host to scan"), "new.example.com");
    await userEvent.click(screen.getByRole("button", { name: "Scan" }));

    expect(await screen.findByText(/does not prove the host's identity/)).toBeInTheDocument();
    const candidate = await screen.findByRole("row", { name: /new\.example\.com/ });
    expect(within(candidate).getByText("unverified")).toBeInTheDocument();
    expect(within(candidate).queryByText("verified")).not.toBeInTheDocument();
  });

  it("reports a refused deletion without claiming the entry was removed", async () => {
    const api = buildApi({
      deleteKnownHosts: vi.fn().mockRejectedValue(new Error("api_mutation_failed")),
    });
    render(<KnownHostsPanel api={api} />);

    const row = await screen.findByRole("row", { name: /bastion\.example\.com/ });
    await userEvent.click(within(row).getByRole("button", { name: "Delete" }));
    await userEvent.click(await screen.findByRole("button", { name: "Confirm delete" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not/i);
  });
});
