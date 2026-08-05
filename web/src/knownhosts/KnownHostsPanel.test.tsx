import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KnownHostsPanel } from "./KnownHostsPanel";
import { ApiError } from "../api/client";
import type { IntegrationsApi, KnownHostCandidate } from "../api/integrations";

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

const candidateFingerprint = "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs";
const candidateKey = "AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS";

const candidate: KnownHostCandidate = {
  host: "new.example.com",
  port: 22,
  keyType: "ssh-ed25519",
  key: candidateKey,
  fingerprint: candidateFingerprint,
  verified: false,
};

const scanNotice =
  "ssh-keyscan proves only that something answered at this address. It does not prove the host's identity.";

function scanResult(...candidates: KnownHostCandidate[]) {
  return { notice: scanNotice, candidates };
}

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
    scanKnownHosts: vi.fn().mockResolvedValue(scanResult(candidate)),
    addKnownHost: vi.fn().mockResolvedValue({ changed: true, transactionId: "tx-2" }),
    passwordVault: vi.fn().mockResolvedValue({ exists: false, unlocked: false, aliases: [] }),
    initialiseVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    unlockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    lockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: false, aliases: [] }),
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

// openAddForm scans and opens the confirmation for the single candidate the
// scan returned.
async function openAddForm(api: IntegrationsApi) {
  render(<KnownHostsPanel api={api} />);
  await userEvent.type(await screen.findByLabelText("Host to scan"), "new.example.com");
  await userEvent.click(screen.getByRole("button", { name: "Scan" }));
  const row = await screen.findByRole("row", { name: /new\.example\.com/ });
  await userEvent.click(within(row).getByRole("button", { name: "Add" }));
}

const fingerprintField = /Fingerprint you obtained through another channel/;
const acknowledgement = /accept the risk/;

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

  it("never labels a scanned key verified, even when the response claims it is", async () => {
    // A scan cannot establish identity, so the label is a property of how the
    // key was obtained rather than of the flag the response carried.
    const api = buildApi({
      scanKnownHosts: vi.fn().mockResolvedValue(scanResult({ ...candidate, verified: true })),
    });
    render(<KnownHostsPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Host to scan"), "new.example.com");
    await userEvent.click(screen.getByRole("button", { name: "Scan" }));

    const row = await screen.findByRole("row", { name: /new\.example\.com/ });
    expect(within(row).getByText("unverified")).toBeInTheDocument();
    expect(within(row).queryByText("verified")).not.toBeInTheDocument();
    expect(within(row).queryByText(/trusted/i)).not.toBeInTheDocument();
  });

  it("keeps the add control unavailable until a fingerprint is typed or the risk is acknowledged", async () => {
    const api = buildApi();
    await openAddForm(api);

    const add = screen.getByRole("button", { name: "Add to known_hosts" });
    expect(add).toBeDisabled();

    await userEvent.type(screen.getByLabelText(fingerprintField), candidateFingerprint);
    expect(add).toBeEnabled();

    await userEvent.clear(screen.getByLabelText(fingerprintField));
    expect(add).toBeDisabled();

    await userEvent.click(screen.getByLabelText(acknowledgement));
    expect(add).toBeEnabled();
    expect(api.addKnownHost).not.toHaveBeenCalled();
  });

  it("refuses a typed fingerprint that does not match the candidate and shows the mismatch", async () => {
    const api = buildApi();
    await openAddForm(api);

    await userEvent.type(screen.getByLabelText(fingerprintField), "SHA256:notTheKeyThatWasScanned");
    await userEvent.click(screen.getByRole("button", { name: "Add to known_hosts" }));

    expect(api.addKnownHost).not.toHaveBeenCalled();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("does not match");
    expect(alert).toHaveTextContent("SHA256:notTheKeyThatWasScanned");
    expect(alert).toHaveTextContent(candidateFingerprint);
  });

  it("sends the typed fingerprint rather than an acknowledgement when the key was proven", async () => {
    const api = buildApi();
    await openAddForm(api);

    await userEvent.type(screen.getByLabelText(fingerprintField), `  ${candidateFingerprint}  `);
    await userEvent.click(screen.getByRole("button", { name: "Add to known_hosts" }));

    await waitFor(() =>
      expect(api.addKnownHost).toHaveBeenCalledWith(
        { host: "new.example.com", port: 22, keyType: "ssh-ed25519", key: candidateKey },
        candidateFingerprint,
        false,
      ),
    );
    expect(await screen.findByText(/tx-2/)).toBeInTheDocument();
  });

  it("adds an unverified key only on an explicit acknowledgement and forgets it afterwards", async () => {
    const api = buildApi();
    await openAddForm(api);

    await userEvent.click(screen.getByLabelText(acknowledgement));
    await userEvent.click(screen.getByRole("button", { name: "Add to known_hosts" }));

    await waitFor(() =>
      expect(api.addKnownHost).toHaveBeenCalledWith(
        { host: "new.example.com", port: 22, keyType: "ssh-ed25519", key: candidateKey },
        "",
        true,
      ),
    );
    // The acknowledgement is spent with the request; reopening asks again.
    const row = await screen.findByRole("row", { name: /new\.example\.com/ });
    await userEvent.click(within(row).getByRole("button", { name: "Add" }));
    expect(screen.getByLabelText(acknowledgement)).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Add to known_hosts" })).toBeDisabled();
  });

  it("does not carry a fingerprint typed for one key over to another", async () => {
    const other: KnownHostCandidate = {
      ...candidate,
      host: "other.example.com",
      keyType: "ssh-rsa",
      key: "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDother",
      fingerprint: "SHA256:aDifferentKeyEntirely",
    };
    const api = buildApi({ scanKnownHosts: vi.fn().mockResolvedValue(scanResult(candidate, other)) });
    await openAddForm(api);

    await userEvent.type(screen.getByLabelText(fingerprintField), candidateFingerprint);
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    const otherRow = await screen.findByRole("row", { name: /aDifferentKeyEntirely/ });
    await userEvent.click(within(otherRow).getByRole("button", { name: "Add" }));

    expect(screen.getByLabelText(fingerprintField)).toHaveValue("");
    expect(screen.getByRole("button", { name: "Add to known_hosts" })).toBeDisabled();
  });

  it("surfaces the refusal code from the add endpoint and stores nothing", async () => {
    // React's test environment installs one flag of its own on the window; any
    // other new global would have come from the panel.
    const frameworkGlobals = ["IS_REACT_ACT_ENVIRONMENT"];
    const globalsBefore = Object.keys(window);
    const api = buildApi({
      addKnownHost: vi.fn().mockRejectedValue(
        new ApiError("unverified_candidate", 409, {
          code: "unverified_candidate",
          message: "a scanned key needs a matching fingerprint or an explicit acknowledgement",
        }),
      ),
    });
    await openAddForm(api);

    await userEvent.click(screen.getByLabelText(acknowledgement));
    await userEvent.click(screen.getByRole("button", { name: "Add to known_hosts" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("unverified_candidate");
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    const added = Object.keys(window).filter(
      (key) => !globalsBefore.includes(key) && !frameworkGlobals.includes(key),
    );
    expect(added).toEqual([]);
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
