import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SyncPanel } from "./SyncPanel";
import type { IntegrationsApi, PullResponse, SyncStatus } from "../api/integrations";

afterEach(() => {
  vi.restoreAllMocks();
});

const unconfigured: SyncStatus = { configured: false, endpoint: "", bucket: "", synced: false };
const configured: SyncStatus = {
  configured: true,
  endpoint: "https://acc.r2.cloudflarestorage.com",
  bucket: "ssh-ui",
  synced: true,
  lastSyncedAt: "2026-08-05T00:00:00Z",
  fileCount: 7,
};

function buildApi(status: SyncStatus, pull: PullResponse, overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return {
    syncStatus: vi.fn().mockResolvedValue(status),
    configureSync: vi.fn().mockResolvedValue({ ...status, configured: true }),
    pushSnapshot: vi.fn().mockResolvedValue({ ...status, synced: true }),
    pullSnapshot: vi.fn().mockResolvedValue(pull),
    ...overrides,
  } as unknown as IntegrationsApi;
}

const nothingToDo: PullResponse = { applied: false, conflicts: [], written: [], removed: [] };

describe("SyncPanel", () => {
  it("says what travels before the form asks for anything", async () => {
    render(<SyncPanel api={buildApi(unconfigured, nothingToDo)} />);

    expect(await screen.findByText(/including your private keys/)).toBeInTheDocument();
    expect(screen.getByText(/attack that passphrase offline/)).toBeInTheDocument();
  });

  it("configures a bucket and clears the credentials from the form", async () => {
    // A secret left in a field after it has been sent is a secret sitting in
    // the DOM for no reason.
    const api = buildApi(unconfigured, nothingToDo);
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://acc.r2.cloudflarestorage.com");
    await userEvent.type(screen.getByLabelText("Bucket name"), "ssh-ui");
    await userEvent.type(screen.getByLabelText("Access key ID"), "AKID");
    await userEvent.type(screen.getByLabelText("Secret access key"), "the-secret");
    await userEvent.click(screen.getByRole("button", { name: "Use this bucket" }));

    await waitFor(() =>
      expect(api.configureSync).toHaveBeenCalledWith({
        endpoint: "https://acc.r2.cloudflarestorage.com",
        bucket: "ssh-ui",
        accessKeyId: "AKID",
        secretAccessKey: "the-secret",
      }),
    );
    await waitFor(() =>
      expect((screen.getByLabelText("Secret access key") as HTMLInputElement).value).toBe(""),
    );
    expect(document.body.textContent ?? "").not.toContain("the-secret");
  });

  it("offers no push or pull until a bucket and a passphrase are given", async () => {
    render(<SyncPanel api={buildApi(unconfigured, nothingToDo)} />);

    expect(await screen.findByRole("button", { name: "Push this workspace" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Check for changes" })).toBeDisabled();
  });

  it("previews before it applies", async () => {
    // A pull that wrote on the first press would be the only write in this
    // application that skipped its preview.
    const api = buildApi(configured, {
      applied: false,
      conflicts: [],
      written: ["config", "connections/work/lon.conf"],
      removed: ["connections/old.conf"],
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Snapshot passphrase"), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: "Check for changes" }));

    await waitFor(() => expect(api.pullSnapshot).toHaveBeenCalledWith("correct horse battery staple", false));
    expect(await screen.findByText("connections/work/lon.conf")).toBeInTheDocument();
    expect(screen.getByText("connections/old.conf")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Apply the snapshot" }));
    await waitFor(() => expect(api.pullSnapshot).toHaveBeenLastCalledWith("correct horse battery staple", true));
  });

  it("shows a conflict and refuses to apply it", async () => {
    // Two configurations that both changed the same block have no correct
    // merge, so this names the files and stops.
    const api = buildApi(configured, {
      applied: false,
      conflicts: [{ path: "config", changedHere: true, changedThere: true }],
      written: [],
      removed: [],
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Snapshot passphrase"), "a passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Check for changes" }));

    expect(await screen.findByText(/changed here and on the other machine/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply the snapshot" })).toBeDisabled();
  });

  it("says so when there is nothing to do", async () => {
    const api = buildApi(configured, nothingToDo);
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Snapshot passphrase"), "a passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Check for changes" }));

    expect(await screen.findByText(/already matches the snapshot/)).toBeInTheDocument();
  });

  it("reports a refused push instead of claiming success", async () => {
    const api = buildApi(configured, nothingToDo, {
      pushSnapshot: vi.fn().mockRejectedValue(new Error("sync_remote_moved")),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Snapshot passphrase"), "a passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Push this workspace" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/pull first|could not be pushed/i);
  });
});
