import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { SyncPanel } from "./SyncPanel";
import type { IntegrationsApi, PullResponse, SyncStatus } from "../api/integrations";

afterEach(() => {
  vi.restoreAllMocks();
});

const unconfigured: SyncStatus = {
  configured: false,
  locked: false,
  endpoint: "",
  bucket: "",
  synced: false,
  direction: "both",
};
const configured: SyncStatus = {
  configured: true,
  locked: false,
  endpoint: "https://acc.r2.cloudflarestorage.com",
  bucket: "ssh-ui",
  synced: true,
  direction: "both",
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
        direction: "both",
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

    await userEvent.type(await screen.findByLabelText("Master password"), "correct horse battery staple");
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

    await userEvent.type(await screen.findByLabelText("Master password"), "a passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Check for changes" }));

    expect(await screen.findByText(/changed here and on the other machine/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply the snapshot" })).toBeDisabled();
  });

  it("says so when there is nothing to do", async () => {
    const api = buildApi(configured, nothingToDo);
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Master password"), "a passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Check for changes" }));

    expect(await screen.findByText(/already matches the snapshot/)).toBeInTheDocument();
  });

  it("sends the chosen direction with the bucket", async () => {
    const api = buildApi(unconfigured, nothingToDo);
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://acc.r2.cloudflarestorage.com");
    await userEvent.type(screen.getByLabelText("Bucket name"), "ssh-ui");
    await userEvent.type(screen.getByLabelText("Access key ID"), "AKID");
    await userEvent.type(screen.getByLabelText("Secret access key"), "the-secret");
    await userEvent.selectOptions(screen.getByLabelText("Direction"), "pull");
    await userEvent.click(screen.getByRole("button", { name: "Use this bucket" }));

    await waitFor(() =>
      expect(api.configureSync).toHaveBeenCalledWith(
        expect.objectContaining({ direction: "pull" }),
      ),
    );
  });

  it("offers no push on a machine set to receive only, and says why", async () => {
    const api = buildApi({ ...configured, direction: "pull" }, nothingToDo);
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Master password"), "a passphrase");
    expect(screen.getByRole("button", { name: "Push this workspace" })).toBeDisabled();
    // The reason stands beside the control. A disabled button with nothing
    // next to it reads as a fault rather than as a setting.
    expect(screen.getByText(/Set to receive only/)).toBeInTheDocument();
  });

  it("offers no apply on a machine set to send only, but still shows what would change", async () => {
    const api = buildApi({ ...configured, direction: "push" }, {
      applied: false,
      conflicts: [],
      written: ["config"],
      removed: [],
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Master password"), "a passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Check for changes" }));

    // Looking is not moving. A machine that may not apply is still allowed to
    // know how far behind it is.
    expect(await screen.findByText("config")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply the snapshot" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Push this workspace" })).toBeEnabled();
  });

  it("reports a refused push instead of claiming success", async () => {
    const api = buildApi(configured, nothingToDo, {
      pushSnapshot: vi.fn().mockRejectedValue(new Error("sync_remote_moved")),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Master password"), "a passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Push this workspace" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/pull first|could not be pushed/i);
  });
  // The settings are sealed with the master password now, so a shut vault
  // cannot fill this form in. Showing the empty form anyway would read as
  // "your bucket is gone" and invite the user to type the access key again.
  it("asks for the master password rather than showing an empty bucket form", async () => {
    const api = buildApi({ ...unconfigured, locked: true }, nothingToDo);
    render(<SyncPanel api={api} />);

    expect(await screen.findByLabelText("Master password")).toBeInTheDocument();
    expect(screen.queryByLabelText("Access key ID")).not.toBeInTheDocument();
    expect(screen.getByText(/sealed with the master password/i)).toBeInTheDocument();
  });

  it("opens the vault in place and reads the settings back", async () => {
    // Nothing is asked at startup: this is the screen asking for itself, at the
    // moment it needs the answer.
    const syncStatus = vi
      .fn()
      .mockResolvedValueOnce({ ...unconfigured, locked: true })
      .mockResolvedValue(configured);
    const api = buildApi(unconfigured, nothingToDo, {
      syncStatus,
      unlockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Master password"), "the master password");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() => expect(api.unlockVault).toHaveBeenCalledWith("the master password"));
    expect(await screen.findByText("https://acc.r2.cloudflarestorage.com/ssh-ui")).toBeInTheDocument();
  });
  // The snapshot is sealed with the master password now, so a mistyped one is
  // something this machine can catch. Before, it produced an archive nobody
  // could open and said so on another machine, months later.
  it("says the master password was wrong rather than blaming the bucket", async () => {
    const api = buildApi(configured, nothingToDo, {
      pushSnapshot: vi.fn().mockRejectedValue(new ApiError("wrong_master_password", 403, null)),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Master password"), "not the master password");
    await userEvent.click(screen.getByRole("button", { name: "Push this workspace" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/not this machine's master password/i);
  });

  // Settings are tried before they are kept, so the screen has to say that
  // nothing was saved — otherwise the user leaves believing it was.
  it("says nothing was saved when the bucket did not answer", async () => {
    const api = buildApi(unconfigured, nothingToDo, {
      configureSync: vi.fn().mockRejectedValue(new ApiError("bucket_refused", 502, null)),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://acc.r2.cloudflarestorage.com");
    await userEvent.type(screen.getByLabelText("Bucket name"), "ssh-ui");
    await userEvent.type(screen.getByLabelText("Access key ID"), "AKID");
    await userEvent.type(screen.getByLabelText("Secret access key"), "the-secret");
    await userEvent.click(screen.getByRole("button", { name: "Use this bucket" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/Nothing was saved/i);
  });

  it("explains an endpoint that carries a path instead of just refusing it", async () => {
    const api = buildApi(unconfigured, nothingToDo, {
      configureSync: vi.fn().mockRejectedValue(new ApiError("endpoint_must_have_no_path", 400, null)),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://acc.r2.cloudflarestorage.com/ssh-ui");
    await userEvent.type(screen.getByLabelText("Bucket name"), "ssh-ui");
    await userEvent.type(screen.getByLabelText("Access key ID"), "AKID");
    await userEvent.type(screen.getByLabelText("Secret access key"), "the-secret");
    await userEvent.click(screen.getByRole("button", { name: "Use this bucket" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/no bucket name and no path/i);
  });
});
