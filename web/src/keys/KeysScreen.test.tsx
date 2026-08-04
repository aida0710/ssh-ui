import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KeysScreen } from "./KeysScreen";
import type { KeysApi } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
});

function buildApi(overrides: Partial<KeysApi> = {}): KeysApi {
  return {
    inventory: vi.fn().mockResolvedValue({
      items: [
        {
          id: "key-one",
          relativePath: "id_work",
          kind: "private_key",
          container: "OPENSSH PRIVATE KEY",
          algorithm: "ed25519",
          keyType: "ssh-ed25519",
          bits: 256,
          encrypted: true,
          fingerprint: "SHA256:abcdef",
          comment: "aida@laptop",
          permission: "0600",
          permissionRisk: false,
          sizeBytes: 444,
          references: [
            {
              directive: "IdentityFile",
              configPath: "/home/.ssh/config",
              line: 2,
              condition: "Host build-*",
              hostPatterns: ["build-*"],
              value: "~/.ssh/id_work",
            },
          ],
          notes: [],
        },
        {
          id: "key-two",
          relativePath: "legacy",
          kind: "private_key",
          container: "RSA PRIVATE KEY",
          algorithm: "rsa",
          keyType: "ssh-rsa",
          bits: 2048,
          encrypted: true,
          fingerprint: "",
          comment: "",
          permission: "0644",
          permissionRisk: true,
          sizeBytes: 1700,
          references: [],
          notes: ["fingerprint_unavailable"],
        },
      ],
      unreadable: [],
      agentDelegations: [],
      unresolvedReferences: [],
      agentAvailable: false,
      agentIdentities: [],
    }),
    algorithms: vi.fn().mockResolvedValue({
      variants: [
        { algorithm: "ed25519", bits: 256, label: "Ed25519", inProcess: true, reason: "" },
        {
          algorithm: "ed25519-sk",
          bits: 0,
          label: "Ed25519 security key",
          inProcess: false,
          reason: "hardware_token_required",
        },
      ],
      source: "ssh -Q key",
      diagnostic: "",
    }),
    generate: vi.fn().mockResolvedValue({
      id: "key-new",
      relativePath: "id_new",
      publicRelativePath: "id_new.pub",
      fingerprint: "SHA256:new",
      keyType: "ssh-ed25519",
      bits: 256,
      encrypted: true,
      transactionId: "tx",
    }),
    hardwareCommand: vi.fn().mockResolvedValue({
      algorithm: "ed25519-sk",
      command: ["ssh-keygen", "-t", "ed25519-sk", "-f", "/home/.ssh/id_yubikey"],
      note: "run_in_terminal",
    }),
    changePassphrase: vi.fn(),
    reveal: vi.fn(),
    trash: vi.fn().mockResolvedValue({ entryId: "entry-1", files: [], skipped: [], transactionId: "tx" }),
    listTrash: vi.fn().mockResolvedValue({
      entries: [
        {
          id: "20260805T090000.000-aabbccdd",
          deletedAt: "2026-08-05T09:00:00Z",
          ageDays: 40,
          stale: true,
          files: [
            {
              originalRelativePath: "id_old",
              trashRelativePath: "ssh-ui/trash/20260805T090000.000-aabbccdd/id_old",
              kind: "private_key",
              fingerprint: "SHA256:012345",
              permission: "0600",
            },
          ],
          restorable: true,
          blockers: [],
        },
      ],
      retentionDays: 30,
    }),
    restore: vi.fn().mockResolvedValue({
      entryId: "20260805T090000.000-aabbccdd",
      restored: ["id_old"],
      blockers: [],
      transactionId: "tx",
    }),
    purge: vi.fn().mockResolvedValue({
      entryId: "20260805T090000.000-aabbccdd",
      removed: ["id_old"],
      transactionId: "tx",
    }),
    ...overrides,
  };
}

describe("KeysScreen", () => {
  it("lists classified files with fingerprint, permissions and referencing Hosts", async () => {
    render(<KeysScreen api={buildApi()} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    expect(within(workRow).getByText("SHA256:abcdef")).toBeInTheDocument();
    expect(within(workRow).getByText("ed25519 · 256")).toBeInTheDocument();
    expect(within(workRow).getByText("0600")).toBeInTheDocument();
    expect(within(workRow).getByText("build-*")).toBeInTheDocument();

    const legacyRow = screen.getByRole("row", { name: /legacy/ });
    expect(within(legacyRow).getByText("Permissions too open")).toBeInTheDocument();
    expect(within(legacyRow).getByText("Fingerprint unavailable")).toBeInTheDocument();
  });

  it("shows the exact ssh-keygen command for a hardware method instead of generating", async () => {
    const api = buildApi();
    render(<KeysScreen api={api} />);

    await screen.findByRole("row", { name: /id_work/ });
    await userEvent.selectOptions(screen.getByLabelText("Algorithm"), "ed25519-sk");
    await userEvent.type(screen.getByLabelText("File name"), "id_yubikey");
    await userEvent.click(screen.getByRole("button", { name: "Show Terminal command" }));

    expect(await screen.findByLabelText("Terminal command")).toHaveTextContent(
      "ssh-keygen -t ed25519-sk -f /home/.ssh/id_yubikey",
    );
    expect(api.generate).not.toHaveBeenCalled();
  });

  it("changes a passphrase and keeps nothing in the form afterwards", async () => {
    const changePassphrase = vi.fn().mockResolvedValue({
      id: "key-one",
      relativePath: "id_work",
      encrypted: true,
      notes: [],
      transactionId: "tx",
    });
    const api = buildApi({ changePassphrase });
    render(<KeysScreen api={api} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    await userEvent.click(within(workRow).getByRole("button", { name: "Change passphrase" }));

    await userEvent.type(screen.getByLabelText("Current passphrase"), "first passphrase");
    await userEvent.type(screen.getByLabelText("New passphrase"), "second passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Save new passphrase" }));

    await waitFor(() =>
      expect(changePassphrase).toHaveBeenCalledWith("key-one", {
        currentPassphrase: "first passphrase",
        newPassphrase: "second passphrase",
        unencrypted: false,
      }),
    );
    await waitFor(() => expect(screen.queryByLabelText("Current passphrase")).not.toBeInTheDocument());

    const reopened = await screen.findByRole("row", { name: /id_work/ });
    await userEvent.click(within(reopened).getByRole("button", { name: "Change passphrase" }));
    expect(screen.getByLabelText("Current passphrase")).toHaveValue("");
    expect(screen.getByLabelText("New passphrase")).toHaveValue("");
  });

  // A passphrase typed into the form must not survive in storage, where it
  // would outlive the operation it was typed for.
  it("keeps a typed passphrase out of browser storage", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    render(<KeysScreen api={buildApi()} />);

    await screen.findByRole("row", { name: /id_work/ });
    await userEvent.type(screen.getByLabelText("File name"), "id_new");
    await userEvent.type(screen.getByLabelText("Passphrase"), "correct horse");

    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("requires a second confirmation before a permanent delete", async () => {
    const api = buildApi();
    render(<KeysScreen api={api} />);

    const trashRow = await screen.findByRole("row", { name: /id_old/ });
    await userEvent.click(within(trashRow).getByRole("button", { name: "Delete permanently" }));
    expect(api.purge).not.toHaveBeenCalled();

    expect(within(trashRow).getByText(/cannot be undone/)).toBeInTheDocument();
    await userEvent.click(within(trashRow).getByRole("button", { name: "Confirm permanent delete" }));
    await waitFor(() => expect(api.purge).toHaveBeenCalledWith("20260805T090000.000-aabbccdd"));
  });

  // Backing out of the confirmation must leave the entry alone.
  it("leaves the trash entry intact when the second confirmation is cancelled", async () => {
    const api = buildApi();
    render(<KeysScreen api={api} />);

    const trashRow = await screen.findByRole("row", { name: /id_old/ });
    await userEvent.click(within(trashRow).getByRole("button", { name: "Delete permanently" }));
    await userEvent.click(within(trashRow).getByRole("button", { name: "Cancel" }));

    expect(api.purge).not.toHaveBeenCalled();
    expect(within(trashRow).getByRole("button", { name: "Delete permanently" })).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /id_old/ })).toBeInTheDocument();
  });

  it("shows a refused restore as blockers instead of guessing", async () => {
    const api = buildApi({
      restore: vi.fn().mockResolvedValue({
        entryId: "20260805T090000.000-aabbccdd",
        restored: [],
        blockers: ["restore_path_occupied:id_old"],
        transactionId: "",
      }),
    });
    render(<KeysScreen api={api} />);

    const trashRow = await screen.findByRole("row", { name: /id_old/ });
    await userEvent.click(within(trashRow).getByRole("button", { name: "Restore" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("restore_path_occupied:id_old");
    expect(screen.getByRole("row", { name: /id_old/ })).toBeInTheDocument();
  });

  it("marks a trash entry older than the retention window without deleting it", async () => {
    render(<KeysScreen api={buildApi()} />);

    const trashRow = await screen.findByRole("row", { name: /id_old/ });
    expect(within(trashRow).getByText("40 days · older than 30 days")).toBeInTheDocument();
    expect(within(trashRow).getByRole("button", { name: "Restore" })).toBeEnabled();
  });

  it("reports an unreadable ssh directory instead of an empty list", async () => {
    const api = buildApi({ inventory: vi.fn().mockRejectedValue(new Error("api_read_failed")) });
    render(<KeysScreen api={api} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("could not be read");
  });
});
