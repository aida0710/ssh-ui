import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KeysScreen } from "./KeysScreen";
import type { KeyInventoryResponse, KeysApi } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
});

// A fresh inventory per call, so a test that adjusts one field cannot leak that
// change into the next test through a shared object.
function buildInventory(): KeyInventoryResponse {
  return {
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
  };
}

// The default fixture has no agent, because the end-to-end environment has
// none either: nothing in this suite may reach the developer's own agent.
function inventoryWithAgent(): KeyInventoryResponse {
  return { ...buildInventory(), agentAvailable: true };
}

function buildApi(overrides: Partial<KeysApi> = {}): KeysApi {
  return {
    inventory: vi.fn().mockResolvedValue(buildInventory()),
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
    publicKey: vi.fn().mockResolvedValue({
      id: "key-three",
      relativePath: "id_work.pub",
      publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmU aida@laptop\n",
      fingerprint: "SHA256:abcdef",
      comment: "aida@laptop",
    }),
    registerWithAgent: vi.fn().mockResolvedValue({
      id: "key-one",
      relativePath: "id_work",
      fingerprint: "SHA256:abcdef",
      lifetimeSeconds: 0,
      storedInKeychain: false,
      identities: [],
    }),
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

  it("names the files it could not classify instead of leaving them out", async () => {
    const inventory = buildInventory();
    inventory.unreadable = [
      { relativePath: "sockets/agent.sock", reason: "not_a_regular_file" },
      { relativePath: "vault", reason: "permission_denied" },
    ];
    render(<KeysScreen api={buildApi({ inventory: vi.fn().mockResolvedValue(inventory) })} />);

    expect(await screen.findByText(/sockets\/agent\.sock — not_a_regular_file/)).toBeInTheDocument();
    expect(screen.getByText(/vault — permission_denied/)).toBeInTheDocument();
    expect(screen.getByText(/missing from the table above/)).toBeInTheDocument();
  });

  it("reports a configuration entry pointing at a key that is not there", async () => {
    const inventory = buildInventory();
    inventory.unresolvedReferences = [
      {
        directive: "IdentityFile",
        value: "~/.ssh/id_gone",
        configPath: "config",
        line: 14,
        reason: "file_missing",
      },
    ];
    render(<KeysScreen api={buildApi({ inventory: vi.fn().mockResolvedValue(inventory) })} />);

    expect(
      await screen.findByText(/IdentityFile ~\/\.ssh\/id_gone — config:14 \(file_missing\)/),
    ).toBeInTheDocument();
  });

  it("shows a certificate's principals and marks one that has run out", async () => {
    const inventory = buildInventory();
    inventory.items = [
      {
        ...inventory.items[0]!,
        id: "cert-one",
        relativePath: "id_work-cert.pub",
        kind: "certificate",
        certificate: {
          keyId: "aida@dubguild",
          principals: ["deploy", "ops"],
          // 2020-01-01T00:00:00Z, comfortably in the past for any run of this
          // suite, so "expired" is a property of the fixture and not of today.
          validBefore: 1577836800,
          neverExpires: false,
          signedKeyType: "ssh-ed25519",
          signedKeyFingerprint: "SHA256:signedkey",
        },
      },
    ];
    render(<KeysScreen api={buildApi({ inventory: vi.fn().mockResolvedValue(inventory) })} />);

    const row = await screen.findByRole("row", { name: /id_work-cert\.pub/ });
    expect(within(row).getByText("key id aida@dubguild")).toBeInTheDocument();
    expect(within(row).getByText("for deploy, ops")).toBeInTheDocument();
    expect(within(row).getByText("expired 2020-01-01 00:00Z")).toBeInTheDocument();
    expect(within(row).getByText("signs ssh-ed25519 SHA256:signedkey")).toBeInTheDocument();
  });

  it("says a certificate with no principal is valid for any of them", async () => {
    const inventory = buildInventory();
    inventory.items = [
      {
        ...inventory.items[0]!,
        id: "cert-two",
        relativePath: "host-cert.pub",
        kind: "certificate",
        certificate: {
          keyId: "host",
          principals: [],
          validBefore: 0,
          neverExpires: true,
          signedKeyType: "ssh-ed25519",
          signedKeyFingerprint: "SHA256:hostkey",
        },
      },
    ];
    render(<KeysScreen api={buildApi({ inventory: vi.fn().mockResolvedValue(inventory) })} />);

    const row = await screen.findByRole("row", { name: /host-cert\.pub/ });
    expect(within(row).getByText("for any principal")).toBeInTheDocument();
    expect(within(row).getByText("never expires")).toBeInTheDocument();
  });

  it("refuses agent registration, and says what is missing, when no agent is reachable", async () => {
    const api = buildApi();
    render(<KeysScreen api={api} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    expect(within(workRow).getByRole("button", { name: "Add to agent" })).toBeDisabled();
    expect(screen.getByText(/No agent is reachable from this process/)).toBeInTheDocument();
    expect(api.registerWithAgent).not.toHaveBeenCalled();
  });

  it("registers a key with the agent, with the lifetime and Keychain choice the user made", async () => {
    const api = buildApi({ inventory: vi.fn().mockResolvedValue(inventoryWithAgent()) });
    render(<KeysScreen api={api} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    await userEvent.click(within(workRow).getByRole("button", { name: "Add to agent" }));

    await userEvent.type(screen.getByLabelText("Key passphrase"), "correct horse");
    await userEvent.selectOptions(screen.getByLabelText("Lifetime"), "3600");
    await userEvent.click(screen.getByLabelText(/store the passphrase in the login Keychain/));
    await userEvent.click(screen.getByRole("button", { name: "Register with the agent" }));

    await waitFor(() =>
      expect(api.registerWithAgent).toHaveBeenCalledWith("key-one", {
        passphrase: "correct horse",
        lifetimeSeconds: 3600,
        storeInKeychain: true,
      }),
    );
    // The form closes and takes the passphrase with it. A passphrase left in
    // component state would survive every later render of this screen.
    await waitFor(() => expect(screen.queryByLabelText("Key passphrase")).not.toBeInTheDocument());
    expect(document.body).not.toHaveTextContent("correct horse");
  });

  it("keeps no passphrase after the agent refuses the key", async () => {
    const api = buildApi({
      inventory: vi.fn().mockResolvedValue(inventoryWithAgent()),
      registerWithAgent: vi.fn().mockRejectedValue(new Error("api_mutation_failed")),
    });
    render(<KeysScreen api={api} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    await userEvent.click(within(workRow).getByRole("button", { name: "Add to agent" }));
    await userEvent.type(screen.getByLabelText("Key passphrase"), "wrong passphrase");
    await userEvent.click(screen.getByRole("button", { name: "Register with the agent" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("could not be added to the agent");
    // The form stays open so the user can retry, but the field is empty.
    expect(screen.getByLabelText("Key passphrase")).toHaveValue("");
    expect(document.body).not.toHaveTextContent("wrong passphrase");
  });

  it("asks for no passphrase for a key that is not encrypted", async () => {
    const inventory = inventoryWithAgent();
    inventory.items = inventory.items.map((item) => ({ ...item, encrypted: false }));
    const api = buildApi({ inventory: vi.fn().mockResolvedValue(inventory) });
    render(<KeysScreen api={api} />);

    const workRow = await screen.findByRole("row", { name: /id_work/ });
    await userEvent.click(within(workRow).getByRole("button", { name: "Add to agent" }));

    expect(screen.queryByLabelText("Key passphrase")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Register with the agent" }));

    await waitFor(() =>
      expect(api.registerWithAgent).toHaveBeenCalledWith("key-one", {
        passphrase: "",
        lifetimeSeconds: 0,
        storeInKeychain: false,
      }),
    );
  });

  it("shows what the agent holds and which entries delegate to it", async () => {
    const inventory = inventoryWithAgent();
    inventory.agentIdentities = [
      { bits: 256, fingerprint: "SHA256:heldbyagent", comment: "aida@laptop", algorithm: "ED25519" },
    ];
    inventory.agentDelegations = [
      {
        directive: "IdentityAgent",
        configPath: "config",
        line: 9,
        condition: "Host deploy",
        hostPatterns: ["deploy"],
        value: "SSH_AUTH_SOCK",
      },
    ];
    render(<KeysScreen api={buildApi({ inventory: vi.fn().mockResolvedValue(inventory) })} />);

    const identityRow = await screen.findByRole("row", { name: /SHA256:heldbyagent/ });
    expect(within(identityRow).getByText("ED25519 · 256")).toBeInTheDocument();
    expect(screen.getByText(/IdentityAgent SSH_AUTH_SOCK — config:9/)).toBeInTheDocument();
  });
  it("shows a public key and copies exactly the text it showed", async () => {
    const user = userEvent.setup();
    const inventory = buildInventory();
    inventory.items = [
      { ...inventory.items[0]!, id: "key-three", relativePath: "id_work.pub", kind: "public_key" },
    ];
    const api = buildApi({ inventory: vi.fn().mockResolvedValue(inventory) });
    render(<KeysScreen api={api} />);

    const row = await screen.findByRole("row", { name: /id_work\.pub/ });
    // A public key is not a secret, so this row offers no reveal and no
    // confirmation — just the key.
    expect(within(row).queryByRole("button", { name: "Show private key" })).not.toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: "Show public key" }));

    const shown = await screen.findByLabelText("Public key");
    expect(shown).toHaveTextContent("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmU aida@laptop");
    await user.click(screen.getByRole("button", { name: "Copy public key" }));

    // Trailing newline and all: the clipboard gets what the panel displayed.
    expect(await navigator.clipboard.readText()).toBe(
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmU aida@laptop",
    );
  });

  it("offers no public key read for a private key", async () => {
    render(<KeysScreen api={buildApi()} />);

    const row = await screen.findByRole("row", { name: /id_work\b/ });
    expect(within(row).queryByRole("button", { name: "Show public key" })).not.toBeInTheDocument();
  });

  it("reports a public key that could not be read", async () => {
    const user = userEvent.setup();
    const inventory = buildInventory();
    inventory.items = [
      { ...inventory.items[0]!, id: "key-three", relativePath: "id_work.pub", kind: "public_key" },
    ];
    const api = buildApi({
      inventory: vi.fn().mockResolvedValue(inventory),
      publicKey: vi.fn().mockRejectedValue(new Error("api_read_failed")),
    });
    render(<KeysScreen api={api} />);

    const row = await screen.findByRole("row", { name: /id_work\.pub/ });
    await user.click(within(row).getByRole("button", { name: "Show public key" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("public key could not be read");
    expect(screen.queryByLabelText("Public key")).not.toBeInTheDocument();
  });
});
