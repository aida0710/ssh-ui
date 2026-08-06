import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SecretsPanel } from "./SecretsPanel";
import { ApiError } from "../api/client";
import type { IntegrationsApi } from "../api/integrations";

function buildApi(overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return {
    passwordVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    initialiseVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    unlockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: true, aliases: [] }),
    lockVault: vi.fn().mockResolvedValue({ exists: true, unlocked: false, aliases: [] }),
    credentials: vi.fn().mockResolvedValue({
      credentials: [
        { kind: "password", name: "office-vm", uses: ["web-1", "web-2"] },
        { kind: "key_passphrase", name: "build-key", uses: ["keys/work/id_work"] },
      ],
    }),
    storeCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    deleteCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    assignCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    unassignCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    ...overrides,
  } as unknown as IntegrationsApi;
}

describe("SecretsPanel", () => {
  it("lists both kinds apart, with what uses each and never a value", async () => {
    render(<SecretsPanel api={buildApi()} />);

    const passwords = await screen.findByRole("region", { name: "Account passwords" });
    expect(within(passwords).getByText("office-vm")).toBeInTheDocument();
    // The point of naming a secret: one entry, two machines.
    expect(within(passwords).getByText(/web-1, web-2/)).toBeInTheDocument();

    const phrases = screen.getByRole("region", { name: "Key passphrases" });
    expect(within(phrases).getByText("build-key")).toBeInTheDocument();
    // And the two lists never hold each other's entries, which is the whole
    // reason they are two lists.
    expect(within(passwords).queryByText("build-key")).not.toBeInTheDocument();
    expect(within(phrases).queryByText("office-vm")).not.toBeInTheDocument();
  });

  it("creates an account password under a name", async () => {
    const user = userEvent.setup();
    const api = buildApi();
    render(<SecretsPanel api={api} />);
    await screen.findByRole("region", { name: "Account passwords" });

    await user.type(screen.getByLabelText("New account password name"), "the office VMs");
    await user.type(screen.getByLabelText("New account password value"), "s3cret");
    await user.click(screen.getByRole("button", { name: "Store account password" }));

    await waitFor(() =>
      expect(api.storeCredential).toHaveBeenCalledWith("password", "the office VMs", "s3cret"),
    );
  });

  it("creates a key passphrase under the other kind", async () => {
    const user = userEvent.setup();
    const api = buildApi();
    render(<SecretsPanel api={api} />);
    await screen.findByRole("region", { name: "Key passphrases" });

    await user.type(screen.getByLabelText("New key passphrase name"), "build");
    await user.type(screen.getByLabelText("New key passphrase value"), "phrase");
    await user.click(screen.getByRole("button", { name: "Store key passphrase" }));

    await waitFor(() =>
      expect(api.storeCredential).toHaveBeenCalledWith("key_passphrase", "build", "phrase"),
    );
  });

  // Removing a name two machines still point at would break both of them,
  // later, somewhere else. The server refuses; the screen says what refused it.
  it("says what still uses a credential the server refused to delete", async () => {
    const user = userEvent.setup();
    const api = buildApi({
      deleteCredential: vi.fn().mockRejectedValue(new ApiError("credential_in_use", 409, null)),
    });
    render(<SecretsPanel api={api} />);
    const passwords = await screen.findByRole("region", { name: "Account passwords" });

    await user.click(within(passwords).getByRole("button", { name: "Delete office-vm" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/still uses/i);
  });

  // Nothing is asked at startup. A shut vault says so here and offers to open,
  // rather than showing an empty list that reads as "your secrets are gone".
  it("offers to unlock rather than showing an empty list", async () => {
    const api = buildApi({
      passwordVault: vi.fn().mockResolvedValue({ exists: true, unlocked: false, aliases: [] }),
      credentials: vi.fn(),
    });
    render(<SecretsPanel api={api} />);

    expect(await screen.findByLabelText("Master password")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Account passwords" })).not.toBeInTheDocument();
    expect(api.credentials).not.toHaveBeenCalled();
  });
});
