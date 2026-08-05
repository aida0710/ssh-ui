import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PasswordPanel } from "./PasswordPanel";
import type { IntegrationsApi, PasswordVaultStatus } from "../api/integrations";

afterEach(() => {
  vi.restoreAllMocks();
});

function buildApi(status: PasswordVaultStatus, overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return {
    passwordVault: vi.fn().mockResolvedValue(status),
    initialiseVault: vi.fn().mockResolvedValue({ ...status, exists: true, unlocked: true }),
    unlockVault: vi.fn().mockResolvedValue({ ...status, unlocked: true }),
    lockVault: vi.fn().mockResolvedValue({ ...status, unlocked: false }),
    storePassword: vi.fn().mockResolvedValue({ ...status, aliases: ["bastion"] }),
    forgetPassword: vi.fn().mockResolvedValue({ ...status, aliases: [] }),
  } as unknown as IntegrationsApi;
}

const locked: PasswordVaultStatus = { exists: true, unlocked: false, aliases: [], minPassphraseLength: 12 };
const empty: PasswordVaultStatus = { exists: false, unlocked: false, aliases: [], minPassphraseLength: 12 };
const unlocked: PasswordVaultStatus = { exists: true, unlocked: true, aliases: [], minPassphraseLength: 12 };
const withPassword: PasswordVaultStatus = { exists: true, unlocked: true, aliases: ["bastion"], minPassphraseLength: 12 };

describe("PasswordPanel", () => {
  it("says what storing a password means before offering the field", async () => {
    // Not a tooltip and not a footnote. Someone deciding whether to use this
    // has to read it first.
    render(<PasswordPanel api={buildApi(unlocked)} alias="bastion" />);

    expect(await screen.findByText(/A key is stronger/)).toBeInTheDocument();
    expect(screen.getByText(/remote account's own credential/)).toBeInTheDocument();
  });

  it("offers to create a vault when there is none, and refuses a short passphrase", async () => {
    const api = buildApi(empty);
    render(<PasswordPanel api={api} alias="bastion" />);

    const field = await screen.findByLabelText("New vault passphrase");
    expect(screen.getByRole("button", { name: "Create the vault" })).toBeDisabled();

    await userEvent.type(field, "short");
    expect(screen.getByRole("button", { name: "Create the vault" })).toBeDisabled();

    await userEvent.type(field, " but now long enough");
    expect(screen.getByRole("button", { name: "Create the vault" })).toBeEnabled();

    await userEvent.click(screen.getByRole("button", { name: "Create the vault" }));
    await waitFor(() => expect(api.initialiseVault).toHaveBeenCalledWith("short but now long enough"));
  });

  it("says the vault is locked instead of claiming no password is stored", async () => {
    // A locked vault genuinely cannot tell. Answering "none" would be a guess,
    // and a wrong one half the time.
    render(<PasswordPanel api={buildApi(locked)} alias="bastion" />);

    expect(await screen.findByText(/vault is locked/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Password for bastion")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Forget the password/ })).not.toBeInTheDocument();
  });

  it("unlocks with a passphrase and then offers the password field", async () => {
    const api = buildApi(locked);
    render(<PasswordPanel api={api} alias="bastion" />);

    await userEvent.type(await screen.findByLabelText("Vault passphrase"), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() => expect(api.unlockVault).toHaveBeenCalledWith("correct horse battery staple"));
    expect(await screen.findByLabelText("Password for bastion")).toBeInTheDocument();
  });

  it("stores a password and never leaves it in the document", async () => {
    const api = buildApi(unlocked);
    render(<PasswordPanel api={api} alias="bastion" />);

    await userEvent.type(await screen.findByLabelText("Password for bastion"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Store the password" }));

    await waitFor(() => expect(api.storePassword).toHaveBeenCalledWith("bastion", "hunter2"));
    // The field is cleared, and nothing renders the value back.
    await waitFor(() => expect(document.body.textContent ?? "").not.toContain("hunter2"));
  });

  it("shows the delete affordance and the unlock caveat once a password is stored", async () => {
    const api = buildApi(withPassword);
    render(<PasswordPanel api={api} alias="bastion" />);

    expect(await screen.findByText(/A password is stored for bastion/)).toBeInTheDocument();
    expect(screen.getByText(/until the passphrase has been entered once/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Password for bastion")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Forget the password for bastion" }));
    await waitFor(() => expect(api.forgetPassword).toHaveBeenCalledWith("bastion"));
  });

  it("drops a typed secret when the host changes", async () => {
    // A passphrase left in a field while the user navigates is a secret
    // sitting in the DOM for no reason.
    const api = buildApi(unlocked);
    const { rerender } = render(<PasswordPanel api={api} alias="bastion" />);

    await userEvent.type(await screen.findByLabelText("Password for bastion"), "hunter2");
    rerender(<PasswordPanel api={api} alias="nas" />);

    await waitFor(() => expect((screen.getByLabelText("Password for nas") as HTMLInputElement).value).toBe(""));
  });

  it("tells the user to add the host key first", async () => {
    render(<PasswordPanel api={buildApi(unlocked)} alias="bastion" />);

    expect(await screen.findByText(/Add this host's key through Known Hosts first/)).toBeInTheDocument();
  });
});
