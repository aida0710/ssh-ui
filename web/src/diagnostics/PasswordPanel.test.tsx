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
    changeMasterPassword: vi.fn(),
    loginItem: vi.fn().mockResolvedValue({ enabled: false, supported: true }),
    updateStatus: vi.fn().mockResolvedValue({ current: "dev", available: false, updatable: true, restartRequired: false }),
    applyUpdate: vi.fn().mockResolvedValue({ current: "dev", available: false, updatable: true, restartRequired: true }),
    setLoginItem: vi.fn().mockResolvedValue({ enabled: true, supported: true }),
    credentials: vi.fn().mockResolvedValue({ credentials: [] }),
    storeCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    deleteCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    assignCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    unassignCredential: vi.fn().mockResolvedValue({ credentials: [] }),
    passwordEligibility: vi.fn().mockResolvedValue({
      alias: "bastion", storable: true, blockers: [], warnings: [],
    }),
    storePassword: vi.fn().mockResolvedValue({ ...status, aliases: ["bastion"] }),
    forgetPassword: vi.fn().mockResolvedValue({ ...status, aliases: [] }),
    // The overrides were declared and never applied, so a test that passed one
    // was quietly getting the default and proving nothing about the case it
    // was written for.
    ...overrides,
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

  it("warns about an unverified host key instead of saying it to every host", async () => {
    // This used to be prose under the field, shown for every host whether or
    // not it applied. A warning that is always there is a warning nobody
    // reads; the server now answers it per host.
    const api = buildApi(unlocked, {
      passwordEligibility: vi.fn().mockResolvedValue({
        alias: "bastion",
        storable: true,
        blockers: [],
        warnings: [{ code: "host_key_unknown", detail: "203.0.113.10" }],
      }),
    });
    render(<PasswordPanel api={api} alias="bastion" />);

    expect(await screen.findByText(/not in known_hosts/)).toBeInTheDocument();
    // A warning is not a refusal: the user may know the key is about to be
    // added, so the field still works.
    expect(screen.getByLabelText("Password for bastion")).toBeEnabled();
  });

  it("refuses to store a password the host would never be offered", async () => {
    const api = buildApi(unlocked, {
      passwordEligibility: vi.fn().mockResolvedValue({
        alias: "bastion",
        storable: false,
        blockers: [{ code: "password_authentication_off", path: "config", line: 4 }],
        warnings: [],
      }),
    });
    render(<PasswordPanel api={api} alias="bastion" />);

    expect(await screen.findByRole("alert")).toHaveTextContent(/could never be used/);
    expect(screen.getByText(/PasswordAuthentication is off/)).toBeInTheDocument();
    expect(screen.getByLabelText("Password for bastion")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Store the password" })).toBeDisabled();
    expect(api.storePassword).not.toHaveBeenCalled();
  });

  // The point of naming a secret: one entry, several machines. Before this the
  // only way to give two hosts the same password was to type it twice, and
  // rotating it meant remembering which hosts shared it.
  it("points this host at a password that already has a name", async () => {
    const api = buildApi(unlocked, {
      credentials: vi.fn().mockResolvedValue({
        credentials: [{ kind: "password", name: "office-vm", uses: ["web-1"] }],
      }),
    });
    render(<PasswordPanel api={api} alias="bastion" />);

    await userEvent.selectOptions(await screen.findByLabelText("Use a stored password"), "office-vm");
    await userEvent.click(screen.getByRole("button", { name: "Use this password" }));

    await waitFor(() =>
      expect(api.assignCredential).toHaveBeenCalledWith("password", "bastion", "office-vm"),
    );
  });

  // The separation made visible. Picking a key's passphrase here would send it
  // to a remote host as a login password, so this picker cannot offer one.
  it("never offers a key passphrase as a host password", async () => {
    const api = buildApi(unlocked, {
      credentials: vi.fn().mockResolvedValue({
        credentials: [
          { kind: "password", name: "office-vm", uses: [] },
          { kind: "key_passphrase", name: "build-key", uses: ["keys/work/id_work"] },
        ],
      }),
    });
    render(<PasswordPanel api={api} alias="bastion" />);

    const picker = await screen.findByLabelText("Use a stored password");
    expect(picker).toHaveTextContent("office-vm");
    expect(picker).not.toHaveTextContent("build-key");
  });

  it("says which shared password this host already uses", async () => {
    const api = buildApi(withPassword, {
      credentials: vi.fn().mockResolvedValue({
        credentials: [{ kind: "password", name: "office-vm", uses: ["bastion", "web-1"] }],
      }),
    });
    render(<PasswordPanel api={api} alias="bastion" />);

    expect(await screen.findByText(/office-vm/)).toBeInTheDocument();
  });
});
