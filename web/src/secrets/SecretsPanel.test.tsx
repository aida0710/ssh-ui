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
    changeMasterPassword: vi.fn().mockResolvedValue({
      vault: { exists: true, unlocked: true, aliases: [] },
      snapshotResealed: true,
    }),
    loginItem: vi.fn().mockResolvedValue({ enabled: false, supported: true }),
    updateStatus: vi.fn().mockResolvedValue({ current: "dev", available: false, restartRequired: false }),
    setLoginItem: vi.fn().mockResolvedValue({ enabled: true, supported: true }),
    ...overrides,
  } as unknown as IntegrationsApi;
}

describe("SecretsPanel", () => {
  it("lists both kinds apart, with what uses each and never a value", async () => {
    render(<SecretsPanel api={buildApi()} />);

    const passwords = await screen.findByRole("region", { name: "Account passwords" });
    expect(within(passwords).getByText("office-vm")).toBeInTheDocument();
    // シークレットに名前を付ける狙い: 1 エントリ、2 台のマシン。
    expect(within(passwords).getByText(/web-1, web-2/)).toBeInTheDocument();

    const phrases = screen.getByRole("region", { name: "Key passphrases" });
    expect(within(phrases).getByText("build-key")).toBeInTheDocument();
    // そして 2 つのリストは互いのエントリを決して保持しない。それが
    // 2 つのリストである理由のすべてだ。
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

  // 2 台のマシンがまだ指している名前を削除すれば、後でどこか別の
  // 場所で両方が壊れる。サーバーは拒否し、画面は何が拒否したかを伝える。
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

  // 起動時には何も尋ねられない。閉じた vault はここでそう言い、開くことを
  // 申し出る。「シークレットが消えた」と読める空リストを見せるのではなく。
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

  // それを変えると、古いパスワードが保持していたすべてが再封印される。
  // だから画面は何が追随し何が追随しなかったかを伝える。届かなかったバケットは
  // 古いパスワードでしか開けないスナップショットを持ち続け、それは些細ではない。
  it("changes the master password and says whether the bucket followed", async () => {
    const user = userEvent.setup();
    const api = buildApi();
    render(<SecretsPanel api={api} />);
    await screen.findByRole("region", { name: "Master password" });

    await user.type(screen.getByLabelText("Current master password"), "the old one is long");
    await user.type(screen.getByLabelText("New master password"), "the new one is long");
    // 片方のフィールドだけでは、誰も復元できないパスワードには足りない。
    expect(screen.getByRole("button", { name: "Change the master password" })).toBeDisabled();

    await user.type(screen.getByLabelText("Confirm new master password"), "the new one is long");
    await user.click(screen.getByRole("button", { name: "Change the master password" }));

    await waitFor(() =>
      expect(api.changeMasterPassword).toHaveBeenCalledWith("the old one is long", "the new one is long"),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(/live snapshot/i);
  });

  it("says the bucket still holds a snapshot the old password opens", async () => {
    const user = userEvent.setup();
    const api = buildApi({
      changeMasterPassword: vi.fn().mockResolvedValue({
        vault: { exists: true, unlocked: true, aliases: [] },
        snapshotResealed: false,
        snapshotProblem: "sync_failed",
      }),
    });
    render(<SecretsPanel api={api} />);
    await screen.findByRole("region", { name: "Master password" });

    await user.type(screen.getByLabelText("Current master password"), "the old one is long");
    await user.type(screen.getByLabelText("New master password"), "the new one is long");
    await user.type(screen.getByLabelText("Confirm new master password"), "the new one is long");
    await user.click(screen.getByRole("button", { name: "Change the master password" }));

    expect(await screen.findByRole("status")).toHaveTextContent(/still opens with the old password/i);
  });

  // 誰も復元できないパスワードは、押す前に読み返す価値のあるものだ。
  it("shows what is being typed when asked", async () => {
    const user = userEvent.setup();
    render(<SecretsPanel api={buildApi()} />);
    await screen.findByRole("region", { name: "Master password" });

    expect(screen.getByLabelText("New master password")).toHaveAttribute("type", "password");
    await user.click(screen.getByRole("button", { name: "Show New master password" }));
    expect(screen.getByLabelText("New master password")).toHaveAttribute("type", "text");
  });

  // 求められない限りオフ。保存済みのあらゆるシークレットへの鍵を握る
  // バックグラウンドプロセスは、誰かの代わりに勝手に設定してよいものではない。
  it("offers to start at login, off, and turns it on when asked", async () => {
    const user = userEvent.setup();
    const api = buildApi();
    render(<SecretsPanel api={api} />);

    const section = await screen.findByRole("region", { name: "Start at login" });
    const toggle = within(section).getByRole("checkbox", { name: "Start sshc when I log in" });
    expect(toggle).not.toBeChecked();

    await user.click(toggle);
    await waitFor(() => expect(api.setLoginItem).toHaveBeenCalledWith(true));
  });

  // 自分のパスを解決できないビルドには登録するものが何もなく、
  // 何もしないスイッチは、スイッチがないより悪い。
  it("shows no switch where it is not supported", async () => {
    const api = buildApi({
      loginItem: vi.fn().mockResolvedValue({ enabled: false, supported: false }),
    });
    render(<SecretsPanel api={api} />);
    await screen.findByRole("region", { name: "Account passwords" });

    expect(screen.queryByRole("region", { name: "Start at login" })).not.toBeInTheDocument();
  });
});
