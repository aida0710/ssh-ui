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
  bucket: "sshc",
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
    // 送信後もフィールドに残されたシークレットは、理由もなく DOM に
    // 座り続けるシークレットだ。
    const api = buildApi(unconfigured, nothingToDo);
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://acc.r2.cloudflarestorage.com");
    await userEvent.type(screen.getByLabelText("Bucket name"), "sshc");
    await userEvent.type(screen.getByLabelText("Access key ID"), "AKID");
    await userEvent.type(screen.getByLabelText("Secret access key"), "the-secret");
    await userEvent.click(screen.getByRole("button", { name: "Use this bucket" }));

    await waitFor(() =>
      expect(api.configureSync).toHaveBeenCalledWith({
        endpoint: "https://acc.r2.cloudflarestorage.com",
        bucket: "sshc",
        path: "",
        region: "",
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

  // リージョンは署名スコープに入る。R2 の "auto" と本物の AWS のバケットの
  // リージョンでは違うので、空欄のままサーバーの既定に任せるのではなく、打ち込んだ
  // ものがそのまま届かなければならない。
  it("sends the region it was given", async () => {
    const api = buildApi(unconfigured, nothingToDo);
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://s3.eu-west-2.amazonaws.com");
    await userEvent.type(screen.getByLabelText("Bucket name"), "sshc");
    await userEvent.type(screen.getByLabelText("Region"), "eu-west-2");
    await userEvent.type(screen.getByLabelText("Access key ID"), "AKID");
    await userEvent.type(screen.getByLabelText("Secret access key"), "the-secret");
    await userEvent.click(screen.getByRole("button", { name: "Use this bucket" }));

    await waitFor(() =>
      expect(api.configureSync).toHaveBeenCalledWith(
        expect.objectContaining({ region: "eu-west-2" }),
      ),
    );
  });

  it("offers no push or pull until a bucket and a passphrase are given", async () => {
    render(<SyncPanel api={buildApi(unconfigured, nothingToDo)} />);

    expect(await screen.findByRole("button", { name: "Push this workspace" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Check for changes" })).toBeDisabled();
  });

  it("previews before it applies", async () => {
    // 最初の押下で書き込んでしまう pull は、このアプリケーションで
    // プレビューを飛ばす唯一の書き込みになってしまう。
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
    // 同じブロックを両方が変更した 2 つの設定に正しいマージはないので、
    // これはファイルを名指して止まる。
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
    await userEvent.type(screen.getByLabelText("Bucket name"), "sshc");
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
    // 理由はコントロールの隣に立つ。無効化されたボタンの隣に何もなければ、
    // それは設定ではなく不具合に見えてしまう。
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

    // 見ることは動かすことではない。適用してはならないマシンでも、
    // 自分がどれだけ遅れているかを知ることは許される。
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
  // 設定は今やマスターパスワードで封印されているので、閉じた vault は
  // このフォームを埋められない。それでも空のフォームを見せれば、
  // 「バケットが消えた」と読め、ユーザーにアクセスキーの再入力を促してしまう。
  it("asks for the master password rather than showing an empty bucket form", async () => {
    const api = buildApi({ ...unconfigured, locked: true }, nothingToDo);
    render(<SyncPanel api={api} />);

    expect(await screen.findByLabelText("Master password")).toBeInTheDocument();
    expect(screen.queryByLabelText("Access key ID")).not.toBeInTheDocument();
    expect(screen.getByText(/sealed with the master password/i)).toBeInTheDocument();
  });

  it("opens the vault in place and reads the settings back", async () => {
    // 起動時には何も尋ねられない: これは画面が答えを必要とする瞬間に
    // 自分自身のために尋ねているのだ。
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
    expect(await screen.findByText("https://acc.r2.cloudflarestorage.com/sshc")).toBeInTheDocument();
  });
  // スナップショットは今やマスターパスワードで封印されているので、
  // 打ち間違いはこのマシンが検知できる。以前は誰も開けないアーカイブを
  // 生み、それを何か月も後に別のマシン上で告げていた。
  it("says the master password was wrong rather than blaming the bucket", async () => {
    const api = buildApi(configured, nothingToDo, {
      pushSnapshot: vi.fn().mockRejectedValue(new ApiError("wrong_master_password", 403, null)),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Master password"), "not the master password");
    await userEvent.click(screen.getByRole("button", { name: "Push this workspace" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/not this machine's master password/i);
  });

  // 設定は保持される前に試されるので、画面は何も保存されなかったと
  // 言わなければならない——さもないと、ユーザーは保存されたと信じたまま去ってしまう。
  it("says nothing was saved when the bucket did not answer", async () => {
    const api = buildApi(unconfigured, nothingToDo, {
      configureSync: vi.fn().mockRejectedValue(new ApiError("bucket_refused", 502, null)),
    });
    render(<SyncPanel api={api} />);

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://acc.r2.cloudflarestorage.com");
    await userEvent.type(screen.getByLabelText("Bucket name"), "sshc");
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

    await userEvent.type(await screen.findByLabelText("Endpoint"), "https://acc.r2.cloudflarestorage.com/sshc");
    await userEvent.type(screen.getByLabelText("Bucket name"), "sshc");
    await userEvent.type(screen.getByLabelText("Access key ID"), "AKID");
    await userEvent.type(screen.getByLabelText("Secret access key"), "the-secret");
    await userEvent.click(screen.getByRole("button", { name: "Use this bucket" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/no bucket name and no path/i);
  });
});
