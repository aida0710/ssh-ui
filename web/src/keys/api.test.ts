import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../api/client";
import { keysApi, PURGE_ACTION_KIND, REVEAL_ACTION_KIND } from "./api";

const csrfToken = "c".repeat(43);
const actionToken = "a".repeat(43);

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  apiClient.setCSRF(csrfToken);
});

afterEach(() => {
  apiClient.clear();
  vi.unstubAllGlobals();
});

describe("keysApi", () => {
  // action の種類はサーバーの session パッケージが所有する。ここで
  // 綴りを変えれば、サーバーが拒否するトークンを鋳造してしまう。
  it("asks for a confirmation using the committed action vocabulary", () => {
    expect(REVEAL_ACTION_KIND).toBe("private_key.reveal");
    expect(PURGE_ACTION_KIND).toBe("trash.purge");
  });

  it("mints a one-time token and spends it on the reveal it was minted for", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ token: actionToken, expiresAt: "2026-08-05T09:02:00Z" }, 201))
      .mockResolvedValueOnce(jsonResponse({
        id: "key-one",
        relativePath: "id_work",
        privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        encrypted: true,
        fingerprint: "SHA256:abcdef",
        transactionId: "tx",
      }));
    vi.stubGlobal("fetch", fetcher);

    const revealed = await keysApi.reveal("key-one");
    expect(revealed.privateKey).toContain("BEGIN OPENSSH PRIVATE KEY");

    const [actionPath, actionInit] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(actionPath).toBe("/api/v1/actions");
    expect(JSON.parse(String(actionInit.body))).toEqual({ kind: "private_key.reveal", target: "key-one" });

    const [revealPath, revealInit] = fetcher.mock.calls[1] as [string, RequestInit];
    expect(revealPath).toBe("/api/v1/keys/key-one/reveal");
    expect(new Headers(revealInit.headers).get("X-SSHC-Action")).toBe(actionToken);
    // トークンは即座に使い切られ、二度と保持されない。
    expect(window.localStorage.getItem("action")).toBeNull();
  });

  it("mints a purge token bound to the entry being deleted", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ token: actionToken, expiresAt: "2026-08-05T09:02:00Z" }, 201))
      .mockResolvedValueOnce(jsonResponse({ entryId: "entry-1", removed: ["id_old"], transactionId: "tx" }));
    vi.stubGlobal("fetch", fetcher);

    await keysApi.purge("entry-1");

    const [, actionInit] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(actionInit.body))).toEqual({ kind: "trash.purge", target: "entry-1" });
    const [purgePath, purgeInit] = fetcher.mock.calls[1] as [string, RequestInit];
    expect(purgePath).toBe("/api/v1/trash/entry-1");
    expect(purgeInit.method).toBe("DELETE");
  });

  // 拒否された restore は失敗ではなく 1 つの答えだ: サーバーは 409 で
  // ブロッカーを返し、UI はそれを捨てずに表示しなければならない。
  it("reads the blockers out of a refused restore", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      entryId: "entry-1",
      restored: [],
      blockers: ["restore_path_occupied:id_old"],
      transactionId: "",
    }, 409)));

    const result = await keysApi.restore("entry-1");
    expect(result.blockers).toEqual(["restore_path_occupied:id_old"]);
    expect(result.restored).toEqual([]);
  });

  it("still throws when a restore fails for any other reason", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ code: "not_found", message: "x" }, 404)));
    await expect(keysApi.restore("entry-1")).rejects.toThrow();
  });

  // 生成された型は契約を記述するだけで、実際に届いたバイト列に
  // ついては何も証明しない。
  it("rejects an inventory payload that does not match the contract", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ items: "not-an-array" })));
    await expect(keysApi.inventory()).rejects.toThrow("invalid_response");

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      items: [{ id: "key-one" }],
      unreadable: [],
      agentDelegations: [],
      unresolvedReferences: [],
      agentAvailable: false,
      agentIdentities: [],
    })));
    await expect(keysApi.inventory()).rejects.toThrow("invalid_response");
  });

  it("rejects a reveal payload with no private key", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ token: actionToken, expiresAt: "2026-08-05T09:02:00Z" }, 201))
      .mockResolvedValueOnce(jsonResponse({ id: "key-one", relativePath: "id_work" }));
    vi.stubGlobal("fetch", fetcher);

    await expect(keysApi.reveal("key-one")).rejects.toThrow("invalid_response");
  });

  it("accepts a well-formed inventory and trash listing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      items: [{
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
        references: [],
        notes: [],
      }],
      unreadable: [],
      agentDelegations: [],
      unresolvedReferences: [],
      agentAvailable: false,
      agentIdentities: [],
    })));
    await expect(keysApi.inventory()).resolves.toMatchObject({ agentAvailable: false });

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      entries: [{
        id: "entry-1",
        deletedAt: "2026-08-05T09:00:00Z",
        ageDays: 40,
        stale: true,
        files: [],
        restorable: true,
        blockers: [],
      }],
      retentionDays: 30,
    })));
    await expect(keysApi.listTrash()).resolves.toMatchObject({ retentionDays: 30 });
  });
});
