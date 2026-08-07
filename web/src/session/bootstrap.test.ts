import { describe, expect, it, vi } from "vitest";
import { bootstrapSession } from "./bootstrap";

describe("bootstrapSession", () => {
  it("exchanges a valid fragment once and removes it from browser history", async () => {
    const replaceState = vi.fn();
    const bootstrap = "b".repeat(43);
    const csrfToken = "c".repeat(43);
    const fetcher = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ csrfToken }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));

    const state = await bootstrapSession(
      { hash: `#bootstrap=${bootstrap}`, pathname: "/", search: "" },
      { replaceState },
      fetcher,
    );

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith("/api/v1/session/bootstrap", expect.objectContaining({
      method: "POST",
      credentials: "same-origin",
      headers: expect.objectContaining({ "X-SSHC-Bootstrap": bootstrap }),
    }));
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
    expect(state.csrfToken).toBe(csrfToken);
  });

  // フラグメントがないことはもはや失敗ではない——それはリロードであり、
  // 以下で扱う。存在していて壊れているフラグメントは依然として失敗だ:
  // 何かがそれを置いたのであり、それは私たちのものではない。
  it.each([
    ["short", "#bootstrap=short", "invalid_bootstrap_fragment"],
    ["overlong", `#bootstrap=${"b".repeat(64)}`, "invalid_bootstrap_fragment"],
  ])("rejects a %s fragment before fetch", async (_name, hash, code) => {
    const fetcher = vi.fn();

    await expect(bootstrapSession(
      { hash, pathname: "/", search: "" },
      { replaceState: vi.fn() },
      fetcher,
    )).rejects.toThrow(code);

    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a non-success response", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));

    await expect(bootstrapSession(
      { hash: `#bootstrap=${"b".repeat(43)}`, pathname: "/", search: "" },
      { replaceState: vi.fn() },
      fetcher,
    )).rejects.toThrow("bootstrap_rejected");
  });

  it("rejects a malformed response without persistent storage", async () => {
    const localSet = vi.spyOn(Storage.prototype, "setItem");
    const fetcher = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ csrfToken: "short" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));

    await expect(bootstrapSession(
      { hash: `#bootstrap=${"b".repeat(43)}`, pathname: "/", search: "" },
      { replaceState: vi.fn() },
      fetcher,
    )).rejects.toThrow("invalid_bootstrap_response");

    expect(localSet).not.toHaveBeenCalled();
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });
});

describe("a reload", () => {
  // フラグメントは初回使用時に使い切られ、history.replaceState がそれを
  // 取り除くので、リロードはクッキーだけを伴って届く。そこで例外を投げることが、
  // バイナリを再起動するまであらゆるリロードでアプリケーションを殺していた原因だ。
  it("renews the token for the session the cookie already names", async () => {
    const replaceState = vi.fn();
    const csrfToken = "d".repeat(43);
    const fetcher = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ csrfToken }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));

    const state = await bootstrapSession({ hash: "", pathname: "/", search: "" }, { replaceState }, fetcher);

    expect(fetcher).toHaveBeenCalledWith("/api/v1/session/renew", expect.objectContaining({
      method: "POST",
      credentials: "same-origin",
    }));
    expect(state.csrfToken).toBe(csrfToken);
    // アドレスバーから取り除くものはない: そもそもフラグメントがなかったからだ。
    expect(replaceState).not.toHaveBeenCalled();
  });

  // もはやセッションを名指さないクッキーは、ここでは回復できない:
  // ブートストラップフラグメントは起動中のプロセスだけが出力する。エラーは
  // 2 つの状況のどちらであるかを伝える。「sshc を再起動する」が答えになるのは
  // 一方だけであり、もう一方には答えにならないからだ。
  it("says the session is gone when the cookie no longer names one", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response("", { status: 401 }));

    await expect(
      bootstrapSession({ hash: "", pathname: "/", search: "" }, { replaceState: vi.fn() }, fetcher),
    ).rejects.toThrow("session_expired");
  });
});
