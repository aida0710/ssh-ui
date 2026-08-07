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

  // A missing fragment is no longer a failure — it is a reload, and is covered
  // below. A fragment that is present and malformed still is: something put it
  // there, and it is not one of ours.
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
  // The fragment is spent on first use and history.replaceState removed it, so
  // a reload arrives with a cookie and nothing else. Throwing there is what
  // killed the application on every reload until the binary was restarted.
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
    // Nothing to remove from the address bar: there was no fragment.
    expect(replaceState).not.toHaveBeenCalled();
  });

  // A cookie that no longer names a session cannot be recovered from here: a
  // bootstrap fragment is printed only by a starting process. The error says
  // which of the two situations it is, because "restart sshc" is the answer
  // to one of them and not the other.
  it("says the session is gone when the cookie no longer names one", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response("", { status: 401 }));

    await expect(
      bootstrapSession({ hash: "", pathname: "/", search: "" }, { replaceState: vi.fn() }, fetcher),
    ).rejects.toThrow("session_expired");
  });
});
