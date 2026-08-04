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
      headers: expect.objectContaining({ "X-SSH-UI-Bootstrap": bootstrap }),
    }));
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
    expect(state.csrfToken).toBe(csrfToken);
  });

  it.each([
    ["missing", "", "invalid_bootstrap_fragment"],
    ["short", "#bootstrap=short", "invalid_bootstrap_fragment"],
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
