import { afterEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "./client";

afterEach(() => {
  apiClient.clear();
  vi.unstubAllGlobals();
});

describe("apiClient", () => {
  it("returns only a runtime-valid health response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ status: "ok", version: "0.1.0" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));

    await expect(apiClient.health()).resolves.toEqual({ status: "ok", version: "0.1.0" });
  });

  it("rejects malformed health payloads", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ status: "ok", version: "" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));

    await expect(apiClient.health()).rejects.toThrow("invalid_health_response");
  });

  it("adds the module-memory CSRF token to mutations", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetcher);
    apiClient.setCSRF("c".repeat(43));

    await expect(apiClient.mutate<{ ok: boolean }>("/api/v1/example", { method: "POST" }))
      .resolves.toEqual({ ok: true });

    const request = fetcher.mock.calls[0]?.[1] as RequestInit;
    expect(new Headers(request.headers).get("X-SSH-UI-CSRF")).toBe("c".repeat(43));
    expect(request.credentials).toBe("same-origin");
  });

  it("rejects mutations before a CSRF token is set", async () => {
    await expect(apiClient.mutate("/api/v1/example", { method: "POST" })).rejects.toThrow("csrf_unavailable");
  });
});
