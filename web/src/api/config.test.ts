import { afterEach, describe, expect, it, vi } from "vitest";
import { apiClient, ApiError } from "./client";
import { configApi } from "./config";

const overviewPayload = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [{ file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 }],
  hosts: [{
    identity: { path: "config", alias: "bastion" },
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    line: 1,
    patterns: ["bastion"],
    editable: true,
  }],
  metadata: { schemaVersion: 1 },
  diagnostics: [],
  notices: [],
};

afterEach(() => {
  apiClient.clear();
  vi.unstubAllGlobals();
});

describe("configApi", () => {
  it("returns a runtime-validated overview", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify(overviewPayload),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));

    const overview = await configApi.overview();

    expect(overview.hosts[0]?.identity.alias).toBe("bastion");
  });

  it("rejects an overview whose shape does not match the contract", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ entry: {}, files: [], hosts: "not-an-array", metadata: {}, diagnostics: [], notices: [] }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));

    await expect(configApi.overview()).rejects.toThrow("invalid_response");
  });

  it("escapes query parameters instead of concatenating them", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({
        form: { entry: overviewPayload.hosts[0], fields: [], raw: "" },
        metadata: { identity: { path: "config", alias: "a b" } },
        effective: { alias: "a b", approximate: true, entries: [] },
        file: {
          file: { path: "config", absolute: "/home/tester/.ssh/config" },
          contents: "", digest: "", editable: true, exists: true,
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetcher);

    await configApi.host("conf.d/10 home.conf", "a b");

    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/config/host?path=conf.d%2F10+home.conf&alias=a+b");
  });

  it("surfaces the problem code and conflict report of a rejected save", async () => {
    const conflict = {
      path: "config",
      externalChange: [{ op: "insert", text: "Host other", newLine: 4 }],
      localChange: [{ op: "delete", text: "\tPort 22", oldLine: 3 }],
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ code: "config_conflict", message: "request rejected", path: "config", conflict }),
      { status: 409, headers: { "Content-Type": "application/problem+json" } },
    )));
    apiClient.setCSRF("c".repeat(43));

    const failure = await configApi.save({ kind: "file_raw", path: "config", raw: "Host a\n" }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ApiError);
    const apiError = failure as ApiError;
    expect(apiError.code).toBe("config_conflict");
    expect(apiError.status).toBe(409);
    expect(apiError.problem?.conflict?.externalChange).toHaveLength(1);
  });
});
