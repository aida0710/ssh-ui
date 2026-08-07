import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiClient } from "./client";
import { integrationsApi, KNOWN_HOSTS_ADD_ACTION_KIND } from "./integrations";

const csrfToken = "c".repeat(43);
const actionToken = "a".repeat(43);

const candidate = {
  host: "new.example.com",
  port: 22,
  keyType: "ssh-ed25519",
  key: "AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS",
};

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

describe("integrationsApi.addKnownHost", () => {
  // アクションの種類はサーバーのセッションパッケージが所有する。ここで綴りを
  // 変えれば、サーバーが拒否するトークンを作ってしまう。
  it("uses the committed action vocabulary", () => {
    expect(KNOWN_HOSTS_ADD_ACTION_KIND).toBe("known_hosts.add");
  });

  it("mints a token bound to the host and sends no evidence of its own", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ token: actionToken, expiresAt: "2026-08-05T09:02:00Z" }, 201))
      .mockResolvedValueOnce(jsonResponse({ changed: true, transactionId: "tx-2" }));
    vi.stubGlobal("fetch", fetcher);

    const result = await integrationsApi.addKnownHost(candidate, "SHA256:proof", false);
    expect(result.transactionId).toBe("tx-2");

    const [actionPath, actionInit] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(actionPath).toBe("/api/v1/actions");
    // 含まれるのは操作と target だけである。トークンが紐付く証跡は
    // 発行時と消費時にサーバー側で導出される。
    expect(JSON.parse(String(actionInit.body))).toEqual({
      kind: "known_hosts.add",
      target: "new.example.com",
    });

    const [addPath, addInit] = fetcher.mock.calls[1] as [string, RequestInit];
    expect(addPath).toBe("/api/v1/known-hosts/add");
    const headers = new Headers(addInit.headers);
    expect(headers.get("X-SSHC-Action")).toBe(actionToken);
    expect(headers.get("X-SSHC-CSRF")).toBe(csrfToken);
    expect(JSON.parse(String(addInit.body))).toEqual({
      ...candidate,
      expectedFingerprint: "SHA256:proof",
      acknowledged: false,
    });
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("raises the server's refusal code when the add is rejected", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ token: actionToken, expiresAt: "2026-08-05T09:02:00Z" }, 201))
      .mockResolvedValueOnce(
        jsonResponse({ code: "unverified_candidate", message: "not proven" }, 409),
      );
    vi.stubGlobal("fetch", fetcher);

    const failure = await integrationsApi.addKnownHost(candidate, "", false).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe("unverified_candidate");
    expect((failure as ApiError).status).toBe(409);
  });
});
