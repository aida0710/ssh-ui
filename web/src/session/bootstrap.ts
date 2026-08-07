import type { components } from "../api/schema";

type BootstrapResponse = components["schemas"]["BootstrapResponse"];

export type SessionState = Readonly<{ csrfToken: string }>;

function isBootstrapResponse(value: unknown): value is BootstrapResponse {
  if (typeof value !== "object" || value === null) return false;
  const token = (value as Record<string, unknown>).csrfToken;
  return typeof token === "string" && /^[A-Za-z0-9_-]{43}$/.test(token);
}

export async function bootstrapSession(
  location: Pick<Location, "hash" | "pathname" | "search">,
  history: Pick<History, "replaceState">,
  fetcher: typeof fetch,
): Promise<SessionState> {
  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  const bootstrap = params.get("bootstrap") ?? "";

  // リロードはクッキーだけを伴って届く: フラグメントは初回使用時に
  // 使い切られ、replaceState が履歴に残らないようアドレスバーから
  // それを取り除いたからだ。それを失敗として扱うことが、あらゆる
  // リロードでアプリケーションを殺していた原因だ——セッションはずっと
  // 生きていて、ページに存在していた CSRF トークンだけがなくなっていた。
  if (bootstrap === "") {
    const renewed = await fetcher("/api/v1/session/renew", {
      method: "POST",
      credentials: "same-origin",
    });
    // もはやセッションを名指さないクッキーは、ここでは回復できない:
    // ブートストラップフラグメントは起動中のプロセスだけが出力する。この
    // 2 つの場合が区別されるのは、sshc の再起動が一方の答えになるからだ。
    if (!renewed.ok) throw new Error("session_expired");
    const payload: unknown = await renewed.json();
    if (!isBootstrapResponse(payload)) throw new Error("invalid_bootstrap_response");
    return { csrfToken: payload.csrfToken };
  }

  if (!/^[A-Za-z0-9_-]{43}$/.test(bootstrap)) {
    throw new Error("invalid_bootstrap_fragment");
  }

  history.replaceState(null, "", `${location.pathname}${location.search}`);
  const response = await fetcher("/api/v1/session/bootstrap", {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-SSHC-Bootstrap": bootstrap },
  });
  if (!response.ok) throw new Error("bootstrap_rejected");

  const payload: unknown = await response.json();
  if (!isBootstrapResponse(payload)) throw new Error("invalid_bootstrap_response");
  return { csrfToken: payload.csrfToken };
}
