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

  // A reload arrives with the cookie and nothing else: the fragment is spent on
  // first use, and replaceState took it out of the address bar so it would not
  // sit in history. Treating that as a failure is what killed the application
  // on every reload — the session was alive the whole time, and only the CSRF
  // token, which lived in the page, was gone.
  if (bootstrap === "") {
    const renewed = await fetcher("/api/v1/session/renew", {
      method: "POST",
      credentials: "same-origin",
    });
    // A cookie that no longer names a session cannot be recovered from here: a
    // bootstrap fragment is printed only by a starting process. The two cases
    // are told apart because restarting ssh-ui is the answer to one of them.
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
    headers: { "X-SSH-UI-Bootstrap": bootstrap },
  });
  if (!response.ok) throw new Error("bootstrap_rejected");

  const payload: unknown = await response.json();
  if (!isBootstrapResponse(payload)) throw new Error("invalid_bootstrap_response");
  return { csrfToken: payload.csrfToken };
}
