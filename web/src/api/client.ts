import type { components } from "./schema";

export type HealthResponse = components["schemas"]["HealthResponse"];
export type Problem = components["schemas"]["Problem"];

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly problem: Problem | null;

  constructor(code: string, status: number, problem: Problem | null) {
    super(code);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.problem = problem;
  }
}

// failureCode is the code the server used to refuse an operation, so an
// interface can quote it instead of paraphrasing it. A failure that never
// reached the server has no code.
export function failureCode(error: unknown): string {
  return error instanceof ApiError ? error.code : "";
}

async function readProblem(response: Response): Promise<Problem | null> {
  try {
    const payload: unknown = await response.json();
    if (typeof payload !== "object" || payload === null) return null;
    const record = payload as Record<string, unknown>;
    if (typeof record.code !== "string" || typeof record.message !== "string") return null;
    return record as Problem;
  } catch {
    return null;
  }
}

// The application is behind the master password, and the vault shuts itself
// after a day of not being used. That can happen between any two requests, so
// every refusal is inspected for it here rather than in each screen: a screen
// that handled it locally would show "that could not be done" on a shell that
// is no longer usable at all.
let onLocked: (() => void) | null = null;

export function whenLocked(handler: (() => void) | null) {
  onLocked = handler;
}

async function failure(response: Response): Promise<ApiError> {
  const problem = await readProblem(response);
  const code = problem?.code ?? "request_failed";
  if (code === "vault_locked") onLocked?.();
  return new ApiError(code, response.status, problem);
}

function validateHealth(value: unknown): HealthResponse {
  if (typeof value !== "object" || value === null) {
    throw new Error("invalid_health_response");
  }

  const record = value as Record<string, unknown>;
  if (record.status !== "ok" || typeof record.version !== "string" || record.version.length === 0) {
    throw new Error("invalid_health_response");
  }
  return { status: "ok", version: record.version };
}

let csrfToken: string | null = null;

export const apiClient = {
  setCSRF(token: string) {
    csrfToken = token;
  },
  clear() {
    csrfToken = null;
  },
  async health(): Promise<HealthResponse> {
    const response = await fetch("/api/v1/health", { credentials: "same-origin" });
    if (!response.ok) throw new Error("health_failed");
    return validateHealth(await response.json());
  },
  // A read carries the token as well, because the cookie alone is not proof
  // of anything: it is not scoped to a port, so another server on 127.0.0.1
  // receives it, while the token stays in this page's memory.
  async read(path: string): Promise<unknown> {
    if (!csrfToken) throw new Error("csrf_unavailable");
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: { "X-SSH-UI-CSRF": csrfToken },
    });
    if (!response.ok) throw await failure(response);
    return response.json() as Promise<unknown>;
  },
  // send performs a mutation and returns the raw response, so a caller can read
  // a body that accompanies a rejection — such as the blockers the server
  // returns with a refused restore, which are an answer rather than a failure.
  async send(path: string, init: RequestInit): Promise<Response> {
    const target = new URL(path, window.location.origin);
    if (target.origin !== window.location.origin) {
      throw new Error("cross_origin_api_mutation");
    }
    if (!csrfToken) throw new Error("csrf_unavailable");

    const headers = new Headers(init.headers);
    headers.set("X-SSH-UI-CSRF", csrfToken);
    return fetch(path, { ...init, credentials: "same-origin", headers });
  },
  async mutate<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.send(path, init);
    if (!response.ok) throw await failure(response);
    return response.json() as Promise<T>;
  },
};
