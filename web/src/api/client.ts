import type { components } from "./schema";

export type HealthResponse = components["schemas"]["HealthResponse"];

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
  async mutate<T>(path: string, init: RequestInit): Promise<T> {
    const target = new URL(path, window.location.origin);
    if (target.origin !== window.location.origin) {
      throw new Error("cross_origin_api_mutation");
    }
    if (!csrfToken) throw new Error("csrf_unavailable");

    const headers = new Headers(init.headers);
    headers.set("X-SSH-UI-CSRF", csrfToken);
    const response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      headers,
    });
    if (!response.ok) throw new Error("api_mutation_failed");
    return response.json() as Promise<T>;
  },
};
