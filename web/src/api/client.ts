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

// failureCode はサーバーが操作を拒否する際に使ったコードであり、インターフェースは
// それを言い換えるのではなく引用できる。サーバーまで届かなかった
// 失敗にはコードがない。
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

// アプリケーションは master password の向こうにあり、vault は使われない
// まま 1 日経つと自ら閉じる。これはどの二つのリクエストの間にも起こり
// 得るため、それを調べるのは各画面ではなくここで一括して行う。
// それを各画面が個別に扱えば、もはやまったく使えなくなったシェル上で
// 「それはできませんでした」と表示することになる。
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
  // 読み取りもトークンを運ぶ。クッキーだけでは何の証明にもならないからである。
  // クッキーはポートにスコープされないため、127.0.0.1 上の別のサーバーもそれを
  // 受け取ってしまうが、トークンはこのページのメモリに留まる。
  async read(path: string): Promise<unknown> {
    if (!csrfToken) throw new Error("csrf_unavailable");
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: { "X-SSHC-CSRF": csrfToken },
    });
    if (!response.ok) throw await failure(response);
    return response.json() as Promise<unknown>;
  },
  // send は更新系の操作を実行し、生のレスポンスを返す。呼び出し側は拒否に
  // 添えられた本体を読めるようにするためである——たとえば復元が
  // 拒否された際にサーバーが返す blockers は、失敗ではなく答えである。
  async send(path: string, init: RequestInit): Promise<Response> {
    const target = new URL(path, window.location.origin);
    if (target.origin !== window.location.origin) {
      throw new Error("cross_origin_api_mutation");
    }
    if (!csrfToken) throw new Error("csrf_unavailable");

    const headers = new Headers(init.headers);
    headers.set("X-SSHC-CSRF", csrfToken);
    return fetch(path, { ...init, credentials: "same-origin", headers });
  },
  async mutate<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.send(path, init);
    if (!response.ok) throw await failure(response);
    return response.json() as Promise<T>;
  },
};
