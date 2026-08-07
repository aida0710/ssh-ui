import { apiClient } from "../api/client";
import type { components } from "../api/schema";

export type RemoteKeyPlan = components["schemas"]["RemoteKeyPlan"];
export type RemoteKeyRegisterResponse = components["schemas"]["RemoteKeyRegisterResponse"];
export type ExecutableDirective = components["schemas"]["ExecutableDirective"];
export type IssueActionResponse = components["schemas"]["IssueActionResponse"];

// action の語彙はサーバーの session パッケージに属し、操作を確認する
// すべてのサブシステムのためにそれを所有する。これはその通信上の値だ。
export const REMOTE_KEY_REGISTER_ACTION_KIND = "remote_key.register";

export type RemoteKeyInput = {
  alias: string;
  keyPath: string;
  publicKey: string;
};

export type RemoteKeyRegisterInput = RemoteKeyInput & { acknowledgeExecutable: boolean };

export type RemoteKeysApi = {
  plan(input: RemoteKeyInput): Promise<RemoteKeyPlan>;
  register(input: RemoteKeyRegisterInput): Promise<RemoteKeyRegisterResponse>;
};

// 生成された型は契約を記述するだけであり、これらのガードは UI が
// 実際に受け取ったペイロードを検査する。型アサーションは実行時には何も証明しない。
function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid_response");
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("invalid_response");
  return value;
}

function asString(value: unknown): string {
  if (typeof value !== "string") throw new Error("invalid_response");
  return value;
}

function asNumber(value: unknown): number {
  if (typeof value !== "number") throw new Error("invalid_response");
  return value;
}

function asBoolean(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("invalid_response");
  return value;
}

function validatePlan(value: unknown): RemoteKeyPlan {
  const record = asRecord(value);
  asString(record.alias);
  asString(record.user);
  asString(record.hostname);
  asString(record.port);
  asString(record.valuesFrom);
  asString(record.fingerprint);
  asString(record.keyPath);
  asString(record.keyLine);
  asString(record.remotePath);
  asString(record.routine);
  asBoolean(record.supported);
  for (const step of asArray(record.manual)) asString(step);
  for (const directive of asArray(record.executableDirectives)) {
    const entry = asRecord(directive);
    asString(entry.keyword);
    asString(entry.command);
    asString(entry.path);
    asNumber(entry.line);
    asBoolean(entry.overridable);
  }
  return record as unknown as RemoteKeyPlan;
}

function validateRegistration(value: unknown): RemoteKeyRegisterResponse {
  const record = asRecord(value);
  asString(record.outcome);
  asNumber(record.exitCode);
  asString(record.stderr);
  asBoolean(record.truncated);
  return record as unknown as RemoteKeyRegisterResponse;
}

const jsonHeaders = { "Content-Type": "application/json" } as const;

// issueAction は登録に必要なワンタイムトークンを鋳造する。リクエストが
// 名指すのは操作とその対象だけであり、トークンが紐付く evidence は
// サーバー側で発行時と消費時の両方で導出されるので、このクライアントが
// ユーザーに一度も見せていない状態にトークンを結び付けることはできない。
async function issueAction(kind: string, target: string): Promise<string> {
  const response = await apiClient.mutate<IssueActionResponse>("/api/v1/actions", {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ kind, target }),
  });
  return asString(asRecord(response).token);
}

export const remoteKeysApi: RemoteKeysApi = {
  // plan は設定を読むだけで何にも接続しないので、確認を消費しない。
  // これが存在するのは、実行を求められるようになる前に、ユーザーが
  // 変更内容を見られるようにするためだ。
  async plan(input) {
    return validatePlan(
      await apiClient.mutate<unknown>("/api/v1/remote-keys/plan", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ alias: input.alias, keyPath: input.keyPath, publicKey: input.publicKey }),
      }),
    );
  },
  async register(input) {
    const token = await issueAction(REMOTE_KEY_REGISTER_ACTION_KIND, input.alias);
    return validateRegistration(
      await apiClient.mutate<unknown>("/api/v1/remote-keys/register", {
        method: "POST",
        headers: { ...jsonHeaders, "X-SSHC-Action": token },
        body: JSON.stringify({
          alias: input.alias,
          keyPath: input.keyPath,
          publicKey: input.publicKey,
          acknowledgeExecutable: input.acknowledgeExecutable,
        }),
      }),
    );
  },
};
