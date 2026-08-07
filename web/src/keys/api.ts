import { apiClient } from "../api/client";
import type { components } from "../api/schema";

export type KeyItem = components["schemas"]["KeyItem"];
export type KeyCertificate = components["schemas"]["KeyCertificate"];
export type UnreadableFile = components["schemas"]["UnreadableFile"];
export type UnresolvedReference = components["schemas"]["UnresolvedReference"];
export type KeyReference = components["schemas"]["KeyReference"];
export type KeyVariant = components["schemas"]["KeyVariant"];
export type KeyInventoryResponse = components["schemas"]["KeyInventoryResponse"];
export type KeyAlgorithmsResponse = components["schemas"]["KeyAlgorithmsResponse"];
export type GenerateKeyResponse = components["schemas"]["GenerateKeyResponse"];
export type HardwareCommandResponse = components["schemas"]["HardwareCommandResponse"];
export type ChangePassphraseResponse = components["schemas"]["ChangePassphraseResponse"];
export type RevealPrivateKeyResponse = components["schemas"]["RevealPrivateKeyResponse"];
export type RegisterKeyResponse = components["schemas"]["RegisterKeyResponse"];
export type AgentIdentitiesResponse = components["schemas"]["AgentIdentitiesResponse"];
export type PublicKeyResponse = components["schemas"]["PublicKeyResponse"];
export type RelocateKeyResponse = components["schemas"]["RelocateKeyResponse"];
export type RelocatedKeyFile = components["schemas"]["RelocatedKeyFile"];
export type RewrittenKeyReference = components["schemas"]["RewrittenKeyReference"];
export type AgentIdentity = components["schemas"]["AgentIdentity"];
export type IssueActionResponse = components["schemas"]["IssueActionResponse"];
export type TrashListResponse = components["schemas"]["TrashListResponse"];
export type TrashKeyResponse = components["schemas"]["TrashKeyResponse"];
export type RestoreTrashResponse = components["schemas"]["RestoreTrashResponse"];
export type PurgeTrashResponse = components["schemas"]["PurgeTrashResponse"];

// action の語彙はサーバーの session パッケージに属し、操作を確認する
// すべてのサブシステムのためにそれを所有する。これらはその通信上の値だ。
export const REVEAL_ACTION_KIND = "private_key.reveal";
export const PURGE_ACTION_KIND = "trash.purge";

// KeyLocationInput は変更しないものを省く。名前とグループは別々の
// 行き先なので、relocation はどちらか一方または両方を変えられ、
// 空のグループは実在の答えだ: グループなしの鍵がある ~/.ssh のルートを指す。
export type KeyLocationInput = {
  newName?: string;
  group?: string;
};

export type GenerateKeyInput = {
  algorithm: string;
  fileName: string;
  group: string;
  comment: string;
  passphrase: string;
  unencrypted: boolean;
  bits?: number;
};

export type HardwareCommandInput = {
  algorithm: string;
  fileName: string;
  group: string;
  comment: string;
};

export type PassphraseInput = {
  currentPassphrase: string;
  newPassphrase: string;
  unencrypted: boolean;
};

// RegisterAgentInput は ssh-add が 1 つの鍵を読み込むのに必要な入力だ。lifetimeSeconds は
// ssh-add 自身の -t で、0 はエージェントが終了するまで鍵を保持することを意味する。
// storeInKeychain は --apple-use-keychain を追加する。パスフレーズがこのリクエスト
// より長生きする唯一の方法であり、それを保持するのはこのアプリではなく macOS だ。
export type RegisterAgentInput = {
  passphrase: string;
  lifetimeSeconds: number;
  storeInKeychain: boolean;
};

export type KeysApi = {
  inventory(): Promise<KeyInventoryResponse>;
  algorithms(): Promise<KeyAlgorithmsResponse>;
  generate(input: GenerateKeyInput): Promise<GenerateKeyResponse>;
  hardwareCommand(input: HardwareCommandInput): Promise<HardwareCommandResponse>;
  changePassphrase(keyId: string, input: PassphraseInput): Promise<ChangePassphraseResponse>;
  reveal(keyId: string): Promise<RevealPrivateKeyResponse>;
  publicKey(keyId: string): Promise<PublicKeyResponse>;
  relocate(keyId: string, change: KeyLocationInput): Promise<RelocateKeyResponse>;
  registerWithAgent(keyId: string, input: RegisterAgentInput): Promise<RegisterKeyResponse>;
  // エージェントから鍵を取り出す。何も破棄しないので確認は
  // 不要で、間違っていた場合の代償はもう一度パスフレーズを求められることだけだ。
  deregisterFromAgent(keyId: string): Promise<AgentIdentitiesResponse>;
  trash(keyId: string): Promise<TrashKeyResponse>;
  listTrash(): Promise<TrashListResponse>;
  restore(entryId: string): Promise<RestoreTrashResponse>;
  purge(entryId: string): Promise<PurgeTrashResponse>;
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

function validateInventory(value: unknown): KeyInventoryResponse {
  const record = asRecord(value);
  for (const item of asArray(record.items)) {
    const entry = asRecord(item);
    asString(entry.id);
    asString(entry.relativePath);
    asString(entry.kind);
    asString(entry.permission);
    asNumber(entry.bits);
    asBoolean(entry.encrypted);
    asArray(entry.references);
    asArray(entry.notes);
  }
  for (const file of asArray(record.unreadable)) {
    const entry = asRecord(file);
    asString(entry.relativePath);
    asString(entry.reason);
  }
  asArray(record.agentDelegations);
  for (const reference of asArray(record.unresolvedReferences)) {
    const entry = asRecord(reference);
    asString(entry.directive);
    asString(entry.value);
    asString(entry.configPath);
    asNumber(entry.line);
    asString(entry.reason);
  }
  asBoolean(record.agentAvailable);
  validateAgentIdentities(record.agentIdentities);
  return record as unknown as KeyInventoryResponse;
}

function validateAgentIdentitiesResponse(value: unknown): AgentIdentitiesResponse {
  const record = asRecord(value);
  asString(record.id);
  asBoolean(record.agentAvailable);
  validateAgentIdentities(record.identities);
  return record as unknown as AgentIdentitiesResponse;
}

function validateAlgorithms(value: unknown): KeyAlgorithmsResponse {
  const record = asRecord(value);
  for (const variant of asArray(record.variants)) {
    const entry = asRecord(variant);
    asString(entry.algorithm);
    asString(entry.label);
    asNumber(entry.bits);
    asBoolean(entry.inProcess);
  }
  asString(record.source);
  return record as unknown as KeyAlgorithmsResponse;
}

function validateReveal(value: unknown): RevealPrivateKeyResponse {
  const record = asRecord(value);
  asString(record.id);
  asString(record.relativePath);
  asString(record.privateKey);
  asBoolean(record.encrypted);
  return record as unknown as RevealPrivateKeyResponse;
}

function validateAgentIdentities(value: unknown): void {
  for (const identity of asArray(value)) {
    const entry = asRecord(identity);
    asNumber(entry.bits);
    asString(entry.fingerprint);
    asString(entry.comment);
    asString(entry.algorithm);
  }
}

function validateRegister(value: unknown): RegisterKeyResponse {
  const record = asRecord(value);
  asString(record.id);
  asString(record.relativePath);
  asString(record.fingerprint);
  asNumber(record.lifetimeSeconds);
  asBoolean(record.storedInKeychain);
  validateAgentIdentities(record.identities);
  return record as unknown as RegisterKeyResponse;
}

function validatePublicKey(value: unknown): PublicKeyResponse {
  const record = asRecord(value);
  asString(record.id);
  asString(record.relativePath);
  asString(record.publicKey);
  asString(record.fingerprint);
  asString(record.comment);
  return record as unknown as PublicKeyResponse;
}

function validateRelocate(value: unknown): RelocateKeyResponse {
  const record = asRecord(value);
  asString(record.relativePath);
  asString(record.group);
  for (const file of asArray(record.files)) {
    const entry = asRecord(file);
    asString(entry.from);
    asString(entry.to);
  }
  for (const reference of asArray(record.references)) {
    const entry = asRecord(reference);
    asString(entry.directive);
    asString(entry.configPath);
    asNumber(entry.line);
    asString(entry.from);
    asString(entry.to);
  }
  asArray(record.skipped);
  asArray(record.notes);
  asArray(record.blockers);
  return record as unknown as RelocateKeyResponse;
}

function validateTrashList(value: unknown): TrashListResponse {
  const record = asRecord(value);
  asNumber(record.retentionDays);
  for (const entry of asArray(record.entries)) {
    const item = asRecord(entry);
    asString(item.id);
    asString(item.deletedAt);
    asNumber(item.ageDays);
    asBoolean(item.stale);
    asBoolean(item.restorable);
    asArray(item.files);
    asArray(item.blockers);
  }
  return record as unknown as TrashListResponse;
}

function validateRestore(value: unknown): RestoreTrashResponse {
  const record = asRecord(value);
  asString(record.entryId);
  asArray(record.restored);
  asArray(record.blockers);
  return record as unknown as RestoreTrashResponse;
}

const jsonHeaders = { "Content-Type": "application/json" } as const;

// issueAction は、開示と完全削除にサーバーが要求するワンタイムトークンを
// 鋳造する。呼び出し側は操作とその対象を名指すだけで、トークンが
// 何に紐付くかは、サーバーがこれから作用する状態から
// 導出する。トークンは即座に使われ、二度と保存されない。
async function issueAction(kind: string, target: string): Promise<string> {
  const response = await apiClient.mutate<IssueActionResponse>("/api/v1/actions", {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ kind, target }),
  });
  return asString(asRecord(response).token);
}

export const keysApi: KeysApi = {
  async inventory() {
    return validateInventory(await apiClient.read("/api/v1/keys"));
  },
  async algorithms() {
    return validateAlgorithms(await apiClient.read("/api/v1/keys/algorithms"));
  },
  generate: (input) =>
    apiClient.mutate<GenerateKeyResponse>("/api/v1/keys", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({
        algorithm: input.algorithm,
        bits: input.bits ?? 0,
        fileName: input.fileName,
        group: input.group,
        comment: input.comment,
        passphrase: input.passphrase,
        unencrypted: input.unencrypted,
      }),
    }),
  hardwareCommand: (input) =>
    apiClient.mutate<HardwareCommandResponse>("/api/v1/keys/hardware-command", {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify(input),
    }),
  changePassphrase: (keyId, input) =>
    apiClient.mutate<ChangePassphraseResponse>(`/api/v1/keys/${encodeURIComponent(keyId)}/passphrase`, {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify(input),
    }),
  async reveal(keyId) {
    const token = await issueAction(REVEAL_ACTION_KIND, keyId);
    return validateReveal(
      await apiClient.mutate<unknown>(`/api/v1/keys/${encodeURIComponent(keyId)}/reveal`, {
        method: "POST",
        headers: { "X-SSHC-Action": token },
      }),
    );
  },
  // 公開鍵は秘密ではないので、これは確認も no-store も監査記録もない
  // 普通の読み取りだ。サーバーは公開鍵でも証明書でもないエントリを
  // すべて拒否し、それがこれを成り立たせている。
  async publicKey(keyId) {
    return validatePublicKey(await apiClient.read(`/api/v1/keys/${encodeURIComponent(keyId)}/public`));
  },
  // ブロックされた relocation は、拒否した理由とともに 409 で応答し、
  // 何も書き込まれなかった。その理由こそが拒否の要点なので、失敗した
  // リクエストとして捨てるのではなく、ボディから読み取る。
  async relocate(keyId, change) {
    const response = await apiClient.send(`/api/v1/keys/${encodeURIComponent(keyId)}/location`, {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify(change),
    });
    if (!response.ok && response.status !== 409) {
      throw new Error("api_mutation_failed");
    }
    return validateRelocate(await response.json());
  },
  // パスフレーズはリクエストボディの中だけを移動し、それより先には進まない。サーバーはそれを
  // ssh-add の標準入力に渡すので、argv にも子プロセスの
  // 環境にも届かない。ここでは複製を一切保持せず、呼び出し側は自身の状態をクリアし、
  // 応答は何がロックを解いたかではなく、いまエージェントが保持しているものを伝える。
  async registerWithAgent(keyId, input) {
    return validateRegister(
      await apiClient.mutate<unknown>(`/api/v1/keys/${encodeURIComponent(keyId)}/agent`, {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify(input),
      }),
    );
  },
  async deregisterFromAgent(keyId) {
    return validateAgentIdentitiesResponse(
      await apiClient.mutate<unknown>(`/api/v1/keys/${encodeURIComponent(keyId)}/agent`, {
        method: "DELETE",
      }),
    );
  },
  trash: (keyId) =>
    apiClient.mutate<TrashKeyResponse>(`/api/v1/keys/${encodeURIComponent(keyId)}/trash`, { method: "POST" }),
  async listTrash() {
    return validateTrashList(await apiClient.read("/api/v1/trash"));
  },
  async restore(entryId) {
    // 拒否された restore は、それを説明するブロッカーとともに 409 で応答する。
    // それはユーザーが必要とする情報であり、捨てるべき通信の失敗ではない。
    const response = await apiClient.send(`/api/v1/trash/${encodeURIComponent(entryId)}/restore`, {
      method: "POST",
    });
    if (!response.ok && response.status !== 409) {
      throw new Error("api_mutation_failed");
    }
    return validateRestore(await response.json());
  },
  async purge(entryId) {
    const token = await issueAction(PURGE_ACTION_KIND, entryId);
    return apiClient.mutate<PurgeTrashResponse>(`/api/v1/trash/${encodeURIComponent(entryId)}`, {
      method: "DELETE",
      headers: { "X-SSHC-Action": token },
    });
  },
};
