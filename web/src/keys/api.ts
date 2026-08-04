import { apiClient } from "../api/client";
import type { components } from "../api/schema";

export type KeyItem = components["schemas"]["KeyItem"];
export type KeyReference = components["schemas"]["KeyReference"];
export type KeyVariant = components["schemas"]["KeyVariant"];
export type KeyInventoryResponse = components["schemas"]["KeyInventoryResponse"];
export type KeyAlgorithmsResponse = components["schemas"]["KeyAlgorithmsResponse"];
export type GenerateKeyResponse = components["schemas"]["GenerateKeyResponse"];
export type HardwareCommandResponse = components["schemas"]["HardwareCommandResponse"];
export type ChangePassphraseResponse = components["schemas"]["ChangePassphraseResponse"];
export type RevealPrivateKeyResponse = components["schemas"]["RevealPrivateKeyResponse"];
export type IssueActionResponse = components["schemas"]["IssueActionResponse"];
export type TrashListResponse = components["schemas"]["TrashListResponse"];
export type TrashKeyResponse = components["schemas"]["TrashKeyResponse"];
export type RestoreTrashResponse = components["schemas"]["RestoreTrashResponse"];
export type PurgeTrashResponse = components["schemas"]["PurgeTrashResponse"];

// The action vocabulary belongs to the server's session package, which owns it
// for every subsystem that confirms an operation. These are its wire values.
export const REVEAL_ACTION_KIND = "private_key.reveal";
export const PURGE_ACTION_KIND = "trash.purge";

export type GenerateKeyInput = {
  algorithm: string;
  fileName: string;
  comment: string;
  passphrase: string;
  unencrypted: boolean;
  bits?: number;
};

export type HardwareCommandInput = {
  algorithm: string;
  fileName: string;
  comment: string;
};

export type PassphraseInput = {
  currentPassphrase: string;
  newPassphrase: string;
  unencrypted: boolean;
};

export type KeysApi = {
  inventory(): Promise<KeyInventoryResponse>;
  algorithms(): Promise<KeyAlgorithmsResponse>;
  generate(input: GenerateKeyInput): Promise<GenerateKeyResponse>;
  hardwareCommand(input: HardwareCommandInput): Promise<HardwareCommandResponse>;
  changePassphrase(keyId: string, input: PassphraseInput): Promise<ChangePassphraseResponse>;
  reveal(keyId: string): Promise<RevealPrivateKeyResponse>;
  trash(keyId: string): Promise<TrashKeyResponse>;
  listTrash(): Promise<TrashListResponse>;
  restore(entryId: string): Promise<RestoreTrashResponse>;
  purge(entryId: string): Promise<PurgeTrashResponse>;
};

// The generated types describe the contract; these guards check the payload the
// UI actually received, because a type assertion proves nothing at runtime.
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
  asArray(record.unreadable);
  asArray(record.agentDelegations);
  asArray(record.unresolvedReferences);
  asBoolean(record.agentAvailable);
  asArray(record.agentIdentities);
  return record as unknown as KeyInventoryResponse;
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

// issueAction mints the one-time token the server requires for a reveal and for
// a permanent delete. The caller names only the operation and its target: what
// the token is bound to is derived by the server from the state it is about to
// act on. The token is used immediately and is never stored.
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
        headers: { "X-SSH-UI-Action": token },
      }),
    );
  },
  trash: (keyId) =>
    apiClient.mutate<TrashKeyResponse>(`/api/v1/keys/${encodeURIComponent(keyId)}/trash`, { method: "POST" }),
  async listTrash() {
    return validateTrashList(await apiClient.read("/api/v1/trash"));
  },
  async restore(entryId) {
    // A refused restore answers 409 with the blockers that explain it. That is
    // information the user needs, not a transport failure to be discarded.
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
      headers: { "X-SSH-UI-Action": token },
    });
  },
};
