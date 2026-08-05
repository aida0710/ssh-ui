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

// The action vocabulary belongs to the server's session package, which owns it
// for every subsystem that confirms an operation. These are its wire values.
export const REVEAL_ACTION_KIND = "private_key.reveal";
export const PURGE_ACTION_KIND = "trash.purge";

// KeyLocationInput leaves out what it does not change. A name and a group are
// separate destinations, so a relocation can change either or both, and an
// empty group is a real answer: the root of ~/.ssh, where an ungrouped key is.
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

// RegisterAgentInput is what ssh-add needs to load one key. lifetimeSeconds is
// ssh-add's own -t: zero means the agent keeps the key until it exits.
// storeInKeychain adds --apple-use-keychain, which is the only way a passphrase
// outlives this request, and it is macOS that keeps it, not this application.
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
  // Taking a key back out of the agent. It destroys nothing and needs no
  // confirmation; the cost of being wrong is one more passphrase prompt.
  deregisterFromAgent(keyId: string): Promise<AgentIdentitiesResponse>;
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
        headers: { "X-SSH-UI-Action": token },
      }),
    );
  },
  // A public key is not a secret, so this is an ordinary read: no confirmation,
  // no no-store, no audit note. The server refuses any entry that is not a
  // public key or a certificate, which is what keeps that true.
  async publicKey(keyId) {
    return validatePublicKey(await apiClient.read(`/api/v1/keys/${encodeURIComponent(keyId)}/public`));
  },
  // A blocked relocation answers 409 with the reasons it refused, and nothing
  // was written. Those reasons are the whole point of the refusal, so they are
  // read out of the body rather than thrown away as a failed request.
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
  // The passphrase travels in the request body and no further. The server hands
  // it to ssh-add on standard input, so it reaches neither argv nor the child
  // environment, and nothing here keeps a copy: the caller clears its own state
  // and the reply carries what the agent now holds, not what unlocked it.
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
