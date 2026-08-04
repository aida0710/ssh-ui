import { apiClient } from "./client";
import type { components } from "./schema";

export type ConfigCheckResponse = components["schemas"]["ConfigCheckResponse"];
export type EffectiveResponse = components["schemas"]["EffectiveResponse"];
export type ReachabilityResponse = components["schemas"]["ReachabilityResponse"];
export type AuthenticationResponse = components["schemas"]["AuthenticationResponse"];
export type TerminalCommandResponse = components["schemas"]["TerminalCommandResponse"];
export type TerminalLaunchResponse = components["schemas"]["TerminalLaunchResponse"];
export type KnownHostsResponse = components["schemas"]["KnownHostsResponse"];
export type KnownHostEntry = components["schemas"]["KnownHostEntry"];
export type KnownHostsChangeResponse = components["schemas"]["KnownHostsChangeResponse"];
export type KnownHostsScanResponse = components["schemas"]["KnownHostsScanResponse"];
export type KnownHostCandidate = components["schemas"]["KnownHostCandidate"];
export type IssueActionResponse = components["schemas"]["IssueActionResponse"];

// The action vocabulary belongs to the server's session package, which owns it
// for every subsystem that confirms an operation. These are its wire values.
export const EVALUATE_ACTION_KIND = "diagnostics.evaluate";
export const REACHABILITY_ACTION_KIND = "diagnostics.reachability";
export const AUTHENTICATION_ACTION_KIND = "diagnostics.authentication";
export const TERMINAL_LAUNCH_ACTION_KIND = "terminal.launch";
export const KNOWN_HOSTS_DELETE_ACTION_KIND = "known_hosts.delete";
export const KNOWN_HOSTS_SCAN_ACTION_KIND = "known_hosts.scan";

export type IntegrationsApi = {
  configCheck(): Promise<ConfigCheckResponse>;
  effective(alias: string, confirm: boolean): Promise<EffectiveResponse>;
  reachability(alias: string): Promise<ReachabilityResponse>;
  authentication(alias: string, acknowledgeExecutable: boolean): Promise<AuthenticationResponse>;
  terminalCommand(alias: string): Promise<TerminalCommandResponse>;
  terminalLaunch(alias: string): Promise<TerminalLaunchResponse>;
  knownHosts(query: string): Promise<KnownHostsResponse>;
  deleteKnownHosts(entries: { line: number; digest: string }[], path: string): Promise<KnownHostsChangeResponse>;
  scanKnownHosts(host: string, port: number): Promise<KnownHostsScanResponse>;
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

function validateConfigCheck(value: unknown): ConfigCheckResponse {
  const record = asRecord(value);
  asString(record.root);
  for (const file of asArray(record.files)) {
    const entry = asRecord(file);
    asString(entry.path);
    asBoolean(entry.editable);
    asBoolean(entry.missing);
    asNumber(entry.loads);
    asNumber(entry.includes);
  }
  for (const diagnostic of asArray(record.diagnostics)) {
    const entry = asRecord(diagnostic);
    asString(entry.severity);
    asString(entry.code);
    asNumber(entry.line);
  }
  return record as unknown as ConfigCheckResponse;
}

function validateEffective(value: unknown): EffectiveResponse {
  const record = asRecord(value);
  asString(record.alias);
  asBoolean(record.evaluated);
  asBoolean(record.requiresConfirmation);
  asString(record.tokenWarning);
  for (const directive of asArray(record.executableDirectives)) {
    const entry = asRecord(directive);
    asString(entry.keyword);
    asString(entry.command);
    asString(entry.path);
    asNumber(entry.line);
    asBoolean(entry.onEvaluate);
    asBoolean(entry.onConnect);
    asBoolean(entry.overridable);
  }
  for (const source of asArray(record.sources)) {
    const entry = asRecord(source);
    asString(entry.keyword);
    asString(entry.value);
    asString(entry.path);
    asNumber(entry.line);
    asBoolean(entry.winner);
  }
  asArray(record.values);
  asArray(record.complexities);
  asArray(record.route);
  asRecord(record.failure);
  return record as unknown as EffectiveResponse;
}

function validateReachability(value: unknown): ReachabilityResponse {
  const record = asRecord(value);
  asString(record.address);
  asString(record.outcome);
  asNumber(record.elapsedMs);
  asString(record.detail);
  asString(record.notice);
  return record as unknown as ReachabilityResponse;
}

function validateAuthentication(value: unknown): AuthenticationResponse {
  const record = asRecord(value);
  asString(record.outcome);
  asBoolean(record.authenticated);
  asNumber(record.exitCode);
  asString(record.stderr);
  asBoolean(record.truncated);
  asNumber(record.elapsedMs);
  return record as unknown as AuthenticationResponse;
}

function validateTerminalCommand(value: unknown): TerminalCommandResponse {
  const record = asRecord(value);
  asString(record.command);
  asBoolean(record.launchable);
  asString(record.warning);
  return record as unknown as TerminalCommandResponse;
}

function validateTerminalLaunch(value: unknown): TerminalLaunchResponse {
  const record = asRecord(value);
  asBoolean(record.launched);
  return record as unknown as TerminalLaunchResponse;
}

function validateKnownHosts(value: unknown): KnownHostsResponse {
  const record = asRecord(value);
  asString(record.path);
  for (const entry of asArray(record.entries)) {
    const item = asRecord(entry);
    asNumber(item.line);
    asString(item.digest);
    asString(item.marker);
    asArray(item.hosts);
    asBoolean(item.hashed);
    asString(item.keyType);
    asString(item.fingerprint);
    asString(item.comment);
  }
  return record as unknown as KnownHostsResponse;
}

function validateChange(value: unknown): KnownHostsChangeResponse {
  const record = asRecord(value);
  asBoolean(record.changed);
  asString(record.transactionId);
  return record as unknown as KnownHostsChangeResponse;
}

function validateScan(value: unknown): KnownHostsScanResponse {
  const record = asRecord(value);
  asString(record.notice);
  for (const candidate of asArray(record.candidates)) {
    const item = asRecord(candidate);
    asString(item.host);
    asNumber(item.port);
    asString(item.keyType);
    asString(item.key);
    asString(item.fingerprint);
    asBoolean(item.verified);
  }
  return record as unknown as KnownHostsScanResponse;
}

const jsonHeaders = { "Content-Type": "application/json" } as const;

// issueAction asks the server to mint a confirmation. The request names only
// the operation and its target: the evidence the token is bound to is derived
// on the server, so this client cannot bind a token to a state the user was
// never shown.
async function issueAction(kind: string, target: string): Promise<string> {
  const response = await apiClient.mutate<IssueActionResponse>("/api/v1/actions", {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ kind, target }),
  });
  return asString(asRecord(response).token);
}

async function postJSON<T>(path: string, body: unknown, actionToken?: string): Promise<T> {
  const headers: Record<string, string> = { ...jsonHeaders };
  if (actionToken) headers["X-SSH-UI-Action"] = actionToken;
  return apiClient.mutate<T>(path, { method: "POST", headers, body: JSON.stringify(body) });
}

export const integrationsApi: IntegrationsApi = {
  async configCheck() {
    return validateConfigCheck(await postJSON<unknown>("/api/v1/diagnostics/config", {}));
  },
  async effective(alias, confirm) {
    // A confirmation is spent only when evaluating would run a command; a safe
    // configuration is read without one.
    const token = confirm ? await issueAction(EVALUATE_ACTION_KIND, alias) : undefined;
    return validateEffective(await postJSON<unknown>("/api/v1/diagnostics/effective", { alias }, token));
  },
  async reachability(alias) {
    const token = await issueAction(REACHABILITY_ACTION_KIND, alias);
    return validateReachability(await postJSON<unknown>("/api/v1/diagnostics/reachability", { alias }, token));
  },
  async authentication(alias, acknowledgeExecutable) {
    const token = await issueAction(AUTHENTICATION_ACTION_KIND, alias);
    return validateAuthentication(
      await postJSON<unknown>("/api/v1/diagnostics/authentication", { alias, acknowledgeExecutable }, token),
    );
  },
  async terminalCommand(alias) {
    return validateTerminalCommand(await postJSON<unknown>("/api/v1/terminal/command", { alias }));
  },
  async terminalLaunch(alias) {
    const token = await issueAction(TERMINAL_LAUNCH_ACTION_KIND, alias);
    return validateTerminalLaunch(await postJSON<unknown>("/api/v1/terminal/launch", { alias }, token));
  },
  async knownHosts(query) {
    return validateKnownHosts(await apiClient.read(`/api/v1/known-hosts?query=${encodeURIComponent(query)}`));
  },
  async deleteKnownHosts(entries, path) {
    const token = await issueAction(KNOWN_HOSTS_DELETE_ACTION_KIND, path);
    return validateChange(await postJSON<unknown>("/api/v1/known-hosts/delete", { entries }, token));
  },
  async scanKnownHosts(host, port) {
    const token = await issueAction(KNOWN_HOSTS_SCAN_ACTION_KIND, host);
    return validateScan(await postJSON<unknown>("/api/v1/known-hosts/scan", { host, port }, token));
  },
};
