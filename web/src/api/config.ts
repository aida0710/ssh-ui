import { apiClient } from "./client";
import type { components } from "./schema";

export type Overview = components["schemas"]["Overview"];
export type HostEntry = components["schemas"]["HostEntry"];
export type HostDetail = components["schemas"]["HostDetail"];
export type HostForm = components["schemas"]["HostForm"];
export type FormField = components["schemas"]["FormField"];
export type FieldEdit = components["schemas"]["FieldEdit"];
export type EditRequest = components["schemas"]["EditRequest"];
export type SavePreview = components["schemas"]["SavePreview"];
export type SaveResult = components["schemas"]["SaveResult"];
export type FileContents = components["schemas"]["FileContents"];
export type FileNode = components["schemas"]["FileNode"];
export type FileDiff = components["schemas"]["FileDiff"];
export type DiffLine = components["schemas"]["DiffLine"];
export type ConflictReport = components["schemas"]["ConflictReport"];
export type HistoryEntry = components["schemas"]["HistoryEntry"];
export type PendingTransaction = components["schemas"]["PendingTransaction"];
export type Metadata = components["schemas"]["Metadata"];
export type GroupMetadata = components["schemas"]["GroupMetadata"];
export type HostMetadata = components["schemas"]["HostMetadata"];
export type Notice = components["schemas"]["Notice"];
export type Diagnostic = components["schemas"]["Diagnostic"];
export type EffectiveDiff = components["schemas"]["EffectiveDiff"];

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

function validateOverview(value: unknown): Overview {
  const record = asRecord(value);
  asString(asRecord(record.entry).absolute);
  for (const file of asArray(record.files)) {
    asString(asRecord(asRecord(file).file).absolute);
  }
  for (const host of asArray(record.hosts)) {
    const entry = asRecord(host);
    asString(asRecord(entry.identity).alias);
    asString(asRecord(entry.file).absolute);
    asArray(entry.patterns);
  }
  asRecord(record.metadata);
  asArray(record.diagnostics);
  asArray(record.notices);
  return record as unknown as Overview;
}

function validateHostDetail(value: unknown): HostDetail {
  const record = asRecord(value);
  const form = asRecord(record.form);
  asArray(form.fields);
  asString(form.raw);
  asRecord(record.metadata);
  asRecord(record.effective);
  validateFileContents(record.file);
  return record as unknown as HostDetail;
}

function validateFileContents(value: unknown): FileContents {
  const record = asRecord(value);
  asString(asRecord(record.file).absolute);
  asString(record.contents);
  asString(record.digest);
  return record as unknown as FileContents;
}

function validateSavePreview(value: unknown): SavePreview {
  const record = asRecord(value);
  asString(record.operation);
  for (const diff of asArray(record.diffs)) {
    const entry = asRecord(diff);
    asString(entry.path);
    asArray(entry.lines);
  }
  return record as unknown as SavePreview;
}

function validateSaveResult(value: unknown): SaveResult {
  const record = asRecord(value);
  asString(record.transactionId);
  asArray(record.written);
  validateSavePreview(record.preview);
  return record as unknown as SaveResult;
}

function validateHistory(value: unknown): HistoryEntry[] {
  const record = asRecord(value);
  const entries = asArray(record.entries);
  for (const entry of entries) {
    const item = asRecord(entry);
    asString(item.id);
    asString(item.operation);
    asArray(item.paths);
  }
  return entries as unknown as HistoryEntry[];
}

function postJSON<T>(path: string, body: unknown): Promise<T> {
  return apiClient.mutate<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export const configApi = {
  async overview(): Promise<Overview> {
    return validateOverview(await apiClient.read("/api/v1/config/overview"));
  },
  async host(path: string, alias: string): Promise<HostDetail> {
    const query = new URLSearchParams({ path, alias });
    return validateHostDetail(await apiClient.read(`/api/v1/config/host?${query.toString()}`));
  },
  async file(path: string): Promise<FileContents> {
    const query = new URLSearchParams({ path });
    return validateFileContents(await apiClient.read(`/api/v1/config/file?${query.toString()}`));
  },
  async preview(request: EditRequest): Promise<SavePreview> {
    return validateSavePreview(await postJSON<unknown>("/api/v1/config/preview", request));
  },
  async save(request: EditRequest): Promise<SaveResult> {
    return validateSaveResult(await postJSON<unknown>("/api/v1/config/save", request));
  },
  async history(): Promise<HistoryEntry[]> {
    return validateHistory(await apiClient.read("/api/v1/history"));
  },
  async restore(transactionId: string, path: string): Promise<SaveResult> {
    return validateSaveResult(await postJSON<unknown>("/api/v1/history/restore", { transactionId, path }));
  },
  async recover(transactionId: string, action: "complete" | "rollback"): Promise<void> {
    await postJSON<unknown>("/api/v1/history/recover", { transactionId, action });
  },
};
