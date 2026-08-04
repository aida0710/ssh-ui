import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { HistoryPanel } from "./HistoryPanel";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), history: vi.fn(), restore: vi.fn(), recover: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(configApi.history).mockResolvedValue([{
    id: "20260805T120000.000-abcd",
    operation: "config.host_fields",
    status: "completed",
    startedAt: "2026-08-05T12:00:00Z",
    finishedAt: "2026-08-05T12:00:01Z",
    paths: ["config"],
    restorable: ["config"],
  }] as never);
  vi.mocked(configApi.overview).mockResolvedValue({
    entry: { path: "config", absolute: "/home/tester/.ssh/config" },
    files: [], hosts: [], metadata: { schemaVersion: 1 }, diagnostics: [], notices: [],
    pending: [{
      id: "20260805T115900.000-ffff",
      operation: "config.file_raw",
      status: "staged",
      startedAt: "2026-08-05T11:59:00Z",
      committed: 1,
      paths: ["config", "conf.d/10-home.conf"],
      canComplete: true,
    }],
  } as never);
});

describe("HistoryPanel", () => {
  it("lists completed transactions and restores one file", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.restore).mockResolvedValue({
      transactionId: "t2", written: ["config"], preview: { operation: "config.restore", diffs: [] },
    } as never);

    render(<HistoryPanel />);

    expect(await screen.findByText("config.host_fields")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Restore config" }));

    await waitFor(() => expect(configApi.restore).toHaveBeenCalledWith("20260805T120000.000-abcd", "config"));
  });

  it("shows an interrupted transaction as unfinished and offers both recoveries", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.recover).mockResolvedValue(undefined as never);

    render(<HistoryPanel />);

    expect(await screen.findByText(/1 of 2 files were written/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Roll back" }));

    await waitFor(() => expect(configApi.recover).toHaveBeenCalledWith("20260805T115900.000-ffff", "rollback"));
  });
});
