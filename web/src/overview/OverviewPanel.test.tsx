import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Overview } from "../api/config";
import type { SyncStatus } from "../api/integrations";
import { OverviewPanel } from "./OverviewPanel";

const overview = {
  entry: { absolute: "/Users/test/.ssh/config", path: "config" },
  files: [],
  hosts: [
    {
      identity: { path: "connections/work.conf", alias: "database" },
      file: { absolute: "/Users/test/.ssh/connections/work.conf", path: "connections/work.conf" },
      line: 1,
      patterns: ["database"],
      editable: true,
      group: "work",
    },
    {
      identity: { path: "config", alias: "bastion" },
      file: { absolute: "/Users/test/.ssh/config", path: "config" },
      line: 4,
      patterns: ["bastion"],
      editable: true,
    },
    {
      identity: { path: "config", alias: "" },
      file: { absolute: "/Users/test/.ssh/config", path: "config" },
      line: 9,
      patterns: ["*.internal"],
      editable: true,
    },
  ],
  groups: [
    { name: "work", directory: "connections/work", keyDirectory: "keys/work", memberCount: 1, directoryPresent: true },
  ],
  metadata: {
    schemaVersion: 1,
    hosts: [
      { identity: { path: "connections/work.conf", alias: "database" }, tags: ["production"], favourite: true },
    ],
  },
  diagnostics: [{ severity: "warning", code: "duplicate_alias" }],
  notices: [],
  pending: [],
} as Overview;

const sync = {
  configured: true,
  locked: false,
  endpoint: "https://example.invalid",
  bucket: "sshc",
  synced: true,
  direction: "both",
  lastSyncedAt: "2026-08-08T00:00:00Z",
  fileCount: 3,
} as SyncStatus;

describe("OverviewPanel", () => {
  it("puts favourites first, searches groups and launches only after a click", async () => {
    const launch = vi.fn().mockResolvedValue({ launched: true });
    render(
      <OverviewPanel
        loadOverview={vi.fn().mockResolvedValue(overview)}
        loadSync={vi.fn().mockResolvedValue(sync)}
        launch={launch}
        onNavigate={vi.fn()}
      />,
    );

    const database = await screen.findByText("database");
    const cards = within(screen.getByRole("list", { name: "Available connections" })).getAllByRole("listitem");
    expect(database).toBeInTheDocument();
    expect(screen.getByText("bastion")).toBeInTheDocument();
    expect(screen.queryByText("Host *.internal")).toBeNull();
    expect(launch).not.toHaveBeenCalled();
    expect(cards[0]).toHaveTextContent("database");

    await userEvent.type(screen.getByRole("searchbox", { name: "Search connections" }), "production");
    expect(screen.getByText("database")).toBeInTheDocument();
    expect(screen.queryByText("bastion")).toBeNull();

    const card = screen.getByText("database").closest("li");
    expect(card).not.toBeNull();
    await userEvent.click(within(card as HTMLElement).getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(launch).toHaveBeenCalledWith("database"));
  });

  it("routes management shortcuts without starting network diagnostics", async () => {
    const navigate = vi.fn();
    const loadOverview = vi.fn().mockResolvedValue(overview);
    render(
      <OverviewPanel
        loadOverview={loadOverview}
        loadSync={vi.fn().mockResolvedValue(sync)}
        launch={vi.fn()}
        onNavigate={navigate}
      />,
    );

    await screen.findByText("database");
    await userEvent.click(screen.getByRole("button", { name: "Open diagnostics" }));
    expect(navigate).toHaveBeenCalledWith("Diagnostics");
    expect(loadOverview).toHaveBeenCalledTimes(1);
  });
});
