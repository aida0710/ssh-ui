import { StrictMode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";

vi.mock("./connections/ConnectionsPage", () => ({ ConnectionsPage: () => <div>connections panel</div> }));
vi.mock("./explorer/ConfigExplorer", () => ({ ConfigExplorer: () => <div>config panel</div> }));
vi.mock("./groups/GroupsPanel", () => ({ GroupsPanel: () => <div>groups panel</div> }));
vi.mock("./history/HistoryPanel", () => ({ HistoryPanel: () => <div>history panel</div> }));
vi.mock("./keys/KeysScreen", () => ({ KeysScreen: () => <div>keys panel</div> }));
vi.mock("./diagnostics/DiagnosticsPanel", () => ({ DiagnosticsPanel: () => <div>diagnostics panel</div> }));
vi.mock("./knownhosts/KnownHostsPanel", () => ({ KnownHostsPanel: () => <div>known hosts panel</div> }));

const csrfToken = "c".repeat(43);

describe("App", () => {
  it("shows the starting status before session setup completes", () => {
    render(<App bootstrap={() => new Promise(() => undefined)} health={vi.fn()} />);

    expect(screen.getByRole("status")).toHaveTextContent("Starting secure local session…");
  });

  it("shows the authenticated shell after bootstrap and health succeed", async () => {
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      />,
    );

    expect(await screen.findByRole("heading", { name: "SSH UI" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Local session active · 0.1.0");
    for (const label of ["Connections", "Config", "Groups", "Keys", "Known Hosts", "Diagnostics", "History"]) {
      expect(screen.getByRole("button", { name: label })).toBeEnabled();
    }
    expect(document.body).not.toHaveTextContent(csrfToken);
  });

  it("switches to the keys panel", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "Keys" }));

    expect(screen.getByText("keys panel")).toBeInTheDocument();
    // The shell owns the only status region; a panel must not add a second.
    expect(screen.getAllByRole("status")).toHaveLength(1);
  });

  it("switches to the known hosts and diagnostics panels", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "Known Hosts" }));
    expect(screen.getByText("known hosts panel")).toBeInTheDocument();
    expect(screen.getAllByRole("status")).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "Diagnostics" }));
    expect(screen.getByText("diagnostics panel")).toBeInTheDocument();
    expect(screen.getAllByRole("status")).toHaveLength(1);
  });

  it("switches to the history panel", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "History" }));

    expect(screen.getByText("history panel")).toBeInTheDocument();
  });

  it("shows a recovery action when bootstrap fails", async () => {
    render(<App bootstrap={vi.fn().mockRejectedValue(new Error("rejected"))} health={vi.fn()} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Secure local session could not be started. Restart ssh-ui and use the newly opened tab.",
    );
  });

  it("uses a shared bootstrap exchange once when StrictMode re-runs effects", async () => {
    const exchange = vi.fn().mockResolvedValue({ csrfToken });
    const sessionPromise = exchange();
    const health = vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" });

    render(
      <StrictMode>
        <App bootstrap={() => sessionPromise} health={health} />
      </StrictMode>,
    );

    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Local session active · 0.1.0"));
    expect(exchange).toHaveBeenCalledTimes(1);
    expect(health).toHaveBeenCalledTimes(1);
  });
});
