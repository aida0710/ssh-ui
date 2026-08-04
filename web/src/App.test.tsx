import { StrictMode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";

vi.mock("./connections/ConnectionsPage", () => ({
  ConnectionsPage: () => <div>connections panel</div>,
}));

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
    for (const label of ["Connections", "Config", "Groups", "History"]) {
      expect(screen.getByRole("button", { name: label })).toBeEnabled();
    }
    for (const label of ["Keys", "Known Hosts"]) {
      expect(screen.getByRole("button", { name: label })).toBeDisabled();
    }
    expect(document.body).not.toHaveTextContent(csrfToken);
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
