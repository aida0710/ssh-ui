import { StrictMode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

// The application is behind the master password, so every test that expects a
// shell has to be given an open vault. The lock screen has tests of its own.
const openVault = () =>
  Promise.resolve({ exists: true, unlocked: true, aliases: [] as string[], minPassphraseLength: 12 });
import { App } from "./App";
import { LanguageProvider } from "./i18n/context";
import { ThemeProvider } from "./theme/context";
import { ja } from "./i18n/messages";

vi.mock("./connections/ConnectionsPage", () => ({
  ConnectionsPage: ({ onOpenFile }: { onOpenFile: (path: string, line: number) => void }) => (
    <div>
      connections panel
      <button type="button" onClick={() => onOpenFile("config", 9)}>open pattern rule</button>
    </div>
  ),
}));
vi.mock("./explorer/ConfigExplorer", () => ({
  ConfigExplorer: ({ target }: { target?: { path: string; line: number } | null }) => (
    <div>{`config panel ${target === null || target === undefined ? "no target" : `${target.path}:${target.line}`}`}</div>
  ),
}));
vi.mock("./groups/GroupsPanel", () => ({ GroupsPanel: () => <div>groups panel</div> }));
vi.mock("./history/HistoryPanel", () => ({ HistoryPanel: () => <div>history panel</div> }));
vi.mock("./keys/KeysScreen", () => ({ KeysScreen: () => <div>keys panel</div> }));
vi.mock("./diagnostics/DiagnosticsPanel", () => ({ DiagnosticsPanel: () => <div>diagnostics panel</div> }));
vi.mock("./knownhosts/KnownHostsPanel", () => ({ KnownHostsPanel: () => <div>known hosts panel</div> }));
vi.mock("./remotekeys/RemoteKeyPanel", () => ({ RemoteKeyPanel: () => <div>remote keys panel</div> }));

const csrfToken = "c".repeat(43);

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

describe("App", () => {
  it("offers the three appearances and remembers the chosen one", async () => {
    const user = userEvent.setup();
    render(
      <ThemeProvider>
        <App
          bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
          health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
          vault={openVault}
        />
      </ThemeProvider>,
    );

    const control = await screen.findByLabelText("Appearance");
    expect(control).toHaveValue("system");

    await user.selectOptions(control, "dark");

    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(window.localStorage.getItem("ssh-ui.theme")).toBe("dark");
  });

  it("shows the starting status before session setup completes", () => {
    render(<App bootstrap={() => new Promise(() => undefined)} health={vi.fn()} vault={openVault} />);

    expect(screen.getByRole("status")).toHaveTextContent("Starting secure local session…");
  });

  it("shows the authenticated shell after bootstrap and health succeed", async () => {
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      vault={openVault}
      />,
    );

    expect(await screen.findByRole("heading", { name: "SSH UI" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Local session active · 0.1.0");
    for (const label of [
      "Connections",
      "Config",
      "Groups",
      "Keys",
      "Known Hosts",
      "Remote Keys",
      "Diagnostics",
      "History",
    ]) {
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
      vault={openVault}
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
      vault={openVault}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "Known Hosts" }));
    expect(screen.getByText("known hosts panel")).toBeInTheDocument();
    expect(screen.getAllByRole("status")).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "Diagnostics" }));
    expect(screen.getByText("diagnostics panel")).toBeInTheDocument();
    expect(screen.getAllByRole("status")).toHaveLength(1);
  });

  it("switches to the remote keys panel", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      vault={openVault}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "Remote Keys" }));

    expect(screen.getByText("remote keys panel")).toBeInTheDocument();
    // The shell owns the only status region; a panel must not add a second.
    expect(screen.getAllByRole("status")).toHaveLength(1);
  });

  it("switches to the history panel", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      vault={openVault}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "History" }));

    expect(screen.getByText("history panel")).toBeInTheDocument();
  });

  it("opens the config file view on the line a pattern rule asks for", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
      vault={openVault}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "open pattern rule" }));

    expect(screen.getByText("config panel config:9")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Config" })).toHaveAttribute("aria-current", "page");
    expect(screen.getAllByRole("status")).toHaveLength(1);
  });

  it("shows a recovery action when bootstrap fails", async () => {
    render(<App bootstrap={vi.fn().mockRejectedValue(new Error("rejected"))} health={vi.fn()} vault={openVault} />);

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
        <App bootstrap={() => sessionPromise} health={health} vault={openVault} />
      </StrictMode>,
    );

    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Local session active · 0.1.0"));
    expect(exchange).toHaveBeenCalledTimes(1);
    expect(health).toHaveBeenCalledTimes(1);
  });
  // The panels translate into English when they are rendered outside the
  // provider, which is what lets a component test render one on its own. That
  // convenience is a hazard here: a shell that stopped mounting the provider
  // would look correct in English and stay English for everyone else.
  it("renders every panel inside the language provider", async () => {
    const user = userEvent.setup();
    render(
      <LanguageProvider initial="ja">
        <App
          bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
          health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
        vault={openVault}
        />
      </LanguageProvider>,
    );

    // The shell itself translates.
    expect(await screen.findByRole("status")).toHaveTextContent(ja["shell.active"].replace("{version}", "0.1.0"));
    expect(screen.getByRole("button", { name: ja["section.keys"] })).toBeInTheDocument();

    // And the section it switches to is inside the same provider, so a panel
    // reached through the shell is translated too.
    await user.click(screen.getByRole("button", { name: ja["section.keys"] }));
    expect(screen.getByText("keys panel")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: ja["shell.primaryNavigation"] })).toBeInTheDocument();
  });

  it("switches language from the header and leaves the open section alone", async () => {
    const user = userEvent.setup();
    render(
      <LanguageProvider initial="en">
        <App
          bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
          health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
        vault={openVault}
        />
      </LanguageProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "History" }));
    expect(screen.getByText("history panel")).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Language"), "ja");

    // The label changed; which panel is open did not. Section identity is not
    // the section's name.
    expect(screen.getByRole("button", { name: ja["section.history"] })).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("history panel")).toBeInTheDocument();
  });
});
