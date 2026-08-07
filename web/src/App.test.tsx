import { StrictMode, type ReactNode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

// アプリケーションはマスターパスワードの向こうにあるため、シェルを期待する
// テストにはすべて開いた vault を与える必要がある。ロック画面には専用のテストがある。
const openVault = () =>
  Promise.resolve({ exists: true, unlocked: true, aliases: [] as string[], minPassphraseLength: 12 });
import { App } from "./App";
import { LanguageProvider } from "./i18n/context";
import { ThemeProvider } from "./theme/context";
import { ja } from "./i18n/messages";

vi.mock("./connections/ConnectionsPage", () => ({
  ConnectionsPage: ({
    onOpenFile,
    onInspector,
  }: {
    onOpenFile: (path: string, line: number) => void;
    onInspector: (content: { attention: boolean; body: ReactNode } | null) => void;
  }) => (
    <div>
      connections panel
      <button type="button" onClick={() => onOpenFile("config", 9)}>open pattern rule</button>
      <button type="button" onClick={() => onInspector({ attention: true, body: <p>inspector body</p> })}>
        offer inspector
      </button>
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
  it("groups the navigation without adding headings to it", async () => {
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
        vault={openVault}
      />,
    );

    await screen.findByRole("heading", { name: "sshc" });

    // グループは見出しではなく名前付きリストである。ここに見出しを置くと
    // パネル自身の<h2>と衝突する。Playwright はアクセシブルネームを
    // 部分一致で照合するため、nav の見出し"Keys and hosts"は見出し
    // "Keys"を探すページレベルのクエリを二重にヒットさせてしまう。
    expect(screen.getByRole("list", { name: "Keys and hosts" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Keys and hosts" })).toBeNull();

    // どの section ボタンも元の名前のままである。
    for (const label of [
      "Connections",
      "Config",
      "Groups",
      "Keys",
      "Known Hosts",
      "Remote Keys",
      "Diagnostics",
      "Secrets",
      "Sync",
      "History",
    ]) {
      expect(screen.getByRole("button", { name: label })).toBeEnabled();
    }
  });

  it("keeps the inspector open across a section change", async () => {
    const user = userEvent.setup();
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
        vault={openVault}
      />,
    );

    await screen.findByText("connections panel");

    // 中身がなければトグルも出さない。常に提示されながら
    // 大抵空なペインは、人に開かせない習慣を教えてしまう。
    expect(screen.queryByRole("button", { name: /details/i })).toBeNull();

    await user.click(screen.getByRole("button", { name: "offer inspector" }));
    await user.click(screen.getByRole("button", { name: "Show details Needs attention" }));

    expect(screen.getByRole("complementary", { name: "Details" })).toHaveTextContent("inspector body");

    await user.click(screen.getByRole("button", { name: "Keys" }));
    await user.click(screen.getByRole("button", { name: "Connections" }));
    await user.click(screen.getByRole("button", { name: "offer inspector" }));

    expect(screen.getByRole("complementary", { name: "Details" })).toBeInTheDocument();
  });

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
    expect(window.localStorage.getItem("sshc.theme")).toBe("dark");
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

    expect(await screen.findByRole("heading", { name: "sshc" })).toBeInTheDocument();
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
    // ステータス領域を持つのはシェルだけであり、パネルが二つ目を追加してはならない。
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
    // ステータス領域を持つのはシェルだけであり、パネルが二つ目を追加してはならない。
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
      "Secure local session could not be started. Restart sshc and use the newly opened tab.",
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
  // パネルはプロバイダの外でレンダリングされると英語に翻訳される。これにより
  // コンポーネントテストが単体でレンダリングできるようになっている。だが
  // この便利さはここでは危険でもある。プロバイダのマウントをやめたシェルは
  // 英語のままでも正しく見えてしまい、他の全員にとっても英語のままになる。
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

    // シェル自身が翻訳を行う。
    expect(await screen.findByRole("status")).toHaveTextContent(ja["shell.active"].replace("{version}", "0.1.0"));
    expect(screen.getByRole("button", { name: ja["section.keys"] })).toBeInTheDocument();

    // 切り替え先の section も同じプロバイダ内にあるため、シェルを
    // 経由して到達したパネルも翻訳される。
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

    // 変わったのはラベルであり、開いているパネルは変わっていない。section の
    // 識別子は section の名前ではない。
    expect(screen.getByRole("button", { name: ja["section.history"] })).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("history panel")).toBeInTheDocument();
  });
});
