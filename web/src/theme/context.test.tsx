import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider, useTheme } from "./context";
import { themeStorageKey } from "./theme";

// jsdom には matchMedia がない。シェルはシステムの好みを一度尋ねてから
// listen するので、最初の半分だけでなく両方をスタブ化する。
let prefersDark = false;
const listeners = new Set<() => void>();

beforeEach(() => {
  prefersDark = false;
  listeners.clear();
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    // 値ではなくゲッターだ。本物の MediaQueryList.matches は尋ねられた
    // その瞬間に読まれ、プロバイダは change ハンドラの中からそれを尋ねる。
    // construction 時に固定された値は、変わる前にシステムが言っていたことを
    // 報告してしまい、リスナーは壊れているように見えてしまう。
    get matches() {
      return query.includes("dark") && prefersDark;
    },
    media: query,
    addEventListener: (_: string, handler: () => void) => listeners.add(handler),
    removeEventListener: (_: string, handler: () => void) => listeners.delete(handler),
  })) as unknown as typeof window.matchMedia;
});

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

function Probe() {
  const { theme, setTheme, resolved } = useTheme();
  return (
    <div>
      <span>{`choice ${theme} resolved ${resolved}`}</span>
      <button type="button" onClick={() => setTheme("dark")}>go dark</button>
    </div>
  );
}

describe("ThemeProvider", () => {
  it("follows the system when nothing was chosen", () => {
    render(<ThemeProvider><Probe /></ThemeProvider>);

    expect(screen.getByText("choice system resolved light")).toBeInTheDocument();
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });

  it("resolves system to dark when the system says dark", () => {
    prefersDark = true;
    render(<ThemeProvider><Probe /></ThemeProvider>);

    expect(screen.getByText("choice system resolved dark")).toBeInTheDocument();
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("remembers a chosen theme and stamps it", async () => {
    const user = userEvent.setup();
    render(<ThemeProvider><Probe /></ThemeProvider>);

    await user.click(screen.getByRole("button", { name: "go dark" }));

    expect(screen.getByText("choice dark resolved dark")).toBeInTheDocument();
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(window.localStorage.getItem(themeStorageKey)).toBe("dark");
  });

  // 選ばれたテーマはそれを意味する。裏でシステムが変わってもそれを覆してはならない。
  it("ignores the system once a theme was chosen", async () => {
    const user = userEvent.setup();
    render(<ThemeProvider initial="light"><Probe /></ThemeProvider>);

    await user.click(screen.getByRole("button", { name: "go dark" }));
    prefersDark = true;
    for (const handler of listeners) handler();

    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  // 「system」に戻るには、上書きされている間に変わった好みを見えなければ
  // ならない。これがリスナーを、選択が「system」の間だけでなく
  // 常に購読しておく理由だ。
  it("picks the system back up when the choice returns to it", async () => {
    const user = userEvent.setup();

    function Returner() {
      const { setTheme, resolved } = useTheme();
      return (
        <div>
          <span>{`resolved ${resolved}`}</span>
          <button type="button" onClick={() => setTheme("system")}>go system</button>
        </div>
      );
    }

    render(<ThemeProvider initial="light"><Returner /></ThemeProvider>);
    expect(screen.getByText("resolved light")).toBeInTheDocument();

    prefersDark = true;
    for (const handler of listeners) handler();
    await user.click(screen.getByRole("button", { name: "go system" }));

    expect(screen.getByText("resolved dark")).toBeInTheDocument();
  });
});
