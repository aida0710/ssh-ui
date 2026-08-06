import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider, useTheme } from "./context";
import { themeStorageKey } from "./theme";

// jsdom has no matchMedia. The shell asks it once for the system preference and
// then listens, so both halves are stubbed rather than only the first.
let prefersDark = false;
const listeners = new Set<() => void>();

beforeEach(() => {
  prefersDark = false;
  listeners.clear();
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    // A getter, not a value. The real MediaQueryList.matches is read at the
    // moment it is asked, and the provider asks for it from inside the change
    // handler; a value frozen at construction would report what the system
    // said before it changed, and the listener would look broken.
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

  // A chosen theme means it. The system changing underneath must not undo it.
  it("ignores the system once a theme was chosen", async () => {
    const user = userEvent.setup();
    render(<ThemeProvider initial="light"><Probe /></ThemeProvider>);

    await user.click(screen.getByRole("button", { name: "go dark" }));
    prefersDark = true;
    for (const handler of listeners) handler();

    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  // Returning to "system" has to be able to see a preference that changed
  // while it was overridden, which is why the listener is always subscribed
  // rather than only while the choice is "system".
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
