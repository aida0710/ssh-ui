import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { applyTheme, detectTheme, rememberTheme, resolveTheme, type Theme } from "./theme";

type ThemeState = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  resolved: "light" | "dark";
};

const ThemeContext = createContext<ThemeState | null>(null);

const darkQuery = "(prefers-color-scheme: dark)";

function systemPrefersDark(): boolean {
  // A browser without matchMedia, or a test environment that has not stubbed
  // it, resolves to light rather than throwing. Appearance is not worth failing
  // the shell over.
  if (typeof window.matchMedia !== "function") return false;
  return window.matchMedia(darkQuery).matches;
}

export function ThemeProvider({ children, initial }: { children: ReactNode; initial?: Theme }) {
  // detectTheme runs once, at mount, for the reason detectLocale does: a user
  // who chose light on a dark system means it, and re-reading storage later
  // would fight the control.
  const [theme, setThemeState] = useState<Theme>(() => initial ?? detectTheme());
  const [prefersDark, setPrefersDark] = useState<boolean>(() => systemPrefersDark());

  // Only consulted while the choice is "system", but subscribed to always: a
  // user can return to "system" without reloading, and the answer has to be
  // current when they do.
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const media = window.matchMedia(darkQuery);
    const update = () => setPrefersDark(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  const resolved = resolveTheme(theme, prefersDark);

  useEffect(() => {
    applyTheme(document.documentElement, resolved);
  }, [resolved]);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    rememberTheme(next);
  }, []);

  const value = useMemo<ThemeState>(() => ({ theme, setTheme, resolved }), [theme, setTheme, resolved]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// A component rendered outside the provider gets the system appearance rather
// than throwing, so a panel test can render one panel without assembling the
// shell around it. App mounts the provider and its own test proves it.
const fallback: ThemeState = { theme: "system", setTheme: () => undefined, resolved: "light" };

export function useTheme(): ThemeState {
  return useContext(ThemeContext) ?? fallback;
}
