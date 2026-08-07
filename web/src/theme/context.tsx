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
  // matchMedia を持たないブラウザや、それをスタブ化していないテスト環境は、
  // 例外を投げるのではなく light に解決する。外観のためにシェル全体を
  // 失敗させる価値はない。
  if (typeof window.matchMedia !== "function") return false;
  return window.matchMedia(darkQuery).matches;
}

export function ThemeProvider({ children, initial }: { children: ReactNode; initial?: Theme }) {
  // detectTheme は detectLocale と同じ理由でマウント時に一度だけ実行する:
  // 暗いシステム上で light を選んだユーザーはそれを意図しており、後で
  // ストレージを読み直せば、その操作と衝突してしまう。
  const [theme, setThemeState] = useState<Theme>(() => initial ?? detectTheme());
  const [prefersDark, setPrefersDark] = useState<boolean>(() => systemPrefersDark());

  // 選択が「system」の間だけ参照するが、常に購読はしておく: ユーザーは
  // リロードせずに「system」へ戻ることができ、そうしたときの答えは
  // 最新でなければならない。
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

// プロバイダの外で描画されたコンポーネントは、例外を投げるのではなくシステムの
// 外観を得る。パネルテストがシェル全体を組み立てずに 1 枚のパネルを描画できる
// ようにするためだ。App はプロバイダをマウントし、それ自身のテストが証明する。
const fallback: ThemeState = { theme: "system", setTheme: () => undefined, resolved: "light" };

export function useTheme(): ThemeState {
  return useContext(ThemeContext) ?? fallback;
}
