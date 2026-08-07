// このアプリケーションの外観と、それについての選択がどう解決されるか。
//
// 選択が 2 値ではなく 3 値を持つのは意図的だ。light と dark の間の
// トグルはシステム設定から離れられても、そこへ二度と戻れない。
// システムに従うことは大半の人が望む状態だ——それは初期状態としてだけでなく、
// いつでも到達可能でなければならない。
export const themes = ["system", "light", "dark"] as const;
export type Theme = (typeof themes)[number];

export const defaultTheme: Theme = "system";

// このアプリケーションが永続的なブラウザストレージに書き込む、2 番目にして
// 最後のキー。`i18n/locale.ts` が最初のものを保持し、`e2e/bootstrap.spec.ts` は
// 両方を名前で許可リストに入れ、それ以外が現れれば失敗するようにしている。
export const themeStorageKey = "sshc.theme";

export function isTheme(value: unknown): value is Theme {
  return typeof value === "string" && (themes as readonly string[]).includes(value);
}

// detectTheme は保存された選択を読み、そうでなければシステムに従う。
//
// ストレージへのアクセスを包んでいるのは、拒否するよう設定されたブラウザが
// 読み取り時に例外を投げるからだ。外観の好みは、シェル全体を失敗させてまで
// 守る価値はない。detectLocale が同じ理由で下したのと同じ決定を映している。
export function detectTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(themeStorageKey);
    if (isTheme(stored)) return stored;
  } catch {
    // ストレージが使えない場合、システム設定がそのまま適用される。
  }
  return defaultTheme;
}

export function rememberTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(themeStorageKey, theme);
  } catch {
    // その選択はこのタブには引き続き適用されるが、タブを超えては残らない。
  }
}

// resolveTheme は 3 値の選択を、スタイルシートが知る 2 値へと畳み込む。
// メディアクエリではなくスクリプトで解決することが、スタイルシートを
// 正確に 2 状態——`:root` と `[data-theme="dark"]`——に保つ理由だ。
export function resolveTheme(theme: Theme, systemPrefersDark: boolean): "light" | "dark" {
  if (theme === "system") return systemPrefersDark ? "dark" : "light";
  return theme;
}

export function applyTheme(root: HTMLElement, resolved: "light" | "dark"): void {
  root.setAttribute("data-theme", resolved);
}
