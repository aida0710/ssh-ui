// The appearance of the application, and how a choice about it is resolved.
//
// The choice has three values rather than two on purpose. A toggle between
// light and dark can leave the system setting but never return to it, and
// following the system is the state most people want to be in — it has to be
// reachable, not only initial.
export const themes = ["system", "light", "dark"] as const;
export type Theme = (typeof themes)[number];

export const defaultTheme: Theme = "system";

// The second — and last — key this application writes to persistent browser
// storage. `i18n/locale.ts` holds the first, and `e2e/bootstrap.spec.ts`
// allowlists both by name so that anything else appearing there fails.
export const themeStorageKey = "ssh-ui.theme";

export function isTheme(value: unknown): value is Theme {
  return typeof value === "string" && (themes as readonly string[]).includes(value);
}

// detectTheme reads the stored choice and otherwise defers to the system.
//
// Storage access is wrapped because a browser configured to refuse it throws on
// read, and an appearance preference is not worth failing the shell over. This
// mirrors detectLocale, which made the same decision for the same reason.
export function detectTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(themeStorageKey);
    if (isTheme(stored)) return stored;
  } catch {
    // Storage is unavailable; the system setting still applies.
  }
  return defaultTheme;
}

export function rememberTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(themeStorageKey, theme);
  } catch {
    // The choice still applies to this tab; it just will not outlive it.
  }
}

// resolveTheme collapses the three-valued choice to the two the stylesheet
// knows about. Resolving in script rather than in a media query is what keeps
// the stylesheet at exactly two states: `:root` and `[data-theme="dark"]`.
export function resolveTheme(theme: Theme, systemPrefersDark: boolean): "light" | "dark" {
  if (theme === "system") return systemPrefersDark ? "dark" : "light";
  return theme;
}

export function applyTheme(root: HTMLElement, resolved: "light" | "dark"): void {
  root.setAttribute("data-theme", resolved);
}
