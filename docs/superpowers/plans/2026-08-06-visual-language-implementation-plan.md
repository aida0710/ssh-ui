# Visual Language Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the application one palette in two themes, one set of shared components, and a right-hand inspector that separates a configuration file's contents from this application's own notes.

**Architecture:** Twenty named colour tokens live in `index.css`, given once for light and once for dark, exposed to Tailwind through `@theme inline`. A small theme module resolves System/Light/Dark to one of two values and stamps it on `<html data-theme>`, so no component ever carries a `dark:` variant. `ui/form.tsx` keeps its exported class strings and its nine callers; only the literals inside them change. New shared components (`Toolbar`, `Sidebar`, `Card`, `Row`, `Notice`, `Button`, `Inspector`, `icons`) are added beside it, and the ten components that style themselves move onto them.

**Tech Stack:** Go 1.26.5, React 19.2.8, Vite 8.1.5, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, Playwright.

## Global Constraints

- Tailwind is **4.3.3**. Tokens are declared with `@theme inline` over custom properties in CSS. There is no `tailwind.config.js` in this project and none is to be added.
- **No component may contain a `dark:` variant.** The two themes differ only in the twenty token values.
- **No component may contain a `zinc-`, `rose-`, `amber-`, or `emerald-` utility** once its task is done. Colour comes from tokens only.
- **The accent is used for one thing per screen: its primary action.** Not selection, not icons, not values, not headings. Amber is a notice, red is destructive, green is the live session.
- Section identifiers in `App.tsx` (`"Connections"`, `"Config"`, …) stay English and untranslated. They are routing vocabulary.
- Tab identifiers in `HostDetail.tsx` (`"Basic"`, `"Jump"`, …) stay English for the same reason.
- **Never add an `<h2>`–`<h6>` to the shell's navigation.** `e2e/bootstrap.spec.ts:137` runs `getByRole("heading", { name: "鍵", level: 2 })`, and Playwright matches accessible names by **substring** unless `exact: true`. A nav heading named `鍵とホスト` makes that query match twice and the test fails on a strict-mode violation. Navigation groups are `<ul aria-label>` with an `aria-hidden` visible label.
- Every message added to `web/src/i18n/messages.ts` must be added to **both** `en` and `ja`. `ja` is typed as a complete record of `en`, so a missing one is a compile error.
- Accessible names and ARIA roles of existing controls must not change. The end-to-end suite selects by `getByRole` (128), `getByLabel` (54) and `getByText` (16); its nine `locator()` calls address `body` or an `aria-label`. No test names a CSS class, so appearance is free to change and names are not.
- `internal/ui/dist` is a committed bundle. Any task that changes `web/src` ends with `make build` before its commit, or the End-to-end CI job fails on a stale bundle.
- Verification commands: `npm test --prefix web` (Vitest), `npm run typecheck --prefix web`, `make test`, `make e2e`, `make build`.

---

### Task 1: The token layer and the theme module

**Files:**
- Create: `web/src/theme/theme.ts`
- Create: `web/src/theme/theme.test.ts`
- Modify: `web/src/index.css` (all 6 lines replaced)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Theme = "system" | "light" | "dark"` and `const themes: readonly Theme[]`
  - `const themeStorageKey = "ssh-ui.theme"`
  - `function isTheme(value: unknown): value is Theme`
  - `function detectTheme(): Theme` — stored choice, else `"system"`
  - `function rememberTheme(theme: Theme): void`
  - `function resolveTheme(theme: Theme, systemPrefersDark: boolean): "light" | "dark"`
  - `function applyTheme(root: HTMLElement, resolved: "light" | "dark"): void` — sets `data-theme`

- [ ] **Step 1: Write the failing test**

Create `web/src/theme/theme.test.ts`:

```ts
import { afterEach, describe, expect, it } from "vitest";
import {
  applyTheme,
  detectTheme,
  isTheme,
  rememberTheme,
  resolveTheme,
  themeStorageKey,
} from "./theme";

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

describe("isTheme", () => {
  it("accepts the three choices and nothing else", () => {
    expect(isTheme("system")).toBe(true);
    expect(isTheme("light")).toBe(true);
    expect(isTheme("dark")).toBe(true);
    expect(isTheme("solarized")).toBe(false);
    expect(isTheme(undefined)).toBe(false);
  });
});

describe("detectTheme", () => {
  it("is system when nothing has been chosen", () => {
    expect(detectTheme()).toBe("system");
  });

  it("reads a remembered choice", () => {
    rememberTheme("light");
    expect(window.localStorage.getItem(themeStorageKey)).toBe("light");
    expect(detectTheme()).toBe("light");
  });

  // A hand-edited or stale value must not decide the appearance.
  it("falls back to system when the stored value is not a theme", () => {
    window.localStorage.setItem(themeStorageKey, "solarized");
    expect(detectTheme()).toBe("system");
  });
});

describe("resolveTheme", () => {
  it("follows the system when the choice is system", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });

  // The whole reason the choice has three values rather than two.
  it("overrides the system when a theme was chosen", () => {
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
  });
});

describe("applyTheme", () => {
  it("stamps the resolved theme on the element", () => {
    applyTheme(document.documentElement, "dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    applyTheme(document.documentElement, "light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test --prefix web -- src/theme/theme.test.ts`
Expected: FAIL — `Failed to resolve import "./theme"`.

- [ ] **Step 3: Write the module**

Create `web/src/theme/theme.ts`:

```ts
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test --prefix web -- src/theme/theme.test.ts`
Expected: PASS, 8 tests.

- [ ] **Step 5: Replace the stylesheet**

Replace the whole of `web/src/index.css`:

```css
@import "tailwindcss";

/* The palette, given once per theme.
 *
 * Names say what a value is for, not what colour it is: a token called
 * `zinc-800` cannot be given a different value in the other theme, and a token
 * called `card` can. Components reference these through Tailwind utilities —
 * `bg-card`, `text-ink-muted`, `border-line` — and never carry a `dark:`
 * variant, because the variant is this file.
 *
 * The rule these encode: the accent belongs to the one action a screen is for.
 * Amber is a notice, red destroys something, green means the local session is
 * alive. Nothing else is coloured, so colour on screen means something
 * happened.
 */
:root {
  color-scheme: light;

  --ui-canvas: #f5f5f7;
  --ui-sidebar: #f4f4f6;
  --ui-tree: #fafafc;
  --ui-toolbar: #fbfbfd;
  --ui-card: #ffffff;
  --ui-line: #e5e5ea;
  --ui-hairline: #f0f0f3;
  --ui-control: #ffffff;
  --ui-control-line: #dcdce1;
  --ui-select-fill: rgb(0 0 0 / 0.07);
  --ui-ink: #1d1d1f;
  --ui-ink-muted: #6e6e73;
  --ui-ink-faint: #a1a1a6;
  --ui-accent: #007aff;
  --ui-accent-ink: #ffffff;
  --ui-notice: #fff6e5;
  --ui-notice-line: #f5dfae;
  --ui-notice-ink: #7a5a10;
  --ui-danger: #d70015;
  --ui-live: #34794a;
}

[data-theme="dark"] {
  color-scheme: dark;

  --ui-canvas: #1c1c1e;
  --ui-sidebar: #252527;
  --ui-tree: #1f1f21;
  --ui-toolbar: #2a2a2c;
  --ui-card: #2c2c2e;
  --ui-line: #3a3a3c;
  --ui-hairline: #3a3a3c;
  --ui-control: #1c1c1e;
  --ui-control-line: #48484a;
  --ui-select-fill: rgb(140 140 150 / 0.26);
  --ui-ink: #f5f5f7;
  --ui-ink-muted: #98989d;
  --ui-ink-faint: #6e6e73;
  --ui-accent: #0a84ff;
  --ui-accent-ink: #ffffff;
  --ui-notice: rgb(255 159 10 / 0.13);
  --ui-notice-line: rgb(255 159 10 / 0.32);
  --ui-notice-ink: #f0b429;
  --ui-danger: #ff6961;
  --ui-live: #5fd88a;
}

@theme inline {
  --color-canvas: var(--ui-canvas);
  --color-sidebar: var(--ui-sidebar);
  --color-tree: var(--ui-tree);
  --color-toolbar: var(--ui-toolbar);
  --color-card: var(--ui-card);
  --color-line: var(--ui-line);
  --color-hairline: var(--ui-hairline);
  --color-control: var(--ui-control);
  --color-control-line: var(--ui-control-line);
  --color-select-fill: var(--ui-select-fill);
  --color-ink: var(--ui-ink);
  --color-ink-muted: var(--ui-ink-muted);
  --color-ink-faint: var(--ui-ink-faint);
  --color-accent: var(--ui-accent);
  --color-accent-ink: var(--ui-accent-ink);
  --color-notice: var(--ui-notice);
  --color-notice-line: var(--ui-notice-line);
  --color-notice-ink: var(--ui-notice-ink);
  --color-danger: var(--ui-danger);
  --color-live: var(--ui-live);
}

:root {
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
  background: var(--ui-canvas);
  color: var(--ui-ink);
}

/* The inspector is the only thing that moves, and it stops moving here. */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

- [ ] **Step 6: Confirm the stylesheet compiles and nothing regressed**

Run: `npm run typecheck --prefix web && npm test --prefix web && npm run build --prefix web`
Expected: typecheck clean, all Vitest suites pass, Vite build succeeds.

The application will look wrong at this point — light tokens with components still asking for `zinc`. That is expected and Task 3 fixes it.

- [ ] **Step 7: Build and commit**

```bash
make build
git add web/src/theme/theme.ts web/src/theme/theme.test.ts web/src/index.css internal/ui/dist
git commit -m "Name the colours after what they are for"
```

---

### Task 2: The theme provider, the header control, and the storage allowlist

**Files:**
- Create: `web/src/theme/context.tsx`
- Create: `web/src/theme/context.test.tsx`
- Modify: `web/src/main.tsx`
- Modify: `web/src/App.tsx:183-205` (the header)
- Modify: `web/src/i18n/messages.ts` (both catalogues)
- Modify: `web/e2e/bootstrap.spec.ts:110-122` and `:144-153`

**Interfaces:**
- Consumes: `Theme`, `themes`, `detectTheme`, `rememberTheme`, `resolveTheme`, `applyTheme` from `./theme`.
- Produces:
  - `function ThemeProvider({ children, initial }: { children: ReactNode; initial?: Theme })`
  - `function useTheme(): { theme: Theme; setTheme: (t: Theme) => void; resolved: "light" | "dark" }`
  - Message keys `shell.theme`, `shell.themeSystem`, `shell.themeLight`, `shell.themeDark`.

- [ ] **Step 1: Write the failing test**

Create `web/src/theme/context.test.tsx`:

```tsx
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
    matches: query.includes("dark") && prefersDark,
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
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test --prefix web -- src/theme/context.test.tsx`
Expected: FAIL — `Failed to resolve import "./context"`.

- [ ] **Step 3: Write the provider**

Create `web/src/theme/context.tsx`:

```tsx
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test --prefix web -- src/theme/context.test.tsx`
Expected: PASS, 4 tests.

- [ ] **Step 5: Add the messages**

In `web/src/i18n/messages.ts`, in the `en` object immediately after `"shell.languageJapanese": "日本語",`:

```ts
  "shell.theme": "Appearance",
  "shell.themeSystem": "System",
  "shell.themeLight": "Light",
  "shell.themeDark": "Dark",
```

And in the `ja` object, immediately after its own `"shell.languageJapanese"` entry:

```ts
  "shell.theme": "外観",
  "shell.themeSystem": "システムに合わせる",
  "shell.themeLight": "ライト",
  "shell.themeDark": "ダーク",
```

- [ ] **Step 6: Mount the provider**

In `web/src/main.tsx`, add the import beside the language one and wrap `App`:

```tsx
import { ThemeProvider } from "./theme/context";
```

```tsx
createRoot(root).render(
  <StrictMode>
    <ThemeProvider>
      <LanguageProvider>
        <App
          bootstrap={() => sessionPromise}
          health={() => apiClient.health()}
        />
      </LanguageProvider>
    </ThemeProvider>
  </StrictMode>,
);
```

- [ ] **Step 7: Add the control to the header**

In `web/src/App.tsx`, add to the existing imports:

```tsx
import { useTheme } from "./theme/context";
import { themes, type Theme } from "./theme/theme";
```

Add inside `App`, beside `const { t, locale, setLocale } = useLanguage();`:

```tsx
  const { theme, setTheme } = useTheme();
```

Add the label map beside `localeLabels`:

```tsx
const themeLabels: Record<Theme, MessageKey> = {
  system: "shell.themeSystem",
  light: "shell.themeLight",
  dark: "shell.themeDark",
};
```

In the header, replace the `ml-auto` on the language label with a plain class and insert the appearance select before it, so the pair sits together at the right:

```tsx
        <label htmlFor="appearance" className="ml-auto text-sm text-ink-muted">
          {t("shell.theme")}
        </label>
        <select
          id="appearance"
          value={theme}
          onChange={(event) => setTheme(event.target.value as Theme)}
          className="rounded border border-control-line bg-control px-2 py-1 text-sm text-ink"
        >
          {themes.map((candidate) => (
            <option key={candidate} value={candidate}>
              {t(themeLabels[candidate])}
            </option>
          ))}
        </select>
        <label htmlFor="language" className="text-sm text-ink-muted">
          {t("shell.language")}
        </label>
```

Leave the existing language `<select>` exactly as it is apart from its class, which becomes `"rounded border border-control-line bg-control px-2 py-1 text-sm text-ink"`.

- [ ] **Step 8: Update the storage allowlist**

In `web/e2e/bootstrap.spec.ts`, replace the assertion block at lines 110–121 with:

```ts
  // An allowlist rather than a count. A count would have passed just as well
  // with a session token in place of the language, and checking the value is
  // what makes that impossible: nothing but "en" or "ja" may be stored, and
  // nothing but the two preference keys may exist.
  const stored = await page.evaluate(() => ({
    keys: Object.keys(window.localStorage).sort(),
    language: window.localStorage.getItem("ssh-ui.language"),
    session: window.sessionStorage.length,
  }));
  expect(stored.keys).toEqual(["ssh-ui.language"]);
  expect(["en", "ja"]).toContain(stored.language);
  expect(stored.session).toBe(0);
});

test("keeps the chosen appearance, and writes nothing else", async ({ page, installation }) => {
  await openApplication(page, installation);
  await expect(sessionStatus(page)).toContainText("Local session active");

  // The application starts following the system, which is a choice not to
  // store anything.
  expect(await page.evaluate(() => Object.keys(window.localStorage))).toEqual([]);

  await page.getByLabel("Appearance").selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  // Returning to System is reachable, which is why the control has three
  // values rather than two.
  await page.getByLabel("Appearance").selectOption("system");
  await page.getByLabel("Language").selectOption("ja");

  const stored = await page.evaluate(() => ({
    keys: Object.keys(window.localStorage).sort(),
    theme: window.localStorage.getItem("ssh-ui.theme"),
  }));
  expect(stored.keys).toEqual(["ssh-ui.language", "ssh-ui.theme"]);
  expect(stored.theme).toBe("system");
```

Then in the language-reload test, replace line 152 with:

```ts
  expect(await page.evaluate(() => Object.keys(window.localStorage).sort())).toEqual(["ssh-ui.language"]);
```

- [ ] **Step 9: Add the shell test**

In `web/src/App.test.tsx`, inside `describe("App", …)`, add:

```tsx
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
```

Add to that file's imports:

```tsx
import { ThemeProvider } from "./theme/context";
```

Add a cleanup after the existing mocks, before `describe`:

```tsx
afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});
```

and extend the vitest import to `import { afterEach, describe, expect, it, vi } from "vitest";`.

- [ ] **Step 10: Run everything**

Run: `npm run typecheck --prefix web && npm test --prefix web`
Expected: PASS.

Run: `make build && make e2e`
Expected: PASS, including the two changed bootstrap tests.

- [ ] **Step 11: Commit**

```bash
git add web/src/theme web/src/main.tsx web/src/App.tsx web/src/App.test.tsx \
        web/src/i18n/messages.ts web/e2e/bootstrap.spec.ts internal/ui/dist
git commit -m "Let the appearance follow the system, or not"
```

---

### Task 3: Move the shared controls onto tokens

This is the task that changes nine panels without editing them.

**Files:**
- Modify: `web/src/ui/form.tsx:10-39`

**Interfaces:**
- Consumes: the token utilities from Task 1.
- Produces: the same exported names — `control`, `narrowControl`, `primaryAction`, `secondaryAction`, `dangerAction`, `fieldLabel`, `hintText`, `sectionCard`, `sectionHeading`, `tableHeadRow`, `tableHeadCell`, `Field`, `CheckboxField`. **No signature changes.**

- [ ] **Step 1: Replace the class strings**

In `web/src/ui/form.tsx`, replace lines 10 through 39 with:

```tsx
export const control =
  "w-full rounded-md border border-control-line bg-control px-2 py-1.5 text-sm text-ink " +
  "placeholder:text-ink-faint focus:border-accent focus:outline-none " +
  "disabled:border-line disabled:text-ink-faint";

// A control that should not stretch: a number, a colour, a short name.
export const narrowControl = control.replace("w-full", "w-40");

// A button label is a name, not a paragraph. Left to wrap, "Remove office"
// broke across two lines the moment its row ran out of room and the button grew
// a second storey. Wrapping the row is right; wrapping the word is not.
//
// The accent lives here and nowhere else. A screen has one primary action, and
// spending the colour on anything further — a selected row, an icon, a value —
// is what stopped colour from meaning anything.
export const primaryAction =
  "whitespace-nowrap rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-ink " +
  "hover:brightness-110 disabled:bg-line disabled:text-ink-faint";

export const secondaryAction =
  "whitespace-nowrap rounded-md border border-control-line bg-card px-3 py-1.5 text-sm text-ink " +
  "hover:bg-select-fill disabled:text-ink-faint";

export const dangerAction =
  "whitespace-nowrap rounded-md border border-control-line px-3 py-1.5 text-sm text-danger " +
  "hover:bg-select-fill";

export const fieldLabel = "text-xs font-medium tracking-wide text-ink-muted";
export const hintText = "text-xs text-ink-muted";
export const sectionCard = "flex flex-col gap-4 rounded-xl border border-line bg-card p-4";
export const sectionHeading = "text-sm font-medium text-ink";

// Table cells had no padding at all, so a header sat against the value above
// it and the columns ran together.
export const tableHeadRow = "border-b border-line text-xs uppercase tracking-wide text-ink-muted";
export const tableHeadCell = "py-2 pr-3 text-left font-medium";
```

Then in `CheckboxField` (line ~80), change `text-zinc-300` to `text-ink` and `accent-zinc-300` to `accent-accent`.

- [ ] **Step 2: Confirm nothing broke**

Run: `npm run typecheck --prefix web && npm test --prefix web`
Expected: PASS. No test asserts a class, so all nine consuming panels keep passing.

- [ ] **Step 3: Verify no colour literal survives in this file**

Run: `grep -nE "zinc-|rose-|amber-|emerald-" web/src/ui/form.tsx`
Expected: no output.

- [ ] **Step 4: Build and commit**

```bash
make build
git add web/src/ui/form.tsx internal/ui/dist
git commit -m "Spend the accent on the one action, and nothing else"
```

---

### Task 4: The icon sprite

**Files:**
- Create: `web/src/ui/icons.tsx`
- Create: `web/src/ui/icons.test.tsx`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type IconName = "connections" | "config" | "groups" | "keys" | "knownHosts" | "remoteKeys" | "diagnostics" | "secrets" | "sync" | "history" | "inspector"`
  - `function IconSprite(): JSX.Element` — the hidden `<svg>` of `<symbol>`s, mounted once by `App`
  - `function Icon({ name, className }: { name: IconName; className?: string }): JSX.Element`

- [ ] **Step 1: Write the failing test**

Create `web/src/ui/icons.test.tsx`:

```tsx
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Icon, IconSprite, iconNames } from "./icons";

describe("icons", () => {
  it("defines a symbol for every name", () => {
    const { container } = render(<IconSprite />);
    for (const name of iconNames) {
      expect(container.querySelector(`#icon-${name}`)).not.toBeNull();
    }
  });

  // An icon beside a word is decoration; the word is the accessible name. An
  // icon that announced itself would make every navigation button read its
  // label twice.
  it("hides itself from the accessibility tree", () => {
    const { container } = render(<Icon name="keys" />);
    expect(container.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("points at the symbol for its name", () => {
    const { container } = render(<Icon name="sync" />);
    expect(container.querySelector("use")?.getAttribute("href")).toBe("#icon-sync");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test --prefix web -- src/ui/icons.test.tsx`
Expected: FAIL — `Failed to resolve import "./icons"`.

- [ ] **Step 3: Write the sprite**

Create `web/src/ui/icons.tsx`:

```tsx
// One sprite of stroke icons, defined once and referenced by `<use>`.
//
// Inline rather than an icon font or a sprite file: the UI is served from an
// embedded filesystem and must not fetch anything, and a font would render as
// squares for the moment before it loaded.
//
// Every icon here sits beside its own label. They are decoration, so they are
// hidden from the accessibility tree; the word is the accessible name.
export const iconNames = [
  "connections",
  "config",
  "groups",
  "keys",
  "knownHosts",
  "remoteKeys",
  "diagnostics",
  "secrets",
  "sync",
  "history",
  "inspector",
] as const;

export type IconName = (typeof iconNames)[number];

const paths: Record<IconName, string> = {
  connections:
    '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M6.6 7.5h.01M6.6 16.5h.01"/>',
  config: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  groups: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  keys: '<circle cx="7.5" cy="15.5" r="3.5"/><path d="M10 13L20 3M17 6l2 2M14 9l2 2"/>',
  knownHosts: '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/>',
  remoteKeys:
    '<path d="M7.5 18a4 4 0 1 1 .6-7.95A5.5 5.5 0 0 1 18.6 11 3.5 3.5 0 0 1 18 18"/><path d="M12 21v-7M9.5 16.5L12 14l2.5 2.5"/>',
  diagnostics: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  secrets: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  sync: '<path d="M20 11a8 8 0 0 0-13.7-4.6L4 8.5"/><path d="M4 4.5v4h4"/><path d="M4 13a8 8 0 0 0 13.7 4.6L20 15.5"/><path d="M20 19.5v-4h-4"/>',
  history: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  inspector: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M15 4v16"/>',
};

export function IconSprite() {
  return (
    <svg aria-hidden="true" style={{ display: "none" }}>
      {iconNames.map((name) => (
        <symbol
          key={name}
          id={`icon-${name}`}
          viewBox="0 0 24 24"
          dangerouslySetInnerHTML={{ __html: paths[name] }}
        />
      ))}
    </svg>
  );
}

export function Icon({ name, className = "h-4 w-4" }: { name: IconName; className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={`shrink-0 ${className}`}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <use href={`#icon-${name}`} />
    </svg>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test --prefix web -- src/ui/icons.test.tsx`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add web/src/ui/icons.tsx web/src/ui/icons.test.tsx
git commit -m "Draw the eleven icons once"
```

---

### Task 5: Card, Row, Notice and Button

**Files:**
- Create: `web/src/ui/surface.tsx`
- Create: `web/src/ui/surface.test.tsx`

**Interfaces:**
- Consumes: token utilities.
- Produces:
  - `function Card({ children }: { children: ReactNode })` — the inset card
  - `function Row({ label, children, hint }: { label: string; children: ReactNode; hint?: string })` — one label-left / value-right row inside a Card
  - `function Notice({ children, tone }: { children: ReactNode; tone?: "notice" | "danger" })` — the amber band, red when destructive
  - `function Button({ kind, ...rest }: { kind?: "primary" | "secondary" | "danger" } & ButtonHTMLAttributes<HTMLButtonElement>)`

- [ ] **Step 1: Write the failing test**

Create `web/src/ui/surface.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Button, Card, Notice, Row } from "./surface";

describe("Row", () => {
  it("names its control through the label", () => {
    render(
      <Card>
        <Row label="HostName">
          <input defaultValue="bastion.eu.example.com" />
        </Row>
      </Card>,
    );

    expect(screen.getByLabelText("HostName")).toHaveValue("bastion.eu.example.com");
  });

  // The hint sits outside the label element on purpose. Inside it, a whole
  // sentence of advice became part of the control's accessible name — the same
  // mistake `Field` in ui/form.tsx already documents.
  it("keeps a hint out of the accessible name", () => {
    render(
      <Card>
        <Row label="Port" hint="OpenSSH defaults to 22 when this is unset.">
          <input defaultValue="22" />
        </Row>
      </Card>,
    );

    expect(screen.getByLabelText("Port")).toHaveValue("22");
    expect(screen.getByText("OpenSSH defaults to 22 when this is unset.")).toBeInTheDocument();
  });
});

describe("Notice", () => {
  it("announces itself as a status", () => {
    render(<Notice>This save rewrites three lines.</Notice>);

    expect(screen.getByRole("status")).toHaveTextContent("This save rewrites three lines.");
  });

  it("announces a destructive one as an alert", () => {
    render(<Notice tone="danger">This cannot be undone.</Notice>);

    expect(screen.getByRole("alert")).toHaveTextContent("This cannot be undone.");
  });
});

describe("Button", () => {
  it("is a button of type button unless told otherwise", () => {
    render(<Button>Save</Button>);

    expect(screen.getByRole("button", { name: "Save" })).toHaveAttribute("type", "button");
  });

  it("passes through disabled", () => {
    render(<Button disabled>Save</Button>);

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test --prefix web -- src/ui/surface.test.tsx`
Expected: FAIL — `Failed to resolve import "./surface"`.

- [ ] **Step 3: Write the components**

Create `web/src/ui/surface.tsx`:

```tsx
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { dangerAction, hintText, primaryAction, secondaryAction } from "./form";

// An inset card of rows, the way macOS System Settings groups related
// settings: a hairline between rows, a border around the group, and the
// group's own explanation underneath rather than inside.
export function Card({ children }: { children: ReactNode }) {
  return <div className="overflow-hidden rounded-xl border border-line bg-card">{children}</div>;
}

// One setting: its name on the left, its control on the right.
//
// The label element wraps the control rather than pointing at it by id, which
// is how every form in this application already associates the two, so the
// accessible name needs no id to be unique across a page that may show the
// same keyword for two hosts.
export function Row({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="border-t border-hairline first:border-t-0">
      <label className="flex items-center gap-3 px-3 py-2">
        <span className="w-32 shrink-0 text-sm text-ink-muted">{label}</span>
        <span className="ml-auto flex min-w-0 flex-1 justify-end">{children}</span>
      </label>
      {hint === undefined ? null : <p className={`px-3 pb-2 ${hintText}`}>{hint}</p>}
    </div>
  );
}

// The amber band. Amber is a notice and red destroys something; nothing else on
// a screen is coloured, so this is what draws the eye before it reads.
export function Notice({ children, tone = "notice" }: { children: ReactNode; tone?: "notice" | "danger" }) {
  const danger = tone === "danger";
  return (
    <p
      role={danger ? "alert" : "status"}
      className={
        danger
          ? "flex items-center gap-2 rounded-lg border border-control-line px-3 py-2 text-sm text-danger"
          : "flex items-center gap-2 rounded-lg border border-notice-line bg-notice px-3 py-2 text-sm text-notice-ink"
      }
    >
      {children}
    </p>
  );
}

type ButtonProps = { kind?: "primary" | "secondary" | "danger" } & ButtonHTMLAttributes<HTMLButtonElement>;

// type="button" by default because every button in this application is one:
// there is no form submission anywhere, and a button that defaulted to
// "submit" inside a <form> would reload the page and lose the session.
export function Button({ kind = "secondary", className = "", type = "button", ...rest }: ButtonProps) {
  const base = kind === "primary" ? primaryAction : kind === "danger" ? dangerAction : secondaryAction;
  return <button type={type} className={`${base} ${className}`} {...rest} />;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test --prefix web -- src/ui/surface.test.tsx`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add web/src/ui/surface.tsx web/src/ui/surface.test.tsx
git commit -m "Give a setting a row, and a group of them a card"
```

---

### Task 6: The shell — toolbar and grouped navigation

**Files:**
- Modify: `web/src/App.tsx:183-239`
- Modify: `web/src/i18n/messages.ts` (both catalogues)
- Modify: `web/src/App.test.tsx`

**Interfaces:**
- Consumes: `Icon`, `IconSprite`, `IconName` from `./ui/icons`.
- Produces: nothing new for later tasks beyond the shell markup Task 7 extends.

- [ ] **Step 1: Add the messages**

In `web/src/i18n/messages.ts`, in `en` after `"shell.primaryNavigation": "Primary",`:

```ts
  "shell.navConnections": "Connections",
  "shell.navKeysHosts": "Keys and hosts",
  "shell.navMaintenance": "Maintenance",
```

In `ja`, after its `"shell.primaryNavigation"` entry:

```ts
  "shell.navConnections": "接続",
  "shell.navKeysHosts": "鍵とホスト",
  "shell.navMaintenance": "保守",
```

- [ ] **Step 2: Write the failing test**

Add to `web/src/App.test.tsx` inside `describe("App", …)`:

```tsx
  it("groups the navigation without adding headings to it", async () => {
    render(
      <App
        bootstrap={vi.fn().mockResolvedValue({ csrfToken })}
        health={vi.fn().mockResolvedValue({ status: "ok", version: "0.1.0" })}
        vault={openVault}
      />,
    );

    await screen.findByRole("heading", { name: "SSH UI" });

    // The groups are named lists, not headings. A heading here would collide
    // with the panels' own <h2>s: Playwright matches accessible names by
    // substring, so a nav heading "Keys and hosts" makes a page-level query for
    // the heading "Keys" match twice.
    expect(screen.getByRole("list", { name: "Keys and hosts" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Keys and hosts" })).toBeNull();

    // Every section button keeps the name it had.
    for (const label of ["Connections", "Config", "Groups", "Keys", "Known Hosts", "Remote Keys", "Diagnostics", "Secrets", "Sync", "History"]) {
      expect(screen.getByRole("button", { name: label })).toBeEnabled();
    }
  });
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test --prefix web -- src/App.test.tsx`
Expected: FAIL — `Unable to find an accessible element with the role "list" and name "Keys and hosts"`.

- [ ] **Step 4: Rewrite the shell**

In `web/src/App.tsx`, add to the imports:

```tsx
import { Icon, IconSprite, type IconName } from "./ui/icons";
```

Add beside `sectionLabels`:

```tsx
const sectionIcons: Record<Section, IconName> = {
  Connections: "connections",
  Config: "config",
  Groups: "groups",
  Keys: "keys",
  "Known Hosts": "knownHosts",
  "Remote Keys": "remoteKeys",
  Diagnostics: "diagnostics",
  Secrets: "secrets",
  Sync: "sync",
  History: "history",
};

// Ten sections listed flat give no clue which are near each other.
//
// The group label is an `aria-label` on the list and an `aria-hidden` span for
// the eye — deliberately not a heading. Playwright matches accessible names by
// substring, so a heading "Keys and hosts" would make the end-to-end suite's
// page-level query for the heading "Keys" match twice and fail on strict mode.
const navGroups: { label: MessageKey; sections: Section[] }[] = [
  { label: "shell.navConnections", sections: ["Connections", "Config", "Groups"] },
  { label: "shell.navKeysHosts", sections: ["Keys", "Known Hosts", "Remote Keys"] },
  { label: "shell.navMaintenance", sections: ["Diagnostics", "Secrets", "Sync", "History"] },
];
```

Replace the returned markup's header and nav (lines 184–225) with:

```tsx
    <div className="flex h-screen flex-col bg-canvas text-ink">
      <IconSprite />
      <header className="flex shrink-0 items-baseline gap-3 border-b border-line bg-toolbar px-6 py-3">
        <h1 className="text-base font-semibold">{t("shell.title")}</h1>
        <p role="status" className="flex items-center gap-1.5 text-xs text-ink-muted">
          <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-live" />
          {state === "ready" ? t("shell.active", { version }) : t("shell.starting")}
        </p>
        <label htmlFor="appearance" className="ml-auto text-sm text-ink-muted">
          {t("shell.theme")}
        </label>
        <select
          id="appearance"
          value={theme}
          onChange={(event) => setTheme(event.target.value as Theme)}
          className="rounded border border-control-line bg-control px-2 py-1 text-sm text-ink"
        >
          {themes.map((candidate) => (
            <option key={candidate} value={candidate}>{t(themeLabels[candidate])}</option>
          ))}
        </select>
        <label htmlFor="language" className="text-sm text-ink-muted">
          {t("shell.language")}
        </label>
        <select
          id="language"
          value={locale}
          onChange={(event) => setLocale(event.target.value as Locale)}
          className="rounded border border-control-line bg-control px-2 py-1 text-sm text-ink"
        >
          {locales.map((candidate) => (
            <option key={candidate} value={candidate}>{t(localeLabels[candidate])}</option>
          ))}
        </select>
      </header>
      <div className="grid min-h-0 flex-1 grid-cols-[15rem_1fr] grid-rows-[minmax(0,1fr)]">
        <nav
          aria-label={t("shell.primaryNavigation")}
          className="relative overflow-y-auto border-r border-line bg-sidebar p-2"
        >
          {navGroups.map((group) => (
            <div key={group.label} className="mb-2">
              <span aria-hidden="true" className="block px-2 pt-2 pb-1 text-xs font-semibold text-ink-muted">
                {t(group.label)}
              </span>
              <ul aria-label={t(group.label)}>
                {group.sections.map((name) => (
                  <li key={name}>
                    <button
                      type="button"
                      disabled={!enabledSections.includes(name)}
                      aria-current={section === name ? "page" : undefined}
                      onClick={() => setSection(name)}
                      className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm ${
                        section === name
                          ? "bg-select-fill text-ink"
                          : enabledSections.includes(name)
                            ? "text-ink hover:bg-select-fill"
                            : "text-ink-faint"
                      }`}
                    >
                      <Icon name={sectionIcons[name]} className="h-4 w-4 text-ink-muted" />
                      {t(sectionLabels[name])}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <main className="relative overflow-y-auto p-6">
```

Leave the long comment block above the `return` in place; it still describes why `min-h-0`, `grid-rows-[minmax(0,1fr)]` and `relative` are there. Add one sentence to it noting that the nav is now three lists rather than one, and that the group label is not a heading.

Also update the error branch at lines 154–161 to use tokens:

```tsx
    return (
      <main className="p-6">
        <h1 className="text-base font-semibold">{t("shell.title")}</h1>
        <p role="alert" className="mt-2 text-sm text-danger">{t("shell.bootstrapFailed")}</p>
      </main>
    );
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test --prefix web -- src/App.test.tsx`
Expected: PASS, including the pre-existing tests that find every section button by name.

- [ ] **Step 6: Prove the end-to-end suite still agrees**

Run: `make build && make e2e`
Expected: PASS. Pay attention to `bootstrap.spec.ts:137` — the heading query that the group labels were kept out of.

- [ ] **Step 7: Commit**

```bash
git add web/src/App.tsx web/src/App.test.tsx web/src/i18n/messages.ts internal/ui/dist
git commit -m "Sort ten sections into the three things they are about"
```

---

### Task 7: The inspector, empty

Building the pane and its toggle before anything fills it keeps the shell change and the Connections change reviewable apart.

**Files:**
- Create: `web/src/ui/Inspector.tsx`
- Create: `web/src/ui/Inspector.test.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/i18n/messages.ts` (both catalogues)

**Interfaces:**
- Consumes: `Icon` from `./icons`, `Button` from `./surface`.
- Produces:
  - `type InspectorContent = { attention: boolean; body: ReactNode } | null`
  - `function InspectorToggle({ open, attention, onToggle }: { open: boolean; attention: boolean; onToggle: () => void })`
  - `function InspectorPane({ label, children }: { label: string; children: ReactNode })`
  - `App` gains state `inspectorOpen: boolean`, and `SectionView` gains a prop `onInspector: (content: InspectorContent) => void`.

- [ ] **Step 1: Add the messages**

In `en`:

```ts
  "shell.inspector": "Details",
  "shell.inspectorShow": "Show details",
  "shell.inspectorHide": "Hide details",
  "shell.inspectorAttention": "Needs attention",
```

In `ja`:

```ts
  "shell.inspector": "詳細",
  "shell.inspectorShow": "詳細を表示",
  "shell.inspectorHide": "詳細を隠す",
  "shell.inspectorAttention": "確認が必要な項目があります",
```

- [ ] **Step 2: Write the failing test**

Create `web/src/ui/Inspector.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { InspectorPane, InspectorToggle } from "./Inspector";

describe("InspectorToggle", () => {
  it("says whether the pane is open", () => {
    render(<InspectorToggle open={false} attention={false} onToggle={vi.fn()} />);

    const button = screen.getByRole("button", { name: "Show details" });
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(button).toHaveAttribute("aria-controls", "inspector");
  });

  it("changes its name when open", () => {
    render(<InspectorToggle open attention={false} onToggle={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Hide details" })).toHaveAttribute("aria-expanded", "true");
  });

  // Diagnostics live inside a pane that is shut by default, so a host with a
  // problem would look exactly like one without. The dot is what makes the
  // pane worth opening, and it has to reach a screen reader too.
  it("says so when what is inside needs attention", () => {
    render(<InspectorToggle open={false} attention onToggle={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Show details Needs attention" })).toBeInTheDocument();
  });

  it("does not say so otherwise", () => {
    render(<InspectorToggle open={false} attention={false} onToggle={vi.fn()} />);

    expect(screen.queryByText("Needs attention")).toBeNull();
  });

  it("reports a click", async () => {
    const onToggle = vi.fn();
    const user = userEvent.setup();
    render(<InspectorToggle open={false} attention={false} onToggle={onToggle} />);

    await user.click(screen.getByRole("button", { name: "Show details" }));

    expect(onToggle).toHaveBeenCalledOnce();
  });
});

describe("InspectorPane", () => {
  it("is a labelled complementary region the toggle can address", () => {
    render(<InspectorPane label="Details">nothing yet</InspectorPane>);

    const pane = screen.getByRole("complementary", { name: "Details" });
    expect(pane).toHaveAttribute("id", "inspector");
    expect(pane).toHaveTextContent("nothing yet");
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test --prefix web -- src/ui/Inspector.test.tsx`
Expected: FAIL — `Failed to resolve import "./Inspector"`.

- [ ] **Step 4: Write the pane**

Create `web/src/ui/Inspector.tsx`:

```tsx
import type { ReactNode } from "react";
import { Icon } from "./icons";
import { useTranslate } from "../i18n/context";

// What a section puts in the right-hand pane, and whether what is in there
// needs attention. A section that returns null gets no toggle at all: a pane
// offered everywhere and empty in nine places out of ten teaches people not to
// open it.
export type InspectorContent = { attention: boolean; body: ReactNode } | null;

export const inspectorId = "inspector";

export function InspectorToggle({
  open,
  attention,
  onToggle,
}: {
  open: boolean;
  attention: boolean;
  onToggle: () => void;
}) {
  const t = useTranslate();
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-controls={inspectorId}
      onClick={onToggle}
      className={`relative rounded-md border border-control-line px-2 py-1 text-ink ${
        open ? "bg-select-fill" : "bg-card"
      }`}
    >
      <span className="sr-only">{t(open ? "shell.inspectorHide" : "shell.inspectorShow")}</span>
      <Icon name="inspector" className="h-4 w-4" />
      {attention ? (
        <>
          {/* The dot is for the eye; the sentence is for everyone else. */}
          <span
            aria-hidden="true"
            className="absolute -right-1 -top-1 h-2 w-2 rounded-full border border-toolbar bg-notice-ink"
          />
          <span className="sr-only">{t("shell.inspectorAttention")}</span>
        </>
      ) : null}
    </button>
  );
}

export function InspectorPane({ label, children }: { label: string; children: ReactNode }) {
  return (
    <aside
      id={inspectorId}
      aria-label={label}
      className="relative overflow-y-auto border-l border-line bg-sidebar p-3"
    >
      {children}
    </aside>
  );
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test --prefix web -- src/ui/Inspector.test.tsx`
Expected: PASS, 6 tests.

- [ ] **Step 6: Wire it into the shell**

In `web/src/App.tsx`:

Add imports:

```tsx
import { InspectorPane, InspectorToggle, type InspectorContent } from "./ui/Inspector";
```

Add state beside the others:

```tsx
  // The pane belongs to the shell, not to a section. Opened on Connections it
  // is still open on Keys: a pane that shut itself on every section change
  // would have to be reopened constantly, and this is a preference about the
  // window rather than about a host.
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [inspector, setInspector] = useState<InspectorContent>(null);
```

Reset the content — but not the open state — when the section changes:

```tsx
  useEffect(() => {
    setInspector(null);
  }, [section]);
```

Add the toggle to the header, immediately before the appearance label:

```tsx
        {inspector === null ? null : (
          <span className="ml-auto">
            <InspectorToggle
              open={inspectorOpen}
              attention={inspector.attention}
              onToggle={() => setInspectorOpen((open) => !open)}
            />
          </span>
        )}
```

and change the appearance label's class from `"ml-auto text-sm text-ink-muted"` to `"text-sm text-ink-muted"` when the toggle is present. The simplest form that always works: keep `ml-auto` on whichever element comes first. Give the toggle wrapper `ml-auto` as above and change the appearance label to `className="text-sm text-ink-muted"`, then add `className="ml-auto"` to a zero-width spacer rendered when `inspector === null`:

```tsx
        {inspector === null ? <span className="ml-auto" /> : null}
```

Make the body grid depend on the pane:

```tsx
      <div
        className={`grid min-h-0 flex-1 grid-rows-[minmax(0,1fr)] ${
          inspector !== null && inspectorOpen
            ? "grid-cols-[15rem_1fr_17rem]"
            : "grid-cols-[15rem_1fr]"
        }`}
      >
```

and after `</main>`:

```tsx
        {inspector !== null && inspectorOpen ? (
          <InspectorPane label={t("shell.inspector")}>{inspector.body}</InspectorPane>
        ) : null}
```

Pass the setter down through `SectionView`. Add to `SectionViewProps`:

```tsx
  // A section supplies the right-hand pane's contents, or null when it has
  // nothing to inspect. Only Connections fills it today.
  onInspector: (content: InspectorContent) => void;
```

and to the call site:

```tsx
              onInspector={setInspector}
```

In `SectionView`, pass it only to `ConnectionsPage`:

```tsx
  if (section === "Connections") {
    return <ConnectionsPage onOpenFile={onOpenFile} onInspector={onInspector} />;
  }
```

- [ ] **Step 7: Add the shell test**

In `web/src/App.test.tsx`, replace the `ConnectionsPage` mock with one that supplies inspector content, and add a test:

```tsx
vi.mock("./connections/ConnectionsPage", () => ({
  ConnectionsPage: ({
    onOpenFile,
    onInspector,
  }: {
    onOpenFile: (path: string, line: number) => void;
    onInspector: (content: { attention: boolean; body: React.ReactNode } | null) => void;
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
```

```tsx
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

    // No content offered, no toggle. A pane that is always offered and usually
    // empty teaches people not to open it.
    expect(screen.queryByRole("button", { name: /details/i })).toBeNull();

    await user.click(screen.getByRole("button", { name: "offer inspector" }));
    await user.click(screen.getByRole("button", { name: "Show details Needs attention" }));

    expect(screen.getByRole("complementary", { name: "Details" })).toHaveTextContent("inspector body");

    await user.click(screen.getByRole("button", { name: "Keys" }));
    await user.click(screen.getByRole("button", { name: "Connections" }));
    await user.click(screen.getByRole("button", { name: "offer inspector" }));

    expect(screen.getByRole("complementary", { name: "Details" })).toBeInTheDocument();
  });
```

Add `import type React from "react";` to the test file if the mock's type annotation needs it.

- [ ] **Step 8: Run everything**

Run: `npm run typecheck --prefix web && npm test --prefix web`
Expected: PASS.

- [ ] **Step 9: Build and commit**

```bash
make build
git add web/src/ui/Inspector.tsx web/src/ui/Inspector.test.tsx web/src/App.tsx \
        web/src/App.test.tsx web/src/i18n/messages.ts internal/ui/dist
git commit -m "Open a pane on the right, and say when it wants opening"
```

---

### Task 8: Fill the inspector from the connection

**Files:**
- Create: `web/src/connections/HostInspector.tsx`
- Create: `web/src/connections/HostInspector.test.tsx`
- Modify: `web/src/connections/HostDetail.tsx:337-464` (the organisation section)
- Modify: `web/src/connections/ConnectionsPage.tsx`
- Modify: `web/src/i18n/messages.ts` (both catalogues)

**Interfaces:**
- Consumes: `InspectorContent` from `../ui/Inspector`; `HostDetail`, `HostMetadata` from `../api/config`.
- Produces:
  - `function HostInspector({ detail, onMetadata }: { detail: HostDetail; onMetadata: (m: HostMetadata) => void })`
  - `function hostNeedsAttention(detail: HostDetail): boolean`
  - `ConnectionsPage` gains prop `onInspector: (content: InspectorContent) => void`.

**What moves and what does not.** `~/.ssh/config` is written by group, comment and rename, so those three stay in the main pane. Colour, tags, favourite and display order exist only in `metadata.json`, so those four move to the inspector, along with this host's notices and the values it inherited from elsewhere.

- [ ] **Step 1: Add the messages**

In `en`:

```ts
  "inspector.appOnly": "This application only",
  "inspector.notices": "Notices",
  "inspector.inherited": "Inherited values",
  "inspector.noNotices": "Nothing to report for this connection.",
  "inspector.noInherited": "Every value on this connection is written in its own block.",
```

In `ja`:

```ts
  "inspector.appOnly": "このアプリだけの情報",
  "inspector.notices": "注意",
  "inspector.inherited": "継承した値",
  "inspector.noNotices": "この接続について報告はありません。",
  "inspector.noInherited": "この接続の値はすべて自身のブロックに書かれています。",
```

- [ ] **Step 2: Write the failing test**

Create `web/src/connections/HostInspector.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HostInspector, hostNeedsAttention } from "./HostInspector";
import type { HostDetail } from "../api/config";

function detailWith(overrides: Partial<HostDetail> = {}): HostDetail {
  return {
    file: { path: "connections/work/bastion.conf", contents: "", sha256: "" },
    form: {
      entry: {
        identity: { path: "connections/work/bastion.conf", alias: "bastion" },
        file: { path: "connections/work/bastion.conf", absolute: "/home/a/.ssh/connections/work/bastion.conf" },
        line: 1,
        patterns: ["bastion"],
        group: "work",
      },
      fields: [],
      raw: "Host bastion\n",
      comment: "",
      commentLines: [],
      notices: [],
    },
    metadata: {},
    effective: { entries: [], notices: [] },
    ...overrides,
  } as unknown as HostDetail;
}

describe("hostNeedsAttention", () => {
  it("is false when nothing is reported", () => {
    expect(hostNeedsAttention(detailWith())).toBe(false);
  });

  it("is true when the block has a notice", () => {
    const detail = detailWith();
    detail.form.notices = [{ code: "duplicate_alias", path: "config", line: 41 }];
    expect(hostNeedsAttention(detail)).toBe(true);
  });

  it("is true when the resolved values carry one", () => {
    const detail = detailWith();
    detail.effective.notices = [{ code: "complex_external_rule" }];
    expect(hostNeedsAttention(detail)).toBe(true);
  });
});

describe("HostInspector", () => {
  it("edits the four things that live only in metadata", async () => {
    const onMetadata = vi.fn();
    const user = userEvent.setup();
    render(<HostInspector detail={detailWith()} onMetadata={onMetadata} />);

    await user.click(screen.getByLabelText("Favourite"));

    expect(onMetadata).toHaveBeenCalledWith(expect.objectContaining({ favourite: true }));
    expect(screen.getByLabelText("Tags")).toBeInTheDocument();
    expect(screen.getByLabelText("Display order")).toBeInTheDocument();
    expect(screen.getByLabelText("Colour")).toBeInTheDocument();
  });

  // The three that write to a file stay in the main pane, because the pane is
  // what separates a configuration file's contents from our own notes.
  it("does not offer the group, the comment or the rename", () => {
    render(<HostInspector detail={detailWith()} onMetadata={vi.fn()} />);

    expect(screen.queryByLabelText("Primary group")).toBeNull();
    expect(screen.queryByLabelText("Comment")).toBeNull();
    expect(screen.queryByLabelText("Rename alias")).toBeNull();
  });

  it("lists the notices this connection has", () => {
    const detail = detailWith();
    detail.form.notices = [{ code: "duplicate_alias", path: "config", line: 41 }];
    render(<HostInspector detail={detail} onMetadata={vi.fn()} />);

    expect(screen.getByText(/config:41/)).toBeInTheDocument();
  });

  // "Inherited" means the value's source is a file other than this block's.
  it("lists only the values that came from elsewhere", () => {
    const detail = detailWith();
    detail.effective.entries = [
      { keyword: "Port", values: ["22"], source: { path: "groups.ssh-ui.conf", line: 3 } },
      { keyword: "User", values: ["aida"], source: { path: "connections/work/bastion.conf", line: 2 } },
    ] as HostDetail["effective"]["entries"];
    render(<HostInspector detail={detail} onMetadata={vi.fn()} />);

    expect(screen.getByText(/Port/)).toBeInTheDocument();
    expect(screen.queryByText(/User/)).toBeNull();
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test --prefix web -- src/connections/HostInspector.test.tsx`
Expected: FAIL — `Failed to resolve import "./HostInspector"`.

- [ ] **Step 4: Write the inspector body**

Create `web/src/connections/HostInspector.tsx`:

```tsx
import type { HostDetail, HostMetadata } from "../api/config";
import { CheckboxField, Field, control, fieldLabel, hintText } from "../ui/form";
import { useTranslate } from "../i18n/context";
import { NoticeList } from "./SavePreview";

// Whether the pane has something in it worth opening for.
//
// This is what the toggle's amber dot is driven by. Without it, moving the
// notices into a pane that is shut by default would mean a connection with
// `duplicate_alias` looked exactly like one without — which would make the
// pane a regression rather than an improvement.
export function hostNeedsAttention(detail: HostDetail): boolean {
  return (detail.form.notices ?? []).length > 0 || (detail.effective.notices ?? []).length > 0;
}

// A value is inherited when the line that set it is in another file. The
// Effective tab still lists every value and its source; this is the short
// answer to "where did this come from", which is the question the pane is for.
function inherited(detail: HostDetail) {
  const own = detail.form.entry.file.path ?? detail.form.entry.file.absolute;
  return detail.effective.entries.filter((entry) => (entry.source.path ?? entry.source.absolute) !== own);
}

export function HostInspector({
  detail,
  onMetadata,
}: {
  detail: HostDetail;
  onMetadata: (metadata: HostMetadata) => void;
}) {
  const t = useTranslate();
  const notices = [...(detail.form.notices ?? []), ...(detail.effective.notices ?? [])];
  const fromElsewhere = inherited(detail);

  return (
    <div className="flex flex-col gap-5">
      <section className="flex flex-col gap-3">
        <h3 className={fieldLabel}>{t("inspector.appOnly")}</h3>

        <CheckboxField
          label={t("host.favourite")}
          checked={detail.metadata.favourite === true}
          onChange={(checked) => onMetadata({ ...detail.metadata, favourite: checked })}
        />

        <Field label={t("host.colour")}>
          <input
            type="color"
            // A colour input has no empty state, so "no colour" is the absence
            // of the value in metadata and this control shows a neutral swatch
            // for it. Clearing is a separate, explicit act.
            value={detail.metadata.colour === undefined || detail.metadata.colour === "" ? "#8e8e93" : detail.metadata.colour}
            onChange={(event) => onMetadata({ ...detail.metadata, colour: event.target.value })}
            className="h-8 w-14 rounded border border-control-line bg-control"
          />
        </Field>

        <Field label={t("host.tags")}>
          <input
            value={(detail.metadata.tags ?? []).join(", ")}
            onChange={(event) =>
              onMetadata({
                ...detail.metadata,
                tags: event.target.value.split(",").map((tag) => tag.trim()).filter((tag) => tag !== ""),
              })
            }
            className={control}
          />
        </Field>

        <Field label={t("host.displayOrder")}>
          <input
            type="number"
            value={String(detail.metadata.order ?? 0)}
            onChange={(event) => onMetadata({ ...detail.metadata, order: Number(event.target.value) || 0 })}
            className={control}
          />
        </Field>
      </section>

      <section className="flex flex-col gap-2">
        <h3 className={fieldLabel}>{t("inspector.notices")}</h3>
        {notices.length === 0 ? (
          <p className={hintText}>{t("inspector.noNotices")}</p>
        ) : (
          <NoticeList notices={notices} />
        )}
      </section>

      <section className="flex flex-col gap-2">
        <h3 className={fieldLabel}>{t("inspector.inherited")}</h3>
        {fromElsewhere.length === 0 ? (
          <p className={hintText}>{t("inspector.noInherited")}</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {fromElsewhere.map((entry, index) => (
              <li key={`${entry.keyword}-${index}`} className="text-xs text-ink-muted">
                {`${entry.keyword} ${entry.values.join(" ")} — ${entry.source.path ?? entry.source.absolute ?? ""}:${entry.source.line ?? 0}`}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test --prefix web -- src/connections/HostInspector.test.tsx`
Expected: PASS, 7 tests.

- [ ] **Step 6: Take the four moved controls out of HostDetail**

In `web/src/connections/HostDetail.tsx`, inside the `<section>` beginning at line 337, delete:
- the `CheckboxField` for `host.favourite` (lines 371–375)
- the colour block (lines 396–419)
- the display-order block (lines 421–430)
- the tags block (lines 432–448)

Keep the group block, the comment block and the rename block — all three write to a configuration file. Update the section's heading comment to say why the split is where it is:

```tsx
      {/*
        What is left here writes to a file: a group is a directory, so changing
        it moves the block; a comment is the line above `Host`; a rename is the
        `Host` line itself. The four settings that exist only in metadata.json
        moved to the inspector, which is what that pane is for.
      */}
```

Remove `CheckboxField` from the import list at lines 10–18 if it is no longer used in the file.

- [ ] **Step 7: Offer the content from ConnectionsPage**

In `web/src/connections/ConnectionsPage.tsx`:

```tsx
import { HostInspector, hostNeedsAttention } from "./HostInspector";
import type { InspectorContent } from "../ui/Inspector";
```

Extend the props:

```tsx
type ConnectionsPageProps = {
  onOpenFile: (path: string, line: number) => void;
  // The right-hand pane's contents, offered up to the shell. Null while no
  // connection is open: there is nothing to inspect until one is.
  onInspector: (content: InspectorContent) => void;
};
```

```tsx
export function ConnectionsPage({ onOpenFile, onInspector }: ConnectionsPageProps) {
```

Add the effect after the detail-loading effect:

```tsx
  // The pane follows the open connection. `onMetadata` is stable enough to
  // rebuild the body on every detail change rather than memoise it: the pane
  // is small, and a stale body would show the previous connection's tags.
  useEffect(() => {
    if (detail === null) {
      onInspector(null);
      return;
    }
    onInspector({
      attention: hostNeedsAttention(detail),
      body: <HostInspector detail={detail} onMetadata={onMetadata} />,
    });
    // onMetadata closes over `overview`, which changes on every reload; the
    // body is rebuilt with it deliberately.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail, overview, onInspector]);
```

- [ ] **Step 8: Update the existing connections tests**

`web/src/connections/ConnectionsPage.test.tsx` renders `ConnectionsPage` directly. Add `onInspector={() => undefined}` to every render of it. `HostDetail.test.tsx` asserts on the four moved controls; move those assertions to `HostInspector.test.tsx` if any duplicate what is already there, and delete them from `HostDetail.test.tsx` otherwise.

Run: `npm test --prefix web -- src/connections`
Expected: PASS after the edits. Read each failure — a failure naming "Tags" or "Colour" in `HostDetail.test.tsx` is a test asserting the old location and should move, not be deleted wholesale.

- [ ] **Step 9: Update the end-to-end suite**

`web/e2e/connections.spec.ts` exercises the metadata controls. Wherever it reaches a colour, tag, favourite or order control, open the pane first:

```ts
  await page.getByRole("button", { name: "Show details" }).click();
```

Run: `make build && make e2e`
Expected: PASS. A failure of the form "strict mode violation" means a control exists in both panes — the deletion in Step 6 was incomplete.

- [ ] **Step 10: Commit**

```bash
git add web/src/connections/HostInspector.tsx web/src/connections/HostInspector.test.tsx \
        web/src/connections/HostDetail.tsx web/src/connections/HostDetail.test.tsx \
        web/src/connections/ConnectionsPage.tsx web/src/connections/ConnectionsPage.test.tsx \
        web/src/i18n/messages.ts web/e2e/connections.spec.ts internal/ui/dist
git commit -m "Keep our own notes out of the file's card"
```

---

### Task 9: The connections components onto tokens

**Files:**
- Modify: `web/src/connections/ConnectionsPage.tsx`
- Modify: `web/src/connections/ConnectionTree.tsx`
- Modify: `web/src/connections/SavePreview.tsx`
- Modify: `web/src/connections/HostDetail.tsx`

**Interfaces:** no signature changes. This is a substitution.

Apply this table throughout the four files. Where a literal is not listed, choose the token whose name says what the element is for.

| Was | Becomes |
| --- | --- |
| `bg-zinc-950` | `bg-canvas` |
| `bg-zinc-900` (a control) | `bg-control` |
| `bg-zinc-900` (a panel or hover) | `bg-select-fill` |
| `bg-zinc-800` (a button) | use `secondaryAction` from `ui/form` |
| `border-zinc-700` | `border-control-line` |
| `border-zinc-800` | `border-line` |
| `text-zinc-100` / `text-zinc-200` | `text-ink` |
| `text-zinc-300` / `text-zinc-400` | `text-ink-muted` |
| `text-zinc-500` | `text-ink-faint` |
| `text-amber-300` | `text-notice-ink` |
| `text-rose-300` | `text-danger` |
| `text-emerald-300` | `text-live` |
| `bg-rose-700` | use `dangerAction` from `ui/form` |
| `border-rose-700` | `border-control-line` with `text-danger` |
| `outline-zinc-600` | `outline-accent` |

- [ ] **Step 1: Replace the ad-hoc controls in ConnectionsPage**

`ConnectionsPage.tsx:345-421` writes its own `<input>`, `<select>` and buttons. Replace their class attributes with the shared constants: `control` for the input and both selects, `Button` with `kind="secondary"` for Create / Duplicate / Move, and `Button` with `kind="danger"` for Delete. Import them:

```tsx
import { control } from "../ui/form";
import { Button } from "../ui/surface";
```

The delete confirmation button keeps both states as `Button kind="danger"`; only its label changes, as now.

- [ ] **Step 2: Apply the table to the other three files**

`ConnectionTree.tsx` — including `blockClass` at lines 332–336, whose drop highlight becomes `bg-select-fill outline outline-1 outline-accent`. The accent is correct here: a live drop target is the one action in progress.

`SavePreview.tsx` — the diff view's `bg-zinc-950` becomes `bg-canvas`, insertions `text-live`, deletions `text-danger`, context `text-ink-muted`.

`HostDetail.tsx` — the tab strip's active state becomes `border-b-2 border-accent text-ink`, its inactive `text-ink-muted`.

- [ ] **Step 3: Verify no literal survives**

Run: `grep -nE "zinc-|rose-|amber-|emerald-" web/src/connections/*.tsx`
Expected: no output.

- [ ] **Step 4: Run the tests**

Run: `npm run typecheck --prefix web && npm test --prefix web -- src/connections`
Expected: PASS.

- [ ] **Step 5: Build and commit**

```bash
make build
git add web/src/connections internal/ui/dist
git commit -m "Take the last zinc out of the connections screen"
```

---

### Task 10: The remaining components onto tokens

**Files:**
- Modify: `web/src/ui/CopyButton.tsx`
- Modify: `web/src/ui/PasswordField.tsx`
- Modify: `web/src/history/HistoryPanel.tsx`
- Modify: `web/src/keys/RevealDialog.tsx`
- Modify: `web/src/knownhosts/KnownHostsPanel.tsx`
- Modify: `web/src/remotekeys/RemoteKeyPanel.tsx`

**Interfaces:** no signature changes.

- [ ] **Step 1: Apply the same table as Task 9**

Use the table in Task 9 verbatim. `RevealDialog.tsx` shows a private key: its `<pre aria-label="Private key">` keeps that exact label — `e2e/keys.spec.ts:38` and `:42` address it — and only its colours change.

- [ ] **Step 2: Verify no literal survives anywhere**

Run: `grep -rnE "zinc-|rose-|amber-|emerald-" web/src --include='*.tsx' --include='*.ts'`
Expected: no output. If a test file matches, it is asserting on a class — read it, because nothing in the suite is supposed to.

- [ ] **Step 3: Run everything**

Run: `npm run typecheck --prefix web && npm test --prefix web`
Expected: PASS.

- [ ] **Step 4: Build and commit**

```bash
make build
git add web/src internal/ui/dist
git commit -m "Finish the palette everywhere else"
```

---

### Task 11: Prove both themes on every screen

**Files:**
- Create: `web/e2e/appearance.spec.ts`
- Modify: `README.md`

- [ ] **Step 1: Write the end-to-end test**

Create `web/e2e/appearance.spec.ts`, following the imports and fixtures of `web/e2e/shell.spec.ts`:

```ts
import { expect, test } from "./support/fixtures";
import { openApplication, sessionStatus } from "./support/app";

const sections = [
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
];

// The failure this guards against is specific and has happened here before:
// `ui/form.tsx` exists because three panels grew their own controls and one had
// none at all, so a field was black text on a black page. A token given a value
// in one theme and not the other reproduces exactly that, on whichever screen
// was missed.
for (const appearance of ["light", "dark"] as const) {
  test(`every section renders in ${appearance}`, async ({ page, installation }) => {
    await openApplication(page, installation);
    await expect(sessionStatus(page)).toContainText("Local session active");

    await page.getByLabel("Appearance").selectOption(appearance);
    await expect(page.locator("html")).toHaveAttribute("data-theme", appearance);

    for (const name of sections) {
      await page.getByRole("button", { name, exact: true }).click();
      // Nothing may be transparent-on-transparent: the shell always paints.
      await expect(page.locator("main")).toBeVisible();
      await expect(page.locator("html")).toHaveAttribute("data-theme", appearance);
    }
  });
}
```

Check `web/e2e/support/` for the actual fixture and helper names before writing the imports; `shell.spec.ts` is the closest existing model.

- [ ] **Step 2: Run it**

Run: `make build && make e2e`
Expected: PASS, 2 new tests.

- [ ] **Step 3: Correct the README**

`README.md` describes the UI's boundaries. Add to the section that covers the Connections UI:

```markdown
- 外観はライトとダークの 2 つで、既定は OS に従います。選択はヘッダーの「外観」で上書きでき、`localStorage` の `ssh-ui.theme` に記録します。ブラウザの永続ストレージへ書くのはこれと `ssh-ui.language` の 2 つだけで、`e2e/bootstrap.spec.ts` がその 2 つ以外が現れたら落ちる allowlist で守っています。
- 色は状態のためだけに使います。accent はその画面の主要な操作 1 つに限り、琥珀は注意、赤は壊す操作、緑はローカルセッションが生きていることを指します。選択されているだけの行に色は付きません。
- 接続の詳細のうち、`~/.ssh/config` に書かれるもの（グループ、コメント、alias）は主画面に、`metadata.json` にしかないもの（色、タグ、お気に入り、表示順）と注意・継承元は右のインスペクタにあります。インスペクタは既定で閉じており、中身に注意がある時だけ開閉ボタンに印が付きます。キーボードショートカットはありません — ⌥⌘I は Chrome・Firefox・Safari のいずれでも開発者ツールが先に取るためです。
```

- [ ] **Step 4: Full gate**

Run: `make test && make e2e && make verify-generated`
Expected: PASS. `make verify-generated` should be unaffected — no OpenAPI contract changed.

- [ ] **Step 5: Commit**

```bash
git add web/e2e/appearance.spec.ts README.md internal/ui/dist
git commit -m "Prove both appearances on all ten screens"
```

---

## Self-Review

**Spec coverage.** Colour rule → Task 3 and the Global Constraints. Tokens → Task 1. Which theme, three values, storage allowlist → Task 2. Components → Tasks 4, 5. `form.tsx` keeps its callers → Task 3. Ten self-styling components → Tasks 9, 10. Three sidebar groups → Task 6. Inspector, shell-owned open state, amber dot, `aside`/`aria-expanded`/`aria-controls`, Connections-only content → Tasks 7, 8. No keyboard shortcut → nothing to build; recorded in the README in Task 11. Nothing merged or renamed → no task touches the section list. Reduced motion → Task 1's stylesheet. Tests → each task, plus Task 11.

**Deviation from the spec, recorded here.** The spec says the sidebar change "adds `<h2>` and a second `<ul>`". It cannot: `e2e/bootstrap.spec.ts:137` queries `getByRole("heading", { name: "鍵", level: 2 })`, and Playwright matches accessible names by substring, so an `<h2>` named `鍵とホスト` would make that query match twice. Task 6 uses `<ul aria-label>` with an `aria-hidden` label instead. The spec is corrected to match.

**Type consistency.** `InspectorContent` is defined in Task 7 and consumed by name in Tasks 7 and 8. `hostNeedsAttention` and `HostInspector` are defined in Task 8 and used only there. `Theme`, `themes`, `resolveTheme`, `applyTheme`, `themeStorageKey` are defined in Task 1 and consumed in Task 2. `IconName`, `Icon`, `IconSprite`, `iconNames` are defined in Task 4 and consumed in Tasks 6 and 7. `Button`, `Card`, `Row`, `Notice` are defined in Task 5 and consumed in Tasks 8 and 9.
