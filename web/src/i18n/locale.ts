// The two languages this application is translated into. English is the
// fallback because it is the language the catalogue is written in, so an
// unknown browser language degrades to complete text rather than to keys.
export const locales = ["en", "ja"] as const;
export type Locale = (typeof locales)[number];

export const defaultLocale: Locale = "en";

// storageKey is the only thing this application writes to persistent browser
// storage. It is named rather than derived so the end-to-end suite can allow
// exactly this key and still fail on anything else — the assertion there is an
// allowlist, not a count, because a count cannot tell a preference from a token.
export const storageKey = "sshc.language";

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (locales as readonly string[]).includes(value);
}

// detectLocale reads the stored choice, then what the browser says, then falls
// back to English.
//
// Storage access is wrapped because a browser configured to refuse it throws on
// read, and a language preference is not worth failing the whole shell over.
export function detectLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(storageKey);
    if (isLocale(stored)) return stored;
  } catch {
    // Storage is unavailable; the browser's own language still applies.
  }
  // "ja-JP" and "ja" both mean Japanese. Matching the subtag rather than the
  // whole string keeps every regional variant working.
  for (const candidate of navigator.languages ?? [navigator.language]) {
    const subtag = candidate.split("-")[0];
    if (isLocale(subtag)) return subtag;
  }
  return defaultLocale;
}

export function rememberLocale(locale: Locale): void {
  try {
    window.localStorage.setItem(storageKey, locale);
  } catch {
    // The choice still applies to this tab; it just will not outlive it.
  }
}
