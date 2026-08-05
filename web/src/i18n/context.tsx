import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { messages, type MessageKey } from "./messages";
import { defaultLocale, detectLocale, rememberLocale, type Locale } from "./locale";

// Values interpolated into a message. Numbers are accepted because a count
// reads as one, and forcing every caller to stringify would be noise.
export type Values = Record<string, string | number>;

export type Translate = (key: MessageKey, values?: Values) => string;

type LanguageState = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: Translate;
};

const LanguageContext = createContext<LanguageState | null>(null);

// interpolate replaces {name} with the value given for it.
//
// A placeholder with no value is left as written rather than replaced with
// "undefined": the braces make it obvious that a caller forgot an argument,
// where the word "undefined" in the middle of a sentence looks like content.
function interpolate(template: string, values: Values | undefined): string {
  if (values === undefined) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in values ? String(values[name]) : whole,
  );
}

export function LanguageProvider({ children, initial }: { children: ReactNode; initial?: Locale }) {
  // detectLocale runs once, at mount. Re-reading it later would fight the
  // switch: a user who chose English on a Japanese system means it.
  const [locale, setLocaleState] = useState<Locale>(() => initial ?? detectLocale());

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    rememberLocale(next);
  }, []);

  const value = useMemo<LanguageState>(() => {
    const catalogue = messages[locale];
    return {
      locale,
      setLocale,
      // A key missing from the chosen language falls back to English rather
      // than rendering the key itself. TypeScript already makes that
      // impossible — the Japanese catalogue is typed by the English one — so
      // this covers only a catalogue loaded at runtime, and it degrades to
      // readable text instead of to `keys.addToAgent`.
      t: (key, values) => interpolate(catalogue[key] ?? messages[defaultLocale][key], values),
    };
  }, [locale, setLocale]);

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

// A panel rendered outside the provider translates into English rather than
// throwing, so a component test can render one panel without assembling the
// shell around it. That is a real hazard — a panel wired up outside the
// provider would look correct in English and stay English for everyone else —
// so the invariant is asserted instead of enforced here: App mounts the
// provider, `App renders every panel inside the language provider` proves it,
// and the end-to-end language spec proves the panels actually change.
const fallback: LanguageState = {
  locale: defaultLocale,
  setLocale: () => undefined,
  t: (key, values) => interpolate(messages[defaultLocale][key], values),
};

export function useLanguage(): LanguageState {
  return useContext(LanguageContext) ?? fallback;
}

export function useTranslate(): Translate {
  return useLanguage().t;
}
