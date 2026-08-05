import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LanguageProvider, useTranslate, useLanguage } from "./context";
import { en, ja } from "./messages";
import { detectLocale, storageKey } from "./locale";

afterEach(() => {
  window.localStorage.clear();
  vi.restoreAllMocks();
});

function Probe() {
  const t = useTranslate();
  const { locale, setLocale } = useLanguage();
  return (
    <>
      <p>{t("shell.starting")}</p>
      <p>{t("shell.active", { version: "0.1.0" })}</p>
      <p>{`locale:${locale}`}</p>
      <button type="button" onClick={() => setLocale("ja")}>
        to japanese
      </button>
    </>
  );
}

describe("the catalogue", () => {
  it("translates every English message", () => {
    // TypeScript already refuses a missing key, so this is the assertion the
    // type system cannot make: that no Japanese entry was left as a copy of
    // the English one by accident.
    const untranslated = Object.keys(en).filter((key) => {
      const source = en[key as keyof typeof en];
      const target = ja[key as keyof typeof en];
      return source === target;
    });
    // These are the ones that are legitimately identical: proper nouns and
    // strings that are already the same in both languages.
    expect(untranslated.sort()).toEqual(
      [
        "diag.hostAlias",
        "diag.terminal",
        "explorer.fileState",
        "host.tabRaw",
        "keys.agentHeading",
        "keys.certKeyId",
        "keys.colFingerprint",
        "keys.reference",
        "keys.renameBlockerOther",
        "keys.renameFilePair",
        "keys.renameReference",
        "keys.unreadableEntry",
        "kh.heading",
        "rk.alias",
        "rk.fingerprint",
        "rk.hostAlias",
        "section.knownHosts",
        "shell.languageEnglish",
        "shell.languageJapanese",
        "shell.title",
      ].sort(),
    );
  });

  it("leaves a placeholder alone when no value is given for it", () => {
    render(
      <LanguageProvider initial="en">
        <Probe />
      </LanguageProvider>,
    );

    // A missing argument shows the braces rather than the word "undefined",
    // which in the middle of a sentence would read as content.
    expect(screen.getByText("Local session active · 0.1.0")).toBeInTheDocument();
  });
});

describe("the language switch", () => {
  it("changes the rendered language and remembers the choice", async () => {
    const user = userEvent.setup();
    render(
      <LanguageProvider initial="en">
        <Probe />
      </LanguageProvider>,
    );

    expect(screen.getByText("Starting secure local session…")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "to japanese" }));

    expect(screen.getByText(ja["shell.starting"])).toBeInTheDocument();
    expect(window.localStorage.getItem(storageKey)).toBe("ja");
  });

  it("writes nothing but the language, and nothing at all until it is changed", async () => {
    const user = userEvent.setup();
    render(
      <LanguageProvider initial="en">
        <Probe />
      </LanguageProvider>,
    );

    // Detection alone must not write: a user who never touches the switch
    // leaves persistent storage empty.
    expect(window.localStorage.length).toBe(0);

    await user.click(screen.getByRole("button", { name: "to japanese" }));

    expect(Object.keys(window.localStorage)).toEqual([storageKey]);
    expect(window.sessionStorage.length).toBe(0);
  });
});

describe("locale detection", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("prefers the stored choice over the browser", () => {
    window.localStorage.setItem(storageKey, "ja");
    vi.spyOn(navigator, "languages", "get").mockReturnValue(["en-GB"]);

    expect(detectLocale()).toBe("ja");
  });

  it("matches a regional variant by its subtag", () => {
    vi.spyOn(navigator, "languages", "get").mockReturnValue(["ja-JP"]);

    expect(detectLocale()).toBe("ja");
  });

  it("falls back to English for a language it has no catalogue for", () => {
    vi.spyOn(navigator, "languages", "get").mockReturnValue(["de-DE", "fr"]);

    expect(detectLocale()).toBe("en");
  });

  it("ignores a stored value that is not a language it has", () => {
    window.localStorage.setItem(storageKey, "../etc/passwd");
    vi.spyOn(navigator, "languages", "get").mockReturnValue(["en-US"]);

    expect(detectLocale()).toBe("en");
  });

  it("survives a browser that refuses storage entirely", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("access denied");
    });
    vi.spyOn(navigator, "languages", "get").mockReturnValue(["ja"]);

    // The preference is lost, not the shell.
    expect(detectLocale()).toBe("ja");
  });
});
