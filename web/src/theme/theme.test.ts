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

  // 手で編集された値や古い値が、外観を決めてはならない。
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

  // 選択が 2 値ではなく 3 値を持つ理由のすべて。
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
