import { describe, expect, it } from "vitest";
import { formatValues, parseValues } from "./values";

describe("parseValues", () => {
  it.each([
    ["single", "22", ["22"]],
    ["several", "one two   three", ["one", "two", "three"]],
    ["quoted with spaces", 'tmux "new session" end', ["tmux", "new session", "end"]],
    ["empty quotes", '""', [""]],
    ["only whitespace", "   ", []],
    ["tabs", "a\tb", ["a", "b"]],
  ])("splits %s the way OpenSSH does", (_name, input, expected) => {
    expect(parseValues(input)).toEqual(expected);
  });

  it("throws when a quote is never closed, because OpenSSH has no escape", () => {
    expect(() => parseValues('"unbalanced')).toThrow("unbalanced_quote");
  });
});

describe("formatValues", () => {
  it("quotes only the values that need it and round-trips", () => {
    const values = ["tmux", "new session", "", "plain"];
    expect(formatValues(values)).toBe('tmux "new session" "" plain');
    expect(parseValues(formatValues(values))).toEqual(values);
  });
});
