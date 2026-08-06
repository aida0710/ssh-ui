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
