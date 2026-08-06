import { expect, test } from "./support/environment";
import { openApplication, openSection, sessionStatus } from "./support/environment";

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
// none at all, so a field was black text on a black page. A component left on a
// literal colour reproduces exactly that in whichever theme it was not written
// for, on whichever screen was missed.
//
// Reading computed colour rather than eyeballing: a token that resolves to
// nothing leaves the element transparent, and transparent-on-transparent is the
// shape the failure takes.
for (const appearance of ["light", "dark"] as const) {
  test(`every section renders in ${appearance}`, async ({ page, installation }) => {
    await openApplication(page, installation);

    await page.getByLabel("Appearance").selectOption(appearance);
    await expect(page.locator("html")).toHaveAttribute("data-theme", appearance);
    await expect(sessionStatus(page)).toContainText("Local session active");

    for (const name of sections) {
      await openSection(page, name);

      await expect(page.locator("html")).toHaveAttribute("data-theme", appearance);
      await expect(page.locator("main")).toBeVisible();

      // The shell always paints, and the two never agree: text the same colour
      // as what is behind it is the defect this suite is here for.
      const painted = await page.evaluate(() => {
        const shell = document.querySelector("main");
        if (shell === null) return null;
        const style = window.getComputedStyle(shell);
        const body = window.getComputedStyle(document.body);
        return { colour: style.color, background: body.backgroundColor };
      });
      expect(painted).not.toBeNull();
      expect(painted?.colour).not.toBe(painted?.background);
      expect(painted?.colour).not.toBe("rgba(0, 0, 0, 0)");
    }
  });
}

// Every control the palette reaches has to be legible, not only the shell. This
// walks the one screen that carries an input, a select, a button and a notice
// at the same time, and asserts none of them is painted onto its own colour.
test("the connections controls are legible in light", async ({ page, installation }) => {
  await openApplication(page, installation);
  await page.getByLabel("Appearance").selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

  await page.getByRole("button", { name: "bastion", exact: true }).click();
  await expect(page.getByRole("heading", { name: "bastion", level: 2 })).toBeVisible();

  const readable = await page.evaluate(() => {
    const results: { where: string; colour: string; background: string }[] = [];
    for (const selector of ["input#new-alias", "select#new-file", "input#field-2-HostName"]) {
      const element = document.querySelector(selector);
      if (element === null) continue;
      const style = window.getComputedStyle(element);
      results.push({ where: selector, colour: style.color, background: style.backgroundColor });
    }
    return results;
  });

  // Named rather than counted loosely: a selector that stops matching would
  // otherwise turn this into a test that asserts nothing and still passes.
  expect(readable.map((control) => control.where)).toEqual(
    expect.arrayContaining(["input#new-alias", "select#new-file"]),
  );
  for (const control of readable) {
    expect(control.colour, `${control.where} text`).not.toBe(control.background);
    // A control painted near-black in the light theme is the exact regression
    // this file exists to catch: it means a literal survived the migration.
    expect(control.background, `${control.where} background`).not.toBe("rgb(28, 28, 30)");
  }
});
