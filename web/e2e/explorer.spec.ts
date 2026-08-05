import { clickAndAwait, expect, openSection, test } from "./support/environment";

test("shows the Include hierarchy and edits an included file", async ({ page, installation }) => {
  await page.goto(installation.url);
  await openSection(page, "Config");

  await expect(page.getByRole("heading", { name: "Include hierarchy" })).toBeVisible();
  await expect(page.getByRole("button", { name: "config", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "conf.d/10-home.conf" })).toBeVisible();

  await page.getByRole("button", { name: "conf.d/10-home.conf" }).click();
  const editor = page.getByLabel(/File text/);
  await expect(editor).toHaveValue(/UnknownFutureDirective some "quoted value" 3/);

  await editor.fill((await editor.inputValue()) + "Host printer\n\tHostName 198.51.100.30\n");
  expect(await clickAndAwait(page, "Save file", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("conf.d/10-home.conf");
  // The unknown directive is the point: the engine has no schema for it and
  // must write it back exactly, quotes and spacing included.
  expect(after).toContain('UnknownFutureDirective some "quoted value" 3');
  expect(after).toContain("Host printer");
  expect(after).toContain("Host nas");
});
