import { clickAndAwait, expect, openSection, test } from "./support/environment";
import type { Page } from "@playwright/test";

async function openBastion(page: Page, url: string) {
  await page.goto(url);
  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "bastion" })
    .click();
  await expect(page.getByRole("tablist", { name: "Host editor" })).toBeVisible();
}

test("edits a host through the form and writes only the line that changed", async ({
  page,
  installation,
}) => {
  const before = await installation.read("config");
  await openBastion(page, installation.url);

  await page.getByLabel("Port", { exact: true }).fill("2244");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("config");
  expect(after).toContain("Port 2244");
  expect(after).not.toContain("Port 2222");
  // The bytes around the change must survive exactly: the comment, the
  // "HostName=" spelling and the run of spaces after User are all things a
  // reformatting editor would quietly normalise.
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.");
  expect(after).toContain("HostName=203.0.113.10");
  expect(after).toContain("User    ops");
  expect(after).toContain("Include conf.d/*.conf");
  expect(after.split("\n").length).toBe(before.split("\n").length);
});

test("edits the same host through Raw and keeps every other byte", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);
  await page.getByRole("tab", { name: "Raw" }).click();

  const editor = page.getByLabel(/Block text/);
  const original = await editor.inputValue();
  await editor.fill(original.replace("Port 2222", "Port 2255\n\tCompression yes"));
  expect(await clickAndAwait(page, "Save block", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("config");
  expect(after).toContain("Port 2255");
  expect(after).toContain("Compression yes");
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.");
  expect(after).toContain("ServerAliveInterval 30");
});

test("shows a save preview diff of exactly what was written", async ({ page, installation }) => {
  await openBastion(page, installation.url);
  await page.getByLabel("Port", { exact: true }).fill("2299");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(200);

  const preview = page.getByRole("region", { name: "Save preview" });
  await expect(preview).toContainText("2299");
  await expect(preview).not.toContainText("Changed on disk since you loaded it");
  expect(await installation.read("config")).toContain("Port 2299");
});

test("refuses a save whose base is stale and shows the three-way conflict", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);

  // Someone edits the file outside the application after the page loaded it.
  const external = (await installation.read("config")).replace(
    "Host *",
    "Host edited-outside\n\tHostName 192.0.2.99\n\nHost *",
  );
  await installation.write("config", external);

  await page.getByLabel("Port", { exact: true }).fill("2277");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(409);

  await expect(page.getByText("Changed on disk since you loaded it")).toBeVisible();
  await expect(page.getByText("Your pending change")).toBeVisible();

  // The decisive assertion: the external edit survived untouched and the
  // pending change was not written over it.
  const after = await installation.read("config");
  expect(after).toBe(external);
  expect(after).not.toContain("Port 2277");
});
