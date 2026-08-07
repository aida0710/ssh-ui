import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

test("records a change in history and restores the previous bytes", async ({
  page,
  installation,
}) => {
  const original = await installation.read("config");

  await openApplication(page, installation);
  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "bastion" })
    .click();
  await page.getByLabel("Port", { exact: true }).fill("2233");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(200);
  expect(await installation.read("config")).toContain("Port 2233");

  await openSection(page, "History");
  await expect(page.getByRole("heading", { name: "Completed changes" })).toBeVisible();
  await expect(page.getByText("config.host_fields")).toBeVisible();

  expect(await clickAndAwait(page, "Restore config", "/api/v1/history/restore")).toBe(200);

  // 復元は、ファイルを単に同等のものにではなく、変更前に
  // 持っていたバイト列そのものに戻す。
  expect(await installation.read("config")).toBe(original);
});
