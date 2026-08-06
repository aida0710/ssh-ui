import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

// This spec deliberately stops short of "Scan". ssh-keyscan opens a connection
// to whatever host it is given, and no automated test in this repository is
// allowed to contact one. The scan-and-add flow, and the fingerprint-or-
// acknowledgement gate in front of it, are covered by the panel's Vitest suite
// against a stubbed API and by manual test M1.
test("lists the known_hosts entries and deletes one through a confirmation", async ({
  page,
  installation,
}) => {
  const before = await installation.read("known_hosts");
  expect(before).toContain("203.0.113.10");

  await openApplication(page, installation);
  await openSection(page, "Known Hosts");
  await expect(page.getByRole("heading", { name: "Known Hosts" })).toBeVisible();

  const row = page.getByRole("row").filter({ hasText: "203.0.113.10" });
  await expect(row).toContainText("ssh-ed25519");
  await expect(row).toContainText("SHA256:");

  // Deleting asks first, and says what it will remove.
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText(/Remove line \d+/)).toBeVisible();

  expect(await clickAndAwait(page, "Confirm delete", "/api/v1/known-hosts/delete")).toBe(200);

  const after = await installation.read("known_hosts");
  expect(after).not.toContain("203.0.113.10");
});

test("keeps the search box scoped to the file it is showing", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Known Hosts");
  await expect(page.getByRole("row").filter({ hasText: "203.0.113.10" })).toBeVisible();

  await page.getByLabel("Search").fill("no-such-host-anywhere");
  await expect(page.getByRole("row").filter({ hasText: "203.0.113.10" })).toHaveCount(0);

  // A search that matches nothing must not have changed the file.
  expect(await installation.read("known_hosts")).toContain("203.0.113.10");
});
