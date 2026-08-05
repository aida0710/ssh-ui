import { expect, openSection, test } from "./support/environment";

// The end-to-end suite drives the built binary against a throwaway HOME, so
// this exercises the real vault file on a real disk. It never launches a
// terminal and never starts ssh: the askpass helper's own behaviour is covered
// by cmd/ssh-ui's tests, and the redemption rules by internal/secret's.
test("creates a vault, stores a password, and never shows it again", async ({ page, installation }) => {
  await page.goto(installation.url);
  await openSection(page, "Connections");
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByRole("tab", { name: "Diagnostics" }).click();

  const panel = page.getByRole("region", { name: "Stored password" });
  await expect(panel).toBeVisible();
  // The warning is above the field, not behind a disclosure.
  await expect(panel.getByText(/A key is stronger/)).toBeVisible();

  await panel.getByLabel("New vault passphrase").fill("correct horse battery staple");
  await panel.getByRole("button", { name: "Create the vault" }).click();

  await panel.getByLabel("Password for bastion").fill("hunter2");
  await panel.getByRole("button", { name: "Store the password" }).click();

  await expect(panel.getByText("A password is stored for bastion.")).toBeVisible();
  // Neither the password nor the passphrase is anywhere in the rendered page.
  await expect(page.locator("body")).not.toContainText("hunter2");
  await expect(page.locator("body")).not.toContainText("correct horse battery staple");

  // And the file on disk is ciphertext: neither the password nor the alias.
  const sealed = await installation.read("ssh-ui/secrets");
  expect(sealed).not.toContain("hunter2");
  expect(sealed).not.toContain("bastion");
});

test("a locked vault says so rather than claiming nothing is stored", async ({ page, installation }) => {
  await page.goto(installation.url);
  await openSection(page, "Connections");
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByRole("tab", { name: "Diagnostics" }).click();

  const panel = page.getByRole("region", { name: "Stored password" });
  await panel.getByLabel("New vault passphrase").fill("correct horse battery staple");
  await panel.getByRole("button", { name: "Create the vault" }).click();
  await expect(panel.getByLabel("Password for bastion")).toBeVisible();

  await panel.getByRole("button", { name: "Lock the vault" }).click();

  await expect(panel.getByText(/vault is locked/)).toBeVisible();
  await expect(panel.getByLabel("Password for bastion")).toHaveCount(0);
});
