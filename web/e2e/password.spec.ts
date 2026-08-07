import { expect, openApplication, openSection, test } from "./support/environment";

// The end-to-end suite drives the built binary against a throwaway HOME, so
// this exercises the real vault file on a real disk. It never launches a
// terminal and never starts ssh: the askpass helper's own behaviour is covered
// by cmd/ssh-ui's tests, and the redemption rules by internal/secret's.
test("stores a password for a host and never shows it again", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByRole("tab", { name: "Diagnostics" }).click();

  const panel = page.getByRole("region", { name: "Stored password" });
  await expect(panel).toBeVisible();
  // The warning is above the field, not behind a disclosure.
  await expect(panel.getByText(/A key is stronger/)).toBeVisible();

  await panel.getByLabel("Password for bastion").fill("hunter2");
  await panel.getByRole("button", { name: "Store a new password for bastion" }).click();

  await expect(panel.getByText("A password is stored for bastion.")).toBeVisible();
  await expect(page.locator("body")).not.toContainText("hunter2");

  // And the file on disk is ciphertext: neither the password nor the alias.
  const sealed = await installation.read("ssh-ui/secrets");
  expect(sealed).not.toContain("hunter2");
  expect(sealed).not.toContain("bastion");
});

// Locking the vault locks the application. It used to lock one panel, which
// left the user inside a shell whose next request would be refused.
test("locking the vault returns the application to its front door", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Secrets");

  await page.getByRole("button", { name: "Lock ssh-ui" }).click();

  await expect(page.getByLabel("Master password", { exact: true })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
});
