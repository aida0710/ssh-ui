import { expect, openSection, test } from "./support/environment";

// The arrangement the whole feature exists for, driven through the built binary
// against a throwaway HOME: one secret under a name, two hosts pointing at it,
// and a file on disk that names neither.
test("gives one named secret to two hosts and writes neither name into the file", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
  await openSection(page, "Secrets");

  await page.getByLabel("Master password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create the vault" }).click();

  const passwords = page.getByRole("region", { name: "Account passwords" });
  await expect(passwords).toBeVisible();
  await passwords.getByLabel("New account password name").fill("office-vm");
  await passwords.getByLabel("New account password value").fill("hunter2");
  await passwords.getByRole("button", { name: "Store account password" }).click();

  await expect(passwords.getByRole("button", { name: "Delete office-vm" })).toBeVisible();
  // The list says the name and what uses it, never the value.
  await expect(page.locator("body")).not.toContainText("hunter2");

  // Two hosts, one name. Each picks it from its own screen, which is the only
  // place a host's password is chosen.
  for (const alias of ["bastion", "nas"]) {
    await openSection(page, "Connections");
    await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: alias }).click();
    await page.getByRole("tab", { name: "Diagnostics" }).click();

    const panel = page.getByRole("region", { name: "Stored password" });
    await panel.getByLabel("Use a stored password").selectOption("office-vm");
    await panel.getByRole("button", { name: "Use this password" }).click();
    await expect(panel.getByText(`A password is stored for ${alias}.`)).toBeVisible();
  }

  await openSection(page, "Secrets");
  await expect(page.getByRole("region", { name: "Account passwords" })).toContainText("bastion, nas");

  // And the sealed file carries none of it: not the secret, not the name, not
  // the hosts that point at it.
  const sealed = await installation.read("ssh-ui/secrets");
  for (const absent of ["hunter2", "office-vm", "bastion", "nas"]) {
    expect(sealed).not.toContain(absent);
  }
});

// A key passphrase in this picker would be sent to a remote host as a login
// password on the next connection. The two namespaces are two namespaces so
// that no screen has to be careful about it.
test("never offers a key passphrase where a host password is chosen", async ({ page, installation }) => {
  await page.goto(installation.url);
  await openSection(page, "Secrets");

  await page.getByLabel("Master password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create the vault" }).click();

  const phrases = page.getByRole("region", { name: "Key passphrases" });
  await phrases.getByLabel("New key passphrase name").fill("build-key");
  await phrases.getByLabel("New key passphrase value").fill("a passphrase");
  await phrases.getByRole("button", { name: "Store key passphrase" }).click();
  await expect(phrases.getByRole("button", { name: "Delete build-key" })).toBeVisible();

  await openSection(page, "Connections");
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByRole("tab", { name: "Diagnostics" }).click();

  const panel = page.getByRole("region", { name: "Stored password" });
  // There is no account password at all, so the picker is not there to offer
  // the wrong kind from.
  await expect(panel.getByLabel("Use a stored password")).toHaveCount(0);
  await expect(panel.getByLabel("Password for bastion")).toBeVisible();
});
