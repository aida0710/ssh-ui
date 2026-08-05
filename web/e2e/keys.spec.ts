import { clickAndAwait, expect, openSection, test } from "./support/environment";

test("lists generated keys and reveals one only after an explicit confirmation", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
  await openSection(page, "Keys");
  await expect(
    page.getByRole("table", { name: "Files classified by content and permissions" }),
  ).toBeVisible();

  await page.getByLabel("File name").fill("id_e2e");
  // "Passphrase" also matches the "create without a passphrase" checkbox, so
  // the textbox is named by role.
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const row = page.getByRole("row", { name: /id_e2e\b/ }).first();
  await expect(row).toBeVisible();
  await expect(row).toContainText("0600");
  expect(await installation.read("id_e2e.pub")).toContain("ssh-ed25519 ");

  // Nothing on the inventory screen shows key material before anyone asked.
  //
  // This is the page-level half of the property. Whether a *response* carries
  // key material it should not is asserted in Go, by
  // TestNoResponseCarriesASecretItIsNotEntitledTo: a field that leaks over the
  // API without being rendered is invisible from here, and pretending
  // otherwise would make this spec a false comfort.
  await expect(page.locator("body")).not.toContainText("BEGIN OPENSSH PRIVATE KEY");

  // The dialog opens without the key. Design §6.3 separates reveal from every
  // other API precisely so that opening this dialog is not itself a disclosure.
  await row.getByRole("button", { name: "Show private key" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('pre[aria-label="Private key"]')).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("BEGIN OPENSSH PRIVATE KEY");

  await dialog.getByRole("button", { name: "Show private key" }).click();
  await expect(dialog.locator('pre[aria-label="Private key"]')).toContainText(
    "BEGIN OPENSSH PRIVATE KEY",
  );

  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(page.locator("body")).not.toContainText("BEGIN OPENSSH PRIVATE KEY");

  // Nothing about the key may outlive the dialog in the browser.
  expect(
    await page.evaluate(() => ({
      local: window.localStorage.length,
      session: window.sessionStorage.length,
    })),
  ).toEqual({ local: 0, session: 0 });
  expect(await page.evaluate(() => document.cookie)).toBe("");
});

// The binary under test is started with HOME and PATH only, so it is handed no
// SSH_AUTH_SOCK and can reach no agent. That is what makes this spec safe to
// automate: it exercises the registration interface against the real server
// without going anywhere near the developer's own agent or Keychain. Design
// §6.3 owns the other half — a real registration is manual test M4.
test("offers agent registration and refuses it honestly when no agent is reachable", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
  await openSection(page, "Keys");

  await page.getByLabel("File name").fill("id_agent");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const row = page.getByRole("row", { name: /id_agent\b/ }).first();
  await expect(row).toBeVisible();

  // The control exists and is reachable from the inventory — the gap this
  // closes was an implemented endpoint with no way to reach it — but it is
  // disabled, and the screen says what is missing rather than failing later.
  const register = row.getByRole("button", { name: "Add to agent" });
  await expect(register).toBeVisible();
  await expect(register).toBeDisabled();
  await expect(page.getByText(/No agent is reachable from this process/)).toBeVisible();
});

// Renaming a key is only useful if the configuration follows it. This spec
// generates a key, points a real Host at it, renames it through the UI and then
// reads the file back: the assertion that matters is the byte on disk, not the
// confirmation on screen.
test("renames a key and carries every directive that named it", async ({ page, installation }) => {
  // The Host is written before the page loads, because the bootstrap fragment
  // is spent on the first navigation and a reload would leave no session.
  await installation.write(
    "conf.d/20-rename.conf",
    "Host renamed\n\tIdentityFile ~/.ssh/id_rename\n\tCertificateFile %d/.ssh/id_rename.pub\n",
  );
  await page.goto(installation.url);
  await openSection(page, "Keys");

  await page.getByLabel("File name").fill("id_rename");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const row = page.getByRole("row", { name: /id_rename\b/ }).first();
  await row.getByRole("button", { name: "Rename" }).click();
  await page.getByLabel("New name").fill("id_renamed");
  expect(await clickAndAwait(page, "Rename key", "/api/v1/keys/")).toBe(200);

  // Both halves moved…
  expect(await installation.read("id_renamed.pub")).toContain("ssh-ed25519 ");
  // …and both directives followed, each keeping the spelling it was written in.
  expect(await installation.read("conf.d/20-rename.conf")).toBe(
    "Host renamed\n\tIdentityFile ~/.ssh/id_renamed\n\tCertificateFile %d/.ssh/id_renamed.pub\n",
  );
  await expect(page.getByText("IdentityFile ~/.ssh/id_rename → ~/.ssh/id_renamed")).toBeVisible();
});

test("refuses a rename whose destination is taken, and writes nothing", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
  await openSection(page, "Keys");

  await page.getByLabel("File name").fill("id_first");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  await page.getByLabel("File name").fill("id_second");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const before = await installation.read("id_first");
  const row = page.getByRole("row", { name: /id_first\b/ }).first();
  await row.getByRole("button", { name: "Rename" }).click();
  await page.getByLabel("New name").fill("id_second");
  expect(await clickAndAwait(page, "Rename key", "/api/v1/keys/")).toBe(409);

  await expect(page.getByRole("alert")).toContainText("already exists");
  // The decisive assertion: a refused rename is not a partial one. Both keys are
  // exactly where they were, with the bytes they had.
  expect(await installation.read("id_first")).toBe(before);
  expect(await installation.read("id_second.pub")).toContain("ssh-ed25519 ");
});
