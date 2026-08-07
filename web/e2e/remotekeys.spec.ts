import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

// A syntactically valid, entirely synthetic public key. Nothing in this spec
// sends it anywhere: only the plan endpoint is exercised, and design §6.6 makes
// that endpoint describe the change without contacting the remote host.
const publicKey =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture@sshc";

// "Register the key" is never clicked here. It opens an SSH connection, which
// no automated test in this repository may do; that half is manual test M2.
test("shows the alias, effective user, fingerprint and the exact line before registering", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Remote Keys");
  await expect(page.getByRole("heading", { name: "Remote Keys" })).toBeVisible();

  // Nothing has been sent yet, and the panel says so.
  await expect(page.getByText("Nothing is sent to the remote host until you confirm it.")).toBeVisible();

  await page.getByLabel("Host alias").fill("bastion");
  await page.getByLabel("Public key file").fill("id_ed25519.pub");
  await page.getByLabel("Public key line").fill(publicKey);

  expect(await clickAndAwait(page, "Show what this would do", "/api/v1/remote-keys/plan")).toBe(200);

  const plan = page.getByRole("region", { name: "Confirm remote registration" });
  await expect(plan).toBeVisible();
  // Design §6.6 requires the confirmation to name the alias, the effective
  // user, the fingerprint and the change it would make.
  await expect(plan).toContainText("bastion");
  await expect(plan).toContainText("ops");
  await expect(plan).toContainText("203.0.113.10:2222");
  await expect(plan).toContainText("SHA256:");

  // The exact line to append is shown, and it is the key that was supplied.
  await expect(plan.locator('pre[aria-label="Public key line to append"]')).toContainText(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl",
  );
  // And so is the fixed routine the remote host would run.
  await expect(plan.locator('pre[aria-label="Remote command"]')).toContainText(
    "authorized_keys",
  );

  // Describing a registration changes nothing on this machine.
  expect(await installation.read("config")).toContain("Host bastion");
});

test("refuses a public key that is not one valid line", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Remote Keys");

  await page.getByLabel("Host alias").fill("bastion");
  await page.getByLabel("Public key file").fill("id_ed25519.pub");
  await page.getByLabel("Public key line").fill("echo pwned");

  expect(await clickAndAwait(page, "Show what this would do", "/api/v1/remote-keys/plan")).toBe(400);
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Confirm remote registration" }),
  ).toHaveCount(0);
});
