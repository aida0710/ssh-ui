import { expect, openApplication, openSection, test } from "./support/environment";

// この end-to-end スイートは使い捨ての HOME に対してビルド済みバイナリ
// を動かすため、実ディスク上の本物の vault ファイルを検証する。terminal
// も ssh も決して起動しない。askpass ヘルパー自体の振る舞いは
// cmd/sshc のテストが、償還規則は internal/secret のテストがカバーする。
test("stores a password for a host and never shows it again", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByRole("tab", { name: "Diagnostics" }).click();

  const panel = page.getByRole("region", { name: "Stored password" });
  await expect(panel).toBeVisible();
  // 警告はフィールドの上にあり、開示の裏には隠れていない。
  await expect(panel.getByText(/A key is stronger/)).toBeVisible();

  await panel.getByLabel("Password for bastion").fill("hunter2");
  await panel.getByRole("button", { name: "Store a new password for bastion" }).click();

  await expect(panel.getByText("A password is stored for bastion.")).toBeVisible();
  await expect(page.locator("body")).not.toContainText("hunter2");

  // そしてディスク上のファイルは暗号文であり、パスワードも alias も含まない。
  const sealed = await installation.read("sshc/secrets");
  expect(sealed).not.toContain("hunter2");
  expect(sealed).not.toContain("bastion");
});

// vault をロックするとアプリケーション全体がロックされる。かつては 1 つのパネルだ
// けがロックされ、ユーザーは次の要求が拒否されるシェルの中に取り残されていた。
test("locking the vault returns the application to its front door", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Secrets");

  await page.getByRole("button", { name: "Lock sshc" }).click();

  await expect(page.getByLabel("Master password", { exact: true })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
});
