import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

// 構文的には正しいが、まったくの合成物である公開鍵。この試験ではそれをどこ
// にも送らない。検証するのは plan エンドポイントだけであり、設計書§6.6 はそのエ
// ンドポイントがリモートホストに接続せずに変更内容を説明することを求める。
const publicKey =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture@sshc";

// "Register the key" はここでは決してクリックしない。それは SSH 接続を開くが、この
// リポジトリのどの自動テストもそれを行ってはならず、その半分は手動テスト M2 である。
test("shows the alias, effective user, fingerprint and the exact line before registering", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Remote Keys");
  await expect(page.getByRole("heading", { name: "Remote Keys" })).toBeVisible();

  // まだ何も送信されておらず、パネルはそう告げる。
  await expect(page.getByText("Nothing is sent to the remote host until you confirm it.")).toBeVisible();

  await page.getByLabel("Host alias").fill("bastion");
  await page.getByLabel("Public key file").fill("id_ed25519.pub");
  await page.getByLabel("Public key line").fill(publicKey);

  expect(await clickAndAwait(page, "Show what this would do", "/api/v1/remote-keys/plan")).toBe(200);

  const plan = page.getByRole("region", { name: "Confirm remote registration" });
  await expect(plan).toBeVisible();
  // 設計書§6.6 は、確認に alias、実効ユーザー、fingerprint、
  // 加えられる変更を明示することを求める。
  await expect(plan).toContainText("bastion");
  await expect(plan).toContainText("ops");
  await expect(plan).toContainText("203.0.113.10:2222");
  await expect(plan).toContainText("SHA256:");

  // 追記される正確な行が表示され、それは指定された鍵そのものだ。
  await expect(plan.locator('pre[aria-label="Public key line to append"]')).toContainText(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl",
  );
  // リモートホストが実行する固定のルーチンも同様に表示される。
  await expect(plan.locator('pre[aria-label="Remote command"]')).toContainText(
    "authorized_keys",
  );

  // 登録内容を説明するだけでは、このマシン上の何も変わらない。
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
