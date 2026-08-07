import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

// この試験は意図的に "Scan" の手前で止める。ssh-keyscan は与えられた
// どんなホストにも接続を開いてしまうため、このリポジトリのどの自動
// テストも接続してはならない。scan-and-add の流れと、その手前にある
// fingerprint または確認のゲートは、スタブ化された API に対するパネルの
// Vitest スイートと手動テスト M1 でカバーされる。
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

  // 削除はまず尋ね、何を取り除くかを告げる。
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

  // 何にもマッチしない検索は、ファイルを変更していないはずだ。
  expect(await installation.read("known_hosts")).toContain("203.0.113.10");
});
