import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

test("shows the Include hierarchy and edits an included file", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Config");

  await expect(page.getByRole("heading", { name: "Include hierarchy" })).toBeVisible();
  await expect(page.getByRole("button", { name: "config", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "conf.d/10-home.conf" })).toBeVisible();

  await page.getByRole("button", { name: "conf.d/10-home.conf" }).click();
  const editor = page.getByLabel(/File text/);
  await expect(editor).toHaveValue(/UnknownFutureDirective some "quoted value" 3/);

  await editor.fill((await editor.inputValue()) + "Host printer\n\tHostName 198.51.100.30\n");
  expect(await clickAndAwait(page, "Save file", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("conf.d/10-home.conf");
  // 未知のディレクティブこそが要点だ。エンジンはそれに
  // 対するスキーマを持たず、引用符や空白も含めて正確に書き戻さなければならない。
  expect(after).toContain('UnknownFutureDirective some "quoted value" 3');
  expect(after).toContain("Host printer");
  expect(after).toContain("Host nas");
});

test("renames an included file and carries the Include that named it", async ({
  page,
  installation,
}) => {
  // エントリファイルは glob を通じて conf.d/10-home.conf に到達するため、
  // conf.d 内でのリネームは書き換えを必要としない。まずリテラルな Include
  // を追加することが、この試験を本当に重要な事柄についてのものにする。
  await installation.write(
    "config",
    (await installation.read("config")).replace(
      "Include conf.d/*.conf",
      "Include conf.d/*.conf\nInclude work/lon.conf",
    ),
  );
  await installation.write("work/lon.conf", "Host lon\n\tHostName 198.51.100.7\n");

  await openApplication(page, installation);
  await openSection(page, "Config");
  await page.getByRole("button", { name: "work/lon.conf" }).click();

  await page.getByLabel("New path").fill("work/london.conf");
  expect(await clickAndAwait(page, "Rename file", "/api/v1/config/save")).toBe(200);

  expect(await installation.read("work/london.conf")).toBe("Host lon\n\tHostName 198.51.100.7\n");
  const entry = await installation.read("config");
  expect(entry).toContain("Include work/london.conf");
  expect(entry).not.toContain("Include work/lon.conf");
  // 再整形するなと告げるファイルの、それ以外のすべてのバイト。
  expect(entry).toContain("# Managed by hand since 2019. Do not reformat.");
  expect(entry).toContain("Include conf.d/*.conf");
  expect(entry).toContain("HostName=203.0.113.10");
});

test("deletes a file after a confirmation and offers it back in History", async ({
  page,
  installation,
}) => {
  await installation.write(
    "config",
    (await installation.read("config")).replace(
      "Include conf.d/*.conf",
      "Include conf.d/*.conf\nInclude work/lon.conf",
    ),
  );
  await installation.write("work/lon.conf", "Host lon\n\tHostName 198.51.100.7\n");

  await openApplication(page, installation);
  await openSection(page, "Config");
  await page.getByRole("button", { name: "work/lon.conf" }).click();

  // 1 回押すと構え、2 回目で実行する。1 クリックの裏に
  // あるファイル操作は、誤クリック 1 つで誰も望まない削除に至ってしまう。
  await page.getByRole("button", { name: "Delete file" }).click();
  expect(await clickAndAwait(page, "Delete it", "/api/v1/config/save")).toBe(200);

  await expect
    .poll(async () => {
      try {
        await installation.read("work/lon.conf");
        return "still there";
      } catch {
        return "gone";
      }
    })
    .toBe("gone");
  expect(await installation.read("config")).not.toContain("work/lon.conf");

  // バイトは失われない。History はそのファイルを復元可能として一覧する。
  await openSection(page, "History");
  await expect(page.getByText("work/lon.conf").first()).toBeVisible();
});

// ディレクトリはファイルの置き場所であるため、explorer はディレクトリも作成・削除する。
// 空のディレクトリはどの Include グラフにも属さないため、ツリーには表示され
// ない——それが存在した証拠は、削除が 1 回目は成功し 2 回目は拒否されることだ。
//
// すべてのステップは自分自身の応答を待つ。「まだ
// アラートがない」は応答が届く前でも成功の後でも真であり、
// それを検証することは次のクリックと競合し、ここでは通っても CI では失敗していた。
test("makes a directory and removes it", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Config");

  const path = page.getByLabel("New file path");
  await path.fill("conf.d/eu");
  expect(await clickAndAwait(page, "Create directory", "/api/v1/config/save")).toBe(200);

  await path.fill("conf.d/eu");
  expect(await clickAndAwait(page, "Delete directory", "/api/v1/config/save")).toBe(200);

  // 消えている。2 回目の削除には削除するものが何もない。
  await path.fill("conf.d/eu");
  expect(await clickAndAwait(page, "Delete directory", "/api/v1/config/save")).toBe(404);
  await expect(page.getByRole("alert")).toBeVisible();
});
