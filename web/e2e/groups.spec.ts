import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

// グループはディレクトリであり、この試験はそこから従う 2 つの事実についてのものだ。エ
// ントリファイルはグループごとに明示された順序で 1 行の Include を得ること、そして接続
// をグループ間で移動するとそのファイルも移動すること——両方の検証はディスク上のバイ
// ト列を読む。「移動した」という画面の表示は ~/.ssh について何も証明しないからだ。
test("declares a group in the entry file and moves a connection into it", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Groups");

  await page.getByLabel("New group name").fill("work");
  await page.getByRole("button", { name: "Add group" }).click();
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  // 宣言は 2 つのマーカーコメントに挟まれた普通の Include 行
  // であり、このアプリケーションを知らない読者にも何であるか分かる。
  const entry = await installation.read("config");
  expect(entry).toContain("# >>> sshc groups (generated).");
  expect(entry).toContain("Include connections/work/*.conf\n");
  expect(entry).toContain("Include groups.sshc.conf\n");
  expect(entry).toContain("# <<< sshc groups");
  // この領域はすべての Host 行より上にある。Host 行の下に書かれた
  // Include はそのブロックに属してしまい、OpenSSH はブロックが一致する
  // ときにしか include したファイルのオプションを適用しない。下のほうに
  // 書くと、グループを 1 つのホストにしか宣言できなくなる。
  expect(entry.indexOf("# >>> sshc groups")).toBeLessThan(entry.indexOf("Host "));

  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "nas" })
    .click();
  await expect(page.getByRole("tablist", { name: "Host editor" })).toBeVisible();

  await page.getByLabel("Primary group").selectOption("work");
  expect(await clickAndAwait(page, "Move to this group", "/api/v1/config/save")).toBe(200);

  // ファイルは移動しても自分の名前を保ち、ブロックはバイト単位でそのまま届いた。
  expect(await installation.read("connections/work/10-home.conf")).toContain("Host nas");
  expect(await installation.read("conf.d/10-home.conf")).toBe("");
});

// connections/work/*.conf は connections/work/eu/lon.conf
// に届かない。'*' は glob(3) でも filepath.Glob でも
// セパレータを越えないからだ。これこそがこの領域がグループ
// ごとに 1 行を出す理由のすべてであり、前提とせずここで検証する。
test("gives a nested group its own Include line, deepest first", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Groups");

  for (const name of ["work", "work/eu"]) {
    await page.getByLabel("New group name").fill(name);
    await page.getByRole("button", { name: "Add group" }).click();
  }
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  const entry = await installation.read("config");
  const child = entry.indexOf("Include connections/work/eu/*.conf");
  const parent = entry.indexOf("Include connections/work/*.conf");
  expect(child).toBeGreaterThan(-1);
  expect(parent).toBeGreaterThan(-1);
  // OpenSSH は最初に読んだ値を保持するため、より深い
  // グループを先に読まなければ、親の設定が子自身の設定に勝ってしまう。
  expect(child).toBeLessThan(parent);
});

test("renames a group and carries its files, its Include line and its keys", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Groups");

  await page.getByLabel("New group name").fill("work");
  await page.getByRole("button", { name: "Add group" }).click();
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "nas" })
    .click();
  await page.getByLabel("Primary group").selectOption("work");
  expect(await clickAndAwait(page, "Move to this group", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Groups");
  // リネームはファイルを書き換えるため、一度にすべての
  // グループに対してではなく、選択したグループに対してのみ提供される。
  await page.getByRole("heading", { name: "work", exact: true }).click();
  await page.getByLabel("Rename work to").fill("client-a");
  expect(await clickAndAwait(page, "Rename work", "/api/v1/config/groups/rename")).toBe(200);

  // ファイル、宣言、空になった元のディレクトリ——この 3 つ
  // すべてが、グループがディレクトリであるときのリネームの意味だ。
  expect(await installation.read("connections/client-a/10-home.conf")).toContain("Host nas");
  const entry = await installation.read("config");
  expect(entry).toContain("Include connections/client-a/*.conf\n");
  expect(entry).not.toContain("Include connections/work/*.conf\n");
});

test("refuses to move a connection into a group nothing declares", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "nas" })
    .click();
  await expect(page.getByRole("tablist", { name: "Host editor" })).toBeVisible();

  // グループが 1 つも宣言されていないため、移動先リストは
  // 空でコントロールは無効化される。失敗すると分かっている移動を、画面は提供しない。
  await expect(page.getByRole("button", { name: "Move to this group" })).toBeDisabled();
  expect(await installation.read("conf.d/10-home.conf")).toContain("Host nas");
});

test("shows a nested group inside its parent, and hides a container from the tree", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Groups");
  for (const name of ["work", "work/eu"]) {
    await page.getByLabel("New group name").fill(name);
    await page.getByRole("button", { name: "Add group" }).click();
  }
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  const tree = page.getByRole("navigation", { name: "Connections" });
  // 子は親のブロックの横ではなく内側に描画され、その
  // 見出しは自分自身のセグメントだけを持つ。
  await expect(tree.getByRole("region", { name: "work" }).getByRole("heading", { name: "eu" })).toBeVisible();

  // "work" は自分自身のものを何も持たないため、隠す操作が提供される。
  //
  // 非表示は metadata.json にしか存在しない 3 つの設定の
  // 1 つであり——色や表示順とともに——インスペクタに置かれる。
  // グループを選択するとペインが埋まる。ペインは求められるまで閉じている。
  await openSection(page, "Groups");
  await page.getByRole("listitem").filter({ hasText: "work" }).first().click();
  await page.getByRole("button", { name: /Show details/ }).click();
  //
  // `check()` ではなくクリックしてから検証する。ペインの
  // 内容はパネルが組み立ててシェルへ渡すため、新しい状態は
  // クリックから 1 描画分遅れて届く——`check()` は同期的に
  // 検証するため、それを「変化しないチェックボックス」だと判定してしまう。
  const hide = page.getByLabel("Hide work from Connections");
  await hide.click();
  await expect(hide).toBeChecked();
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  await expect(tree.getByRole("region", { name: "work" })).toHaveCount(0);
  // 子は親の見出しが消えても生き残る。
  await expect(tree.getByRole("region", { name: "work/eu" })).toBeVisible();
});
