import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";

test("lists generated keys and reveals one only after an explicit confirmation", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Keys");
  await expect(
    page.getByRole("table", { name: "Files classified by content and permissions" }),
  ).toBeVisible();

  await page.getByLabel("File name").fill("id_e2e");
  // "Passphrase" は "create without a passphrase" チェック
  // ボックスにもマッチするため、テキストボックスは role で指定する。
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const row = page.getByRole("row", { name: /id_e2e\b/ }).first();
  await expect(row).toBeVisible();
  await expect(row).toContainText("0600");
  expect(await installation.read("id_e2e.pub")).toContain("ssh-ed25519 ");

  // インベントリ画面は、誰かが求める前には鍵の実体を何も表示しない。
  //
  // これはこの性質のページレベル側の半分である。*レスポンス*
  // が持つべきでない鍵の実体を運んでいないかは、Go の
  // TestNoResponseCarriesASecretItIsNotEntitledTo で検証される。
  // 描画されずに API 経由で漏れるフィールドはここからは見えず、
  // そうでないふりをすればこの試験は偽の安心にすぎなくなる。
  await expect(page.locator("body")).not.toContainText("BEGIN OPENSSH PRIVATE KEY");

  // ダイアログは鍵を持たずに開く。設計書§6.3 が reveal を他の API から分離
  // しているのは、まさにこのダイアログを開くこと自体が開示にならないためだ。
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

  // 鍵に関するいかなるものも、ブラウザ内でダイアログより長生きしてはならない。
  expect(
    await page.evaluate(() => ({
      local: window.localStorage.length,
      session: window.sessionStorage.length,
    })),
  ).toEqual({ local: 0, session: 0 });
  expect(await page.evaluate(() => document.cookie)).toBe("");
});

test("stores an encrypted key passphrase from the key row and shows only its name afterwards", async ({
  page,
  installation,
}) => {
  const passphrase = "e2e key phrase that must leave the DOM";
  await openApplication(page, installation);
  await openSection(page, "Keys");
  await page.getByLabel("File name").fill("id_saved_phrase");
  await page.getByRole("textbox", { name: "Passphrase" }).fill(passphrase);
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const row = page.getByRole("row", { name: /id_saved_phrase\b/ }).first();
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Save passphrase" }).click();
  await page.getByLabel("Passphrase name").fill("saved-e2e-key");
  await page.getByLabel("Passphrase value").fill(passphrase);
  const assigned = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api/v1/credentials/key_passphrase/assign" &&
      response.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "Save and use for this key" }).click();
  expect((await assigned).status()).toBe(200);

  await expect(page.getByLabel("Passphrase value")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(passphrase);
  await openSection(page, "Secrets");
  const passphrases = page.getByRole("region", { name: "Key passphrases" });
  await expect(passphrases).toContainText("saved-e2e-key");
  await expect(passphrases).toContainText("id_saved_phrase");
  await expect(page.locator("body")).not.toContainText(passphrase);
});

// 試験対象のバイナリは HOME と PATH だけで起動されるため、SSH_AUTH_SOCK
// を渡されずどの agent にも到達できない。これがこの試験を自動化
// しても安全にしている理由だ。開発者自身の agent や Keychain には一
// 切近づかず、実サーバーに対して登録インターフェースを検証する。
// 設計書§6.3 が残りの半分を担う——実際の登録は手動テスト M4 である。
test("offers agent registration and refuses it honestly when no agent is reachable", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Keys");

  await page.getByLabel("File name").fill("id_agent");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const row = page.getByRole("row", { name: /id_agent\b/ }).first();
  await expect(row).toBeVisible();

  // コントロールは存在し、インベントリから到達できる——
  // これが埋めるのは、実装済みなのに到達手段のないエンド
  // ポイントという穴だ——ただし無効化されており、後で失敗するのではなく画面が不足を告げる。
  const register = row.getByRole("button", { name: "Add to agent" });
  await expect(register).toBeVisible();
  await expect(register).toBeDisabled();
  await expect(page.getByText(/No agent is reachable from this process/)).toBeVisible();
});

// 鍵のリネームは設定がそれに追従してこそ意味がある。この
// 試験は鍵を生成し、実際の Host をそれに向け、UI 経由で
// リネームしてからファイルを読み返す。重要な検証は画面上の
// 確認ではなく、ディスク上のバイトだ。
test("renames a key and carries every directive that named it", async ({ page, installation }) => {
  // Host はページが読み込まれる前に書き込まれる。bootstrap
  // フラグメントは最初のナビゲーションで消費され、リロードするとセッションが残らないからだ。
  await installation.write(
    "conf.d/20-rename.conf",
    "Host renamed\n\tIdentityFile ~/.ssh/id_rename\n\tCertificateFile %d/.ssh/id_rename.pub\n",
  );
  await openApplication(page, installation);
  await openSection(page, "Keys");

  await page.getByLabel("File name").fill("id_rename");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const row = page.getByRole("row", { name: /id_rename\b/ }).first();
  await row.getByRole("button", { name: "Rename or move" }).click();
  await page.getByLabel("Name", { exact: true }).fill("id_renamed");
  expect(await clickAndAwait(page, "Rename or move the key", "/api/v1/keys/")).toBe(200);

  // 両方の半分が移動した……
  expect(await installation.read("id_renamed.pub")).toContain("ssh-ed25519 ");
  // ……そして両方のディレクティブが追従し、それぞれ書かれたときの綴りを保った。
  expect(await installation.read("conf.d/20-rename.conf")).toBe(
    "Host renamed\n\tIdentityFile ~/.ssh/id_renamed\n\tCertificateFile %d/.ssh/id_renamed.pub\n",
  );
  await expect(page.getByText("IdentityFile ~/.ssh/id_rename → ~/.ssh/id_renamed")).toBeVisible();
});

test("refuses a rename whose destination is taken, and writes nothing", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await openSection(page, "Keys");

  await page.getByLabel("File name").fill("id_first");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  await page.getByLabel("File name").fill("id_second");
  await page.getByRole("textbox", { name: "Passphrase" }).fill("end-to-end-passphrase");
  expect(await clickAndAwait(page, "Create key", "/api/v1/keys")).toBe(201);

  const before = await installation.read("id_first");
  const row = page.getByRole("row", { name: /id_first\b/ }).first();
  await row.getByRole("button", { name: "Rename or move" }).click();
  await page.getByLabel("Name", { exact: true }).fill("id_second");
  expect(await clickAndAwait(page, "Rename or move the key", "/api/v1/keys/")).toBe(409);

  await expect(page.getByRole("alert")).toContainText("already exists");
  // 決め手となる検証はこうだ。拒否されたリネームは部分的な
  // ものではない。両方の鍵は元あった場所に、元あったバイトのまま残る。
  expect(await installation.read("id_first")).toBe(before);
  expect(await installation.read("id_second.pub")).toContain("ssh-ed25519 ");
});
