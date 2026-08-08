import { clickAndAwait, expect, openSection, test, openApplication } from "./support/environment";
import type { Page } from "@playwright/test";

async function openBastion(page: Page, url: string) {
  await openApplication(page, { url });
  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "bastion" })
    .click();
  await expect(page.getByRole("tablist", { name: "Host editor" })).toBeVisible();
}

test("edits a host through the form and writes only the line that changed", async ({
  page,
  installation,
}) => {
  const before = await installation.read("config");
  await openBastion(page, installation.url);

  await page.getByLabel("Port", { exact: true }).fill("2244");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("config");
  expect(after).toContain("Port 2244");
  expect(after).not.toContain("Port 2222");
  // 変更の周囲のバイト列は正確に生き残らなければならない。
  // コメント、"HostName=" の綴り、User の後ろの連続した
  // 空白はすべて、整形するエディタなら黙って正規化してしまうものだ。
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.");
  expect(after).toContain("HostName=203.0.113.10");
  expect(after).toContain("User    ops");
  expect(after).toContain("Include conf.d/*.conf");
  expect(after.split("\n").length).toBe(before.split("\n").length);
});

test("edits the same host through Raw and keeps every other byte", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);
  await page.getByRole("tab", { name: "Raw" }).click();

  const editor = page.getByLabel(/Block text/);
  const original = await editor.inputValue();
  await editor.fill(original.replace("Port 2222", "Port 2255\n\tCompression yes"));
  expect(await clickAndAwait(page, "Save block", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("config");
  expect(after).toContain("Port 2255");
  expect(after).toContain("Compression yes");
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.");
  expect(after).toContain("ServerAliveInterval 30");
});

test("shows a save preview diff of exactly what was written", async ({ page, installation }) => {
  await openBastion(page, installation.url);
  await page.getByLabel("Port", { exact: true }).fill("2299");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(200);

  const preview = page.getByRole("region", { name: "Save preview" });
  await expect(preview).toContainText("2299");
  await expect(preview).not.toContainText("Changed on disk since you loaded it");
  expect(await installation.read("config")).toContain("Port 2299");
});

test("refuses a save whose base is stale and shows the three-way conflict", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);

  // ページがファイルを読み込んだ後で、誰かがアプリケーションの外でそのファイルを編集する。
  const external = (await installation.read("config")).replace(
    "Host *",
    "Host edited-outside\n\tHostName 192.0.2.99\n\nHost *",
  );
  await installation.write("config", external);

  await page.getByLabel("Port", { exact: true }).fill("2277");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(409);

  await expect(page.getByText("Changed on disk since you loaded it")).toBeVisible();
  await expect(page.getByText("Your pending change")).toBeVisible();

  // 決め手となる検証はこうだ。外部での編集はそのまま生き残り、
  // 保留中の変更がそれを上書きしなかったこと。
  const after = await installation.read("config");
  expect(after).toBe(external);
  expect(after).not.toContain("Port 2277");
});

// Diagnostics タブはかつて、検査は後のサブシステムで届くと
// 言っていたが、実際にはとうに届いていた。今では開いている
// 接続を宛先として、本物の検査を実行する。
//
// ここで検証するのはコマンドビルダーだけだ。argv を組み立てるだけ
// で何も起動しない。到達性テストと認証テストは実際にホストへ接続
// するため、このリポジトリのどの自動テストもそれを行ってはなら
// ない——それらは手動テスト M2 と M3 である。ボタンが存在し、それ自体
// では何も起動しないことこそ、この試験が正直に主張できる性質だ。
test("diagnoses the open connection from its own tab, and starts nothing unasked", async ({
  page,
  installation,
}) => {
  const started: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST") started.push(new URL(request.url()).pathname);
  });

  await openBastion(page, installation.url);
  await page.getByRole("tab", { name: "Diagnostics" }).click();

  const panel = page.getByRole("region", { name: "Diagnostics for bastion" });
  await expect(panel).toBeVisible();
  // 接続は既知であるため、タブは alias を尋ねない。
  await expect(panel.getByLabel("Host alias")).toHaveCount(0);
  expect(started.filter((path) => path.startsWith("/api/v1/diagnostics/"))).toEqual([]);
  expect(started.filter((path) => path.startsWith("/api/v1/terminal/"))).toEqual([]);

  expect(await clickAndAwait(page, "Terminal command", "/api/v1/terminal/command")).toBe(200);
  // このバイナリと alias。かつては 5 つの環境変数と 1 つの
  // フラグだったが、それは Terminal ボタンが自分で組み立てる
  // ものであり、有効な使い捨てトークンをシェルの履歴に残していた。
  await expect(panel.getByText(/sshc bastion$/)).toBeVisible();
  await expect(panel.getByText(/SSHC_ASKPASS_TOKEN/)).toHaveCount(0);

  // それでも何も起動しない。コマンドの組み立てと実行は
  // 別の操作であり、確認が必要なのは後者だけだ。
  expect(started).not.toContain("/api/v1/terminal/launch");
});

test("sends the Effective tab to the authoritative check instead of describing it", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);
  await page.getByRole("tab", { name: "Effective" }).click();

  await expect(page.getByText(/only it evaluates `Match`/)).toBeVisible();
  await page.getByRole("button", { name: "Open the Diagnostics tab" }).click();

  await expect(page.getByRole("region", { name: "Diagnostics for bastion" })).toBeVisible();
});

// スキーマが常に持っていながらどの画面からも編集できな
// かったメタデータ。色、表示順、そして Host ブロックが消えたノートだ。
test("edits the display order it stores, and shows a favourite in the tree", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);

  // 色、タグ、favorite フラグ、表示順は metadata.json にしか
  // 存在しない設定なので、ファイルに書き出されるディレクティブの
  // 隣ではなくインスペクタに置かれる。ペインは求められる
  // まで閉じている。
  await page.getByRole("button", { name: "Show details" }).click();

  // ファイルをポーリングするのではなく書き込みを待つ。
  // メタデータのドキュメントは最初の保存が作るまで存在しない。
  const [ordered] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.url().includes("/api/v1/config/save") && response.request().method() === "POST",
    ),
    page.getByLabel(/Display order/).fill("-1"),
  ]);
  expect(ordered.status()).toBe(200);
  expect(JSON.parse(await installation.read("sshc/metadata.json")).hosts[0].order).toBe(-1);

  // favorite マーカーはかつてスクリーンリーダー用の説明にしか存在せず、
  // 目の見えるユーザーは設定してもそれを見つけられなかった。check()
  // ではなくクリックで検証する。保存が完了するとパネルはサーバーから
  // 再読み込みされ、ツリーに星が現れることこそが本当に重要な検証だ。
  await page.getByLabel("Favourite").click();
  const row = page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: /bastion/ });
  await expect(row.getByText("\u2605")).toBeVisible();
});

test("re-associates a note whose connection is gone, without guessing", async ({
  page,
  installation,
}) => {
  await installation.write(
    "sshc/metadata.json",
    JSON.stringify({
      schemaVersion: 1,
      groups: [{ name: "work" }],
      hosts: [
        { identity: { path: "config", alias: "retired" }, tags: ["ci"], note: "the old builder" },
      ],
    }),
  );
  await openApplication(page, installation);
  await openSection(page, "Connections");

  const panel = page.getByRole("region", { name: "Settings whose connection is gone" });
  await expect(panel).toBeVisible();
  await expect(panel.getByText("retired in config")).toBeVisible();
  // ノートは設定ファイルのコメントに置き換えられて廃止され、
  // 所属はもうディレクトリで表されるため、パネルはエントリを
  // それがまだ持っているもの——設定ファイルに居場所のない見た目——で説明する。
  await expect(panel.getByText(/tags ci/)).toBeVisible();

  await panel.getByLabel("Re-associate retired with").selectOption("config\u0000bastion");
  expect(await clickAndAwait(page, "Re-associate retired", "/api/v1/config/save")).toBe(200);

  // ノートはユーザーが名指ししたホストへ移り、サーバーの
  // orphan フラグはそれが説明する文書には書き戻されない。
  const saved = JSON.parse(await installation.read("sshc/metadata.json"));
  expect(saved.hosts).toHaveLength(1);
  expect(saved.hosts[0]).toMatchObject({
    identity: { path: "config", alias: "bastion" },
    note: "the old builder",
  });
  expect(saved.hosts[0].orphan).toBeUndefined();
});

test("writes a comment into the configuration file above the Host line", async ({
  page,
  installation,
}) => {
  const before = await installation.read("config");
  await openBastion(page, installation.url);

  await page.getByLabel("Comment").fill("the production bastion\nask infra before changing it");
  expect(await clickAndAwait(page, "Save comment", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("config");
  expect(after).toContain("# the production bastion\n# ask infra before changing it\nHost bastion\n");

  // ファイル自身のバナーは空行の上にあるため、最初の
  // ブロックではなくファイルに属する。ブロックの編集はそれに触れてはならない。
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.\n\nInclude conf.d/*.conf");
  // そしてコメントが加えなかったすべてのバイトは変わらない。
  expect(after.replace("# the production bastion\n# ask infra before changing it\n", "")).toBe(before);
});

test("removes the comment lines when the comment is cleared", async ({ page, installation }) => {
  const before = await installation.read("config");
  await openBastion(page, installation.url);

  await page.getByLabel("Comment").fill("temporary");
  expect(await clickAndAwait(page, "Save comment", "/api/v1/config/save")).toBe(200);
  await expect(page.getByLabel("Comment")).toHaveValue("temporary");

  await page.getByLabel("Comment").fill("");
  expect(await clickAndAwait(page, "Save comment", "/api/v1/config/save")).toBe(200);

  // 元のバイト列に戻る。コメントの追加と削除は往復である。
  expect(await installation.read("config")).toBe(before);
});

// 意味を持つコメントは誤って別のものに帰属しうる。この
// 2 つがブロックがファイルを去る方法であり、どちらも
// 放っておけば、たまたま後に続いた接続にその説明を渡してしまう。
test("takes a comment with the connection it describes when the block moves", async ({
  page,
  installation,
}) => {
  await installation.write(
    "conf.d/10-home.conf",
    "# the file server\nHost nas\n\tHostName 198.51.100.20\n\n# the printer\nHost printer\n\tHostName 198.51.100.30\n",
  );
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "nas" }).click();
  await expect(page.getByLabel("Comment")).toHaveValue("the file server");

  await page.getByRole("button", { name: "Manage connection" }).click();
  await page.getByLabel("Move to file").selectOption("config");
  expect(await clickAndAwait(page, "Move connection", "/api/v1/config/save")).toBe(200);

  // コメントはブロックと一緒に届いた……
  expect(await installation.read("config")).toContain("# the file server\nHost nas\n");
  // ……そして printer は nas のものを継承せず、自分自身のものを保った。
  const source = await installation.read("conf.d/10-home.conf");
  expect(source).not.toContain("the file server");
  expect(source).toContain("# the printer\nHost printer\n");
});

test("takes a comment with the connection when the block is deleted", async ({
  page,
  installation,
}) => {
  await installation.write(
    "conf.d/10-home.conf",
    "# the file server\nHost nas\n\tHostName 198.51.100.20\n\n# the printer\nHost printer\n\tHostName 198.51.100.30\n",
  );
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "nas" }).click();

  await page.getByRole("button", { name: "Manage connection" }).click();
  await page.getByRole("button", { name: "Delete connection" }).click();
  expect(await clickAndAwait(page, "Confirm delete", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("conf.d/10-home.conf");
  // 置き去りにされていたら、"# the file server" は printer の
  // 説明になってしまっていた——誰も触れていない接続についての静かな嘘だ。
  expect(after).not.toContain("the file server");
  expect(after).toContain("# the printer\nHost printer\n");
});

test("moves a connection into a group by dragging it", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Groups");
  await page.getByLabel("New group name").fill("work");
  await page.getByRole("button", { name: "Add group" }).click();
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  const tree = page.getByRole("navigation", { name: "Connections" });
  // 見出しはグループに何も入っていない段階から画面にある。
  // それこそがドロップ先になりうる理由であり、何かを持つまで
  // 隠れているグループには、ドラッグで中身を入れることが決してできない。
  await expect(tree.getByRole("heading", { name: "work" })).toBeVisible();

  await tree.getByRole("button", { name: "bastion" }).dragTo(tree.getByRole("heading", { name: "work" }));

  // ファイルを読み返して、グループの Include 名を確かめる。
  // ブロックが connections/work/config.conf にあることこそ、
  // 移動が単にファイルが書かれた場所ではなく、OpenSSH が読む場所へ届いた証拠だ。
  await expect(async () => {
    expect(await installation.read("connections/work/config.conf")).toContain("Host bastion");
  }).toPass();
  expect(await installation.read("config")).not.toContain("Host bastion\n");
});

// インスペクタを開くと 3 列目が追加される。中央の列がその
// ぶんの幅を譲らねばならないが、素の `1fr` ではそれができ
// ない。CSS grid では minmax(auto, 1fr) を使うことで、
// トラックが内容の幅を保ち、詳細はペインの下に潜り込む。
// 詳細欄の上部にあるボタンが真っ先にその下へ消えていた。
test("opening the inspector narrows the detail rather than hiding it under the pane", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);
  await page.getByRole("button", { name: "Show details" }).click();
  await page.getByRole("button", { name: "Manage connection" }).click();

  const pane = page.getByRole("complementary", { name: "Details" });
  await expect(pane).toBeVisible();

  const paneLeft = (await pane.boundingBox())?.x ?? 0;
  expect(paneLeft).toBeGreaterThan(0);

  // 詳細が提供するすべてのコントロールは、ペインの端より左側にとどまる。
  for (const name of ["Duplicate connection", "Move connection", "Delete connection", "Save changes"]) {
    const box = await page.getByRole("button", { name, exact: true }).boundingBox();
    expect(box, `${name} has no box`).not.toBeNull();
    expect(box!.x + box!.width, `${name} runs under the inspector`).toBeLessThanOrEqual(paneLeft);
  }
});
