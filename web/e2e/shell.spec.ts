import { expect, openSection, test, openApplication } from "./support/environment";

// このスイートが動く 1280x720 のビューポートに Connections パネルが収まり
// きらないほど長い設定。これがなければ、以下の検証は何もスクロールしな
// いままヘッダーをスクロールで消してしまうシェルの上でも通ってしまう。
const manyHosts = Array.from(
  { length: 40 },
  (_unused, index) => `Host lab-${String(index).padStart(2, "0")}\n\tHostName 198.51.100.${index + 1}\n`,
).join("\n");

test("keeps the header and the primary navigation still while a panel scrolls", async ({
  page,
  installation,
}) => {
  await installation.write("conf.d/20-lab.conf", manyHosts);
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await expect(
    page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "lab-00" }),
  ).toBeVisible();

  const header = page.getByRole("banner");
  const tree = page.getByRole("navigation", { name: "Connections" });
  const resting = await header.boundingBox();
  expect(resting).not.toBeNull();

  // リストは今や自分自身のペインを持ち、パネル全体を道連れに
  // せず単独でスクロールする。そのスクローラーはツリーが置かれている要素である。
  //
  // 本当に overflow していなければならない。そうでなければ、これ以降のすべての
  // 検証はヘッダーを画面外へスクロールしてしまうシェルの上でも成立してしまう。
  const overflow = await tree.evaluate((element) => {
    const scroller = element.parentElement;
    if (scroller === null) return 0;
    return scroller.scrollHeight - scroller.clientHeight;
  });
  expect(overflow, "the fixture is not tall enough to scroll the list").toBeGreaterThan(0);

  // ドキュメント自体はスクロールしてはならない。これが退行そのものだ。ペー
  // ジレベルのスクロールがヘッダーとセクションボタンを持ち去っていたのであ
  // り、他に何も消費できなければパネル上のホイール操作がそれを生んでいた。
  const documentOverflow = await page.evaluate(() => {
    const root = document.scrollingElement ?? document.documentElement;
    return root.scrollHeight - root.clientHeight;
  });
  expect(documentOverflow, "the document scrolls, so the header can leave the viewport").toBe(0);

  const windowOffset = await page.evaluate(() => {
    window.scrollTo(0, 10_000);
    return window.scrollY;
  });
  expect(windowOffset).toBe(0);

  await tree.evaluate((element) => element.parentElement?.scrollTo(0, element.parentElement.scrollHeight));
  expect(await tree.evaluate((element) => element.parentElement?.scrollTop ?? 0)).toBeGreaterThan(0);

  expect(await header.boundingBox()).toEqual(resting);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeInViewport();
  await expect(page.getByRole("button", { name: "History", exact: true })).toBeInViewport();

  // スクロールされたパネルの下端には、それでも到達できなければならない。ビューポー
  // トに固定されながらパネルをスクロール可能にし忘れたシェルは、それを隠してしまう。
  await expect(
    page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "lab-39" }),
  ).toBeInViewport();
});

test("scrolls the primary navigation on its own when the viewport is short", async ({
  page,
  installation,
}) => {
  await page.setViewportSize({ width: 1280, height: 320 });
  await openApplication(page, installation);
  await openSection(page, "Connections");

  const navigation = page.getByRole("navigation", { name: "Primary" });
  const overflow = await navigation.evaluate((element) => element.scrollHeight - element.clientHeight);
  expect(overflow, "the navigation is not taller than the short viewport").toBeGreaterThan(0);

  await navigation.evaluate((element) => element.scrollTo(0, element.scrollHeight));
  expect(await navigation.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);

  // この高さでも最後のセクションに到達できなければならない。
  // シェルが自身のスクロールを持つ前は、そこへ到達するには
  // ドキュメント全体をスクロールし、途中でヘッダーを失う必要があった。
  await expect(page.getByRole("button", { name: "History", exact: true })).toBeInViewport();
  await expect(page.getByRole("banner")).toBeInViewport();
});
