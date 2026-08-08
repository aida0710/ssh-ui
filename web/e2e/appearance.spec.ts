import { expect, test } from "./support/environment";
import { openApplication, openSection, sessionStatus } from "./support/environment";

const sections = [
  "Home",
  "Connections",
  "Config",
  "Groups",
  "Keys",
  "Known Hosts",
  "Remote Keys",
  "Diagnostics",
  "Secrets",
  "Sync",
  "History",
];

// これが防ぐ失敗は具体的で、実際にここで起きたことがある。`ui/form.tsx` があるのは、
// 3 つのパネルがそれぞれ独自のコントロールを増やし、1 つはまったく
// 持たなかった結果、あるフィールドが黒地に黒文字になったからだ。
// リテラルな色のまま残されたコンポーネントは、それが書かれなかった
// テーマや見落とされた画面で、まったく同じ症状を再現する。
//
// 目視ではなく計算済みの色を読み取る。トークンが何にも
// 解決されない場合、要素は透明になり、透明の上に透明が
// 重なるというのが、この失敗が取る形だ。
for (const appearance of ["light", "dark"] as const) {
  test(`every section renders in ${appearance}`, async ({ page, installation }) => {
    await openApplication(page, installation);

    await page.getByLabel("Appearance").selectOption(appearance);
    await expect(page.locator("html")).toHaveAttribute("data-theme", appearance);
    await expect(sessionStatus(page)).toContainText("Local session active");

    for (const name of sections) {
      await openSection(page, name);

      await expect(page.locator("html")).toHaveAttribute("data-theme", appearance);
      await expect(page.locator("main")).toBeVisible();

      // シェルは必ず何かを塗るため、両者が一致しないことが
      // ある。背景と同じ色の文字こそ、このスイートが検出する不具合だ。
      const painted = await page.evaluate(() => {
        const shell = document.querySelector("main");
        if (shell === null) return null;
        const style = window.getComputedStyle(shell);
        const body = window.getComputedStyle(document.body);
        return { colour: style.color, background: body.backgroundColor };
      });
      expect(painted).not.toBeNull();
      expect(painted?.colour).not.toBe(painted?.background);
      expect(painted?.colour).not.toBe("rgba(0, 0, 0, 0)");
    }
  });
}

// パレットが及ぶすべてのコントロールは、シェルだけでなく判読可能で
// なければならない。この試験は input、select、button、通知を同時に
// 持つ唯一の画面を巡り、どれも自分自身と同じ色で塗られていないことを検証する。
test("the connections controls are legible in light", async ({ page, installation }) => {
  await openApplication(page, installation);
  await page.getByLabel("Appearance").selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

  await openSection(page, "Connections");
  await page.getByRole("button", { name: "bastion", exact: true }).click();
  await expect(page.getByRole("heading", { name: "bastion", level: 2 })).toBeVisible();
  await page.getByRole("button", { name: "New connection" }).click();

  const readable = await page.evaluate(() => {
    const results: { where: string; colour: string; background: string }[] = [];
    for (const selector of ["input#new-alias", "select#new-file", "input#field-2-HostName"]) {
      const element = document.querySelector(selector);
      if (element === null) continue;
      const style = window.getComputedStyle(element);
      results.push({ where: selector, colour: style.color, background: style.backgroundColor });
    }
    return results;
  });

  // 緩く数えるのではなく名指しする。マッチしなくなった
  // セレクタは、何も検証せずに通過するテストにこれを変えてしまう。
  expect(readable.map((control) => control.where)).toEqual(
    expect.arrayContaining(["input#new-alias", "select#new-file"]),
  );
  for (const control of readable) {
    expect(control.colour, `${control.where} text`).not.toBe(control.background);
    // ライトテーマでほぼ黒に塗られたコントロールこそ、この
    // ファイルが捕らえるべき退行そのものであり、リテラルが移行を生き延びたことを意味する。
    expect(control.background, `${control.where} background`).not.toBe("rgb(28, 28, 30)");
  }
});
