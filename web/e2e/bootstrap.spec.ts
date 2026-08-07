import { clickAndAwait, expect, openSection, sessionStatus, test, openApplication } from "./support/environment";

test("exchanges the fragment for a session and removes it from the address bar", async ({
  page,
  context,
  installation,
}) => {
  await openApplication(page, installation);

  await expect(page.getByRole("heading", { name: "sshc", level: 1 })).toBeVisible();
  await expect(sessionStatus(page)).toContainText("Local session active");

  expect(await page.evaluate(() => window.location.hash)).toBe("");
  // これが空になるのは HttpOnly のおかげだ。スクリプトから
  // 読める cookie は、ページに足がかりを得た何にでも読めてしまう。
  expect(await page.evaluate(() => document.cookie)).toBe("");

  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "sshc_session");
  expect(session).toBeDefined();
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  expect(session?.secure).toBe(false);
});

test("refuses a replayed bootstrap fragment in a fresh browser context", async ({
  browser,
  installation,
}) => {
  const first = await browser.newContext();
  const firstPage = await first.newPage();
  await firstPage.goto(installation.url);
  // フロントドアに到達できることが、セッションが確立された
  // 証拠だ。vault 状態は、セッションを依然として要求するルート経由で読み取られる。
  await expect(firstPage.getByLabel("Master password", { exact: true })).toBeVisible();
  await first.close();

  const second = await browser.newContext();
  const secondPage = await second.newPage();
  await secondPage.goto(installation.url);
  await expect(secondPage.getByRole("alert")).toContainText(
    "Secure local session could not be started",
  );
  await second.close();
});

test("contacts no origin but its own", async ({ page, installation }) => {
  const requested: string[] = [];
  page.on("request", (request) => requested.push(request.url()));

  await openApplication(page, installation);
  await openSection(page, "Config");
  await expect(page.getByRole("heading", { name: "Include hierarchy" })).toBeVisible();

  const origin = new URL(installation.url).origin;
  const foreign = requested.filter((url) => !url.startsWith(origin) && !url.startsWith("data:"));
  expect(foreign, `these requests left the origin: ${foreign.join(", ")}`).toEqual([]);
});

test("enforces the content security policy in the browser, not only in the header", async ({
  page,
  installation,
}) => {
  const response = await openApplication(page, installation);
  expect(response?.headers()["content-security-policy"]).toBe(
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
      "form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; require-trusted-types-for 'script'",
  );

  // インラインスクリプトは実行されてはならない。textContent 付きの
  // script 要素を追加すればそれを注入することになるが、今や 2 つの壁がある。
  // require-trusted-types が代入自体を拒否し、script-src 'self' が結果
  // の実行を拒否する。どちらでも合格であり、起きてはならないのはスクリ
  const inlineRan = await page.evaluate(async () => {
    const marker = "__sshc_inline_marker";
    try {
      const element = document.createElement("script");
      element.textContent = `window.${marker} = true;`;
      document.head.appendChild(element);
    } catch {
      // プトの実行だ。内容を持つ script 要素になる前に、既に拒否されている。
      return false;
    }
    await new Promise((done) => setTimeout(done, 100));
    return Boolean((window as unknown as Record<string, unknown>)[marker]);
  });
  expect(inlineRan, "an inline script executed despite the policy").toBe(false);

  // connect-src 'self' は、他オリジンへの fetch がマシンを
  // 出る前に阻止するはずであり、この検証にネットワークは要らない。
  const crossOrigin = await page.evaluate(async () => {
    try {
      await fetch("https://example.invalid/collect", { mode: "no-cors" });
      return "allowed";
    } catch {
      return "blocked";
    }
  });
  expect(crossOrigin).toBe("blocked");
});

test("keeps no secret in persistent browser storage", async ({ page, installation }) => {
  await openApplication(page, installation);
  await expect(sessionStatus(page)).toContainText("Local session active");

  // ユーザーが言語を選ぶまで何も書き込まれないため、手を
  // 付けていないセッションは以前と同じく両ストアを空のままにする。
  expect(
    await page.evaluate(() => ({
      local: window.localStorage.length,
      session: window.sessionStorage.length,
    })),
  ).toEqual({ local: 0, session: 0 });

  await page.getByLabel("Language").selectOption("ja");

  // 数ではなく許可リストで見る。数だけなら、言語の代わりに
  // セッショントークンが入っていても同様に通ってしまう。値を
  // 確認することでそれを不可能にする。保存されてよいのは
  // "en" か "ja" だけで、存在してよいのは 2 つの設定キーだけだ。
  const stored = await page.evaluate(() => ({
    keys: Object.keys(window.localStorage).sort(),
    language: window.localStorage.getItem("sshc.language"),
    session: window.sessionStorage.length,
  }));
  expect(stored.keys).toEqual(["sshc.language"]);
  expect(["en", "ja"]).toContain(stored.language);
  expect(stored.session).toBe(0);
});

test("keeps the chosen appearance, and writes nothing else", async ({ page, installation }) => {
  await openApplication(page, installation);
  await expect(sessionStatus(page)).toContainText("Local session active");

  // アプリケーションはシステムに従う状態で起動するが、これは
  // 何も保存しないという選択である。
  expect(await page.evaluate(() => Object.keys(window.localStorage))).toEqual([]);

  await page.getByLabel("Appearance").selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  // System へ戻ることができるため、このコントロールは 2 値
  // ではなく 3 値を持つ。
  await page.getByLabel("Appearance").selectOption("system");
  await page.getByLabel("Language").selectOption("ja");

  const stored = await page.evaluate(() => ({
    keys: Object.keys(window.localStorage).sort(),
    theme: window.localStorage.getItem("sshc.theme"),
  }));
  expect(stored.keys).toEqual(["sshc.language", "sshc.theme"]);
  expect(stored.theme).toBe("system");
});

test("keeps the chosen language across a reload, and translates the panels", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await expect(sessionStatus(page)).toContainText("Local session active");

  await page.getByLabel("Language").selectOption("ja");
  await expect(page.getByRole("button", { name: "鍵", exact: true })).toBeVisible();

  // シェルだけでなくパネルでも。provider は描画される
  // セクションより上位になければならず、それは実ページでしか証明できない。
  await page.getByRole("button", { name: "鍵", exact: true }).click();
  await expect(page.getByRole("heading", { name: "鍵", level: 2 })).toBeVisible();
  await expect(page.getByRole("button", { name: "鍵を作成" })).toBeVisible();

  // 選択はページより長生きし、今やセッションもそうなった。
  // このテストはかつて逆を検証していた。リロードはセッションを
  // 復元できず、言語が生き残った証拠は*拒否*が日本語で届く
  // ことだった。その拒否は、テストが事実として書き留めていた不具合だった。
  await page.reload();
  // シェルは日本語で戻ってくる。これは選択がページより長生きしたとい
  // うことであり、そもそも戻ってくること自体がセッションがページより
  // 長生きしたということだ。開いていたセクションは記憶されないし、その
  // 必要もないため、まだそこにあると期待せずパネルへ改めて到達する。
  await expect(page.getByRole("button", { name: "鍵", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "鍵", exact: true }).click();
  await expect(page.getByRole("button", { name: "鍵を作成" })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(window.localStorage).sort())).toEqual(["sshc.language"]);
});

// フラグメントは初回使用で消費されアドレスバーから取り
// 除かれるため、リロードは cookie だけを携えて到着する。
// その cookie からセッションを更新できるようになるまで、
// リロードのたびにバイナリを再起動するまでアプリケーションは死んでいた。
test("survives a reload", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await expect(page.getByRole("navigation", { name: "Connections" })).toBeVisible();

  await page.reload();

  await openSection(page, "Connections");
  await expect(
    page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }),
  ).toBeVisible();

  // そして更新されたトークンは書き込みにも使える。これは
  // リロードが失っていた半分だ。cookie は常に無事で、トークンだけが無事でなかった。
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByLabel("Port", { exact: true }).fill("2255");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(200);
  expect(await installation.read("config")).toContain("Port 2255");
});
