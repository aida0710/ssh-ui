import { expect, openSection, sessionStatus, test } from "./support/environment";

test("exchanges the fragment for a session and removes it from the address bar", async ({
  page,
  context,
  installation,
}) => {
  await page.goto(installation.url);

  await expect(page.getByRole("heading", { name: "SSH UI", level: 1 })).toBeVisible();
  await expect(sessionStatus(page)).toContainText("Local session active");

  expect(await page.evaluate(() => window.location.hash)).toBe("");
  // HttpOnly is what makes this empty. A cookie readable from script would be
  // readable by anything that got a foothold in the page.
  expect(await page.evaluate(() => document.cookie)).toBe("");

  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "ssh_ui_session");
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
  await expect(sessionStatus(firstPage)).toContainText("Local session active");
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

  await page.goto(installation.url);
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
  const response = await page.goto(installation.url);
  expect(response?.headers()["content-security-policy"]).toBe(
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
      "form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
  );

  // An inline script must not run. Appending a script element with textContent
  // injects an inline script, which script-src 'self' refuses.
  const inlineRan = await page.evaluate(async () => {
    const marker = "__ssh_ui_inline_marker";
    const element = document.createElement("script");
    element.textContent = `window.${marker} = true;`;
    document.head.appendChild(element);
    await new Promise((done) => setTimeout(done, 100));
    return Boolean((window as unknown as Record<string, unknown>)[marker]);
  });
  expect(inlineRan, "an inline script executed despite script-src 'self'").toBe(false);

  // connect-src 'self' must block a fetch to another origin before it leaves
  // the machine, so this assertion needs no network.
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
  await page.goto(installation.url);
  await expect(sessionStatus(page)).toContainText("Local session active");

  const stored = await page.evaluate(() => ({
    local: window.localStorage.length,
    session: window.sessionStorage.length,
  }));
  expect(stored).toEqual({ local: 0, session: 0 });
});
