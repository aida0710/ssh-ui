import { clickAndAwait, expect, openSection, sessionStatus, test, openApplication } from "./support/environment";

test("exchanges the fragment for a session and removes it from the address bar", async ({
  page,
  context,
  installation,
}) => {
  await openApplication(page, installation);

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
  // Reaching the front door is what proves the session was established: the
  // vault status is read through a route that still requires one.
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
  await openApplication(page, installation);
  await expect(sessionStatus(page)).toContainText("Local session active");

  // Nothing is written until the user chooses a language, so an untouched
  // session leaves both stores empty exactly as before.
  expect(
    await page.evaluate(() => ({
      local: window.localStorage.length,
      session: window.sessionStorage.length,
    })),
  ).toEqual({ local: 0, session: 0 });

  await page.getByLabel("Language").selectOption("ja");

  // An allowlist rather than a count. A count would have passed just as well
  // with a session token in place of the language, and checking the value is
  // what makes that impossible: nothing but "en" or "ja" may be stored, and
  // nothing but that one key may exist.
  const stored = await page.evaluate(() => ({
    keys: Object.keys(window.localStorage),
    language: window.localStorage.getItem("ssh-ui.language"),
    session: window.sessionStorage.length,
  }));
  expect(stored.keys).toEqual(["ssh-ui.language"]);
  expect(["en", "ja"]).toContain(stored.language);
  expect(stored.session).toBe(0);
});

test("keeps the chosen language across a reload, and translates the panels", async ({
  page,
  installation,
}) => {
  await openApplication(page, installation);
  await expect(sessionStatus(page)).toContainText("Local session active");

  await page.getByLabel("Language").selectOption("ja");
  await expect(page.getByRole("button", { name: "鍵", exact: true })).toBeVisible();

  // A panel, not just the shell: the provider has to be above the section
  // being rendered, and only a real page proves that.
  await page.getByRole("button", { name: "鍵", exact: true }).click();
  await expect(page.getByRole("heading", { name: "鍵", level: 2 })).toBeVisible();
  await expect(page.getByRole("button", { name: "鍵を作成" })).toBeVisible();

  // The choice outlives the page, and so now does the session. This used to
  // assert the opposite: a reload could not restore the session, and the proof
  // that the language had survived was that the *refusal* arrived in Japanese.
  // The refusal was a defect the test had written down as a fact.
  await page.reload();
  // The shell comes back in Japanese, which is the choice outliving the page,
  // and it comes back at all, which is the session outliving it. The open
  // section is not remembered and is not meant to be, so the panel is reached
  // again rather than expected to still be there.
  await expect(page.getByRole("button", { name: "鍵", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "鍵", exact: true }).click();
  await expect(page.getByRole("button", { name: "鍵を作成" })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(window.localStorage))).toEqual(["ssh-ui.language"]);
});

// The fragment is spent on first use and taken out of the address bar, so a
// reload arrives with the cookie and nothing else. Until the session could be
// renewed from that cookie, every reload left the application dead until the
// binary was started again.
test("survives a reload", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Connections");
  await expect(page.getByRole("navigation", { name: "Connections" })).toBeVisible();

  await page.reload();

  await openSection(page, "Connections");
  await expect(
    page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }),
  ).toBeVisible();

  // And the renewed token works for a write, which is the half a reload used to
  // lose: the cookie was always fine, the token was not.
  await page.getByRole("navigation", { name: "Connections" }).getByRole("button", { name: "bastion" }).click();
  await page.getByLabel("Port", { exact: true }).fill("2255");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(200);
  expect(await installation.read("config")).toContain("Port 2255");
});
