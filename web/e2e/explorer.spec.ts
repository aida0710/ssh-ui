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
  // The unknown directive is the point: the engine has no schema for it and
  // must write it back exactly, quotes and spacing included.
  expect(after).toContain('UnknownFutureDirective some "quoted value" 3');
  expect(after).toContain("Host printer");
  expect(after).toContain("Host nas");
});

test("renames an included file and carries the Include that named it", async ({
  page,
  installation,
}) => {
  // The entry file reaches conf.d/10-home.conf through a glob, so a rename
  // within conf.d needs no rewriting. Adding a literal Include first is what
  // makes this test about the thing that matters.
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
  // Every other byte of a file that says not to reformat it.
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

  // One press arms it, the second does it. A file operation behind a single
  // click is one misplaced click away from a deletion nobody asked for.
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

  // The bytes are not lost: History lists the file as restorable.
  await openSection(page, "History");
  await expect(page.getByText("work/lon.conf").first()).toBeVisible();
});

// A directory is where a file goes, so the explorer makes and removes one too.
// An empty directory is in no Include graph, so the tree does not list it —
// what proves it existed is that removing it works once and refuses twice.
//
// Every step waits on its own response. "No alert yet" is true before the
// answer arrives as well as after a success, so asserting it raced the next
// click and passed here while failing in CI.
test("makes a directory and removes it", async ({ page, installation }) => {
  await openApplication(page, installation);
  await openSection(page, "Config");

  const path = page.getByLabel("New file path");
  await path.fill("conf.d/eu");
  expect(await clickAndAwait(page, "Create directory", "/api/v1/config/save")).toBe(200);

  await path.fill("conf.d/eu");
  expect(await clickAndAwait(page, "Delete directory", "/api/v1/config/save")).toBe(200);

  // Gone: the second removal has nothing to remove.
  await path.fill("conf.d/eu");
  expect(await clickAndAwait(page, "Delete directory", "/api/v1/config/save")).toBe(404);
  await expect(page.getByRole("alert")).toBeVisible();
});
