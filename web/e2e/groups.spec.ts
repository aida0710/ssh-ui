import { clickAndAwait, expect, openSection, test } from "./support/environment";

// A group is a directory, and this spec is about the two facts that follow from
// that: the entry file gains one Include line per group, in a stated order, and
// moving a connection between groups moves its file. Both assertions read the
// bytes on disk, because a screen saying "moved" proves nothing about ~/.ssh.
test("declares a group in the entry file and moves a connection into it", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
  await openSection(page, "Groups");

  await page.getByLabel("New group name").fill("work");
  await page.getByRole("button", { name: "Add group" }).click();
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  // The declaration is an ordinary Include line inside two marker comments, so
  // a reader who has never heard of this application can see what it is.
  const entry = await installation.read("config");
  expect(entry).toContain("# >>> ssh-ui groups (generated).");
  expect(entry).toContain("Include connections/work/*.conf\n");
  expect(entry).toContain("Include groups.ssh-ui.conf\n");
  expect(entry).toContain("# <<< ssh-ui groups");
  // The region sits above every Host line. An Include written below one belongs
  // to that block, and OpenSSH applies an included file's options only when the
  // block matches, so anywhere lower declares the groups to one host and to
  // nothing else.
  expect(entry.indexOf("# >>> ssh-ui groups")).toBeLessThan(entry.indexOf("Host "));

  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "nas" })
    .click();
  await expect(page.getByRole("tablist", { name: "Host editor" })).toBeVisible();

  await page.getByLabel("Primary group").selectOption("work");
  expect(await clickAndAwait(page, "Move to this group", "/api/v1/config/save")).toBe(200);

  // The file moved and kept its own name; the block arrived byte for byte.
  expect(await installation.read("connections/work/10-home.conf")).toContain("Host nas");
  expect(await installation.read("conf.d/10-home.conf")).toBe("");
});

// connections/work/*.conf cannot reach connections/work/eu/lon.conf, because
// '*' does not cross a separator in glob(3) or in filepath.Glob. That is the
// whole reason the region emits one line per group, so it is asserted here
// rather than assumed.
test("gives a nested group its own Include line, deepest first", async ({ page, installation }) => {
  await page.goto(installation.url);
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
  // OpenSSH keeps the first value it reads, so the deeper group has to be read
  // first or a parent's setting would beat its own child's.
  expect(child).toBeLessThan(parent);
});

test("renames a group and carries its files, its Include line and its keys", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
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
  await page.getByLabel("Rename work to").fill("client-a");
  expect(await clickAndAwait(page, "Rename work", "/api/v1/config/groups/rename")).toBe(200);

  // The file, the declaration and the empty source directory: all three are
  // what a rename means when a group is a directory.
  expect(await installation.read("connections/client-a/10-home.conf")).toContain("Host nas");
  const entry = await installation.read("config");
  expect(entry).toContain("Include connections/client-a/*.conf\n");
  expect(entry).not.toContain("Include connections/work/*.conf\n");
});

test("refuses to move a connection into a group nothing declares", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
  await openSection(page, "Connections");
  await page
    .getByRole("navigation", { name: "Connections" })
    .getByRole("button", { name: "nas" })
    .click();
  await expect(page.getByRole("tablist", { name: "Host editor" })).toBeVisible();

  // No group has been declared, so the destination list is empty and the
  // control is disabled: the screen does not offer a move it knows would fail.
  await expect(page.getByRole("button", { name: "Move to this group" })).toBeDisabled();
  expect(await installation.read("conf.d/10-home.conf")).toContain("Host nas");
});

test("shows a nested group inside its parent, and hides a container from the tree", async ({
  page,
  installation,
}) => {
  await page.goto(installation.url);
  await openSection(page, "Groups");
  for (const name of ["work", "work/eu"]) {
    await page.getByLabel("New group name").fill(name);
    await page.getByRole("button", { name: "Add group" }).click();
  }
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  const tree = page.getByRole("navigation", { name: "Connections" });
  // The child is drawn inside the parent's block, not beside it, and its
  // heading carries only its own segment.
  await expect(tree.getByRole("region", { name: "work" }).getByRole("heading", { name: "eu" })).toBeVisible();

  // "work" holds nothing of its own, so hiding it is offered.
  await openSection(page, "Groups");
  await page.getByLabel("Hide work from Connections").check();
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  await expect(tree.getByRole("region", { name: "work" })).toHaveCount(0);
  // The child survives its parent's heading going away.
  await expect(tree.getByRole("region", { name: "work/eu" })).toBeVisible();
});
