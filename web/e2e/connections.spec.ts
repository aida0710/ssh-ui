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
  // The bytes around the change must survive exactly: the comment, the
  // "HostName=" spelling and the run of spaces after User are all things a
  // reformatting editor would quietly normalise.
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

  // Someone edits the file outside the application after the page loaded it.
  const external = (await installation.read("config")).replace(
    "Host *",
    "Host edited-outside\n\tHostName 192.0.2.99\n\nHost *",
  );
  await installation.write("config", external);

  await page.getByLabel("Port", { exact: true }).fill("2277");
  expect(await clickAndAwait(page, "Save changes", "/api/v1/config/save")).toBe(409);

  await expect(page.getByText("Changed on disk since you loaded it")).toBeVisible();
  await expect(page.getByText("Your pending change")).toBeVisible();

  // The decisive assertion: the external edit survived untouched and the
  // pending change was not written over it.
  const after = await installation.read("config");
  expect(after).toBe(external);
  expect(after).not.toContain("Port 2277");
});

// The Diagnostics tab used to say the checks would arrive with a later
// subsystem, long after they had. It now runs the real ones, addressed by the
// open connection.
//
// Only the command builder is exercised here: it composes an argv and starts
// nothing. Reachability and the authentication test dial a host, and no
// automated test in this repository may do that — they are manual tests M2 and
// M3. That the buttons exist and start nothing on their own is the property
// this spec can honestly assert.
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
  // The connection is already known, so the tab asks for no alias.
  await expect(panel.getByLabel("Host alias")).toHaveCount(0);
  expect(started.filter((path) => path.startsWith("/api/v1/diagnostics/"))).toEqual([]);
  expect(started.filter((path) => path.startsWith("/api/v1/terminal/"))).toEqual([]);

  expect(await clickAndAwait(page, "Terminal command", "/api/v1/terminal/command")).toBe(200);
  await expect(panel.getByText("ssh -- bastion")).toBeVisible();

  // Still nothing launched: building the command and running it are separate
  // operations, and only the second one needs a confirmation.
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

// Metadata the schema has always carried but no screen could edit: a colour, a
// display order, and a note whose Host block is gone.
test("edits the display order it stores, and shows a favourite in the tree", async ({
  page,
  installation,
}) => {
  await openBastion(page, installation.url);

  // The colour, the tags, the favourite flag and the display order are the
  // settings that exist only in metadata.json, so they live in the inspector
  // rather than beside the directives that get written to a file. The pane is
  // shut until asked for.
  await page.getByRole("button", { name: "Show details" }).click();

  // Waiting on the write rather than polling the file: the metadata document
  // does not exist until the first save creates it.
  const [ordered] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.url().includes("/api/v1/config/save") && response.request().method() === "POST",
    ),
    page.getByLabel(/Display order/).fill("-1"),
  ]);
  expect(ordered.status()).toBe(200);
  expect(JSON.parse(await installation.read("ssh-ui/metadata.json")).hosts[0].order).toBe(-1);

  // The favourite marker used to live only in the screen reader description,
  // so a sighted user could set one and then not find it. Clicking rather than
  // checking: the panel reloads from the server as the save lands, and the star
  // appearing in the tree is the assertion that matters anyway.
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
    "ssh-ui/metadata.json",
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
  // The note is retired in favour of a configuration comment, and membership is
  // the directory now, so the panel describes the entry by what it still
  // carries: the presentation that has no home in the configuration.
  await expect(panel.getByText(/tags ci/)).toBeVisible();

  await panel.getByLabel("Re-associate retired with").selectOption("config\u0000bastion");
  expect(await clickAndAwait(page, "Re-associate retired", "/api/v1/config/save")).toBe(200);

  // The note moved to the host the user named, and the server's orphan flag is
  // not written back into the document it describes.
  const saved = JSON.parse(await installation.read("ssh-ui/metadata.json"));
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

  // The file's own banner sits above a blank line, so it belongs to the file
  // and not to the first block. Editing the block must leave it alone.
  expect(after).toContain("# Managed by hand since 2019. Do not reformat.\n\nInclude conf.d/*.conf");
  // And every byte the comment did not add is unchanged.
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

  // Back to the original bytes: adding and removing a comment is a round trip.
  expect(await installation.read("config")).toBe(before);
});

// A comment that means something can be mis-attributed. These are the two ways
// a block leaves a file, and both would otherwise hand its description to
// whichever connection happened to follow it.
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

  await page.getByLabel("Move to file").selectOption("config");
  expect(await clickAndAwait(page, "Move connection", "/api/v1/config/save")).toBe(200);

  // The comment arrived with the block…
  expect(await installation.read("config")).toContain("# the file server\nHost nas\n");
  // …and the printer kept its own rather than inheriting nas's.
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

  await page.getByRole("button", { name: "Delete connection" }).click();
  expect(await clickAndAwait(page, "Confirm delete", "/api/v1/config/save")).toBe(200);

  const after = await installation.read("conf.d/10-home.conf");
  // Left behind, "# the file server" would have become the printer's
  // description — a silent lie about a connection nobody touched.
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
  // The heading is on screen before anything is in the group, which is what
  // makes it a target at all: a group that hid until it held something could
  // never be filled by dragging.
  await expect(tree.getByRole("heading", { name: "work" })).toBeVisible();

  await tree.getByRole("button", { name: "bastion" }).dragTo(tree.getByRole("heading", { name: "work" }));

  // Read back through the file the group's Include names. That the block is in
  // connections/work/config.conf is what proves the move landed somewhere
  // OpenSSH reads, rather than merely somewhere a file was written.
  await expect(async () => {
    expect(await installation.read("connections/work/config.conf")).toContain("Host bastion");
  }).toPass();
  expect(await installation.read("config")).not.toContain("Host bastion\n");
});
