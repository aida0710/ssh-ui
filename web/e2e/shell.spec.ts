import { expect, openSection, test, openApplication } from "./support/environment";

// A configuration long enough that the Connections panel cannot fit in the
// 1280x720 viewport this suite runs at. Without it the assertions below would
// pass on a shell that scrolls its header away, because nothing would scroll.
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

  // The list is its own pane now, and scrolls on its own rather than taking the
  // whole panel with it. Its scroller is the element the tree sits in.
  //
  // It must genuinely overflow. If it did not, every assertion after this one
  // would hold on a shell that scrolls the header off screen.
  const overflow = await tree.evaluate((element) => {
    const scroller = element.parentElement;
    if (scroller === null) return 0;
    return scroller.scrollHeight - scroller.clientHeight;
  });
  expect(overflow, "the fixture is not tall enough to scroll the list").toBeGreaterThan(0);

  // The document itself must not scroll. This is the regression: a page-level
  // scroll is what carried the header and the section buttons away, and a
  // wheel over the panel produced one when nothing else could consume it.
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

  // The bottom of a scrolled panel must still be reachable. A shell clamped to
  // the viewport that forgot to make the panel scrollable would hide it.
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

  // The last section must be reachable at this height. Before the shell owned
  // its own scrolling, reaching it meant scrolling the whole document and
  // losing the header on the way.
  await expect(page.getByRole("button", { name: "History", exact: true })).toBeInViewport();
  await expect(page.getByRole("banner")).toBeInViewport();
});
