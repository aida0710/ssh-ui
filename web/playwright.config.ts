import { defineConfig, devices } from "@playwright/test";

// Traces, videos and screenshots are all disabled on purpose. One end-to-end
// flow reveals a private key on screen by design, and an artefact directory is
// exactly the kind of place a secret is forgotten. Failures are diagnosed from
// the assertion message and the server's own output.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    // The suite selects by English text. The application picks its language
    // from the browser, so the locale is pinned here rather than left to the
    // runner: without this, the same specs would pass or fail depending on
    // the machine they run on.
    locale: "en-US",
    trace: "off",
    video: "off",
    screenshot: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
