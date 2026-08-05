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
    trace: "off",
    video: "off",
    screenshot: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
