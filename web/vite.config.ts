import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../internal/ui/dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    restoreMocks: true,
    // Vitest must never collect a Playwright spec: e2e/*.spec.ts drives a real
    // browser against a real binary and would fail meaninglessly under jsdom.
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
