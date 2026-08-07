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
    // Vitest は Playwright の spec を決して収集してはならない。e2e/*.spec.ts は本物の
    // ブラウザを本物のバイナリに対して動かすため、jsdom 下では無意味に失敗する。
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
