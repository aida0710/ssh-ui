import { defineConfig, devices } from "@playwright/test";

// trace、動画、スクリーンショットはすべて意図的に無効化されてい
// る。1 つの end-to-end フローは設計上、秘密鍵を画面に表示するので
// あり、成果物のディレクトリはまさに secret が忘れ去られる類いの場
// 所だ。失敗は検証のメッセージとサーバー自身の出力から診断する。
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
    // このスイートは英語のテキストで要素を選ぶ。アプリケー
    // ションはブラウザから言語を選ぶため、ロケールをランナー任せ
    // にせずここで固定する。そうしなければ、同じ spec が実行
    // するマシンによって合格したり失敗したりしてしまう。
    locale: "en-US",
    trace: "off",
    video: "off",
    screenshot: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
