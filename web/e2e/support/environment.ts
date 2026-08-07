import { test as base, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

// binaryPath は試験対象の成果物である。`make e2e` が
// 先にそれをビルドする。バイナリがなければ、dev サーバーへ
// 静かに後退するのではなく大声で失敗する。このスイートの主眼は出荷される成果物だからだ。
const binaryPath = resolve(process.cwd(), "..", "bin", "sshc");

// フィクスチャの home を書くのはこのファイルだけであり、他の何ものでもない。異
// なる初期状態を必要とする各 spec は `installation.write` を通じてそれを書く。
const entryConfig = [
  "# Managed by hand since 2019. Do not reformat.",
  "",
  "Include conf.d/*.conf",
  "",
  "Host bastion",
  "\tHostName=203.0.113.10",
  "\tUser    ops",
  "\tPort 2222",
  "",
  "Host *",
  "\tServerAliveInterval 30",
  "",
].join("\n");

const includedConfig = [
  "Host nas",
  "\tHostName 198.51.100.20",
  '\tUnknownFutureDirective some "quoted value" 3',
  "",
].join("\n");

// 構文的には正しいが、まったくの合成物である host key。
// このスイート内の何ものも、それが指すアドレスに接続しない。
const knownHosts =
  "203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZpeHR1cmVrZXlmaXh0dXJla2V5Zml4dHVyZWtl fixture\n";

export type Installation = {
  home: string;
  url: string;
  read(relative: string): Promise<string>;
  write(relative: string, contents: string): Promise<void>;
};

async function buildHome(): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), "sshc-e2e-"));
  if (!home.startsWith(tmpdir())) {
    throw new Error("the end-to-end home is not inside the temporary directory");
  }
  const root = join(home, ".ssh");
  await mkdir(join(root, "conf.d"), { recursive: true, mode: 0o700 });
  await writeFile(join(root, "config"), entryConfig, { mode: 0o600 });
  await writeFile(join(root, "conf.d", "10-home.conf"), includedConfig, { mode: 0o600 });
  await writeFile(join(root, "known_hosts"), knownHosts, { mode: 0o600 });
  return home;
}

function startBinary(home: string): Promise<{ child: ChildProcess; url: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    // HOME は使い捨てのディレクトリであり、PATH が継承される
    // のは子プロセスが報告対象になりうる OpenSSH のプログラムを
    // 見つけるためだけだ。このスイートのどの spec も、それを起動するルートを引き起こさない。
    const child = spawn(binaryPath, ["-open=false"], {
      env: { HOME: home, PATH: process.env.PATH ?? "" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let buffered = "";
    const timer = setTimeout(
      () => rejectPromise(new Error("sshc printed no URL within 10s")),
      10_000,
    );
    child.stdout?.on("data", (chunk: Buffer) => {
      buffered += chunk.toString("utf8");
      const newline = buffered.indexOf("\n");
      if (newline < 0) return;
      clearTimeout(timer);
      resolvePromise({ child, url: buffered.slice(0, newline).trim() });
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      rejectPromise(new Error(`sshc exited with ${String(code)} before printing a URL`));
    });
  });
}

export const test = base.extend<{ installation: Installation }>({
  installation: async ({}, use) => {
    const home = await buildHome();
    const { child, url } = await startBinary(home);
    const installation: Installation = {
      home,
      url,
      async read(relative) {
        return readFile(join(home, ".ssh", relative), "utf8");
      },
      async write(relative, contents) {
        const target = join(home, ".ssh", relative);
        await mkdir(dirname(target), { recursive: true, mode: 0o700 });
        await writeFile(target, contents, { mode: 0o600 });
      },
    };
    await use(installation);
    child.kill("SIGTERM");
    await new Promise((done) => child.on("exit", done));
    await rm(home, { recursive: true, force: true });
  },
});

// masterPassword は、すべての spec がアプリケーションを開く
// ときに使うものだ。今やアプリケーション全体がその背後に
// あるため、ロック解除は secret についての試験の一部ではなく起動の一部になっている。
export const masterPassword = "an end to end master password";

// openApplication はナビゲートし、フロントドアを通過する。
//
// 新規インストールの最初の起動は masterPassword の選択を
// 求め、以後の起動はそれの入力を求める。spec がバイナリを
// 再起動しない限り 2 番目の画面には出会わないため、これは
// 最初のケースを扱いつつ、どちらにも対応できるよう書かれている。
export async function openApplication(page: Page, installation: { url: string }) {
  const response = await page.goto(installation.url);
  const confirmation = page.getByLabel("Confirm master password", { exact: true });
  await expect(page.getByLabel("Master password", { exact: true })).toBeVisible();
  await page.getByLabel("Master password", { exact: true }).fill(masterPassword);
  if (await confirmation.isVisible()) {
    await confirmation.fill(masterPassword);
    await page.getByRole("button", { name: "Create the vault" }).click();
  } else {
    await page.getByRole("button", { name: "Open" }).click();
  }
  await expect(sessionStatus(page)).toContainText("Local session active");
  // ページがそれをどう扱ったかではなく、ナビゲーション自身の
  // 応答が運んだヘッダーを検証する spec のための、その応答そのもの。
  return response;
}

// sessionStatus はヘッダー自身のステータス行である。
//
// role だけで選ぶのではなく banner にスコープする。パネルは自分自身の
// role="status"要素を持つため、スコープなしのクエリはシェル単体の Vitest
// スイートでは一意でも、組み立てられたアプリケーションでは曖昧になる。
export function sessionStatus(page: Page) {
  return page.getByRole("banner").getByRole("status");
}

// openSection はプライマリナビゲーションを操作する前にまずセッションを待つた
// め、spec がシェルのまだ描画していないパネルをクリックしてしまうことはない。
// 名前は完全一致で照合する。"Keys" は "Remote Keys" の
// 接頭辞であるため、部分一致では組み立てられたナビゲーションの中で曖昧になる。
export async function openSection(page: Page, name: string): Promise<void> {
  await expect(sessionStatus(page)).toContainText("Local session active");
  await page
    .getByRole("navigation", { name: "Primary" })
    .getByRole("button", { name, exact: true })
    .click();
}

// clickAndAwait はボタンを押し、それが引き起こす API 応答で
// 解決し、その応答の status を返す。
//
// 代わりに見出しを待つのはここでは偽の成功になる。Save
// preview パネルは無条件に見出しを描画するため、見出しを
// 「保存が終わった」ことだと扱う spec は書き込みより前に
// ファイルを読んでしまい、振る舞いではなくタイミングによって合否が決まってしまう。
export async function clickAndAwait(
  page: Page,
  buttonName: string,
  pathFragment: string,
): Promise<number> {
  const [response] = await Promise.all([
    page.waitForResponse(
      (candidate) =>
        candidate.url().includes(pathFragment) && candidate.request().method() === "POST",
    ),
    page.getByRole("button", { name: buttonName, exact: true }).click(),
  ]);
  return response.status();
}

export { expect };

