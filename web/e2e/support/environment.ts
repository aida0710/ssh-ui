import { test as base, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

// binaryPath is the artefact under test. `make e2e` builds it first; a missing
// binary fails loudly rather than falling back to a dev server, because the
// point of this suite is the shipped artefact.
const binaryPath = resolve(process.cwd(), "..", "bin", "sshc");

// The fixture home is written by this file and by nothing else. Every spec that
// needs a different starting state writes it through `installation.write`.
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

// A syntactically valid but entirely synthetic host key. Nothing in this suite
// contacts the address it names.
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
    // HOME is the throwaway directory and PATH is inherited only so the child
    // can find the OpenSSH programs it may report on. No spec in this suite
    // triggers a route that starts one.
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

// masterPassword is what every spec opens the application with. The whole
// application is behind it now, so unlocking is part of starting rather than
// part of a test about secrets.
export const masterPassword = "an end to end master password";

// openApplication navigates and gets past the front door.
//
// The first run of a fresh installation asks for a master password to be
// chosen; a later one asks for it back. Specs get the second screen only if
// they restart the binary, so this handles the first and is written to cope
// with either.
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
  // The navigation's own response, for the spec that asserts the headers it
  // carried rather than what the page did with them.
  return response;
}

// sessionStatus is the header's own status line.
//
// It is scoped to the banner rather than selected by role alone: panels carry
// their own role="status" elements, so an unscoped query is ambiguous in the
// assembled application even though it is unique in the shell's Vitest suite.
export function sessionStatus(page: Page) {
  return page.getByRole("banner").getByRole("status");
}

// openSection navigates the primary navigation and waits for the session first,
// so a spec never clicks into a panel the shell has not rendered yet.
// The name is matched exactly: "Keys" is a prefix of "Remote Keys", so a
// substring match is ambiguous in the assembled navigation.
export async function openSection(page: Page, name: string): Promise<void> {
  await expect(sessionStatus(page)).toContainText("Local session active");
  await page
    .getByRole("navigation", { name: "Primary" })
    .getByRole("button", { name, exact: true })
    .click();
}

// clickAndAwait presses a button and resolves on the API response it triggers,
// returning that response's status.
//
// Waiting on a heading instead would be a false green here: the Save preview
// panel renders its heading unconditionally, so a spec that treated the heading
// as "the save finished" would read the file before the write and pass or fail
// on timing rather than on behaviour.
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

