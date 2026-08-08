import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConfigExplorer } from "./ConfigExplorer";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), file: vi.fn(), preview: vi.fn(), save: vi.fn() } };
});

const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [
    {
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      editable: true,
      loads: 1,
      includes: [{
        line: 2,
        pattern: "conf.d/*.conf",
        matches: [{ path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }],
      }],
    },
    { file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }, editable: true, loads: 1 },
    { file: { absolute: "/etc/ssh/ssh_config", external: true }, editable: false, loads: 1 },
  ],
  hosts: [],
  metadata: { schemaVersion: 1 },
  diagnostics: [{ severity: "warning", code: "include_no_match", path: "config", line: 2, detail: "conf.d/*.conf" }],
  notices: [],
};

beforeEach(() => {
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.file).mockImplementation(async (path) => ({
    file: { path, absolute: `/home/tester/.ssh/${path}` },
    contents: path === "config" ? "Include conf.d/*.conf\n" : "Host nas\n\tUser aida\n",
    digest: "digest",
    editable: true,
    exists: true,
  }) as never);
});

describe("ConfigExplorer", () => {
  it("opens the entry file by default instead of leaving the editor empty", async () => {
    render(<ConfigExplorer />);

    await waitFor(() => expect(configApi.file).toHaveBeenCalledWith("config"));
    expect(await screen.findByLabelText(/File text.*config/)).toHaveValue("Include conf.d/*.conf\n");
  });

  it("keeps the latest file selection when the automatic entry load returns late", async () => {
    let finishEntry: ((value: unknown) => void) | undefined;
    vi.mocked(configApi.file).mockImplementation((path) => {
      if (path === "config") {
        return new Promise((resolve) => {
          finishEntry = resolve;
        }) as never;
      }
      return Promise.resolve({
        file: { path, absolute: `/home/tester/.ssh/${path}` },
        contents: "Host nas\n\tUser aida\n",
        digest: "digest",
        editable: true,
        exists: true,
      }) as never;
    });
    const user = userEvent.setup();
    render(<ConfigExplorer />);

    await user.click(await screen.findByRole("button", { name: "conf.d/10-home.conf" }));
    expect(await screen.findByLabelText(/File text.*conf\.d\/10-home\.conf/)).toBeInTheDocument();

    finishEntry?.({
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      contents: "Include conf.d/*.conf\n",
      digest: "entry-digest",
      editable: true,
      exists: true,
    });
    await waitFor(() =>
      expect(screen.getByLabelText(/File text.*conf\.d\/10-home\.conf/)).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText(/File text — config\./)).not.toBeInTheDocument();
  });

  it("shows the include hierarchy, the reference graph and the diagnostics", async () => {
    render(<ConfigExplorer />);

    expect(await screen.findByRole("button", { name: "config" })).toBeInTheDocument();
    expect(screen.getByText("conf.d/*.conf")).toBeInTheDocument();
    expect(screen.getByText(/include_no_match/)).toBeInTheDocument();
  });

  it("marks a file outside ~/.ssh as read only", async () => {
    render(<ConfigExplorer />);

    expect(await screen.findByText("/etc/ssh/ssh_config")).toBeInTheDocument();
    expect(screen.getByText(/outside ~\/\.ssh/i)).toBeInTheDocument();
  });

  it("marks which file the editor is showing", async () => {
    const user = userEvent.setup();
    render(<ConfigExplorer />);

    const target = await screen.findByRole("button", { name: "conf.d/10-home.conf" });
    expect(target).toHaveAttribute("aria-current", "false");

    await user.click(target);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "conf.d/10-home.conf" })).toHaveAttribute("aria-current", "true"),
    );
    expect(screen.getByRole("button", { name: "config" })).toHaveAttribute("aria-current", "false");
  });

  it("says when the draft no longer matches what was read", async () => {
    const user = userEvent.setup();
    render(<ConfigExplorer />);

    await user.click(await screen.findByRole("button", { name: "conf.d/10-home.conf" }));
    const editor = await screen.findByLabelText(/File text/);
    expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument();

    await user.type(editor, "\tPort 2222\n");

    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();
  });

  it("offers no file creation until a path is typed", async () => {
    const user = userEvent.setup();
    render(<ConfigExplorer />);

    expect(await screen.findByRole("button", { name: "Create file" })).toBeDisabled();

    await user.type(screen.getByLabelText("New file path"), "conf.d/30-lab.conf");

    expect(screen.getByRole("button", { name: "Create file" })).toBeEnabled();
  });

  it("edits a whole file and saves it with the loaded base", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["conf.d/10-home.conf"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);

    render(<ConfigExplorer />);

    await user.click(await screen.findByRole("button", { name: "conf.d/10-home.conf" }));
    const editor = await screen.findByLabelText(/File text/);
    await user.clear(editor);
    await user.type(editor, "Host nas\n\tUser root\n");
    await user.click(screen.getByRole("button", { name: "Save file" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "conf.d/10-home.conf",
      base: "Host nas\n\tUser aida\n",
      raw: "Host nas\n\tUser root\n",
    }));
  });

  it("opens a target file and selects the targeted line", async () => {
    render(<ConfigExplorer target={{ path: "conf.d/10-home.conf", line: 2 }} />);

    const editor = (await screen.findByLabelText(/File text/)) as HTMLTextAreaElement;

    expect(configApi.file).toHaveBeenCalledWith("conf.d/10-home.conf");
    await waitFor(() => expect(editor.selectionStart).toBe("Host nas\n".length));
    expect(editor.selectionEnd).toBe("Host nas\n\tUser aida".length);
    expect(editor).toHaveFocus();
    expect(screen.getByText(/conf\.d\/10-home\.conf.*line 2/)).toBeInTheDocument();
  });

  it("creates a new configuration file inside ~/.ssh", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t2", written: ["conf.d/30-lab.conf"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);

    render(<ConfigExplorer />);

    await user.type(await screen.findByLabelText("New file path"), "conf.d/30-lab.conf");
    await user.click(screen.getByRole("button", { name: "Create file" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "conf.d/30-lab.conf",
      base: "",
      raw: "# created by sshc\n",
    }));
  });
});
