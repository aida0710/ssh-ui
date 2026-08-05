import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConnectionsPage } from "./ConnectionsPage";
import { ApiError } from "../api/client";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return { ...actual, configApi: { overview: vi.fn(), host: vi.fn(), file: vi.fn(), preview: vi.fn(), save: vi.fn() } };
});

const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [{ file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 }],
  hosts: [{
    identity: { path: "config", alias: "bastion" },
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    line: 1, patterns: ["bastion"], editable: true,
  }],
  metadata: { schemaVersion: 1 },
  diagnostics: [],
  notices: [],
};

const detail = {
  form: {
    entry: overview.hosts[0],
    fields: [{ line: 2, keyword: "Port", values: ["22"], category: "basic", editable: true }],
    raw: "Host bastion\n\tPort 22\n",
  },
  metadata: { identity: { path: "config", alias: "bastion" } },
  effective: { alias: "bastion", approximate: true, entries: [] },
  file: {
    file: { path: "config", absolute: "/home/tester/.ssh/config" },
    contents: "Host bastion\n\tPort 22\n", digest: "digest", editable: true, exists: true,
  },
};

beforeEach(() => {
  // The module factory builds these with vi.fn(), which restoreMocks leaves
  // alone, so their call records have to be cleared per test by hand.
  vi.clearAllMocks();
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.host).mockResolvedValue(detail as never);
});

describe("ConnectionsPage", () => {
  it("loads the tree, opens a host and saves a field edit with the loaded base", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["config"], preview: { operation: "config.host_fields", diffs: [] },
    } as never);

    render(<ConnectionsPage onOpenFile={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    const input = await screen.findByLabelText("Port");
    await user.clear(input);
    await user.type(input, "2222");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "host_fields",
      path: "config",
      alias: "bastion",
      base: "Host bastion\n\tPort 22\n",
      fields: [{ action: "set", line: 2, values: ["2222"] }],
    }));
    expect(configApi.host).toHaveBeenCalledWith("config", "bastion");
  });

  it("keeps the diff of what was written on screen after the save reloads the host", async () => {
    // The save reselects the host it wrote. That used to hand the selection
    // effect a new object with the same two values, so the effect fetched the
    // detail a second time and, on the answer, cleared the preview: the diff
    // was visible for exactly as long as one request took. The end-to-end suite
    // saw it because it happened to look inside that window, and failed in CI
    // when it did not.
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1",
      written: ["config"],
      preview: {
        operation: "config.host_fields",
        diffs: [{
          path: "config",
          lines: [
            { op: "delete", text: "\tPort 22", oldLine: 2 },
            { op: "insert", text: "\tPort 2299", newLine: 2 },
          ],
        }],
      },
    } as never);

    render(<ConnectionsPage onOpenFile={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    const input = await screen.findByLabelText("Port");
    await user.clear(input);
    await user.type(input, "2299");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    // Twice in the whole flow: once for the selection, once for the reload the
    // save performs itself. A third is the duplicate that discarded the diff.
    await waitFor(() => expect(configApi.host).toHaveBeenCalledTimes(2));
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(configApi.host).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("region", { name: "Save preview" })).toHaveTextContent("Port 2299");
  });

  it("discards the diff when a different connection is opened", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      hosts: [
        ...overview.hosts,
        {
          identity: { path: "config", alias: "nas" },
          file: { path: "config", absolute: "/home/tester/.ssh/config" },
          line: 5, patterns: ["nas"], editable: true,
        },
      ],
    } as never);
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1",
      written: ["config"],
      preview: {
        operation: "config.host_fields",
        diffs: [{ path: "config", lines: [{ op: "insert", text: "\tPort 2299", newLine: 2 }] }],
      },
    } as never);

    render(<ConnectionsPage onOpenFile={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    const input = await screen.findByLabelText("Port");
    await user.clear(input);
    await user.type(input, "2299");
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText(/Port 2299/);

    await user.click(screen.getByRole("button", { name: /nas/ }));

    // The diff describes bytes in a block that is no longer open.
    await waitFor(() =>
      expect(screen.getByRole("region", { name: "Save preview" }))
        .toHaveTextContent("Change a value to see exactly what would be written."));
  });

  it("sends a pattern rule to the file view and never asks for its host detail", async () => {
    const user = userEvent.setup();
    const onOpenFile = vi.fn();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      hosts: [
        ...overview.hosts,
        {
          identity: { path: "", alias: "" },
          file: { path: "config", absolute: "/home/tester/.ssh/config" },
          line: 9, patterns: ["*"], wildcard: true, editable: true,
        },
      ],
    } as never);

    render(<ConnectionsPage onOpenFile={onOpenFile} />);

    await user.click(await screen.findByRole("button", { name: /pattern rule/i }));

    expect(onOpenFile).toHaveBeenCalledWith("config", 9);
    expect(configApi.host).not.toHaveBeenCalled();
    expect(screen.getByText("Select a connection to edit it.")).toBeInTheDocument();
  });

  it("keeps the edit visible and shows the conflict when the file changed on disk", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockRejectedValue(new ApiError("config_conflict", 409, {
      code: "config_conflict",
      message: "request rejected",
      path: "config",
      conflict: {
        path: "config",
        externalChange: [{ op: "insert", text: "Host other", newLine: 3 }],
        localChange: [{ op: "delete", text: "\tPort 22", oldLine: 2 }],
      },
    }));

    render(<ConnectionsPage onOpenFile={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    const input = await screen.findByLabelText("Port");
    await user.clear(input);
    await user.type(input, "2222");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/changed outside this application/i);
    expect(screen.getByText("Changed on disk since you loaded it")).toBeInTheDocument();
    expect(screen.getByLabelText("Port")).toHaveValue("2222");
  });

  it("creates a host by appending a block to the chosen file", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["config"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);
    vi.mocked(configApi.file).mockResolvedValue({
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      contents: "Host bastion\n\tPort 22\n", digest: "digest", editable: true, exists: true,
    } as never);

    render(<ConnectionsPage onOpenFile={vi.fn()} />);

    await user.type(await screen.findByLabelText("New connection alias"), "build01");
    await user.click(screen.getByRole("button", { name: "Create connection" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "config",
      base: "Host bastion\n\tPort 22\n",
      raw: "Host bastion\n\tPort 22\n\nHost build01\n\tHostName build01\n",
    }));
  });

  it("moves a host to another file with both loaded bases", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      files: [
        { file: { path: "config", absolute: "/home/tester/.ssh/config" }, editable: true, loads: 1 },
        { file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" }, editable: true, loads: 1 },
      ],
    } as never);
    vi.mocked(configApi.file).mockResolvedValue({
      file: { path: "conf.d/10-home.conf", absolute: "/home/tester/.ssh/conf.d/10-home.conf" },
      contents: "Host nas\n\tUser aida\n", digest: "digest", editable: true, exists: true,
    } as never);
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1",
      written: ["config", "conf.d/10-home.conf"],
      preview: { operation: "config.move", diffs: [] },
    } as never);

    render(<ConnectionsPage onOpenFile={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    await user.selectOptions(await screen.findByLabelText("Move to file"), "conf.d/10-home.conf");
    await user.click(screen.getByRole("button", { name: "Move connection" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "move",
      path: "config",
      base: "Host bastion\n\tPort 22\n",
      alias: "bastion",
      destinationPath: "conf.d/10-home.conf",
      destinationBase: "Host nas\n\tUser aida\n",
    }));
  });

  it("deletes the selected host block without touching the rest of the file", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1", written: ["config"], preview: { operation: "config.file_raw", diffs: [] },
    } as never);

    render(<ConnectionsPage onOpenFile={vi.fn()} />);

    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    await user.click(await screen.findByRole("button", { name: "Delete connection" }));
    await user.click(screen.getByRole("button", { name: "Confirm delete" }));

    await waitFor(() => expect(configApi.save).toHaveBeenCalledWith({
      kind: "file_raw",
      path: "config",
      base: "Host bastion\n\tPort 22\n",
      raw: "",
    }));
  });
});

describe("taking a connection out of every group", () => {
  const grouped = {
    ...detail,
    form: { ...detail.form, entry: { ...detail.form.entry, group: "work" } },
  };

  it("sends it to the entry file, with that file's own bytes as the precondition", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.host).mockResolvedValue(grouped as never);
    vi.mocked(configApi.file).mockResolvedValue({
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      contents: "Host other\n", digest: "d", editable: true, exists: true,
    } as never);
    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "tx", written: [], preview: { operation: "config.move", diffs: [] },
    } as never);

    render(<ConnectionsPage onOpenFile={vi.fn()} />);
    await user.click(await screen.findByRole("button", { name: /bastion/ }));
    await user.selectOptions(await screen.findByLabelText("Primary group"), "");
    await user.click(screen.getByRole("button", { name: "Move to this group" }));

    await waitFor(() =>
      expect(configApi.save).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "move",
          alias: "bastion",
          destinationPath: "config",
          destinationBase: "Host other\n",
        }),
      ),
    );
  });
});
