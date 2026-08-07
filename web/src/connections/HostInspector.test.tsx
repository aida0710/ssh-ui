import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HostInspector, hostNeedsAttention } from "./HostInspector";
import type { HostDetail } from "../api/config";

function build(): HostDetail {
  return {
    form: {
      entry: {
        identity: { path: "connections/work/bastion.conf", alias: "bastion" },
        file: {
          path: "connections/work/bastion.conf",
          absolute: "/home/tester/.ssh/connections/work/bastion.conf",
        },
        line: 1,
        patterns: ["bastion"],
        group: "work",
        editable: true,
      },
      fields: [],
      raw: "Host bastion\n",
      comment: "",
      commentLines: 0,
      notices: [],
    },
    metadata: { identity: { path: "connections/work/bastion.conf", alias: "bastion" }, favourite: false },
    effective: { alias: "bastion", approximate: true, entries: [], notices: [] },
    file: {
      file: {
        path: "connections/work/bastion.conf",
        absolute: "/home/tester/.ssh/connections/work/bastion.conf",
      },
      contents: "Host bastion\n",
      digest: "digest",
      editable: true,
      exists: true,
    },
  } as HostDetail;
}

describe("hostNeedsAttention", () => {
  it("is false when nothing is reported", () => {
    expect(hostNeedsAttention(build())).toBe(false);
  });

  it("is true when the block has a notice", () => {
    const detail = build();
    detail.form.notices = [{ code: "duplicate_alias", path: "config", line: 41 }];
    expect(hostNeedsAttention(detail)).toBe(true);
  });

  it("is true when the resolved values carry one", () => {
    const detail = build();
    detail.effective.notices = [{ code: "complex_external_rule" }];
    expect(hostNeedsAttention(detail)).toBe(true);
  });
});

describe("HostInspector", () => {
  it("edits the four things that live only in metadata", async () => {
    const onMetadata = vi.fn();
    const user = userEvent.setup();
    render(<HostInspector detail={build()} onMetadata={onMetadata} />);

    await user.click(screen.getByLabelText("Favourite"));

    expect(onMetadata).toHaveBeenCalledWith(expect.objectContaining({ favourite: true }));
    // The captions are the ones the panel already used, byte for byte, so the
    // end-to-end suite's `getByLabel(/Display order/)` still names the same
    // control after the move.
    expect(screen.getByLabelText(/^Tags/)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Display order/)).toBeInTheDocument();
    expect(screen.getByLabelText("Colour")).toBeInTheDocument();
  });

  it("edits the display order the metadata schema has always carried", async () => {
    const onMetadata = vi.fn();
    const user = userEvent.setup();
    render(<HostInspector detail={build()} onMetadata={onMetadata} />);

    // One character at a time: this input is controlled by metadata the mocked
    // parent never writes back, so each keystroke starts from the same value.
    await user.type(screen.getByLabelText(/^Display order/), "7");

    expect(onMetadata).toHaveBeenLastCalledWith(expect.objectContaining({ order: 7 }));
  });

  it("clears a colour rather than leaving the picker's fallback as a real value", async () => {
    const onMetadata = vi.fn();
    const user = userEvent.setup();
    const detail = build();
    detail.metadata = { ...detail.metadata, colour: "#f97316" };
    render(<HostInspector detail={detail} onMetadata={onMetadata} />);

    // A colour input has no empty state, so an unset colour shows a neutral
    // swatch. Clearing has to be its own act or "no colour" would be
    // indistinguishable from "the colour that happens to be grey".
    await user.click(screen.getByRole("button", { name: "Clear colour" }));

    expect(onMetadata).toHaveBeenLastCalledWith(expect.objectContaining({ colour: "" }));
  });

  it("offers no clear button when there is no colour to clear", () => {
    render(<HostInspector detail={build()} onMetadata={vi.fn()} />);

    expect(screen.queryByRole("button", { name: "Clear colour" })).not.toBeInTheDocument();
  });

  // The three that write to a file stay in the main pane, because the pane is
  // what separates a configuration file's contents from our own notes.
  it("does not offer the group, the comment or the rename", () => {
    render(<HostInspector detail={build()} onMetadata={vi.fn()} />);

    expect(screen.queryByLabelText("Primary group")).toBeNull();
    expect(screen.queryByLabelText("Comment")).toBeNull();
    expect(screen.queryByLabelText("Rename alias")).toBeNull();
  });

  it("lists the notices this connection has", () => {
    const detail = build();
    detail.form.notices = [{ code: "duplicate_alias", path: "config", line: 41 }];
    render(<HostInspector detail={detail} onMetadata={vi.fn()} />);

    expect(screen.getByText(/config:41/)).toBeInTheDocument();
  });

  // "Inherited" means the value's source is a file other than this block's.
  it("lists only the values that came from elsewhere", () => {
    const detail = build();
    detail.effective.entries = [
      { keyword: "Port", values: ["22"], source: { path: "groups.sshc.conf", line: 3 } },
      { keyword: "User", values: ["aida"], source: { path: "connections/work/bastion.conf", line: 2 } },
    ];
    render(<HostInspector detail={detail} onMetadata={vi.fn()} />);

    expect(screen.getByText(/Port 22/)).toBeInTheDocument();
    expect(screen.queryByText(/User aida/)).toBeNull();
  });
});
