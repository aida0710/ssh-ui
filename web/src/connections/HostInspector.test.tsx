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
    // キャプションはパネルが既に使っていたものとバイト単位で同一であるため、
    // エンドツーエンドスイートの`getByLabel(/Display order/)`は移動後も
    // 同じコントロールを指し続ける。
    expect(screen.getByLabelText(/^Tags/)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Display order/)).toBeInTheDocument();
    expect(screen.getByLabelText("Colour")).toBeInTheDocument();
  });

  it("edits the display order the metadata schema has always carried", async () => {
    const onMetadata = vi.fn();
    const user = userEvent.setup();
    render(<HostInspector detail={build()} onMetadata={onMetadata} />);

    // 一文字ずつ。この入力欄はモックされた親が決して書き戻さない
    // メタデータに制御されているため、各キー入力は同じ値から始まる。
    await user.type(screen.getByLabelText(/^Display order/), "7");

    expect(onMetadata).toHaveBeenLastCalledWith(expect.objectContaining({ order: 7 }));
  });

  it("clears a colour rather than leaving the picker's fallback as a real value", async () => {
    const onMetadata = vi.fn();
    const user = userEvent.setup();
    const detail = build();
    detail.metadata = { ...detail.metadata, colour: "#f97316" };
    render(<HostInspector detail={detail} onMetadata={onMetadata} />);

    // colour 入力欄には空の状態がないため、未設定の colour は中立の
    // 見本を示す。クリア操作はそれ自体独立した行為でなければ、
    // 「colour がない」ことと「たまたまグレーである colour」が区別できなくなる。
    await user.click(screen.getByRole("button", { name: "Clear colour" }));

    expect(onMetadata).toHaveBeenLastCalledWith(expect.objectContaining({ colour: "" }));
  });

  it("offers no clear button when there is no colour to clear", () => {
    render(<HostInspector detail={build()} onMetadata={vi.fn()} />);

    expect(screen.queryByRole("button", { name: "Clear colour" })).not.toBeInTheDocument();
  });

  // ファイルへ書き込む三つはメインペインに残る。ペインは設定
  // ファイルの中身と自分たち自身の note とを分けるものだからである。
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

  // "Inherited"とは、値の由来がこのブロック以外のファイルであることを意味する。
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
