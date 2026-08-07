import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { GroupInspector } from "./GroupInspector";
import type { GroupMetadata } from "../api/config";

function group(overrides: Partial<GroupMetadata> = {}): GroupMetadata {
  return { name: "company", ...overrides } as GroupMetadata;
}

describe("GroupInspector", () => {
  it("edits the three things that live only in metadata", async () => {
    const onUpdate = vi.fn();
    const user = userEvent.setup();
    render(<GroupInspector group={group()} members={[]} onUpdate={onUpdate} />);

    // 一文字ずつ。このコントロールはモックされた親が決して書き戻さない
    // メタデータに制御されているため、各キー入力は同じ値から始まる。
    await user.type(screen.getByLabelText("Display order"), "3");
    expect(onUpdate).toHaveBeenLastCalledWith({ order: 3 });

    expect(screen.getByLabelText("Colour")).toBeInTheDocument();
    expect(screen.getByLabelText("Hide company from Connections")).toBeInTheDocument();
  });

  it("offers hiding for a group that holds no connections of its own", async () => {
    const onUpdate = vi.fn();
    const user = userEvent.setup();
    render(<GroupInspector group={group({ name: "company/eu" })} members={[]} onUpdate={onUpdate} />);

    const toggle = screen.getByLabelText("Hide company/eu from Connections");
    expect(toggle).toBeEnabled();

    await user.click(toggle);

    expect(onUpdate).toHaveBeenCalledWith({ hidden: true });
  });

  // 接続を保持するグループを隠せば、それらも一緒に見えなくなってしまう。
  // コントロールを拒否する方が、黙って何もしないフラグよりましである。
  it("refuses hiding for a group that holds connections, and says why", () => {
    render(<GroupInspector group={group()} members={["build01"]} onUpdate={vi.fn()} />);

    expect(screen.getByLabelText("Hide company from Connections")).toBeDisabled();
    expect(screen.getByText(/holds connections of its own/)).toBeInTheDocument();
  });

  // colour 入力欄には空の状態がないため、未設定の colour は中立の
  // 見本を示し、クリア操作はそれ自体独立した行為でなければならない
  // ——さもなければ「colour がない」ことと「たまたまグレーである colour」が区別できなくなる。
  it("offers no clear button until there is a colour to clear", async () => {
    const onUpdate = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(<GroupInspector group={group()} members={[]} onUpdate={onUpdate} />);

    expect(screen.queryByRole("button", { name: "Clear company colour" })).toBeNull();

    rerender(<GroupInspector group={group({ colour: "#f97316" })} members={[]} onUpdate={onUpdate} />);
    await user.click(screen.getByRole("button", { name: "Clear company colour" }));

    expect(onUpdate).toHaveBeenLastCalledWith({ colour: "" });
  });
});
