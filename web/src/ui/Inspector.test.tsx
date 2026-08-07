import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { InspectorPane, InspectorToggle } from "./Inspector";

describe("InspectorToggle", () => {
  it("says whether the pane is open", () => {
    render(<InspectorToggle open={false} attention={false} onToggle={vi.fn()} />);

    const button = screen.getByRole("button", { name: "Show details" });
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(button).toHaveAttribute("aria-controls", "inspector");
  });

  it("changes its name when open", () => {
    render(<InspectorToggle open attention={false} onToggle={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Hide details" })).toHaveAttribute("aria-expanded", "true");
  });

  // notice は既定で閉じているペインの中に住んでいるので、問題を抱えた
  // ホストは問題のないホストとまったく同じに見えてしまう。ドットこそが
  // ペインを開く価値のあるものにし、それはスクリーンリーダーにも届かなければならない。
  it("says so when what is inside needs attention", () => {
    render(<InspectorToggle open={false} attention onToggle={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Show details Needs attention" })).toBeInTheDocument();
  });

  // accessible name 全体への完全一致であり、それがこのテストを上の
  // テストの弱い版ではなく正反対のものにしている。
  it("does not say so otherwise", () => {
    render(<InspectorToggle open={false} attention={false} onToggle={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Show details" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Needs attention/ })).toBeNull();
  });

  it("reports a click", async () => {
    const onToggle = vi.fn();
    const user = userEvent.setup();
    render(<InspectorToggle open={false} attention={false} onToggle={onToggle} />);

    await user.click(screen.getByRole("button", { name: "Show details" }));

    expect(onToggle).toHaveBeenCalledOnce();
  });
});

describe("InspectorPane", () => {
  it("is a labelled complementary region the toggle can address", () => {
    render(<InspectorPane label="Details">nothing yet</InspectorPane>);

    const pane = screen.getByRole("complementary", { name: "Details" });
    expect(pane).toHaveAttribute("id", "inspector");
    expect(pane).toHaveTextContent("nothing yet");
  });
});
