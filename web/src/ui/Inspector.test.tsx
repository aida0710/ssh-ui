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

  // Notices live inside a pane that is shut by default, so a host with a
  // problem would look exactly like one without. The dot is what makes the
  // pane worth opening, and it has to reach a screen reader too.
  it("says so when what is inside needs attention", () => {
    render(<InspectorToggle open={false} attention onToggle={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Show details Needs attention" })).toBeInTheDocument();
  });

  // An exact match on the whole accessible name, which is what makes this the
  // opposite of the test above rather than a weaker version of it.
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
