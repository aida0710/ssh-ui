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

    // One character at a time: the control is driven by metadata the mocked
    // parent never writes back, so each keystroke starts from the same value.
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

  // Hiding a group that holds connections would take them out of view with it.
  // Refusing the control is better than a flag that quietly does nothing.
  it("refuses hiding for a group that holds connections, and says why", () => {
    render(<GroupInspector group={group()} members={["build01"]} onUpdate={vi.fn()} />);

    expect(screen.getByLabelText("Hide company from Connections")).toBeDisabled();
    expect(screen.getByText(/holds connections of its own/)).toBeInTheDocument();
  });

  // A colour input has no empty state, so an unset colour shows a neutral
  // swatch and clearing has to be its own act — otherwise "no colour" is
  // indistinguishable from "the colour that happens to be grey".
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
