import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { CopyButton } from "./CopyButton";

describe("CopyButton", () => {
  it("writes exactly the value it was given", async () => {
    const user = userEvent.setup();
    render(<CopyButton value="ssh -- bastion" label="copy.command" />);

    await user.click(screen.getByRole("button", { name: "Copy command" }));

    expect(await navigator.clipboard.readText()).toBe("ssh -- bastion");
    expect(screen.getByText("Copied.")).toBeInTheDocument();
  });

  it("says the write was refused rather than claiming it succeeded", async () => {
    const user = userEvent.setup();
    // A browser policy or an extension can refuse the write. A button that
    // reported success anyway would send the user to paste something that is
    // not there.
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));
    render(<CopyButton value="ssh -- bastion" label="copy.command" />);

    await user.click(screen.getByRole("button", { name: "Copy command" }));

    expect(await screen.findByText(/refused to write to the clipboard/)).toBeInTheDocument();
    expect(screen.queryByText("Copied.")).not.toBeInTheDocument();
  });

  it("stops claiming a copy once the value has changed underneath it", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<CopyButton value="first" label="copy.command" />);

    await user.click(screen.getByRole("button", { name: "Copy command" }));
    expect(screen.getByText("Copied.")).toBeInTheDocument();

    // The clipboard still holds "first". Saying "Copied." next to "second"
    // would tell the user the thing on screen is the thing they can paste.
    rerender(<CopyButton value="second" label="copy.command" />);

    expect(screen.queryByText("Copied.")).not.toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe("first");
  });

  it("names what it copies, so two buttons on one screen are distinguishable", () => {
    render(
      <>
        <CopyButton value="a" label="copy.keyLine" />
        <CopyButton value="b" label="copy.remoteCommand" />
      </>,
    );

    expect(screen.getByRole("button", { name: "Copy key line" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy remote command" })).toBeInTheDocument();
  });
});
