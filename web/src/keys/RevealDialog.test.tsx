import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RevealDialog } from "./RevealDialog";

const privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n";

function revealing() {
  return vi.fn().mockResolvedValue({
    id: "key-one",
    relativePath: "id_work",
    privateKey,
    encrypted: true,
    fingerprint: "SHA256:abcdef",
    transactionId: "tx",
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("RevealDialog", () => {
  it("shows nothing until the user confirms and states what it cannot protect", async () => {
    const reveal = revealing();
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={vi.fn()} />);

    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
    expect(screen.getByRole("dialog")).toHaveTextContent("browser extensions");
    expect(reveal).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));

    expect(await screen.findByLabelText("Private key")).toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
    expect(reveal).toHaveBeenCalledTimes(1);
  });

  it("drops the key material and never stores it when the dialog closes", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const onClose = vi.fn();
    const reveal = revealing();
    const { unmount } = render(
      <RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={onClose} />,
    );

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));
    expect(await screen.findByLabelText("Private key")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(screen.queryByLabelText("Private key")).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");

    unmount();
    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  // A key left on a global would outlive the dialog and be readable from the
  // console by anything else running in the page.
  it("puts the key material on no global object", async () => {
    const reveal = revealing();
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));
    expect(await screen.findByLabelText("Private key")).toBeInTheDocument();

    const globals = window as unknown as Record<string, unknown>;
    for (const name of Object.keys(globals)) {
      const value = globals[name];
      if (typeof value === "string" && value.includes("BEGIN OPENSSH PRIVATE KEY")) {
        throw new Error(`key material was left on window.${name}`);
      }
    }
  });

  it("reports a failed reveal without leaving stale material behind", async () => {
    const reveal = vi.fn().mockRejectedValue(new Error("api_mutation_failed"));
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("could not be shown");
    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
  });

  // One confirmation buys one reveal. Showing the key again must cost a new
  // token, so the dialog must not keep the material to re-display.
  it("requires a fresh confirmation to show the key a second time", async () => {
    const reveal = revealing();
    const onClose = vi.fn();
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={onClose} />);

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));
    expect(await screen.findByLabelText("Private key")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));

    expect(screen.getByRole("button", { name: "Show private key" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Private key")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Show private key" }));
    expect(await screen.findByLabelText("Private key")).toBeInTheDocument();
    expect(reveal).toHaveBeenCalledTimes(2);
  });
  it("copies exactly the key it showed, and offers no copy before the reveal", async () => {
    const user = userEvent.setup();
    const reveal = revealing();
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={vi.fn()} />);

    // Opening the dialog is not a disclosure, so there is nothing to copy yet.
    expect(screen.queryByRole("button", { name: "Copy private key" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show private key" }));
    await screen.findByLabelText("Private key");
    await user.click(screen.getByRole("button", { name: "Copy private key" }));

    expect(await navigator.clipboard.readText()).toBe(privateKey);
  });

  it("takes the copy control away with the key when the dialog closes", async () => {
    const user = userEvent.setup();
    const reveal = revealing();
    render(<RevealDialog keyId="key-one" relativePath="id_work" api={{ reveal }} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Show private key" }));
    await screen.findByLabelText("Private key");
    await user.click(screen.getByRole("button", { name: "Close" }));

    expect(screen.queryByRole("button", { name: "Copy private key" })).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("BEGIN OPENSSH PRIVATE KEY");
  });
});
