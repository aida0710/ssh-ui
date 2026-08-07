import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { UpdateBadge } from "./UpdateBadge";
import type { IntegrationsApi, UpdateStatus } from "../api/integrations";

function buildApi(status: UpdateStatus, overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return {
    updateStatus: vi.fn().mockResolvedValue(status),
    applyUpdate: vi.fn().mockResolvedValue({ ...status, available: false, restartRequired: true }),
    ...overrides,
  } as unknown as IntegrationsApi;
}

describe("UpdateBadge", () => {
  it("shows the version and offers nothing when there is nothing newer", async () => {
    render(<UpdateBadge api={buildApi({ current: "0.1.0", updatable: true, available: false, restartRequired: false })} />);

    expect(await screen.findByText("Version 0.1.0")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Update" })).not.toBeInTheDocument();
  });

  // Replacing a file is not a thing to do to somebody without saying which
  // file, so the path is shown before the button is pressed.
  it("names the file it would replace, and says a restart is needed after", async () => {
    const api = buildApi({
      current: "0.1.0",
      updatable: true,
      latest: "0.2.0",
      available: true,
      restartRequired: false,
      path: "/Users/tester/.local/bin/ssh-ui",
    });
    render(<UpdateBadge api={api} />);

    expect(await screen.findByText("0.2.0 is available")).toBeInTheDocument();
    expect(screen.getByText("/Users/tester/.local/bin/ssh-ui")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Update" }));
    await waitFor(() => expect(api.applyUpdate).toHaveBeenCalled());
    // What is running goes on running: replacing a file does not replace what
    // is already in memory, and saying otherwise would be a lie.
    expect(await screen.findByText(/Restart ssh-ui/)).toBeInTheDocument();
  });

  it("says the update failed rather than claiming it happened", async () => {
    const api = buildApi(
      { current: "0.1.0", updatable: true, latest: "0.2.0", available: true, restartRequired: false },
      { applyUpdate: vi.fn().mockRejectedValue(new Error("update_failed")) },
    );
    render(<UpdateBadge api={api} />);

    await userEvent.click(await screen.findByRole("button", { name: "Update" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be applied/i);
  });

  // A machine with no network still shows its version.
  it("shows nothing at all when the check cannot run", async () => {
    const api = buildApi({ current: "0.1.0", updatable: true, available: false, restartRequired: false }, {
      updateStatus: vi.fn().mockRejectedValue(new Error("update_check_failed")),
    });
    const { container } = render(<UpdateBadge api={api} />);
    await waitFor(() => expect(api.updateStatus).toHaveBeenCalled());
    expect(container.textContent).toBe("");
  });

  // A build made from a working tree says how it is updated instead of
  // offering a button it could not honour.
  it("tells a source build to use make update", async () => {
    render(<UpdateBadge api={buildApi({ current: "dev", available: false, updatable: false, restartRequired: false })} />);

    expect(await screen.findByText(/make update/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Update" })).not.toBeInTheDocument();
  });
});
