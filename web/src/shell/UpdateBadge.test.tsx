import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { UpdateBadge } from "./UpdateBadge";
import type { IntegrationsApi, UpdateStatus } from "../api/integrations";

function buildApi(status: UpdateStatus, overrides: Partial<IntegrationsApi> = {}): IntegrationsApi {
  return { updateStatus: vi.fn().mockResolvedValue(status), ...overrides } as unknown as IntegrationsApi;
}

describe("UpdateBadge", () => {
  it("shows the version and offers nothing when there is nothing newer", async () => {
    render(<UpdateBadge api={buildApi({ current: "0.1.0", available: false })} />);

    expect(await screen.findByText("Version 0.1.0")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  // ボタンではなくリンクだ。このアプリケーションは何も取得せず
  // 何も置き換えない: 新しいバージョンがあると伝え、決めるのは人だ。
  it("links to the release rather than offering to install it", async () => {
    render(
      <UpdateBadge
        api={buildApi({
          current: "0.1.0",
          latest: "0.2.0",
          available: true,
          pageUrl: "https://example.invalid/releases/v0.2.0",
        })}
      />,
    );

    const link = await screen.findByRole("link", { name: /0\.2\.0 is available/ });
    expect(link).toHaveAttribute("href", "https://example.invalid/releases/v0.2.0");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  // ネットワークのないマシンでも、自分のバージョンは表示し続ける。
  it("shows nothing at all when the check cannot run", async () => {
    const api = buildApi({ current: "0.1.0", available: false }, {
      updateStatus: vi.fn().mockRejectedValue(new Error("update_check_failed")),
    });
    const { container } = render(<UpdateBadge api={api} />);
    await waitFor(() => expect(api.updateStatus).toHaveBeenCalled());
    expect(container.textContent).toBe("");
  });
});
