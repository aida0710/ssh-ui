import { beforeEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({
  bootstrapSession: vi.fn(),
  health: vi.fn(),
  render: vi.fn(),
}));

vi.mock("./session/bootstrap", () => ({ bootstrapSession: mocked.bootstrapSession }));
vi.mock("./api/client", () => ({ apiClient: { health: mocked.health } }));
vi.mock("react-dom/client", () => ({ createRoot: () => ({ render: mocked.render }) }));

describe("main", () => {
  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    mocked.bootstrapSession.mockReset().mockResolvedValue({ csrfToken: "c".repeat(43) });
    mocked.health.mockReset();
    mocked.render.mockReset();
    vi.resetModules();
  });

  it("creates one shared bootstrap exchange before rendering StrictMode", async () => {
    await import("./main");

    expect(mocked.bootstrapSession).toHaveBeenCalledTimes(1);
    expect(mocked.render).toHaveBeenCalledTimes(1);
  });
});
